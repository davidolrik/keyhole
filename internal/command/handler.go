package command

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/audit"
	"go.olrik.dev/keyhole/internal/crypto"
	"go.olrik.dev/keyhole/internal/storage"
	"go.olrik.dev/keyhole/internal/vault"
)

const (
	maxSecretSize   = 64 * 1024 // 64KB
	maxSetAttempts  = 3
	inviteCodeBytes = 32
)

// Handler routes parsed commands to storage and crypto operations.
type Handler struct {
	store           storage.Store
	fileStore       *storage.FileStore
	enc             *crypto.Encryptor
	vaultMgr        *vault.Manager
	serverSecret    []byte
	dataDir         string
	admins          map[string]bool
	version         string
	auditLog        *audit.Logger
	readLineTimeout time.Duration
	inviteCodeTTL   time.Duration
}

// NewHandler creates a Handler.
func NewHandler(store storage.Store, fileStore *storage.FileStore, enc *crypto.Encryptor, vaultMgr *vault.Manager, serverSecret []byte, dataDir string, admins []string, version string, auditLog *audit.Logger, readLineTimeout time.Duration, inviteCodeTTL time.Duration) *Handler {
	adminSet := make(map[string]bool, len(admins))
	for _, a := range admins {
		adminSet[a] = true
	}
	return &Handler{
		store:           store,
		fileStore:       fileStore,
		enc:             enc,
		vaultMgr:        vaultMgr,
		serverSecret:    serverSecret,
		dataDir:         dataDir,
		admins:          adminSet,
		version:         version,
		auditLog:        auditLog,
		readLineTimeout: readLineTimeout,
		inviteCodeTTL:   inviteCodeTTL,
	}
}

// Handle executes a Command in the context of an SSH session.
// sess is the gliderlabs SSH session; username and pubKey are the authenticated identity.
func (h *Handler) Handle(sess ssh.Session, username string, pubKey gossh.PublicKey, cmd Command) error {
	switch cmd.Op {
	case OpGet:
		if cmd.Vault != "" {
			return h.handleVaultGet(sess, username, pubKey, cmd.Vault, cmd.Path)
		}
		return h.handleGet(sess, username, pubKey, cmd.Path)
	case OpSet:
		if cmd.Vault != "" {
			return h.handleVaultSet(sess, username, pubKey, cmd.Vault, cmd.Path)
		}
		return h.handleSet(sess, username, pubKey, cmd.Path)
	case OpList:
		if cmd.Vault != "" {
			return h.handleVaultList(sess, username, cmd.Vault, cmd.Path, cmd.GlobMatch)
		}
		return h.handleList(sess, username, cmd.Path, cmd.GlobMatch)
	case OpInvite:
		return h.handleInvite(sess, username)
	case OpRegister:
		return h.handleRegister(sess, username, pubKey, cmd.InviteCode)
	case OpVaultCreate:
		return h.handleVaultCreate(sess, username, pubKey, cmd.Vault)
	case OpVaultInvite:
		return h.handleVaultInvite(sess, username, pubKey, cmd.Vault, cmd.TargetUser)
	case OpVaultAccept:
		return h.handleVaultAccept(sess, username, pubKey, cmd.Vault, cmd.InviteCode)
	case OpVaultPromote:
		return h.handleVaultPromote(sess, username, cmd.Vault, cmd.TargetUser)
	case OpVaultDemote:
		return h.handleVaultDemote(sess, username, cmd.Vault, cmd.TargetUser)
	case OpVaultRevoke:
		return h.handleVaultRevoke(sess, username, cmd.Vault, cmd.TargetUser)
	case OpVaultMembers:
		return h.handleVaultMembers(sess, username, cmd.Vault)
	case OpVaultList:
		return h.handleVaultListAll(sess, username)
	case OpVaultDestroy:
		return h.handleVaultDestroy(sess, username, cmd.Vault)
	case OpMove:
		return h.handleMove(sess, username, pubKey, cmd)
	case OpHelp:
		return h.handleHelp(sess)
	default:
		return fmt.Errorf("unknown operation")
	}
}

func (h *Handler) handleGet(sess ssh.Session, username string, pubKey gossh.PublicKey, path string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	ciphertext, err := h.store.Read(username, path)
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	plaintext, err := h.enc.DecryptAndUpgrade(ag, pubKey, h.serverSecret, username, path, ciphertext, func(upgraded []byte) error {
		return h.store.Write(username, path, upgraded)
	})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	defer crypto.Zeroize(plaintext)

	_, err = sess.Write(plaintext)
	return err
}

func (h *Handler) handleSet(sess ssh.Session, username string, pubKey gossh.PublicKey, path string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	var plaintext []byte
	defer func() { crypto.Zeroize(plaintext) }()

	if isTerminal(sess) {
		// PTY session: prompt with echo concealment and double-confirm
		plaintext, err = promptSecret(sess, h.readLineTimeout)
		if err != nil {
			return err
		}
	} else {
		// No PTY: print a prompt (visible for interactive users; harmless for piped input).
		// Echo is not suppressed — use 'ssh -t' for hidden input.
		fmt.Fprint(sess.Stderr(), "Enter secret (use 'ssh -t' for hidden input): ")
		plaintext, err = readLine(sess, h.readLineTimeout)
		if err != nil {
			return fmt.Errorf("read secret: %w", err)
		}
	}

	ciphertext, err := h.enc.Encrypt(ag, pubKey, h.serverSecret, username, path, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := h.store.Write(username, path, ciphertext); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}

	fmt.Fprintln(sess, "Secret stored.")
	return nil
}

func (h *Handler) handleList(sess ssh.Session, username string, prefix string, glob bool) error {
	var paths []string
	var err error

	if glob {
		// Fetch the narrowest superset we can from the store, then filter
		// by the literal prefix using strings.HasPrefix.
		// For "account/g*" the store prefix is "account"; for bare "g*" it's "".
		storePrefix := ""
		if idx := strings.LastIndex(prefix, "/"); idx >= 0 {
			storePrefix = prefix[:idx]
		}
		all, err := h.store.List(username, storePrefix)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		for _, p := range all {
			if strings.HasPrefix(p, prefix) {
				paths = append(paths, p)
			}
		}
	} else {
		paths, err = h.store.List(username, prefix)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
	}

	useColor := supportsColor(sess)
	for _, p := range paths {
		fmt.Fprintln(sess, FormatPath(p, useColor))
	}
	return nil
}

// FormatPath formats a secret path for display.
// When color is true and the path has a directory component, the directory
// prefix (including its trailing slash) is rendered in blue.
func FormatPath(p string, color bool) string {
	if !color {
		return p
	}
	idx := strings.LastIndex(p, "/")
	if idx == -1 {
		// No directory prefix — plain leaf at the root level.
		return p
	}
	const (
		blue  = "\033[34m"
		reset = "\033[0m"
	)
	// Color the directory part (up to and including the trailing slash) blue.
	return blue + p[:idx+1] + reset + p[idx+1:]
}

func (h *Handler) handleVaultGet(sess ssh.Session, username string, pubKey gossh.PublicKey, vaultName, path string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if !h.vaultMgr.HasAccess(vaultName, username) {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("get", username, sess.RemoteAddr().String(), vaultName, "not a member")
		}
		return fmt.Errorf("permission denied: not a member of vault %q", vaultName)
	}

	vaultKey, err := h.vaultMgr.VaultKey(vaultName, username, ag, pubKey)
	if err != nil {
		return fmt.Errorf("vault key: %w", err)
	}
	defer crypto.Zeroize(vaultKey)

	ciphertext, err := h.fileStore.ReadVaultSecret(vaultName, path)
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	plaintext, err := decryptVaultSecret(vaultKey, path, h.serverSecret, ciphertext, func(upgraded []byte) error {
		return h.fileStore.WriteVaultSecret(vaultName, path, upgraded)
	})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	defer crypto.Zeroize(plaintext)

	_, err = sess.Write(plaintext)
	return err
}

func (h *Handler) handleVaultSet(sess ssh.Session, username string, pubKey gossh.PublicKey, vaultName, path string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if !h.vaultMgr.HasAccess(vaultName, username) {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("set", username, sess.RemoteAddr().String(), vaultName, "not a member")
		}
		return fmt.Errorf("permission denied: not a member of vault %q", vaultName)
	}

	var plaintext []byte
	defer func() { crypto.Zeroize(plaintext) }()
	if isTerminal(sess) {
		plaintext, err = promptSecret(sess, h.readLineTimeout)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprint(sess.Stderr(), "Enter secret (use 'ssh -t' for hidden input): ")
		plaintext, err = readLine(sess, h.readLineTimeout)
		if err != nil {
			return fmt.Errorf("read secret: %w", err)
		}
	}

	vaultKey, err := h.vaultMgr.VaultKey(vaultName, username, ag, pubKey)
	if err != nil {
		return fmt.Errorf("vault key: %w", err)
	}
	defer crypto.Zeroize(vaultKey)

	secretKey, err := crypto.DeriveVaultSecretKey(vaultKey, path, h.serverSecret)
	if err != nil {
		return fmt.Errorf("derive secret key: %w", err)
	}
	defer crypto.Zeroize(secretKey)

	ciphertext, err := crypto.EncryptWithKey(secretKey, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := h.fileStore.WriteVaultSecret(vaultName, path, ciphertext); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}

	fmt.Fprintln(sess, "Secret stored.")
	return nil
}

func (h *Handler) handleVaultList(sess ssh.Session, username, vaultName, prefix string, glob bool) error {
	if !h.vaultMgr.HasAccess(vaultName, username) {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("list", username, sess.RemoteAddr().String(), vaultName, "not a member")
		}
		return fmt.Errorf("permission denied: not a member of vault %q", vaultName)
	}

	var paths []string
	var err error

	if glob {
		storePrefix := ""
		if idx := strings.LastIndex(prefix, "/"); idx >= 0 {
			storePrefix = prefix[:idx]
		}
		all, err := h.fileStore.ListVaultSecrets(vaultName, storePrefix)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		for _, p := range all {
			if strings.HasPrefix(p, prefix) {
				paths = append(paths, p)
			}
		}
	} else {
		paths, err = h.fileStore.ListVaultSecrets(vaultName, prefix)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
	}

	useColor := supportsColor(sess)
	for _, p := range paths {
		fmt.Fprintln(sess, FormatPath(p, useColor))
	}
	return nil
}

func (h *Handler) handleVaultCreate(sess ssh.Session, username string, pubKey gossh.PublicKey, vaultName string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.vaultMgr.Create(vaultName, username, ag, pubKey); err != nil {
		return fmt.Errorf("create vault: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("create", username, sess.RemoteAddr().String(), vaultName)
	}
	fmt.Fprintf(sess, "Vault %q created.\n", vaultName)
	return nil
}

func (h *Handler) handleVaultInvite(sess ssh.Session, username string, pubKey gossh.PublicKey, vaultName, targetUser string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	token, err := h.vaultMgr.Invite(vaultName, username, targetUser, ag, pubKey)
	if err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("invite", username, sess.RemoteAddr().String(), vaultName, err.Error(), "target", targetUser)
		}
		return fmt.Errorf("vault invite: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("invite", username, sess.RemoteAddr().String(), vaultName, "target", targetUser)
	}
	fmt.Fprintln(sess, token)
	return nil
}

func (h *Handler) handleVaultAccept(sess ssh.Session, username string, pubKey gossh.PublicKey, vaultName, token string) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.vaultMgr.Accept(vaultName, username, token, ag, pubKey); err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("accept", username, sess.RemoteAddr().String(), vaultName, err.Error())
		}
		return fmt.Errorf("vault accept: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("accept", username, sess.RemoteAddr().String(), vaultName)
	}
	fmt.Fprintf(sess, "Joined vault %q.\n", vaultName)
	return nil
}

func (h *Handler) handleVaultPromote(sess ssh.Session, username, vaultName, targetUser string) error {
	_, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.vaultMgr.Promote(vaultName, username, targetUser); err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("promote", username, sess.RemoteAddr().String(), vaultName, err.Error(), "target", targetUser)
		}
		return fmt.Errorf("vault promote: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("promote", username, sess.RemoteAddr().String(), vaultName, "target", targetUser)
	}
	fmt.Fprintf(sess, "Promoted %q to admin in vault %q.\n", targetUser, vaultName)
	return nil
}

func (h *Handler) handleVaultDemote(sess ssh.Session, username, vaultName, targetUser string) error {
	_, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.vaultMgr.Demote(vaultName, username, targetUser); err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("demote", username, sess.RemoteAddr().String(), vaultName, err.Error(), "target", targetUser)
		}
		return fmt.Errorf("vault demote: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("demote", username, sess.RemoteAddr().String(), vaultName, "target", targetUser)
	}
	fmt.Fprintf(sess, "Demoted %q to member in vault %q.\n", targetUser, vaultName)
	return nil
}

func (h *Handler) handleVaultRevoke(sess ssh.Session, username, vaultName, targetUser string) error {
	_, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.vaultMgr.Revoke(vaultName, username, targetUser); err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("revoke", username, sess.RemoteAddr().String(), vaultName, err.Error(), "target", targetUser)
		}
		return fmt.Errorf("vault revoke: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("revoke", username, sess.RemoteAddr().String(), vaultName, "target", targetUser)
	}
	fmt.Fprintf(sess, "Revoked %q from vault %q.\n", targetUser, vaultName)
	return nil
}

func (h *Handler) handleVaultMembers(sess ssh.Session, username, vaultName string) error {
	// HasAccess returns false for both non-existent vaults and non-members,
	// producing a uniform error that doesn't leak vault existence.
	if !h.vaultMgr.HasAccess(vaultName, username) {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("members", username, sess.RemoteAddr().String(), vaultName, "not a member")
		}
		return fmt.Errorf("permission denied: not a member of vault %q", vaultName)
	}

	members, err := h.vaultMgr.Members(vaultName)
	if err != nil {
		return fmt.Errorf("vault members: %w", err)
	}

	for user, role := range members {
		fmt.Fprintf(sess, "  %s (%s)\n", user, role)
	}
	return nil
}

func (h *Handler) handleVaultListAll(sess ssh.Session, username string) error {
	vaults, err := h.vaultMgr.ListVaults(username)
	if err != nil {
		return fmt.Errorf("list vaults: %w", err)
	}

	for _, v := range vaults {
		fmt.Fprintln(sess, v)
	}
	return nil
}

func (h *Handler) handleVaultDestroy(sess ssh.Session, username, vaultName string) error {
	if vaultName == "personal" {
		return fmt.Errorf("cannot destroy the personal vault")
	}

	// Use a single error message for both "vault not found" and "not owner"
	// to avoid leaking vault existence to non-owners.
	members, err := h.vaultMgr.Members(vaultName)
	if err != nil || members[username] != vault.RoleOwner {
		return fmt.Errorf("only the vault owner can destroy a vault")
	}

	fmt.Fprintf(sess, "WARNING: This will permanently destroy vault %q and all its secrets.\n", vaultName)
	fmt.Fprintln(sess, "This action cannot be undone.")
	fmt.Fprintf(sess, "\nType the vault name to confirm: ")

	confirmation, err := readLine(sess, h.readLineTimeout)
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}

	if strings.TrimSpace(string(confirmation)) != vaultName {
		fmt.Fprintln(sess, "Destroy cancelled.")
		return nil
	}

	if err := h.vaultMgr.Destroy(vaultName, username); err != nil {
		if h.auditLog != nil {
			h.auditLog.VaultOpDenied("destroy", username, sess.RemoteAddr().String(), vaultName, err.Error())
		}
		return fmt.Errorf("destroy vault: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("destroy", username, sess.RemoteAddr().String(), vaultName)
	}
	fmt.Fprintf(sess, "Vault %q destroyed.\n", vaultName)
	return nil
}

func (h *Handler) handleMove(sess ssh.Session, username string, pubKey gossh.PublicKey, cmd Command) error {
	ag, cleanup, err := requireAgent(sess)
	if err != nil {
		return err
	}
	defer cleanup()

	// Read the source secret
	var plaintext []byte
	defer func() { crypto.Zeroize(plaintext) }()
	if cmd.Vault != "" {
		// Source is a vault
		if !h.vaultMgr.HasAccess(cmd.Vault, username) {
			if h.auditLog != nil {
				h.auditLog.VaultOpDenied("move", username, sess.RemoteAddr().String(), cmd.Vault, "not a member")
			}
			return fmt.Errorf("permission denied: not a member of vault %q", cmd.Vault)
		}
		vaultKey, err := h.vaultMgr.VaultKey(cmd.Vault, username, ag, pubKey)
		if err != nil {
			return fmt.Errorf("source vault key: %w", err)
		}
		defer crypto.Zeroize(vaultKey)
		ciphertext, err := h.fileStore.ReadVaultSecret(cmd.Vault, cmd.Path)
		if err != nil {
			return fmt.Errorf("read source: %w", err)
		}
		plaintext, err = decryptVaultSecret(vaultKey, cmd.Path, h.serverSecret, ciphertext, func(upgraded []byte) error {
			return h.fileStore.WriteVaultSecret(cmd.Vault, cmd.Path, upgraded)
		})
		if err != nil {
			return fmt.Errorf("decrypt source: %w", err)
		}
	} else {
		// Source is personal
		ciphertext, err := h.store.Read(username, cmd.Path)
		if err != nil {
			return fmt.Errorf("read source: %w", err)
		}
		plaintext, err = h.enc.DecryptAndUpgrade(ag, pubKey, h.serverSecret, username, cmd.Path, ciphertext, func(upgraded []byte) error {
			return h.store.Write(username, cmd.Path, upgraded)
		})
		if err != nil {
			return fmt.Errorf("decrypt source: %w", err)
		}
	}

	// Show confirmation with vault members if moving to a shared vault
	srcDisplay := cmd.Path
	if cmd.Vault != "" {
		srcDisplay = cmd.Vault + ":" + cmd.Path
	}
	dstDisplay := cmd.TargetPath
	if cmd.TargetVault != "" {
		dstDisplay = cmd.TargetVault + ":" + cmd.TargetPath
	}

	fmt.Fprintf(sess, "Moving %s → %s\n", srcDisplay, dstDisplay)

	if cmd.TargetVault != "" {
		if !h.vaultMgr.HasAccess(cmd.TargetVault, username) {
			if h.auditLog != nil {
				h.auditLog.VaultOpDenied("move", username, sess.RemoteAddr().String(), cmd.TargetVault, "not a member")
			}
			return fmt.Errorf("permission denied: not a member of vault %q", cmd.TargetVault)
		}
		members, err := h.vaultMgr.Members(cmd.TargetVault)
		if err != nil {
			return fmt.Errorf("read members: %w", err)
		}
		fmt.Fprintf(sess, "\nVault %q members:\n", cmd.TargetVault)
		for user, role := range members {
			fmt.Fprintf(sess, "  %s (%s)\n", user, role)
		}
		fmt.Fprintf(sess, "\nThese users will have access to this secret. Continue? [y/N]: ")

		buf := make([]byte, 1)
		n, err := sess.Read(buf)
		if err != nil || n == 0 || (buf[0] != 'y' && buf[0] != 'Y') {
			fmt.Fprintln(sess, "Move cancelled.")
			return nil
		}
	}

	// Write to destination
	if cmd.TargetVault != "" {
		vaultKey, err := h.vaultMgr.VaultKey(cmd.TargetVault, username, ag, pubKey)
		if err != nil {
			return fmt.Errorf("destination vault key: %w", err)
		}
		defer crypto.Zeroize(vaultKey)
		secretKey, err := crypto.DeriveVaultSecretKey(vaultKey, cmd.TargetPath, h.serverSecret)
		if err != nil {
			return fmt.Errorf("derive destination key: %w", err)
		}
		defer crypto.Zeroize(secretKey)
		ciphertext, err := crypto.EncryptWithKey(secretKey, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt destination: %w", err)
		}
		if err := h.fileStore.WriteVaultSecret(cmd.TargetVault, cmd.TargetPath, ciphertext); err != nil {
			return fmt.Errorf("write destination: %w", err)
		}
	} else {
		ciphertext, err := h.enc.Encrypt(ag, pubKey, h.serverSecret, username, cmd.TargetPath, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt destination: %w", err)
		}
		if err := h.store.Write(username, cmd.TargetPath, ciphertext); err != nil {
			return fmt.Errorf("write destination: %w", err)
		}
	}

	// Delete source — return an error if deletion fails so the user knows
	// the secret exists in both locations and can take corrective action.
	if cmd.Vault != "" {
		if err := h.fileStore.DeleteVaultSecret(cmd.Vault, cmd.Path); err != nil {
			return fmt.Errorf("secret copied to destination but source could not be deleted: %w", err)
		}
	} else {
		if err := h.store.Delete(username, cmd.Path); err != nil {
			return fmt.Errorf("secret copied to destination but source could not be deleted: %w", err)
		}
	}

	fmt.Fprintln(sess, "Secret moved.")
	return nil
}

func (h *Handler) handleInvite(sess ssh.Session, username string) error {
	if !h.admins[username] {
		if h.auditLog != nil {
			h.auditLog.AuthDenied(username, sess.RemoteAddr().String(), "non-admin attempted invite generation")
		}
		return fmt.Errorf("permission denied: %q is not an admin", username)
	}

	code, err := generateInviteCode()
	if err != nil {
		return fmt.Errorf("generate invite: %w", err)
	}

	inviteDir := filepath.Join(h.dataDir, "invites")
	if err := os.MkdirAll(inviteDir, 0700); err != nil {
		return fmt.Errorf("create invites dir: %w", err)
	}

	invitePath := filepath.Join(inviteDir, code)
	if err := storage.WriteFileNoFollow(invitePath, []byte(time.Now().UTC().Format(time.RFC3339)), 0600); err != nil {
		return fmt.Errorf("write invite: %w", err)
	}

	if h.auditLog != nil {
		h.auditLog.VaultOp("invite_generated", username, sess.RemoteAddr().String(), "")
	}

	fmt.Fprintln(sess, code)
	return nil
}

func (h *Handler) handleRegister(sess ssh.Session, username string, pubKey gossh.PublicKey, inviteCode string) error {
	// Validate username
	if err := validateUsername(username); err != nil {
		return err
	}

	// Validate invite code exists and has not expired.
	// This check is intentionally before the username-exists check to
	// prevent username enumeration: without a valid invite code, the
	// caller learns nothing about whether the username is taken.
	invitePath := filepath.Join(h.dataDir, "invites", inviteCode)
	inviteData, err := storage.ReadFileNoFollow(invitePath, maxSecretSize)
	if err != nil {
		// Perform equivalent work to the expiration check and username-exists
		// check below so that all rejection paths take similar time,
		// preventing timing side-channels that reveal code existence or
		// username availability.
		created, _ := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
		time.Since(created)
		os.Remove(invitePath) // no-op on non-existent file; matches expired-path work
		os.Stat(filepath.Join(h.dataDir, username, ".ssh", "authorized_keys"))
		return fmt.Errorf("invalid or expired invite code")
	}
	if len(inviteData) > 0 {
		created, err := time.Parse(time.RFC3339, string(inviteData))
		if err == nil && time.Since(created) > h.inviteCodeTTL {
			if rmErr := os.Remove(invitePath); rmErr != nil {
				log.Printf("WARNING: failed to remove expired invite %s: %v", invitePath, rmErr)
			}
			os.Stat(filepath.Join(h.dataDir, username, ".ssh", "authorized_keys"))
			return fmt.Errorf("invalid or expired invite code")
		}
	}

	// Check user doesn't already exist. Return the same generic error as
	// the invite code check above to avoid leaking username existence.
	authKeysPath := filepath.Join(h.dataDir, username, ".ssh", "authorized_keys")
	if _, err := os.Stat(authKeysPath); err == nil {
		return fmt.Errorf("invalid or expired invite code")
	}

	// Show the connecting key and ask for confirmation
	fingerprint := gossh.FingerprintSHA256(pubKey)
	authorizedLine := string(gossh.MarshalAuthorizedKey(pubKey))

	fmt.Fprintf(sess, "Registering key: %s", authorizedLine)
	fmt.Fprintf(sess, "Fingerprint: %s\n", fingerprint)
	fmt.Fprintf(sess, "Accept? [y/N]: ")

	// Read single character response
	buf := make([]byte, 1)
	n, err := sess.Read(buf)
	if err != nil || n == 0 {
		return fmt.Errorf("registration cancelled")
	}
	if buf[0] != 'y' && buf[0] != 'Y' {
		fmt.Fprintln(sess, "Registration cancelled.")
		return nil
	}

	// Atomically consume invite code: rename instead of stat+remove to prevent
	// TOCTOU races where two concurrent registrations could both use the same code.
	consumedDir := filepath.Join(h.dataDir, "invites", "consumed")
	if err := os.MkdirAll(consumedDir, 0700); err != nil {
		return fmt.Errorf("create consumed dir: %w", err)
	}
	consumedPath := filepath.Join(consumedDir, inviteCode)
	if err := os.Rename(invitePath, consumedPath); err != nil {
		return fmt.Errorf("invalid or expired invite code")
	}

	// Create authorized_keys atomically using O_EXCL to prevent a TOCTOU race
	// where two concurrent registrations both pass the os.Stat check above.
	sshDir := filepath.Join(h.dataDir, username, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("create ssh dir: %w", err)
	}
	if err := writeAuthorizedKeysExclusive(authKeysPath, []byte(authorizedLine)); err != nil {
		return fmt.Errorf("username %q already exists", username)
	}

	if h.auditLog != nil {
		h.auditLog.Registration(username, sess.RemoteAddr().String(), fingerprint, inviteCode)
	}

	fmt.Fprintf(sess, "Registration successful. You can now connect as %s.\n", username)
	return nil
}

func (h *Handler) handleHelp(sess ssh.Session) error {
	fmt.Fprint(sess, helpText(supportsColor(sess), h.version))
	return nil
}

// helpText returns the help string, optionally with ANSI colors.
func helpText(color bool, version string) string {
	// ANSI helpers — return empty strings when color is off so the format
	// strings below are identical in both modes.
	bold := ansi(color, "\033[1m")
	cyan := ansi(color, "\033[36m")
	yellow := ansi(color, "\033[33m")
	dim := ansi(color, "\033[2m")
	gray := ansi(color, "\033[90m")
	white := ansi(color, "\033[37m")
	reset := ansi(color, "\033[0m")

	// cmd formats one command row, aligning descriptions regardless of ANSI codes
	// by padding args to a fixed visible width.
	const argsCol = 10
	cmd := func(name, args, desc string) string {
		pad := strings.Repeat(" ", max(0, argsCol-visibleLen(args)))
		return fmt.Sprintf("  %s%-8s%s %s%s  %s\n", cyan, name, reset, args, pad, desc)
	}

	// cmd2 formats a vault subcommand with wider name column
	const argsCol2 = 16
	cmd2 := func(name, args, desc string) string {
		pad := strings.Repeat(" ", max(0, argsCol2-visibleLen(args)))
		return fmt.Sprintf("  %s%-16s%s %s%s  %s\n", cyan, name, reset, args, pad, desc)
	}

	versionStr := ""
	if version != "" {
		versionStr = " " + dim + version + reset
	}

	return bold + cyan + "Keyhole" + reset + versionStr + " " + gray + "—" + reset + " " + white + "SSH-based secret storage" + reset + "\n" +
		"\n" +
		bold + "USAGE\n" + reset +
		"  " + dim + "ssh [-A] <user>@<host> [-p <port>] <command> [args]" + reset + "\n" +
		"\n" +
		bold + "COMMANDS\n" + reset +
		cmd("get", yellow+"[vault:]<path>"+reset, "Decrypt and print a secret") +
		cmd("set", yellow+"[vault:]<path>"+reset, "Encrypt and store a secret") +
		cmd("list", yellow+"[vault:][prefix]"+reset, "List secrets") +
		cmd("ls", yellow+"[vault:][prefix]"+reset, "Alias for list") +
		cmd("move", yellow+"<src> <dst>"+reset, "Move secret between vaults") +
		cmd("invite", "", "Generate a single-use invite code "+dim+"[admin]"+reset) +
		cmd("register", yellow+"<code>"+reset, "Register your SSH key") +
		cmd("help", "", "Show this help") +
		"\n" +
		bold + "VAULT COMMANDS\n" + reset +
		cmd2("vault create", yellow+"<name>"+reset, "Create a shared vault") +
		cmd2("vault invite", yellow+"<name> <user>"+reset, "Invite user to vault") +
		cmd2("vault accept", yellow+"<name> <token>"+reset, "Accept vault invite") +
		cmd2("vault promote", yellow+"<name> <user>"+reset, "Promote member to admin") +
		cmd2("vault demote", yellow+"<name> <user>"+reset, "Demote admin to member") +
		cmd2("vault revoke", yellow+"<name> <user>"+reset, "Remove user from vault") +
		cmd2("vault members", yellow+"<name>"+reset, "List vault members") +
		cmd2("vault destroy", yellow+"<name>"+reset, "Permanently destroy a vault "+dim+"[owner]"+reset) +
		cmd2("vault list", "", "List your vaults") +
		"\n" +
		bold + "NOTES\n" + reset +
		"  " + cyan + "get" + reset + " and " + cyan + "set" + reset + " require SSH agent forwarding (" + bold + "-A" + reset + ")\n" +
		"  Secrets are isolated per user (use vaults to share)\n" +
		"  Paths may contain slashes, e.g. " + dim + "account/github" + reset + "\n" +
		"  Vault prefix: " + dim + "tv:foo/bar" + reset + " accesses " + dim + "foo/bar" + reset + " in vault " + dim + "tv" + reset + "\n"
}

// ansi returns the escape sequence when color is enabled, otherwise empty string.
func ansi(color bool, seq string) string {
	if color {
		return seq
	}
	return ""
}

// visibleLen returns the number of visible (non-ANSI-escape) characters in s.
func visibleLen(s string) int {
	n, i := 0, 0
	for i < len(s) {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // skip 'm'
		} else {
			n++
			i++
		}
	}
	return n
}

// decryptVaultSecret decrypts a vault secret, falling back to legacy (nil-salt)
// key derivation if the salted key fails. On legacy fallback, re-encrypts with
// the salted key and calls writeback to persist the upgrade.
func decryptVaultSecret(vaultKey []byte, path string, serverSecret, ciphertext []byte, writeback func([]byte) error) ([]byte, error) {
	// Try salted derivation first
	secretKey, err := crypto.DeriveVaultSecretKey(vaultKey, path, serverSecret)
	if err != nil {
		return nil, err
	}
	plaintext, err := crypto.DecryptWithKey(secretKey, ciphertext)
	if err == nil {
		// Perform equivalent work to the legacy fallback path below so that
		// both paths take similar time, preventing timing side-channels that
		// reveal which key derivation scheme was used.
		crypto.DeriveVaultSecretKeyLegacy(vaultKey, path)
		crypto.DecryptWithKey(secretKey, ciphertext)
		crypto.Zeroize(secretKey)
		return plaintext, nil
	}

	// Fall back to legacy (nil-salt) derivation
	legacyKey, keyErr := crypto.DeriveVaultSecretKeyLegacy(vaultKey, path)
	if keyErr != nil {
		crypto.Zeroize(secretKey)
		return nil, err
	}
	plaintext, legacyErr := crypto.DecryptWithKey(legacyKey, ciphertext)
	crypto.Zeroize(legacyKey)
	if legacyErr != nil {
		crypto.Zeroize(secretKey)
		return nil, err
	}

	// Re-encrypt with salted key and write back
	if writeback != nil {
		newCiphertext, encErr := crypto.EncryptWithKey(secretKey, plaintext)
		if encErr == nil {
			writeback(newCiphertext)
		}
	}
	crypto.Zeroize(secretKey)

	return plaintext, nil
}

// requireAgent returns the forwarded SSH agent from the session, or an error if not available.
// It creates a temporary Unix socket, forwards agent connections through the SSH channel,
// and connects to that socket to get an agent.ExtendedAgent.
// The caller MUST call the returned cleanup function when done to close the agent
// channel back to the client — failing to do so leaves the SSH connection open.
func requireAgent(sess ssh.Session) (agent.ExtendedAgent, func(), error) {
	if !ssh.AgentRequested(sess) {
		return nil, nil, fmt.Errorf("SSH agent forwarding required (use ssh -A)")
	}

	l, err := ssh.NewAgentListener()
	if err != nil {
		return nil, nil, fmt.Errorf("create agent listener: %w", err)
	}
	go ssh.ForwardAgentConnections(l, sess)

	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		l.Close()
		return nil, nil, fmt.Errorf("connect to agent socket: %w", err)
	}

	// The listener's address is the socket path inside a temp directory
	// created by ssh.NewAgentListener (e.g. /tmp/auth-agentXXX/listener.sock).
	// Closing the listener removes the socket but leaves the directory behind.
	agentDir := filepath.Dir(l.Addr().String())
	cleanup := func() {
		conn.Close()          // closing conn causes io.Copy loops in ForwardAgentConnections to exit
		l.Close()             // causes l.Accept() to return, stopping the ForwardAgentConnections goroutine
		os.RemoveAll(agentDir) // remove the temp directory left behind by NewAgentListener
	}
	return agent.NewClient(conn), cleanup, nil
}

// isTerminal reports whether the session has an allocated PTY.
func isTerminal(sess ssh.Session) bool {
	_, _, hasPTY := sess.Pty()
	return hasPTY
}

// supportsColor reports whether the session should use ANSI colors.
// Colors are on by default — the server cannot detect whether the client's
// stdout is a terminal without a PTY, so we assume color support and let
// clients opt out via NO_COLOR or TERM=dumb (forwarded with SendEnv in
// ssh_config, or set explicitly with ssh -o SetEnv=NO_COLOR=1).
func supportsColor(sess ssh.Session) bool {
	pty, _, hasPTY := sess.Pty()
	if hasPTY && pty.Term == "dumb" {
		return false
	}
	for _, env := range sess.Environ() {
		k, v, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		if k == "NO_COLOR" {
			return false
		}
		if k == "TERM" && (v == "dumb" || v == "") {
			return false
		}
	}
	return true
}

// promptSecret prompts the user to enter and confirm a secret with echo disabled.
// promptSecret prompts for a secret with echo concealment and requires confirmation.
// Requires a PTY (call only when isTerminal is true).
func promptSecret(sess ssh.Session, timeout time.Duration) ([]byte, error) {
	for attempt := 0; attempt < maxSetAttempts; attempt++ {
		// \x1b[8m = ANSI "conceal" mode: text is invisible on screen (best-effort echo suppression)
		fmt.Fprint(sess, "Enter secret: \x1b[8m")
		first, err := readLine(sess, timeout)
		fmt.Fprint(sess, "\x1b[0m") // reset concealment
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		fmt.Fprintln(sess)

		fmt.Fprint(sess, "Confirm secret: \x1b[8m")
		second, err := readLine(sess, timeout)
		fmt.Fprint(sess, "\x1b[0m")
		if err != nil {
			return nil, fmt.Errorf("read confirmation: %w", err)
		}
		fmt.Fprintln(sess)

		if string(first) == string(second) {
			crypto.Zeroize(second)
			return first, nil
		}
		crypto.Zeroize(first)
		crypto.Zeroize(second)
		fmt.Fprintln(sess, "Secrets do not match. Try again.")
	}
	return nil, fmt.Errorf("too many failed attempts")
}

// readLine reads one line from the session, stopping at newline or EOF.
// A timeout limits how long the entire read can take, preventing slow
// trickle attacks from holding goroutines indefinitely.
// On timeout, the session's stdin is closed to unblock the reading goroutine
// and prevent goroutine accumulation under sustained slow-trickle attacks.
func readLine(sess ssh.Session, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var buf []byte
		b := make([]byte, 1)
		for {
			n, err := sess.Read(b)
			if n > 0 {
				if b[0] == '\n' || b[0] == '\r' {
					break
				}
				buf = append(buf, b[0])
				if len(buf) > maxSecretSize {
					ch <- result{nil, fmt.Errorf("secret too large (max %d bytes)", maxSecretSize)}
					return
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				ch <- result{nil, err}
				return
			}
		}
		ch <- result{buf, nil}
	}()

	select {
	case r := <-ch:
		return r.data, r.err
	case <-time.After(timeout):
		sess.Close()
		return nil, fmt.Errorf("read timeout")
	}
}

// writeAuthorizedKeysExclusive creates an authorized_keys file exclusively.
// Returns an error if the file already exists, preventing TOCTOU races
// during concurrent user registration.
func writeAuthorizedKeysExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// generateInviteCode generates a cryptographically random invite code.
func generateInviteCode() (string, error) {
	b := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "kh_" + hex.EncodeToString(b), nil
}

// reservedUsernames are names that conflict with internal data directory
// structure and cannot be used as usernames.
var reservedUsernames = map[string]bool{
	"vaults":  true,
	"invites": true,
}

// validateUsername rejects usernames that contain characters outside the safe
// set [a-zA-Z0-9_-]. An allowlist prevents log injection (newlines, control
// characters), filesystem edge cases, and terminal escape sequences.
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > maxUsernameLength {
		return fmt.Errorf("username exceeds maximum length of %d characters", maxUsernameLength)
	}
	if reservedUsernames[username] {
		return fmt.Errorf("username %q is reserved", username)
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return fmt.Errorf("username contains invalid character %q", c)
		}
	}
	return nil
}
