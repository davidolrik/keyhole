package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/crypto"
	"go.olrik.dev/keyhole/internal/storage"
)

const (
	vaultKeySize   = 512 // 4096 bits
	challengeVer   = "keyhole-v1"
	wrappingHKDFInfo = "keyhole-vault-wrapping-v1"
)

// Role represents a vault membership role.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type vaultMeta struct {
	Owner   string `json:"owner"`
	Created string `json:"created"`
}

// Manager handles vault operations: create, key management, and access control.
type Manager struct {
	store        *storage.FileStore
	serverSecret []byte
}

// NewManager creates a vault Manager.
func NewManager(store *storage.FileStore, serverSecret []byte) *Manager {
	return &Manager{store: store, serverSecret: serverSecret}
}

// Create creates a new shared vault. The creator becomes the owner.
// A random vault key is generated and wrapped for the owner using their SSH agent.
func (m *Manager) Create(name, username string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) error {
	if err := ValidateVaultName(name); err != nil {
		return err
	}

	// Check vault doesn't already exist
	if _, err := m.store.ReadVaultMeta(name); err == nil {
		return fmt.Errorf("vault %q already exists", name)
	}

	// Generate random vault key
	vaultKey := make([]byte, vaultKeySize)
	if _, err := io.ReadFull(rand.Reader, vaultKey); err != nil {
		return fmt.Errorf("generate vault key: %w", err)
	}

	// Wrap vault key for the owner
	wrappedKey, err := m.wrapVaultKey(vaultKey, username, name, ag, pubKey)
	if err != nil {
		return fmt.Errorf("wrap vault key: %w", err)
	}

	// Write metadata
	meta := vaultMeta{
		Owner:   username,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err := m.store.WriteVaultMeta(name, metaJSON); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	// Write members
	members := map[string]Role{username: RoleOwner}
	membersJSON, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	if err := m.store.WriteVaultMembers(name, membersJSON); err != nil {
		return fmt.Errorf("write members: %w", err)
	}

	// Write wrapped vault key
	if err := m.store.WriteVaultKey(name, username, wrappedKey); err != nil {
		return fmt.Errorf("write vault key: %w", err)
	}

	return nil
}

// VaultKey decrypts and returns the vault key for the given user.
func (m *Manager) VaultKey(name, username string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	wrappedKey, err := m.store.ReadVaultKey(name, username)
	if err != nil {
		return nil, fmt.Errorf("read vault key: %w", err)
	}

	wrappingKey, err := m.deriveWrappingKey(username, name, ag, pubKey)
	if err != nil {
		return nil, fmt.Errorf("derive wrapping key: %w", err)
	}

	vaultKey, err := crypto.DecryptWithKey(wrappingKey, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap vault key: %w", err)
	}

	return vaultKey, nil
}

// HasAccess returns true if the user is a member of the vault.
func (m *Manager) HasAccess(name, username string) bool {
	members, err := m.Members(name)
	if err != nil {
		return false
	}
	_, ok := members[username]
	return ok
}

// Members returns the vault's member→role map.
func (m *Manager) Members(name string) (map[string]Role, error) {
	data, err := m.store.ReadVaultMembers(name)
	if err != nil {
		return nil, fmt.Errorf("read members: %w", err)
	}
	var members map[string]Role
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("unmarshal members: %w", err)
	}
	return members, nil
}

// ListVaults returns the names of vaults the user has access to.
func (m *Manager) ListVaults(username string) ([]string, error) {
	allVaults, err := m.store.ListVaults()
	if err != nil {
		return nil, err
	}
	var result []string
	for _, v := range allVaults {
		if m.HasAccess(v, username) {
			result = append(result, v)
		}
	}
	return result, nil
}

// Invite generates a pending invite for targetUser on the vault.
// The inviter must be an owner or admin. Returns an invite token.
func (m *Manager) Invite(name, inviter, targetUser string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) (string, error) {
	members, err := m.Members(name)
	if err != nil {
		return "", fmt.Errorf("read members: %w", err)
	}

	role, ok := members[inviter]
	if !ok || (role != RoleOwner && role != RoleAdmin) {
		return "", fmt.Errorf("permission denied: %q is not an owner or admin of vault %q", inviter, name)
	}

	if _, exists := members[targetUser]; exists {
		return "", fmt.Errorf("user %q is already a member of vault %q", targetUser, name)
	}

	// Decrypt the inviter's vault key
	vaultKey, err := m.VaultKey(name, inviter, ag, pubKey)
	if err != nil {
		return "", fmt.Errorf("decrypt vault key: %w", err)
	}

	// Generate a random invite token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	token := fmt.Sprintf("%x", tokenBytes)

	// Derive a wrapping key from the token and encrypt the vault key with it
	tokenKey := deriveTokenKey(tokenBytes)
	wrappedWithToken, err := crypto.EncryptWithKey(tokenKey, vaultKey)
	if err != nil {
		return "", fmt.Errorf("wrap vault key with token: %w", err)
	}

	if err := m.store.WritePendingInvite(name, targetUser, wrappedWithToken); err != nil {
		return "", fmt.Errorf("write pending invite: %w", err)
	}

	return token, nil
}

// Accept completes a vault invite. The user provides the invite token,
// decrypts the vault key, and re-encrypts it with their own agent-derived key.
func (m *Manager) Accept(name, username, token string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) error {
	// Read the pending invite
	wrappedWithToken, err := m.store.ReadPendingInvite(name, username)
	if err != nil {
		return fmt.Errorf("read pending invite: %w", err)
	}

	// Derive the token key and decrypt the vault key
	tokenRaw, err := hexDecode(token)
	if err != nil {
		return fmt.Errorf("invalid invite token: %w", err)
	}

	tokenKey := deriveTokenKey(tokenRaw)
	vaultKey, err := crypto.DecryptWithKey(tokenKey, wrappedWithToken)
	if err != nil {
		return fmt.Errorf("decrypt vault key with token: %w", err)
	}

	// Wrap the vault key with the user's own agent-derived key
	wrappedKey, err := m.wrapVaultKey(vaultKey, username, name, ag, pubKey)
	if err != nil {
		return fmt.Errorf("wrap vault key: %w", err)
	}

	// Write the user's vault key
	if err := m.store.WriteVaultKey(name, username, wrappedKey); err != nil {
		return fmt.Errorf("write vault key: %w", err)
	}

	// Add user to members
	members, err := m.Members(name)
	if err != nil {
		return fmt.Errorf("read members: %w", err)
	}
	members[username] = RoleMember
	membersJSON, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	if err := m.store.WriteVaultMembers(name, membersJSON); err != nil {
		return fmt.Errorf("write members: %w", err)
	}

	// Remove pending invite
	if err := m.store.DeletePendingInvite(name, username); err != nil {
		// Non-fatal
	}

	return nil
}

// Promote promotes a vault member to admin. Only owners and admins can promote.
func (m *Manager) Promote(name, promoter, targetUser string) error {
	members, err := m.Members(name)
	if err != nil {
		return fmt.Errorf("read members: %w", err)
	}

	promoterRole, ok := members[promoter]
	if !ok || (promoterRole != RoleOwner && promoterRole != RoleAdmin) {
		return fmt.Errorf("permission denied: %q is not an owner or admin of vault %q", promoter, name)
	}

	targetRole, ok := members[targetUser]
	if !ok {
		return fmt.Errorf("user %q is not a member of vault %q", targetUser, name)
	}
	if targetRole == RoleOwner {
		return fmt.Errorf("cannot promote the owner")
	}
	if targetRole == RoleAdmin {
		return fmt.Errorf("user %q is already an admin", targetUser)
	}

	members[targetUser] = RoleAdmin
	membersJSON, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	return m.store.WriteVaultMembers(name, membersJSON)
}

// deriveTokenKey derives an AES-256 key from an invite token using HKDF-SHA256.
func deriveTokenKey(tokenBytes []byte) []byte {
	reader := hkdf.New(sha256.New, tokenBytes, nil, []byte("keyhole-vault-invite-v1"))
	key := make([]byte, 32)
	io.ReadFull(reader, key)
	return key
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		if i+1 >= len(s) {
			return nil, fmt.Errorf("odd hex string length")
		}
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("invalid hex character")
		}
		b[i/2] = byte(hi<<4 | lo)
	}
	return b, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// wrapVaultKey encrypts the vault key for a user using their agent-derived wrapping key.
func (m *Manager) wrapVaultKey(vaultKey []byte, username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	wrappingKey, err := m.deriveWrappingKey(username, vaultName, ag, pubKey)
	if err != nil {
		return nil, err
	}
	return crypto.EncryptWithKey(wrappingKey, vaultKey)
}

// deriveWrappingKey derives the AES-256 wrapping key for a user's vault key copy.
// challenge = SHA256(serverSecret:keyhole-v1:username:__vault_key__/vaultname)
func (m *Manager) deriveWrappingKey(username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	path := "__vault_key__/" + vaultName
	challenge := buildChallenge(m.serverSecret, username, path)

	sig, err := ag.Sign(pubKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("agent sign: %w", err)
	}

	reader := hkdf.New(sha256.New, sig.Blob, nil, []byte(wrappingHKDFInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// buildChallenge constructs the deterministic challenge for agent signing.
func buildChallenge(serverSecret []byte, username, path string) []byte {
	h := sha256.New()
	h.Write(serverSecret)
	h.Write([]byte(":"))
	h.Write([]byte(challengeVer + ":"))
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(path))
	return h.Sum(nil)
}

// ValidateVaultName checks that a vault name is safe and not reserved.
func ValidateVaultName(name string) error {
	if name == "" {
		return fmt.Errorf("vault name cannot be empty")
	}
	if name == "personal" {
		return fmt.Errorf("vault name %q is reserved", name)
	}
	if strings.HasPrefix(name, "_") {
		return fmt.Errorf("vault names starting with '_' are reserved")
	}
	for _, c := range name {
		if c == '/' || c == '.' || c == '\\' || c == ':' || c == '\x00' {
			return fmt.Errorf("vault name contains invalid character %q", c)
		}
	}
	return nil
}
