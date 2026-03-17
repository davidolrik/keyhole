package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/crypto"
	"go.olrik.dev/keyhole/internal/storage"
)

const (
	vaultKeySize     = 512 // 4096 bits
	challengeVer     = "keyhole-v1"
	wrappingHKDFInfo = "keyhole-vault-wrapping-v1"
	vaultInviteTTL   = 72 * time.Hour
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

type pendingInvite struct {
	WrappedKey []byte `json:"wrapped_key"`
	Created    string `json:"created"`
}

// Manager handles vault operations: create, key management, and access control.
type Manager struct {
	store        *storage.FileStore
	serverSecret []byte

	// vaultMu provides per-vault mutual exclusion for read-modify-write
	// operations on members.json, preventing TOCTOU race conditions.
	vaultMu   sync.Mutex
	vaultLocks map[string]*sync.Mutex
}

// NewManager creates a vault Manager.
func NewManager(store *storage.FileStore, serverSecret []byte) *Manager {
	return &Manager{
		store:        store,
		serverSecret: serverSecret,
		vaultLocks:   make(map[string]*sync.Mutex),
	}
}

// lockVault acquires a per-vault mutex, creating one if needed.
func (m *Manager) lockVault(name string) {
	m.vaultMu.Lock()
	mu, ok := m.vaultLocks[name]
	if !ok {
		mu = &sync.Mutex{}
		m.vaultLocks[name] = mu
	}
	m.vaultMu.Unlock()
	mu.Lock()
}

// unlockVault releases the per-vault mutex.
func (m *Manager) unlockVault(name string) {
	m.vaultMu.Lock()
	mu := m.vaultLocks[name]
	m.vaultMu.Unlock()
	mu.Unlock()
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
// Falls back to legacy (nil-salt) wrapping key derivation if the salted key
// fails, and re-wraps with the salted key on successful fallback.
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
	if err == nil {
		crypto.Zeroize(wrappingKey)
		return vaultKey, nil
	}

	// Fall back to legacy (nil-salt) wrapping key
	legacyKey, keyErr := m.deriveWrappingKeyLegacy(username, name, ag, pubKey)
	if keyErr != nil {
		crypto.Zeroize(wrappingKey)
		return nil, fmt.Errorf("unwrap vault key: %w", err)
	}
	vaultKey, legacyErr := crypto.DecryptWithKey(legacyKey, wrappedKey)
	crypto.Zeroize(legacyKey)
	if legacyErr != nil {
		crypto.Zeroize(wrappingKey)
		return nil, fmt.Errorf("unwrap vault key: %w", err)
	}

	// Re-wrap with salted wrapping key
	newWrapped, encErr := crypto.EncryptWithKey(wrappingKey, vaultKey)
	crypto.Zeroize(wrappingKey)
	if encErr == nil {
		m.store.WriteVaultKey(name, username, newWrapped)
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
	m.lockVault(name)
	defer m.unlockVault(name)
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

	// Reject if there's already a pending invite to avoid silently
	// invalidating a previously issued token.
	if _, err := m.store.ReadPendingInvite(name, targetUser); err == nil {
		return "", fmt.Errorf("user %q already has a pending invite for vault %q", targetUser, name)
	}

	// Decrypt the inviter's vault key
	vaultKey, err := m.VaultKey(name, inviter, ag, pubKey)
	if err != nil {
		return "", fmt.Errorf("decrypt vault key: %w", err)
	}
	defer crypto.Zeroize(vaultKey)

	// Generate a random invite token
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	token := fmt.Sprintf("%x", tokenBytes)

	// Derive a wrapping key from the token and encrypt the vault key with it
	tokenKey, err := deriveTokenKey(tokenBytes, m.serverSecret, name, targetUser)
	if err != nil {
		return "", fmt.Errorf("derive token key: %w", err)
	}
	wrappedWithToken, err := crypto.EncryptWithKey(tokenKey, vaultKey)
	crypto.Zeroize(tokenKey)
	if err != nil {
		return "", fmt.Errorf("wrap vault key with token: %w", err)
	}

	invite := pendingInvite{
		WrappedKey: wrappedWithToken,
		Created:    time.Now().UTC().Format(time.RFC3339),
	}
	inviteData, err := json.Marshal(invite)
	if err != nil {
		return "", fmt.Errorf("marshal pending invite: %w", err)
	}
	if err := m.store.WritePendingInvite(name, targetUser, inviteData); err != nil {
		return "", fmt.Errorf("write pending invite: %w", err)
	}

	return token, nil
}

// Accept completes a vault invite. The user provides the invite token,
// decrypts the vault key, and re-encrypts it with their own agent-derived key.
func (m *Manager) Accept(name, username, token string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) error {
	m.lockVault(name)
	defer m.unlockVault(name)
	// Read the pending invite. On failure, perform equivalent work to the
	// expiration/token check below so that "no invite" and "wrong token"
	// take similar time, preventing timing side-channels that reveal
	// whether a pending invite exists.
	inviteData, readErr := m.store.ReadPendingInvite(name, username)
	if readErr != nil {
		// Use a dummy invite and run the full verification path so that
		// "no invite" and "wrong token" take similar time, preventing
		// timing side-channels that reveal whether a pending invite exists.
		inviteData = []byte(`{"wrapped_key":"AA==","created":"` +
			time.Now().UTC().Format(time.RFC3339) + `"}`)
	}

	var invite pendingInvite
	if err := json.Unmarshal(inviteData, &invite); err != nil {
		return fmt.Errorf("invalid or expired vault invite")
	}

	// Check if the invite has expired
	created, err := time.Parse(time.RFC3339, invite.Created)
	if err != nil {
		return fmt.Errorf("invalid or expired vault invite")
	}
	if time.Since(created) > vaultInviteTTL {
		m.store.DeletePendingInvite(name, username)
		return fmt.Errorf("invalid or expired vault invite")
	}

	wrappedWithToken := invite.WrappedKey

	// Derive the token key and decrypt the vault key
	tokenRaw, err := hex.DecodeString(token)
	if err != nil {
		return fmt.Errorf("invalid or expired vault invite")
	}

	tokenKey, err := deriveTokenKey(tokenRaw, m.serverSecret, name, username)
	if err != nil {
		return fmt.Errorf("derive token key: %w", err)
	}
	vaultKey, err := crypto.DecryptWithKey(tokenKey, wrappedWithToken)
	crypto.Zeroize(tokenKey)
	if err != nil {
		// Fall back to legacy (nil-salt) token key derivation
		legacyKey, keyErr := deriveTokenKeyWithSalt(tokenRaw, nil, name, username)
		if keyErr != nil {
			return fmt.Errorf("decrypt vault key with token: %w", err)
		}
		vaultKey, err = crypto.DecryptWithKey(legacyKey, wrappedWithToken)
		crypto.Zeroize(legacyKey)
		if err != nil {
			return fmt.Errorf("decrypt vault key with token: %w", err)
		}
	}

	// Check readErr after performing equivalent cryptographic work above,
	// so that a missing invite is indistinguishable from a wrong token.
	if readErr != nil {
		return fmt.Errorf("invalid or expired vault invite")
	}

	// Wrap the vault key with the user's own agent-derived key
	wrappedKey, err := m.wrapVaultKey(vaultKey, username, name, ag, pubKey)
	if err != nil {
		return fmt.Errorf("wrap vault key: %w", err)
	}

	// Write the user's vault key first, then update members.json.
	// If members write fails, clean up the vault key to avoid orphaned state.
	if err := m.store.WriteVaultKey(name, username, wrappedKey); err != nil {
		return fmt.Errorf("write vault key: %w", err)
	}

	// Add user to members
	members, err := m.Members(name)
	if err != nil {
		m.store.DeleteVaultKey(name, username)
		return fmt.Errorf("read members: %w", err)
	}
	if _, exists := members[username]; exists {
		m.store.DeleteVaultKey(name, username)
		return fmt.Errorf("user %q is already a member of vault %q", username, name)
	}
	members[username] = RoleMember
	membersJSON, err := json.Marshal(members)
	if err != nil {
		m.store.DeleteVaultKey(name, username)
		return fmt.Errorf("marshal members: %w", err)
	}
	if err := m.store.WriteVaultMembers(name, membersJSON); err != nil {
		m.store.DeleteVaultKey(name, username)
		return fmt.Errorf("write members: %w", err)
	}

	// Remove pending invite — log failures since stale invite files waste
	// storage but don't affect correctness.
	if err := m.store.DeletePendingInvite(name, username); err != nil {
		log.Printf("warning: failed to delete pending invite for %s in vault %s: %v", username, name, err)
	}

	return nil
}

// Promote promotes a vault member to admin. Only owners and admins can promote.
func (m *Manager) Promote(name, promoter, targetUser string) error {
	m.lockVault(name)
	defer m.unlockVault(name)
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

// Demote demotes a vault admin to member. Only owners and admins can demote.
func (m *Manager) Demote(name, demoter, targetUser string) error {
	m.lockVault(name)
	defer m.unlockVault(name)
	members, err := m.Members(name)
	if err != nil {
		return fmt.Errorf("read members: %w", err)
	}

	demoterRole, ok := members[demoter]
	if !ok || (demoterRole != RoleOwner && demoterRole != RoleAdmin) {
		return fmt.Errorf("permission denied: %q is not an owner or admin of vault %q", demoter, name)
	}

	targetRole, ok := members[targetUser]
	if !ok {
		return fmt.Errorf("user %q is not a member of vault %q", targetUser, name)
	}
	if targetRole == RoleOwner {
		return fmt.Errorf("cannot demote the owner")
	}
	if targetRole == RoleMember {
		return fmt.Errorf("user %q is already a member", targetUser)
	}

	members[targetUser] = RoleMember
	membersJSON, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	return m.store.WriteVaultMembers(name, membersJSON)
}

// Revoke removes a user from a vault. Only owners and admins can revoke.
// The owner cannot be revoked. The user's wrapped vault key is also deleted.
func (m *Manager) Revoke(name, revoker, targetUser string) error {
	m.lockVault(name)
	defer m.unlockVault(name)
	members, err := m.Members(name)
	if err != nil {
		return fmt.Errorf("read members: %w", err)
	}

	revokerRole, ok := members[revoker]
	if !ok || (revokerRole != RoleOwner && revokerRole != RoleAdmin) {
		return fmt.Errorf("permission denied: %q is not an owner or admin of vault %q", revoker, name)
	}

	targetRole, ok := members[targetUser]
	if !ok {
		return fmt.Errorf("user %q is not a member of vault %q", targetUser, name)
	}
	if targetRole == RoleOwner {
		return fmt.Errorf("cannot revoke the owner")
	}

	// Remove from members
	delete(members, targetUser)
	membersJSON, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	if err := m.store.WriteVaultMembers(name, membersJSON); err != nil {
		return fmt.Errorf("write members: %w", err)
	}

	// Delete the user's wrapped vault key
	if err := m.store.DeleteVaultKey(name, targetUser); err != nil {
		// Non-fatal: key may not exist (e.g. pending invite that was never accepted)
	}

	// Clean up any pending invite to prevent a revoked user from rejoining
	// via a stale invite token.
	m.store.DeletePendingInvite(name, targetUser)

	return nil
}

// Destroy permanently deletes a vault. Only the vault owner can do this.
func (m *Manager) Destroy(name, username string) error {
	m.lockVault(name)
	defer m.unlockVault(name)
	data, err := m.store.ReadVaultMeta(name)
	if err != nil {
		return fmt.Errorf("read vault meta: %w", err)
	}
	var meta vaultMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("unmarshal meta: %w", err)
	}
	if meta.Owner != username {
		return fmt.Errorf("only the vault owner can destroy a vault")
	}
	return m.store.DeleteVault(name)
}

// deriveTokenKey derives an AES-256 key from an invite token using HKDF-SHA256,
// with serverSecret as the HKDF salt.
func deriveTokenKey(tokenBytes, serverSecret []byte, vaultName, username string) ([]byte, error) {
	return deriveTokenKeyWithSalt(tokenBytes, serverSecret, vaultName, username)
}

func deriveTokenKeyWithSalt(tokenBytes, salt []byte, vaultName, username string) ([]byte, error) {
	info := "keyhole-vault-invite-v1:" + vaultName + ":" + username
	reader := hkdf.New(sha256.New, tokenBytes, salt, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf derive token key: %w", err)
	}
	return key, nil
}

// wrapVaultKey encrypts the vault key for a user using their agent-derived wrapping key.
func (m *Manager) wrapVaultKey(vaultKey []byte, username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	wrappingKey, err := m.deriveWrappingKey(username, vaultName, ag, pubKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(wrappingKey)
	return crypto.EncryptWithKey(wrappingKey, vaultKey)
}

// deriveWrappingKey derives the AES-256 wrapping key for a user's vault key copy,
// using serverSecret as the HKDF salt.
func (m *Manager) deriveWrappingKey(username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	return m.deriveWrappingKeyWithSalt(username, vaultName, ag, pubKey, m.serverSecret)
}

// deriveWrappingKeyLegacy derives the wrapping key with nil HKDF salt (legacy).
func (m *Manager) deriveWrappingKeyLegacy(username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey) ([]byte, error) {
	return m.deriveWrappingKeyWithSalt(username, vaultName, ag, pubKey, nil)
}

func (m *Manager) deriveWrappingKeyWithSalt(username, vaultName string, ag agent.ExtendedAgent, pubKey ssh.PublicKey, salt []byte) ([]byte, error) {
	path := "__vault_key__/" + vaultName
	challenge := buildChallenge(m.serverSecret, username, path)

	sig, err := ag.Sign(pubKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("agent sign: %w", err)
	}

	reader := hkdf.New(sha256.New, sig.Blob, salt, []byte(wrappingHKDFInfo))
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
		if c == '/' || c == '.' || c == '\\' || c == ':' || c == '\x00' ||
			c == '*' || c == '?' || c == '[' || c == ']' {
			return fmt.Errorf("vault name contains invalid character %q", c)
		}
	}
	return nil
}
