package vault_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/storage"
	"go.olrik.dev/keyhole/internal/vault"
)

func newTestAgent(t *testing.T) (agent.ExtendedAgent, ssh.PublicKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: edPriv}); err != nil {
		t.Fatalf("agent.Add: %v", err)
	}
	return kr.(agent.ExtendedAgent), sshPub
}

func TestCreate(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))

	if err := mgr.Create("teamvault", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Vault should exist and alice should be the owner
	members, err := mgr.Members("teamvault")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	role, ok := members["alice"]
	if !ok {
		t.Fatal("alice not in members")
	}
	if role != "owner" {
		t.Errorf("alice role = %q, want owner", role)
	}
}

func TestCreateDuplicate(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	err := mgr.Create("tv", "alice", ag, pubKey)
	if err == nil {
		t.Error("expected error creating duplicate vault")
	}
}

func TestVaultKey(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	key, err := mgr.VaultKey("tv", "alice", ag, pubKey)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	if len(key) != 512 {
		t.Errorf("vault key length = %d, want 512", len(key))
	}
}

func TestHasAccess(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !mgr.HasAccess("tv", "alice") {
		t.Error("alice should have access to tv")
	}
	if mgr.HasAccess("tv", "bob") {
		t.Error("bob should not have access to tv")
	}
}

func TestListVaults(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("alpha", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create alpha: %v", err)
	}
	if err := mgr.Create("beta", "alice", ag, pubKey); err != nil {
		t.Fatalf("Create beta: %v", err)
	}

	vaults, err := mgr.ListVaults("alice")
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Errorf("ListVaults = %v (len %d), want 2", vaults, len(vaults))
	}
}

func TestInviteAndAccept(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Alice invites bob
	token, err := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if token == "" {
		t.Fatal("invite token is empty")
	}

	// Bob should not have access yet
	if mgr.HasAccess("tv", "bob") {
		t.Error("bob should not have access before accepting")
	}

	// Bob accepts the invite
	if err := mgr.Accept("tv", "bob", token, bobAg, bobPub); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// Bob should now have access
	if !mgr.HasAccess("tv", "bob") {
		t.Error("bob should have access after accepting")
	}

	// Bob should be able to decrypt the vault key
	key, err := mgr.VaultKey("tv", "bob", bobAg, bobPub)
	if err != nil {
		t.Fatalf("VaultKey (bob): %v", err)
	}
	aliceKey, err := mgr.VaultKey("tv", "alice", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("VaultKey (alice): %v", err)
	}
	if string(key) != string(aliceKey) {
		t.Error("bob and alice should have the same vault key")
	}
}

func TestInviteWrongToken(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub); err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Wrong token should fail
	err := mgr.Accept("tv", "bob", "wrong-token", bobAg, bobPub)
	if err == nil {
		t.Error("expected error accepting with wrong token")
	}
}

func TestInviteNonOwnerFails(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Bob (not a member) can't invite
	_, err := mgr.Invite("tv", "bob", "charlie", bobAg, bobPub)
	if err == nil {
		t.Error("expected error when non-member invites")
	}
}

func TestPromote(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)

	// Bob is a member, promote to admin
	if err := mgr.Promote("tv", "alice", "bob"); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	members, _ := mgr.Members("tv")
	if members["bob"] != vault.RoleAdmin {
		t.Errorf("bob role = %q, want admin", members["bob"])
	}
}

func TestDemote(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)
	mgr.Promote("tv", "alice", "bob")

	// Verify bob is admin
	members, _ := mgr.Members("tv")
	if members["bob"] != vault.RoleAdmin {
		t.Fatalf("bob role = %q, want admin", members["bob"])
	}

	// Demote bob back to member
	if err := mgr.Demote("tv", "alice", "bob"); err != nil {
		t.Fatalf("Demote: %v", err)
	}

	members, _ = mgr.Members("tv")
	if members["bob"] != vault.RoleMember {
		t.Errorf("bob role = %q, want member", members["bob"])
	}
}

func TestDemoteOwnerFails(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Invite bob, accept, promote to admin
	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)
	mgr.Promote("tv", "alice", "bob")

	// Cannot demote the owner
	err := mgr.Demote("tv", "bob", "alice")
	if err == nil {
		t.Error("expected error demoting the owner")
	}
}

func TestDemoteMemberFails(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)

	// Cannot demote someone who is already a member
	err := mgr.Demote("tv", "alice", "bob")
	if err == nil {
		t.Error("expected error demoting a member")
	}
}

func TestMemberCannotDemote(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)
	charlieAg, charliePub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Invite bob and charlie, promote both to admin
	tokenB, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", tokenB, bobAg, bobPub)

	tokenC, _ := mgr.Invite("tv", "alice", "charlie", aliceAg, alicePub)
	mgr.Accept("tv", "charlie", tokenC, charlieAg, charliePub)
	mgr.Promote("tv", "alice", "charlie")

	// Bob (member) cannot demote charlie (admin)
	err := mgr.Demote("tv", "bob", "charlie")
	if err == nil {
		t.Error("expected error when member tries to demote")
	}
}

func TestAdminCanInvite(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Invite bob, accept, promote to admin
	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)
	mgr.Promote("tv", "alice", "bob")

	// Bob (admin) should be able to invite charlie
	_, err := mgr.Invite("tv", "bob", "charlie", bobAg, bobPub)
	if err != nil {
		t.Errorf("admin invite: %v", err)
	}
}

func TestMemberCannotInvite(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)

	// Bob (member, not admin) should NOT be able to invite
	_, err := mgr.Invite("tv", "bob", "charlie", bobAg, bobPub)
	if err == nil {
		t.Error("expected error when member tries to invite")
	}
}

func TestValidateVaultName(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	ag, pubKey := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))

	tests := []struct {
		name    string
		wantErr bool
	}{
		{"valid", false},
		{"my-vault", false},
		{"personal", true},  // reserved
		{"_internal", true}, // reserved prefix
		{"has/slash", true},
		{"has.dot", true},
		{"has:colon", true},
		{"has\\back", true},
		{"", true},
	}
	for _, tt := range tests {
		err := mgr.Create(tt.name, "alice", ag, pubKey)
		if (err != nil) != tt.wantErr {
			t.Errorf("Create(%q) err=%v, wantErr=%v", tt.name, err, tt.wantErr)
		}
	}
}

func TestInviteTokenDomainSeparation(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)
	charlieAg, charliePub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))

	// Create two vaults
	if err := mgr.Create("vault-a", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create vault-a: %v", err)
	}
	if err := mgr.Create("vault-b", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create vault-b: %v", err)
	}

	// Invite bob to vault-a
	tokenA, err := mgr.Invite("vault-a", "alice", "bob", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite bob to vault-a: %v", err)
	}

	// Invite charlie to vault-b
	_, err = mgr.Invite("vault-b", "alice", "charlie", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite charlie to vault-b: %v", err)
	}

	// Bob's token for vault-a should NOT work for charlie on vault-b
	// (different vault name and username in HKDF info)
	err = mgr.Accept("vault-b", "charlie", tokenA, charlieAg, charliePub)
	if err == nil {
		t.Error("expected error using vault-a token to accept vault-b invite")
	}

	// Bob's token should work for vault-a
	if err := mgr.Accept("vault-a", "bob", tokenA, bobAg, bobPub); err != nil {
		t.Fatalf("Accept vault-a with correct token: %v", err)
	}
}

func TestExpiredVaultInvite(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, err := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Tamper with the pending invite's timestamp to make it expired
	invitePath := filepath.Join(dir, "vaults", "tv", "pending", "bob.invite")
	data, err := os.ReadFile(invitePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var invite struct {
		WrappedKey json.RawMessage `json:"wrapped_key"`
		Created    string          `json:"created"`
	}
	if err := json.Unmarshal(data, &invite); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Set creation time to 4 days ago (beyond 72h TTL)
	invite.Created = time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339)
	tampered, _ := json.Marshal(invite)
	if err := os.WriteFile(invitePath, tampered, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = mgr.Accept("tv", "bob", token, bobAg, bobPub)
	if err == nil {
		t.Error("expected error accepting expired vault invite")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %q, expected to mention 'expired'", err)
	}
}

func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)

	// Bob should have access
	if !mgr.HasAccess("tv", "bob") {
		t.Fatal("bob should have access before revoke")
	}

	// Revoke bob
	if err := mgr.Revoke("tv", "alice", "bob"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Bob should no longer have access
	if mgr.HasAccess("tv", "bob") {
		t.Error("bob should not have access after revoke")
	}

	// Bob's wrapped key file should be deleted
	_, err := store.ReadVaultKey("tv", "bob")
	if err == nil {
		t.Error("bob's vault key should be deleted after revoke")
	}
}

func TestRevokeOwnerFails(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", token, bobAg, bobPub)
	mgr.Promote("tv", "alice", "bob")

	// Cannot revoke the owner
	err := mgr.Revoke("tv", "bob", "alice")
	if err == nil {
		t.Error("expected error revoking the owner")
	}
}

func TestMemberCannotRevoke(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)
	charlieAg, charliePub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tokenB, _ := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	mgr.Accept("tv", "bob", tokenB, bobAg, bobPub)

	tokenC, _ := mgr.Invite("tv", "alice", "charlie", aliceAg, alicePub)
	mgr.Accept("tv", "charlie", tokenC, charlieAg, charliePub)

	// Bob (member) cannot revoke charlie
	err := mgr.Revoke("tv", "bob", "charlie")
	if err == nil {
		t.Error("expected error when member tries to revoke")
	}
}

func TestConcurrentPromoteDemote(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Create 10 members
	agents := make([]agent.ExtendedAgent, 10)
	pubs := make([]ssh.PublicKey, 10)
	for i := 0; i < 10; i++ {
		agents[i], pubs[i] = newTestAgent(t)
		name := fmt.Sprintf("user%d", i)
		token, err := mgr.Invite("tv", "alice", name, aliceAg, alicePub)
		if err != nil {
			t.Fatalf("Invite %s: %v", name, err)
		}
		if err := mgr.Accept("tv", name, token, agents[i], pubs[i]); err != nil {
			t.Fatalf("Accept %s: %v", name, err)
		}
	}

	// Concurrently promote all 10 members
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("user%d", i)
			mgr.Promote("tv", "alice", name)
		}(i)
	}
	wg.Wait()

	// Verify all 10 are admin
	members, err := mgr.Members("tv")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("user%d", i)
		if members[name] != vault.RoleAdmin {
			t.Errorf("%s role = %q, want admin", name, members[name])
		}
	}
}

func TestAcceptCleansUpKeyOnMembersWriteFailure(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, err := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Make members.json read-only so the write fails after vault key is written
	membersPath := filepath.Join(dir, "vaults", "tv", "members.json")
	if err := os.Chmod(membersPath, 0400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(membersPath, 0600) // restore for cleanup

	// Accept should fail because members.json can't be written
	err = mgr.Accept("tv", "bob", token, bobAg, bobPub)
	if err == nil {
		t.Fatal("expected error when members.json is read-only")
	}

	// The vault key for bob should have been cleaned up
	keyPath := filepath.Join(dir, "vaults", "tv", "keys", "bob.enc")
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("orphaned vault key should have been cleaned up after members write failure")
	}
}

func TestAcceptLogsPendingInviteDeletionFailure(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)
	bobAg, bobPub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	token, err := mgr.Invite("tv", "alice", "bob", aliceAg, alicePub)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Make the pending directory read-only so invite deletion fails
	pendingDir := filepath.Join(dir, "vaults", "tv", "pending")
	if err := os.Chmod(pendingDir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(pendingDir, 0700)

	// Capture log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	// Accept should succeed (invite deletion is non-fatal)
	if err := mgr.Accept("tv", "bob", token, bobAg, bobPub); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// But a warning should have been logged
	if !strings.Contains(logBuf.String(), "failed to delete pending invite") {
		t.Errorf("expected warning about pending invite deletion failure, got: %q", logBuf.String())
	}
}

func TestRevokeNonMemberFails(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)
	aliceAg, alicePub := newTestAgent(t)

	mgr := vault.NewManager(store, []byte("server-secret"))
	if err := mgr.Create("tv", "alice", aliceAg, alicePub); err != nil {
		t.Fatalf("Create: %v", err)
	}

	err := mgr.Revoke("tv", "alice", "bob")
	if err == nil {
		t.Error("expected error revoking a non-member")
	}
}
