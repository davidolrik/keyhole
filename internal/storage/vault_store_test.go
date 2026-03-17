package storage_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.olrik.dev/keyhole/internal/storage"
)

func TestVaultStore_WriteReadSecret(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	data := []byte("encrypted-vault-data")
	if err := store.WriteVaultSecret("teamvault", "db/password", data); err != nil {
		t.Fatalf("WriteVaultSecret: %v", err)
	}

	got, err := store.ReadVaultSecret("teamvault", "db/password")
	if err != nil {
		t.Fatalf("ReadVaultSecret: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("ReadVaultSecret = %q, want %q", got, data)
	}
}

func TestVaultStore_ReadSecretNotFound(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	_, err := store.ReadVaultSecret("teamvault", "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("ReadVaultSecret nonexistent = %v, want ErrNotFound", err)
	}
}

func TestVaultStore_ListSecrets(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	secrets := []string{"db/prod", "db/staging", "api/key"}
	for _, s := range secrets {
		if err := store.WriteVaultSecret("tv", s, []byte("data")); err != nil {
			t.Fatalf("WriteVaultSecret %q: %v", s, err)
		}
	}

	t.Run("list all", func(t *testing.T) {
		got, err := store.ListVaultSecrets("tv", "")
		if err != nil {
			t.Fatalf("ListVaultSecrets: %v", err)
		}
		if len(got) != 3 {
			t.Errorf("ListVaultSecrets all = %v (len %d), want 3", got, len(got))
		}
	})

	t.Run("list with prefix", func(t *testing.T) {
		got, err := store.ListVaultSecrets("tv", "db")
		if err != nil {
			t.Fatalf("ListVaultSecrets: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("ListVaultSecrets db = %v (len %d), want 2", got, len(got))
		}
	})

	t.Run("list empty vault", func(t *testing.T) {
		got, err := store.ListVaultSecrets("empty", "")
		if err != nil {
			t.Fatalf("ListVaultSecrets: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("ListVaultSecrets empty = %v, want empty", got)
		}
	})
}

func TestVaultStore_DeleteSecret(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WriteVaultSecret("tv", "secret", []byte("data")); err != nil {
		t.Fatalf("WriteVaultSecret: %v", err)
	}
	if err := store.DeleteVaultSecret("tv", "secret"); err != nil {
		t.Fatalf("DeleteVaultSecret: %v", err)
	}
	_, err := store.ReadVaultSecret("tv", "secret")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("ReadVaultSecret after delete = %v, want ErrNotFound", err)
	}
}

func TestVaultStore_MetaRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	meta := []byte(`{"owner":"alice","created":"2026-01-01T00:00:00Z"}`)
	if err := store.WriteVaultMeta("tv", meta); err != nil {
		t.Fatalf("WriteVaultMeta: %v", err)
	}
	got, err := store.ReadVaultMeta("tv")
	if err != nil {
		t.Fatalf("ReadVaultMeta: %v", err)
	}
	if string(got) != string(meta) {
		t.Errorf("ReadVaultMeta = %q, want %q", got, meta)
	}
}

func TestVaultStore_MembersRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	members := []byte(`{"alice":"owner","bob":"member"}`)
	if err := store.WriteVaultMembers("tv", members); err != nil {
		t.Fatalf("WriteVaultMembers: %v", err)
	}
	got, err := store.ReadVaultMembers("tv")
	if err != nil {
		t.Fatalf("ReadVaultMembers: %v", err)
	}
	if string(got) != string(members) {
		t.Errorf("ReadVaultMembers = %q, want %q", got, members)
	}
}

func TestVaultStore_VaultKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	wrappedKey := []byte("wrapped-key-data")
	if err := store.WriteVaultKey("tv", "alice", wrappedKey); err != nil {
		t.Fatalf("WriteVaultKey: %v", err)
	}
	got, err := store.ReadVaultKey("tv", "alice")
	if err != nil {
		t.Fatalf("ReadVaultKey: %v", err)
	}
	if string(got) != string(wrappedKey) {
		t.Errorf("ReadVaultKey = %q, want %q", got, wrappedKey)
	}
}

func TestVaultStore_PendingInviteRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	pending := []byte("pending-invite-data")
	if err := store.WritePendingInvite("tv", "bob", pending); err != nil {
		t.Fatalf("WritePendingInvite: %v", err)
	}
	got, err := store.ReadPendingInvite("tv", "bob")
	if err != nil {
		t.Fatalf("ReadPendingInvite: %v", err)
	}
	if string(got) != string(pending) {
		t.Errorf("ReadPendingInvite = %q, want %q", got, pending)
	}

	if err := store.DeletePendingInvite("tv", "bob"); err != nil {
		t.Fatalf("DeletePendingInvite: %v", err)
	}
	_, err = store.ReadPendingInvite("tv", "bob")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("ReadPendingInvite after delete = %v, want ErrNotFound", err)
	}
}

func TestVaultStore_ReadSecretRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	// Write a normal secret
	if err := store.WriteVaultSecret("tv", "small", []byte("ok")); err != nil {
		t.Fatalf("WriteVaultSecret: %v", err)
	}

	// Manually write an oversized file
	largePath := filepath.Join(dir, "vaults", "tv", "secrets", "huge.enc")
	if err := os.MkdirAll(filepath.Dir(largePath), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	large := make([]byte, 256*1024)
	if err := os.WriteFile(largePath, large, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Normal read should work
	if _, err := store.ReadVaultSecret("tv", "small"); err != nil {
		t.Fatalf("ReadVaultSecret small: %v", err)
	}

	// Oversized read should fail
	_, err := store.ReadVaultSecret("tv", "huge")
	if err == nil {
		t.Fatal("ReadVaultSecret oversized should fail")
	}
}

func TestVaultStore_WriteMetaRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	// Create a real meta.json first
	if err := store.WriteVaultMeta("tv", []byte(`{"owner":"alice"}`)); err != nil {
		t.Fatalf("WriteVaultMeta: %v", err)
	}

	// Replace meta.json with a symlink
	metaPath := filepath.Join(dir, "vaults", "tv", "meta.json")
	targetDir := t.TempDir()
	targetFile := filepath.Join(targetDir, "evil.json")
	os.Remove(metaPath)
	if err := os.Symlink(targetFile, metaPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.WriteVaultMeta("tv", []byte(`{"owner":"evil"}`))
	if err == nil {
		t.Fatal("WriteVaultMeta through symlink should fail")
	}
}

func TestVaultStore_ReadMetaRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	// Create real meta
	if err := store.WriteVaultMeta("tv", []byte(`{"owner":"alice"}`)); err != nil {
		t.Fatalf("WriteVaultMeta: %v", err)
	}

	// Replace with symlink to the real file
	metaPath := filepath.Join(dir, "vaults", "tv", "meta.json")
	realCopy := metaPath + ".real"
	os.Rename(metaPath, realCopy)
	if err := os.Symlink(realCopy, metaPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := store.ReadVaultMeta("tv")
	if err == nil {
		t.Fatal("ReadVaultMeta through symlink should fail")
	}
}

func TestVaultStore_WriteVaultKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	// Write a real key first
	if err := store.WriteVaultKey("tv", "alice", []byte("key-data")); err != nil {
		t.Fatalf("WriteVaultKey: %v", err)
	}

	// Replace with symlink
	keyPath := filepath.Join(dir, "vaults", "tv", "keys", "alice.enc")
	targetDir := t.TempDir()
	os.Remove(keyPath)
	if err := os.Symlink(filepath.Join(targetDir, "evil.enc"), keyPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.WriteVaultKey("tv", "alice", []byte("evil-key"))
	if err == nil {
		t.Fatal("WriteVaultKey through symlink should fail")
	}
}

func TestVaultStore_ReadVaultKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WriteVaultKey("tv", "alice", []byte("key-data")); err != nil {
		t.Fatalf("WriteVaultKey: %v", err)
	}

	keyPath := filepath.Join(dir, "vaults", "tv", "keys", "alice.enc")
	realCopy := keyPath + ".real"
	os.Rename(keyPath, realCopy)
	if err := os.Symlink(realCopy, keyPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := store.ReadVaultKey("tv", "alice")
	if err == nil {
		t.Fatal("ReadVaultKey through symlink should fail")
	}
}

func TestVaultStore_WritePendingInviteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WritePendingInvite("tv", "bob", []byte("invite")); err != nil {
		t.Fatalf("WritePendingInvite: %v", err)
	}

	invitePath := filepath.Join(dir, "vaults", "tv", "pending", "bob.invite")
	targetDir := t.TempDir()
	os.Remove(invitePath)
	if err := os.Symlink(filepath.Join(targetDir, "evil.invite"), invitePath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.WritePendingInvite("tv", "bob", []byte("evil"))
	if err == nil {
		t.Fatal("WritePendingInvite through symlink should fail")
	}
}

func TestVaultStore_ReadPendingInviteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WritePendingInvite("tv", "bob", []byte("invite")); err != nil {
		t.Fatalf("WritePendingInvite: %v", err)
	}

	invitePath := filepath.Join(dir, "vaults", "tv", "pending", "bob.invite")
	realCopy := invitePath + ".real"
	os.Rename(invitePath, realCopy)
	if err := os.Symlink(realCopy, invitePath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := store.ReadPendingInvite("tv", "bob")
	if err == nil {
		t.Fatal("ReadPendingInvite through symlink should fail")
	}
}

func TestVaultStore_DeleteVaultKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WriteVaultKey("tv", "alice", []byte("key-data")); err != nil {
		t.Fatalf("WriteVaultKey: %v", err)
	}

	keyPath := filepath.Join(dir, "vaults", "tv", "keys", "alice.enc")
	realCopy := keyPath + ".real"
	os.Rename(keyPath, realCopy)
	if err := os.Symlink(realCopy, keyPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.DeleteVaultKey("tv", "alice")
	if err == nil {
		t.Fatal("DeleteVaultKey through symlink should fail")
	}
}

func TestVaultStore_DeletePendingInviteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WritePendingInvite("tv", "bob", []byte("invite")); err != nil {
		t.Fatalf("WritePendingInvite: %v", err)
	}

	invitePath := filepath.Join(dir, "vaults", "tv", "pending", "bob.invite")
	realCopy := invitePath + ".real"
	os.Rename(invitePath, realCopy)
	if err := os.Symlink(realCopy, invitePath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.DeletePendingInvite("tv", "bob")
	if err == nil {
		t.Fatal("DeletePendingInvite through symlink should fail")
	}
}

func TestVaultStore_WriteMembersRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WriteVaultMembers("tv", []byte(`{"alice":"owner"}`)); err != nil {
		t.Fatalf("WriteVaultMembers: %v", err)
	}

	membersPath := filepath.Join(dir, "vaults", "tv", "members.json")
	targetDir := t.TempDir()
	os.Remove(membersPath)
	if err := os.Symlink(filepath.Join(targetDir, "evil.json"), membersPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := store.WriteVaultMembers("tv", []byte(`{"evil":"owner"}`))
	if err == nil {
		t.Fatal("WriteVaultMembers through symlink should fail")
	}
}

func TestVaultStore_ReadMembersRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	if err := store.WriteVaultMembers("tv", []byte(`{"alice":"owner"}`)); err != nil {
		t.Fatalf("WriteVaultMembers: %v", err)
	}

	membersPath := filepath.Join(dir, "vaults", "tv", "members.json")
	realCopy := membersPath + ".real"
	os.Rename(membersPath, realCopy)
	if err := os.Symlink(realCopy, membersPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := store.ReadVaultMembers("tv")
	if err == nil {
		t.Fatal("ReadVaultMembers through symlink should fail")
	}
}

func TestVaultStore_ListVaults(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewFileStore(dir)

	// Create two vaults with metadata
	if err := store.WriteVaultMeta("alpha", []byte(`{"owner":"alice"}`)); err != nil {
		t.Fatalf("WriteVaultMeta alpha: %v", err)
	}
	if err := store.WriteVaultMeta("beta", []byte(`{"owner":"bob"}`)); err != nil {
		t.Fatalf("WriteVaultMeta beta: %v", err)
	}

	vaults, err := store.ListVaults()
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Errorf("ListVaults = %v (len %d), want 2", vaults, len(vaults))
	}

	found := map[string]bool{}
	for _, v := range vaults {
		found[v] = true
	}
	if !found["alpha"] || !found["beta"] {
		t.Errorf("ListVaults = %v, want alpha and beta", vaults)
	}
}
