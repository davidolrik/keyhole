package command

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAuthorizedKeysExclusive(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, "alice", ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	// First write should succeed
	err := writeAuthorizedKeysExclusive(authKeysPath, []byte("ssh-ed25519 AAAA alice\n"))
	if err != nil {
		t.Fatalf("first write should succeed: %v", err)
	}

	// Second write should fail because file already exists
	err = writeAuthorizedKeysExclusive(authKeysPath, []byte("ssh-ed25519 BBBB attacker\n"))
	if err == nil {
		t.Fatal("second write should fail because file already exists")
	}

	// Verify the original content is preserved
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(data) != "ssh-ed25519 AAAA alice\n" {
		t.Errorf("file content = %q, want original key", string(data))
	}
}
