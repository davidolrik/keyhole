package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/crypto"
)

// newTestAgent creates an in-memory agent with a fresh Ed25519 key.
// Returns the agent and the public key added to it.
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
	// agent.NewKeyring() concrete type implements ExtendedAgent
	extAgent, ok := kr.(agent.ExtendedAgent)
	if !ok {
		t.Fatal("keyring does not implement ExtendedAgent")
	}
	return extAgent, sshPub
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("test-server-secret")
	plaintext := []byte("my secret password")

	enc := crypto.NewEncryptor()

	ciphertext, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "account/github", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := enc.Decrypt(ag, pubKey, serverSecret, "alice", "account/github", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestDifferentServerSecretsProduceDifferentCiphertext(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	plaintext := []byte("my secret")

	enc := crypto.NewEncryptor()

	ct1, err := enc.Encrypt(ag, pubKey, []byte("server-secret-1"), "alice", "path", plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, err := enc.Encrypt(ag, pubKey, []byte("server-secret-2"), "alice", "path", plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	// Ciphertexts should differ because the derived keys differ
	if bytes.Equal(ct1, ct2) {
		t.Error("expected different ciphertexts for different server secrets")
	}

	// Decrypting with wrong server secret should fail
	_, err = enc.Decrypt(ag, pubKey, []byte("server-secret-2"), "alice", "path", ct1)
	if err == nil {
		t.Error("expected error when decrypting with wrong server secret")
	}
}

func TestDifferentPathsProduceDifferentCiphertext(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("server-secret")
	plaintext := []byte("same plaintext")

	enc := crypto.NewEncryptor()

	ct1, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "path/one", plaintext)
	if err != nil {
		t.Fatalf("Encrypt path/one: %v", err)
	}
	ct2, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "path/two", plaintext)
	if err != nil {
		t.Fatalf("Encrypt path/two: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("expected different ciphertexts for different paths")
	}

	// Cross-decryption should fail
	_, err = enc.Decrypt(ag, pubKey, serverSecret, "alice", "path/two", ct1)
	if err == nil {
		t.Error("expected error when decrypting with wrong path")
	}
}

func TestDifferentUsersProduceDifferentCiphertext(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("server-secret")
	plaintext := []byte("same plaintext")
	path := "account/secret"

	enc := crypto.NewEncryptor()

	ct1, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", path, plaintext)
	if err != nil {
		t.Fatalf("Encrypt alice: %v", err)
	}
	ct2, err := enc.Encrypt(ag, pubKey, serverSecret, "bob", path, plaintext)
	if err != nil {
		t.Fatalf("Encrypt bob: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("expected different ciphertexts for different users")
	}
}

func TestDecryptAndUpgradeLegacyData(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("test-server-secret")
	plaintext := []byte("my legacy secret")
	enc := crypto.NewEncryptor()

	// Create legacy ciphertext (nil salt)
	legacyCiphertext, err := enc.EncryptLegacy(ag, pubKey, serverSecret, "alice", "account/old", plaintext)
	if err != nil {
		t.Fatalf("EncryptLegacy: %v", err)
	}

	// Standard Decrypt (salted) should fail on legacy ciphertext
	_, err = enc.Decrypt(ag, pubKey, serverSecret, "alice", "account/old", legacyCiphertext)
	if err == nil {
		t.Fatal("expected error decrypting legacy ciphertext with salted Decrypt")
	}

	// DecryptAndUpgrade should succeed via fallback
	var upgraded []byte
	got, err := enc.DecryptAndUpgrade(ag, pubKey, serverSecret, "alice", "account/old", legacyCiphertext, func(newCiphertext []byte) error {
		upgraded = newCiphertext
		return nil
	})
	if err != nil {
		t.Fatalf("DecryptAndUpgrade: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
	if upgraded == nil {
		t.Error("writeback should have been called for legacy data")
	}

	// The upgraded ciphertext should be decryptable with standard (salted) Decrypt
	got2, err := enc.Decrypt(ag, pubKey, serverSecret, "alice", "account/old", upgraded)
	if err != nil {
		t.Fatalf("Decrypt upgraded ciphertext: %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Errorf("upgraded plaintext = %q, want %q", got2, plaintext)
	}
}

func TestDecryptAndUpgradeAlreadySalted(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("test-server-secret")
	plaintext := []byte("my salted secret")
	enc := crypto.NewEncryptor()

	// Create salted ciphertext
	ciphertext, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "account/new", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// DecryptAndUpgrade should NOT call writeback for already-salted data
	writebackCalled := false
	got, err := enc.DecryptAndUpgrade(ag, pubKey, serverSecret, "alice", "account/new", ciphertext, func(newCiphertext []byte) error {
		writebackCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("DecryptAndUpgrade: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
	if writebackCalled {
		t.Error("writeback should NOT have been called for already-salted data")
	}
}

func TestDecryptTruncatedData(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("server-secret")
	enc := crypto.NewEncryptor()

	ciphertext, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "path", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Truncate to fewer than the nonce size
	_, err = enc.Decrypt(ag, pubKey, serverSecret, "alice", "path", ciphertext[:5])
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}
