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
