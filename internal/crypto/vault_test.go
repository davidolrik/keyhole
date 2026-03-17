package crypto_test

import (
	"bytes"
	"testing"

	"go.olrik.dev/keyhole/internal/crypto"
)

func TestDeriveVaultSecretKey(t *testing.T) {
	vaultKey := make([]byte, 512)
	for i := range vaultKey {
		vaultKey[i] = byte(i % 256)
	}

	key, err := crypto.DeriveVaultSecretKey(vaultKey, "foo/bar", []byte("server-secret"))
	if err != nil {
		t.Fatalf("DeriveVaultSecretKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestDeriveVaultSecretKeySaltProducesDifferentKeys(t *testing.T) {
	vaultKey := make([]byte, 512)
	for i := range vaultKey {
		vaultKey[i] = byte(i % 256)
	}

	salted, err := crypto.DeriveVaultSecretKey(vaultKey, "foo/bar", []byte("server-secret"))
	if err != nil {
		t.Fatalf("DeriveVaultSecretKey salted: %v", err)
	}
	legacy, err := crypto.DeriveVaultSecretKeyLegacy(vaultKey, "foo/bar")
	if err != nil {
		t.Fatalf("DeriveVaultSecretKeyLegacy: %v", err)
	}

	if bytes.Equal(salted, legacy) {
		t.Error("salted and legacy keys should differ")
	}
}

func TestDeriveVaultSecretKeyDifferentPaths(t *testing.T) {
	vaultKey := make([]byte, 512)
	for i := range vaultKey {
		vaultKey[i] = byte(i % 256)
	}

	key1, err := crypto.DeriveVaultSecretKey(vaultKey, "path/one", []byte("server-secret"))
	if err != nil {
		t.Fatalf("DeriveVaultSecretKey path/one: %v", err)
	}
	key2, err := crypto.DeriveVaultSecretKey(vaultKey, "path/two", []byte("server-secret"))
	if err != nil {
		t.Fatalf("DeriveVaultSecretKey path/two: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different paths should produce different keys")
	}
}

func TestEncryptDecryptWithKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("my vault secret")

	ciphertext, err := crypto.EncryptWithKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}

	got, err := crypto.DecryptWithKey(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithKey: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptWithKey = %q, want %q", got, plaintext)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	ciphertext, err := crypto.EncryptWithKey(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}

	_, err = crypto.DecryptWithKey(key2, ciphertext)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestCrossPathDecryptFails(t *testing.T) {
	vaultKey := make([]byte, 512)
	for i := range vaultKey {
		vaultKey[i] = byte(i % 256)
	}

	key1, _ := crypto.DeriveVaultSecretKey(vaultKey, "path/one", []byte("server-secret"))
	key2, _ := crypto.DeriveVaultSecretKey(vaultKey, "path/two", []byte("server-secret"))

	ciphertext, err := crypto.EncryptWithKey(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}

	_, err = crypto.DecryptWithKey(key2, ciphertext)
	if err == nil {
		t.Error("expected error decrypting with key derived from different path")
	}
}

func TestDecryptWithKeyTruncatedData(t *testing.T) {
	_, err := crypto.DecryptWithKey(make([]byte, 32), []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestDecryptWithKeyRejectsTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("authentic data")

	ciphertext, err := crypto.EncryptWithKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}

	// Flip a bit in the ciphertext body (after the 12-byte nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0x01

	_, err = crypto.DecryptWithKey(key, tampered)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext")
	}

	// Flip a bit in the nonce
	tamperedNonce := make([]byte, len(ciphertext))
	copy(tamperedNonce, ciphertext)
	tamperedNonce[0] ^= 0x01

	_, err = crypto.DecryptWithKey(key, tamperedNonce)
	if err == nil {
		t.Error("expected error when decrypting ciphertext with tampered nonce")
	}

	// Append extra byte
	extended := append(ciphertext, 0x42)
	_, err = crypto.DecryptWithKey(key, extended)
	if err == nil {
		t.Error("expected error when decrypting ciphertext with appended data")
	}
}

func TestDecryptPersonalRejectsTamperedCiphertext(t *testing.T) {
	ag, pubKey := newTestAgent(t)
	serverSecret := []byte("test-server-secret")
	enc := crypto.NewEncryptor()

	ciphertext, err := enc.Encrypt(ag, pubKey, serverSecret, "alice", "path", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a bit in the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0x01

	_, err = enc.Decrypt(ag, pubKey, serverSecret, "alice", "path", tampered)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext")
	}
}
