package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

// Zeroize overwrites a byte slice with zeros to prevent key material from
// lingering in memory longer than necessary.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

const vaultHKDFInfo = "keyhole-vault-v1"

// DeriveVaultSecretKey derives an AES-256 key from a vault key and path using
// HKDF-SHA256, with serverSecret as the HKDF salt.
func DeriveVaultSecretKey(vaultKey []byte, path string, serverSecret []byte) ([]byte, error) {
	return deriveVaultSecretKey(vaultKey, path, serverSecret)
}

// DeriveVaultSecretKeyLegacy derives an AES-256 key using nil HKDF salt.
// Used for fallback decryption of data encrypted before salt was added.
func DeriveVaultSecretKeyLegacy(vaultKey []byte, path string) ([]byte, error) {
	return deriveVaultSecretKey(vaultKey, path, nil)
}

func deriveVaultSecretKey(vaultKey []byte, path string, salt []byte) ([]byte, error) {
	// Colon-separated info is unambiguous because paths are validated to
	// reject ':' characters at input.
	info := []byte(vaultHKDFInfo + ":" + path)
	reader := hkdf.New(sha256.New, vaultKey, salt, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// EncryptWithKey encrypts plaintext with a symmetric AES-256-GCM key.
// The returned ciphertext is nonce || GCM-sealed data.
func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptWithKey decrypts ciphertext with a symmetric AES-256-GCM key.
func DecryptWithKey(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	plaintext, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
