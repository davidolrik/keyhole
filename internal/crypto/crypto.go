package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	nonceSize    = 12 // GCM standard nonce size
	keySize      = 32 // AES-256
	hkdfInfo     = "keyhole-key-v1"
	challengeVer = "keyhole-v1"
)

// Encryptor encrypts and decrypts secrets using an SSH agent for key derivation.
type Encryptor struct{}

// NewEncryptor creates a new Encryptor.
func NewEncryptor() *Encryptor {
	return &Encryptor{}
}

// Encrypt encrypts plaintext for the given user and path using the SSH agent.
// The derived key uses the server secret as the HKDF salt.
func (e *Encryptor) Encrypt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, plaintext []byte) ([]byte, error) {
	return e.encryptWithSalt(ag, pubKey, serverSecret, username, path, plaintext, serverSecret)
}

// encryptWithSalt encrypts plaintext using an explicit HKDF salt.
func (e *Encryptor) encryptWithSalt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, plaintext []byte, salt []byte) ([]byte, error) {
	key, err := e.deriveKeyWithSalt(ag, pubKey, serverSecret, username, path, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return EncryptWithKey(key, plaintext)
}

// Decrypt decrypts ciphertext for the given user and path using the SSH agent.
// Uses the server secret as HKDF salt. For legacy data encrypted without salt,
// use DecryptAndUpgrade instead.
func (e *Encryptor) Decrypt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, ciphertext []byte) ([]byte, error) {
	key, err := e.deriveKeyWithSalt(ag, pubKey, serverSecret, username, path, serverSecret)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return DecryptWithKey(key, ciphertext)
}

// DecryptAndUpgrade decrypts ciphertext, falling back to nil-salt (legacy)
// derivation if the salted key fails. On legacy fallback, re-encrypts with the
// salted key and calls writeback to persist the upgrade. The writeback is
// best-effort — failure is not propagated.
func (e *Encryptor) DecryptAndUpgrade(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, ciphertext []byte, writeback func([]byte) error) ([]byte, error) {
	// Try salted derivation first
	plaintext, err := e.Decrypt(ag, pubKey, serverSecret, username, path, ciphertext)
	if err == nil {
		return plaintext, nil
	}

	// Fall back to nil-salt (legacy) derivation
	legacyKey, keyErr := e.deriveKeyWithSalt(ag, pubKey, serverSecret, username, path, nil)
	if keyErr != nil {
		return nil, err
	}
	plaintext, legacyErr := DecryptWithKey(legacyKey, ciphertext)
	if legacyErr != nil {
		return nil, err
	}

	// Re-encrypt with salted key and write back
	if writeback != nil {
		newCiphertext, encErr := e.Encrypt(ag, pubKey, serverSecret, username, path, plaintext)
		if encErr == nil {
			writeback(newCiphertext)
		}
	}

	return plaintext, nil
}

// deriveKey derives an AES-256 key using the server secret as HKDF salt.
func (e *Encryptor) deriveKey(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string) ([]byte, error) {
	return e.deriveKeyWithSalt(ag, pubKey, serverSecret, username, path, serverSecret)
}

// deriveKeyWithSalt derives an AES-256 key by having the agent sign a
// deterministic challenge, then running the signature through HKDF-SHA256
// with the given salt.
func (e *Encryptor) deriveKeyWithSalt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, salt []byte) ([]byte, error) {
	challenge := buildChallenge(serverSecret, username, path)

	sig, err := ag.Sign(pubKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("agent sign: %w", err)
	}

	reader := hkdf.New(sha256.New, sig.Blob, salt, []byte(hkdfInfo))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// buildChallenge constructs the deterministic challenge that the agent signs.
// challenge = SHA-256(serverSecret + ":" + "keyhole-v1:" + username + ":" + path)
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
