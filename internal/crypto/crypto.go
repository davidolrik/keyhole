package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
// The derived key is: HKDF-SHA256(agent.Sign(SHA256(serverSecret:keyhole-v1:username:path)))
func (e *Encryptor) Encrypt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, plaintext []byte) ([]byte, error) {
	key, err := e.deriveKey(ag, pubKey, serverSecret, username, path)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

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

// Decrypt decrypts ciphertext for the given user and path using the SSH agent.
func (e *Encryptor) Decrypt(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	key, err := e.deriveKey(ag, pubKey, serverSecret, username, path)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
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

// deriveKey derives an AES-256 key by having the agent sign a deterministic challenge.
func (e *Encryptor) deriveKey(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string) ([]byte, error) {
	challenge := buildChallenge(serverSecret, username, path)

	sig, err := ag.Sign(pubKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("agent sign: %w", err)
	}

	// Use HKDF-SHA256 to derive a 32-byte key from the signature blob
	reader := hkdf.New(sha256.New, sig.Blob, nil, []byte(hkdfInfo))
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
