package crypto

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// EncryptLegacy encrypts using nil HKDF salt, for testing legacy fallback.
func (e *Encryptor) EncryptLegacy(ag agent.ExtendedAgent, pubKey ssh.PublicKey, serverSecret []byte, username, path string, plaintext []byte) ([]byte, error) {
	return e.encryptWithSalt(ag, pubKey, serverSecret, username, path, plaintext, nil)
}
