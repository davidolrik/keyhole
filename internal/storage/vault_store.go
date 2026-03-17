package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxMetadataSize = 1024 * 1024  // 1MB limit for metadata files
const maxWrappedKeySize = 64 * 1024  // 64KB limit for wrapped key files

// Vault storage layout:
//   {dataDir}/vaults/{vaultname}/meta.json
//   {dataDir}/vaults/{vaultname}/members.json
//   {dataDir}/vaults/{vaultname}/keys/{username}.enc
//   {dataDir}/vaults/{vaultname}/pending/{username}.invite
//   {dataDir}/vaults/{vaultname}/secrets/{path}.enc

// WriteVaultSecret stores an encrypted secret in a vault.
func (s *FileStore) WriteVaultSecret(vault, secretPath string, ciphertext []byte) error {
	fpath := s.vaultSecretPath(vault, secretPath)
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, ciphertext, 0600)
}

// ReadVaultSecret reads an encrypted secret from a vault.
func (s *FileStore) ReadVaultSecret(vault, secretPath string) ([]byte, error) {
	fpath := s.vaultSecretPath(vault, secretPath)
	return readFileNoFollow(fpath, maxSecretFileSize)
}

// ListVaultSecrets returns all secret paths in a vault that match the given prefix.
func (s *FileStore) ListVaultSecrets(vault, prefix string) ([]string, error) {
	root := s.vaultSecretsRoot(vault)
	var results []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".enc") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(rel, ".enc")
		rel = filepath.ToSlash(rel)

		if prefix == "" || rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			results = append(results, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// DeleteVaultSecret removes a secret from a vault.
func (s *FileStore) DeleteVaultSecret(vault, secretPath string) error {
	fpath := s.vaultSecretPath(vault, secretPath)
	if err := removeNoFollow(fpath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// WriteVaultMeta writes the vault metadata (meta.json).
func (s *FileStore) WriteVaultMeta(vault string, data []byte) error {
	fpath := filepath.Join(s.vaultDir(vault), "meta.json")
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, data, 0600)
}

// ReadVaultMeta reads the vault metadata.
func (s *FileStore) ReadVaultMeta(vault string) ([]byte, error) {
	fpath := filepath.Join(s.vaultDir(vault), "meta.json")
	return readFileNoFollow(fpath, maxMetadataSize)
}

// WriteVaultMembers writes the vault members file (members.json).
func (s *FileStore) WriteVaultMembers(vault string, data []byte) error {
	fpath := filepath.Join(s.vaultDir(vault), "members.json")
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, data, 0600)
}

// ReadVaultMembers reads the vault members file.
func (s *FileStore) ReadVaultMembers(vault string) ([]byte, error) {
	fpath := filepath.Join(s.vaultDir(vault), "members.json")
	return readFileNoFollow(fpath, maxMetadataSize)
}

// WriteVaultKey writes a user's wrapped vault key.
func (s *FileStore) WriteVaultKey(vault, username string, wrappedKey []byte) error {
	fpath := s.vaultKeyPath(vault, username)
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, wrappedKey, 0600)
}

// ReadVaultKey reads a user's wrapped vault key.
func (s *FileStore) ReadVaultKey(vault, username string) ([]byte, error) {
	fpath := s.vaultKeyPath(vault, username)
	return readFileNoFollow(fpath, maxWrappedKeySize)
}

// DeleteVaultKey removes a user's wrapped vault key.
func (s *FileStore) DeleteVaultKey(vault, username string) error {
	fpath := s.vaultKeyPath(vault, username)
	if err := removeNoFollow(fpath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// WritePendingInvite writes a pending invite for a user.
func (s *FileStore) WritePendingInvite(vault, username string, data []byte) error {
	fpath := s.pendingInvitePath(vault, username)
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, data, 0600)
}

// ReadPendingInvite reads a pending invite for a user.
func (s *FileStore) ReadPendingInvite(vault, username string) ([]byte, error) {
	fpath := s.pendingInvitePath(vault, username)
	return readFileNoFollow(fpath, maxMetadataSize)
}

// DeletePendingInvite removes a pending invite.
func (s *FileStore) DeletePendingInvite(vault, username string) error {
	fpath := s.pendingInvitePath(vault, username)
	if err := removeNoFollow(fpath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// ListVaults returns the names of all vaults that have a meta.json.
func (s *FileStore) ListVaults() ([]string, error) {
	vaultsDir := filepath.Join(s.dataDir, "vaults")
	entries, err := os.ReadDir(vaultsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var vaults []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Reject symlinked vault directories to prevent directory traversal.
		entryPath := filepath.Join(vaultsDir, e.Name())
		info, err := os.Lstat(entryPath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		metaPath := filepath.Join(vaultsDir, e.Name(), "meta.json")
		if _, err := os.Lstat(metaPath); err == nil {
			vaults = append(vaults, e.Name())
		}
	}
	return vaults, nil
}

// DeleteVault removes an entire vault directory and all its contents.
// It rejects symlinked vault directories to prevent a TOCTOU attack
// where the directory is replaced with a symlink between validation
// and deletion.
func (s *FileStore) DeleteVault(vault string) error {
	vaultPath := s.vaultDir(vault)
	info, err := os.Lstat(vaultPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vault directory is a symlink")
	}
	return os.RemoveAll(vaultPath)
}

func (s *FileStore) vaultDir(vault string) string {
	return filepath.Join(s.dataDir, "vaults", vault)
}

func (s *FileStore) vaultSecretsRoot(vault string) string {
	return filepath.Join(s.vaultDir(vault), "secrets")
}

func (s *FileStore) vaultSecretPath(vault, secretPath string) string {
	return filepath.Join(s.vaultSecretsRoot(vault), filepath.FromSlash(secretPath)+".enc")
}

func (s *FileStore) vaultKeyPath(vault, username string) string {
	return filepath.Join(s.vaultDir(vault), "keys", username+".enc")
}

func (s *FileStore) pendingInvitePath(vault, username string) string {
	return filepath.Join(s.vaultDir(vault), "pending", username+".invite")
}
