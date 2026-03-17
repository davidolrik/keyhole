package storage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrNotFound is returned when a secret does not exist.
var ErrNotFound = errors.New("secret not found")

// maxSecretFileSize limits the size of secret files read from disk to prevent
// memory exhaustion from files placed directly in the data directory.
// This is larger than the 64KB input limit to account for encryption overhead.
const maxSecretFileSize = 128 * 1024 // 128KB

// Store is the interface for reading and writing secrets.
type Store interface {
	Write(username, path string, ciphertext []byte) error
	Read(username, path string) ([]byte, error)
	Delete(username, path string) error
	List(username, prefix string) ([]string, error)
}

// FileStore stores secrets as files on disk.
// Each secret is stored at {dataDir}/{username}/account/{path}.enc
type FileStore struct {
	dataDir string
}

// NewFileStore creates a FileStore rooted at dataDir.
func NewFileStore(dataDir string) *FileStore {
	return &FileStore{dataDir: dataDir}
}

// Write encrypts and stores a secret for username at the given path.
func (s *FileStore) Write(username, secretPath string, ciphertext []byte) error {
	fpath := s.filePath(username, secretPath)
	dir := filepath.Dir(fpath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return WriteFileNoFollow(fpath, ciphertext, 0600)
}

// Read returns the raw ciphertext for the given username and path.
func (s *FileStore) Read(username, secretPath string) ([]byte, error) {
	fpath := s.filePath(username, secretPath)
	return readFileNoFollow(fpath, maxSecretFileSize)
}

// Delete removes a secret for the given username and path.
func (s *FileStore) Delete(username, secretPath string) error {
	fpath := s.filePath(username, secretPath)
	if err := removeNoFollow(fpath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// List returns all secret paths for username that start with prefix.
// Paths are returned relative to the user's secret root (e.g. "account/github").
func (s *FileStore) List(username, prefix string) ([]string, error) {
	root := s.secretRoot(username)
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
		// Convert to relative path and strip .enc suffix
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(rel, ".enc")
		// Use forward slashes in returned paths
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

// secretRoot returns the directory where a user's secrets are stored.
func (s *FileStore) secretRoot(username string) string {
	return filepath.Join(s.dataDir, username, "account")
}

// filePath returns the full filesystem path for a user's secret.
func (s *FileStore) filePath(username, secretPath string) string {
	return filepath.Join(s.secretRoot(username), filepath.FromSlash(secretPath)+".enc")
}

// WriteFileNoFollow creates or truncates a file with O_NOFOLLOW to atomically
// prevent symlink traversal, eliminating the TOCTOU race between a symlink
// check and the subsequent write.
func WriteFileNoFollow(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("symlink detected at %q", filepath.Base(path))
		}
		return err
	}
	_, writeErr := f.Write(data)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

// removeNoFollow verifies a path is not a symlink using Lstat, then removes it.
// Unlike reads and writes, os.Remove on a symlink removes the link itself (not
// the target), so there is no traversal risk. The check prevents accidental
// deletion of symlinks that should not exist in the data directory.
func removeNoFollow(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink detected at %q", filepath.Base(path))
	}
	return os.Remove(path)
}

// ReadFileNoFollow opens a file with O_NOFOLLOW to atomically prevent symlink
// traversal, then reads its contents using a LimitedReader to enforce maxSize
// without a separate stat call. This eliminates TOCTOU races between symlink
// checks and file reads, and between size checks and file reads.
func ReadFileNoFollow(path string, maxSize int64) ([]byte, error) {
	return readFileNoFollow(path, maxSize)
}

func readFileNoFollow(path string, maxSize int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("symlink detected at %q", filepath.Base(path))
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file %q exceeds size limit (%d bytes)", filepath.Base(path), maxSize)
	}
	return data, nil
}
