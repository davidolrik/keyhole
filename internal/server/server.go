package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"go.olrik.dev/keyhole/internal/audit"
	"go.olrik.dev/keyhole/internal/command"
	"go.olrik.dev/keyhole/internal/crypto"
	"go.olrik.dev/keyhole/internal/storage"
	"go.olrik.dev/keyhole/internal/vault"
)

const serverSecretLength = 64

// contextKey is a type for SSH context keys to avoid collisions.
type contextKey string

const keyVerifiedKey contextKey = "keyVerified"

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const (
	defaultConnRateLimit   = 10
	defaultIdleTimeout     = 60 * time.Second
	defaultMaxTimeout      = 5 * time.Minute
	defaultReadLineTimeout = 90 * time.Second
)

// Config holds the runtime configuration for the server.
type Config struct {
	Listen          string
	DataDir         string
	Admins          []string
	ServerSecret    []byte // alphanumeric; if empty, loaded from {DataDir}/server_secret
	Version         string
	ConnRateLimit   int           // max auth attempts per minute per IP; 0 = default (10)
	ReadLineTimeout time.Duration // timeout for reading a line of input; 0 = default (60s)
}

// Server is the keyhole SSH server.
type Server struct {
	cfg          Config
	sshSrv       *ssh.Server
	store        *storage.FileStore
	enc          *crypto.Encryptor
	serverSecret []byte
	hostKey      gossh.Signer
	auditLog     *audit.Logger
	connLimiter  *rateLimiter
}

// New creates a new Server, initializing host key and server secret on first run.
func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := checkDataDirPermissions(cfg.DataDir); err != nil {
		return nil, err
	}

	hostKey, err := loadOrGenerateHostKey(filepath.Join(cfg.DataDir, "host_key"))
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	serverSecret, err := resolveServerSecret(cfg.ServerSecret, filepath.Join(cfg.DataDir, "server_secret"))
	if err != nil {
		return nil, fmt.Errorf("server secret: %w", err)
	}

	store := storage.NewFileStore(cfg.DataDir)
	enc := crypto.NewEncryptor()
	vaultMgr := vault.NewManager(store, serverSecret)

	auditLog, err := audit.NewLogger(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}

	readLineTimeout := cfg.ReadLineTimeout
	if readLineTimeout == 0 {
		readLineTimeout = defaultReadLineTimeout
	}
	handler := command.NewHandler(store, store, enc, vaultMgr, serverSecret, cfg.DataDir, cfg.Admins, cfg.Version, auditLog, readLineTimeout)

	connLimit := cfg.ConnRateLimit
	if connLimit == 0 {
		connLimit = defaultConnRateLimit
	}

	s := &Server{
		cfg:          cfg,
		store:        store,
		enc:          enc,
		serverSecret: serverSecret,
		hostKey:      hostKey,
		auditLog:     auditLog,
		connLimiter:  newRateLimiter(connLimit, time.Minute),
	}

	sshSrv := &ssh.Server{
		IdleTimeout: defaultIdleTimeout,
		MaxTimeout:  defaultMaxTimeout,
		HostSigners: []ssh.Signer{hostKey},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return s.publicKeyHandler(ctx, key)
		},
		Handler: func(sess ssh.Session) {
			s.sessionHandler(sess, handler)
		},
	}

	s.sshSrv = sshSrv
	return s, nil
}

// AddUserKey writes a public key to the user's authorized_keys file.
// Used for bootstrapping the first admin and for testing.
func (s *Server) AddUserKey(username string, pubKey gossh.PublicKey) error {
	sshDir := filepath.Join(s.cfg.DataDir, username, ".ssh")
	if isSymlink(sshDir) {
		return fmt.Errorf("symlink detected at .ssh directory for %q", username)
	}
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("create ssh dir: %w", err)
	}
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if isSymlink(authKeysPath) {
		return fmt.Errorf("symlink detected at authorized_keys for %q", username)
	}
	line := gossh.MarshalAuthorizedKey(pubKey)
	return os.WriteFile(authKeysPath, line, 0600)
}

// Serve accepts connections on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	return s.sshSrv.Serve(ln)
}

// ListenAndServe starts the server on the configured address.
func (s *Server) ListenAndServe() error {
	s.sshSrv.Addr = s.cfg.Listen
	return s.sshSrv.ListenAndServe()
}

// Close stops accepting connections and closes the audit log.
func (s *Server) Close() error {
	err := s.sshSrv.Close()
	if closeErr := s.auditLog.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return err
}

// publicKeyHandler authenticates a connecting client.
// Only Ed25519 keys are accepted. All Ed25519 keys are allowed through to
// prevent username enumeration — the session handler restricts unverified
// sessions to register and help only.
func (s *Server) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	username := ctx.User()
	remote := ctx.RemoteAddr().String()

	// Rate limit per IP to prevent brute-force and DoS attacks.
	ip, _, err := net.SplitHostPort(remote)
	if err != nil {
		// Malformed address — use the raw remote string as the rate-limit key
		// to prevent bypass via addresses that fail to parse.
		ip = remote
	}
	if !s.connLimiter.allow(ip) {
		s.auditLog.AuthDenied(username, remote, "rate limited")
		return false
	}

	// Reject usernames with path-unsafe characters early to prevent
	// directory traversal in the authorized_keys lookup below.
	if !isValidUsername(username) {
		s.auditLog.AuthDenied(username, remote, "invalid username")
		return false
	}

	if key.Type() != gossh.KeyAlgoED25519 {
		reason := "non-Ed25519 key type " + key.Type()
		log.Printf("auth: rejecting %s for user %q", reason, username)
		s.auditLog.AuthDenied(username, remote, reason)
		return false
	}

	// Check authorized_keys if they exist. Mark the key as verified only
	// when it matches. Unregistered users and wrong-key users both get
	// through auth identically — the session handler enforces access.
	authKeysPath := filepath.Join(s.cfg.DataDir, username, ".ssh", "authorized_keys")
	if isSymlink(filepath.Join(s.cfg.DataDir, username, ".ssh")) || isSymlink(authKeysPath) {
		log.Printf("auth: symlink detected in authorized_keys path for %q", username)
		s.auditLog.AuthDenied(username, remote, "symlink detected in authorized_keys path")
		return false
	}
	data, err := os.ReadFile(authKeysPath)
	if err == nil && checkAuthorizedKeys(data, key) {
		ctx.SetValue(keyVerifiedKey, true)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Printf("auth: error reading authorized_keys for %q: %v", username, err)
		s.auditLog.AuthDenied(username, remote, "error reading authorized_keys")
		return false
	}

	s.auditLog.Connect(username, remote, gossh.FingerprintSHA256(key))
	return true
}

// isSymlink reports whether path is a symbolic link.
func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

// checkAuthorizedKeys reports whether key is listed in the authorized_keys data.
func checkAuthorizedKeys(data []byte, key ssh.PublicKey) bool {
	for len(data) > 0 {
		pubKey, _, _, rest, err := gossh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		if ssh.KeysEqual(pubKey, key) {
			return true
		}
		data = rest
	}
	return false
}

// sessionHandler handles an authenticated SSH session.
func (s *Server) sessionHandler(sess ssh.Session, handler *command.Handler) {
	username := sess.User()
	remote := sess.RemoteAddr().String()

	// All output — including errors — is written to sess (stdout) rather than
	// sess.Stderr(). With a PTY allocated, stdout goes through the PTY master
	// which applies CRLF conversion, keeping the cursor at column 0 after each
	// line. sess.Stderr() is a plain SSH extended-data channel that bypasses
	// CRLF conversion, causing subsequent output to appear indented.
	errorf := func(format string, args ...any) {
		fmt.Fprintf(sess, "error: "+format+"\n", args...)
	}

	// Reject usernames with path-unsafe characters to prevent directory
	// traversal via the SSH username, which is used in filesystem paths
	// before any command-level validation occurs.
	if !isValidUsername(username) {
		s.auditLog.AuthDenied(username, remote, "invalid username")
		errorf("not authorized")
		sess.Exit(1)
		return
	}

	argv := sess.Command()
	cmd, err := command.Parse(argv)
	if err != nil {
		s.auditLog.Command(username, remote, "unknown", "", err)
		errorf("%v", err)
		sess.Exit(1)
		return
	}

	// Unverified sessions (wrong key or unregistered) may only register.
	// The same error is returned in both cases to prevent username enumeration.
	verified, _ := sess.Context().Value(keyVerifiedKey).(bool)
	if !verified {
		if cmd.Op != command.OpRegister {
			regErr := fmt.Errorf("not authorized")
			s.auditLog.Command(username, remote, cmd.Op.String(), cmd.Path, regErr)
			errorf("%v", regErr)
			sess.Exit(1)
			return
		}
	}

	pubKey := sess.PublicKey()
	sshPubKey, err := gossh.ParsePublicKey(pubKey.Marshal())
	if err != nil {
		s.auditLog.Command(username, remote, cmd.Op.String(), cmd.Path, err)
		errorf("parse public key: %v", err)
		sess.Exit(1)
		return
	}

	cmdErr := handler.Handle(sess, username, sshPubKey, cmd)
	s.auditLog.Command(username, remote, cmd.Op.String(), cmd.Path, cmdErr)
	if cmdErr != nil {
		errorf("%s", sanitizeError(cmdErr))
		sess.Exit(1)
		return
	}
	sess.Exit(0)
}

// sanitizeError returns only the outermost error message, stripping wrapped
// internal details that could leak implementation information to SSH clients.
func sanitizeError(err error) string {
	if wrapped := errors.Unwrap(err); wrapped != nil {
		// Strip the wrapped cause — return only the outer context.
		full := err.Error()
		suffix := ": " + wrapped.Error()
		return strings.TrimSuffix(full, suffix)
	}
	return err.Error()
}

// checkDataDirPermissions warns if the data directory is accessible by group or others.
func checkDataDirPermissions(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat data dir: %w", err)
	}
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("data directory %s has permissions %04o; must not be accessible by group or others (expected 0700)", dir, perm)
	}
	return nil
}

// loadOrGenerateHostKey loads an Ed25519 host key from path, generating one if absent.
func loadOrGenerateHostKey(path string) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// Generate and persist a new host key
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}
		pemBlock, err := gossh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return nil, fmt.Errorf("marshal host key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		if err := os.WriteFile(path, pemBytes, 0600); err != nil {
			return nil, fmt.Errorf("write host key: %w", err)
		}
		data = pemBytes
	}

	signer, err := gossh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	log.Printf("host key fingerprint: %s", gossh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

const minServerSecretLength = 64

// resolveServerSecret returns the server secret from the config value if provided,
// otherwise falls back to loading or generating from a file.
func resolveServerSecret(configValue []byte, path string) ([]byte, error) {
	if len(configValue) != 0 {
		secret := make([]byte, len(configValue))
		copy(secret, configValue)
		if len(secret) < minServerSecretLength {
			return nil, fmt.Errorf("server secret must be at least %d characters", minServerSecretLength)
		}
		return secret, nil
	}
	return loadOrGenerateServerSecret(path)
}

// loadOrGenerateServerSecret loads the server secret from path, generating one if absent.
func loadOrGenerateServerSecret(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		log.Printf("WARNING: generating new server secret at %s — back it up! Losing it makes all secrets unrecoverable.", path)
		secret, err := generateAlphanumericSecret(serverSecretLength)
		if err != nil {
			return nil, fmt.Errorf("generate server secret: %w", err)
		}
		if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
			return nil, fmt.Errorf("write server secret: %w", err)
		}
		return []byte(secret), nil
	}

	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return nil, fmt.Errorf("server secret file %s has permission %04o; must not be group- or world-readable (try: chmod 600 %s)", path, mode, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	secret := []byte(strings.TrimSpace(string(data)))
	if len(secret) < minServerSecretLength {
		return nil, fmt.Errorf("server secret in %s must be at least %d characters", path, minServerSecretLength)
	}
	return secret, nil
}

const maxUsernameLength = 64

// isValidUsername returns true if username contains only safe characters
// [a-zA-Z0-9_-]. This prevents path traversal when the username is used
// in filesystem paths.
func isValidUsername(username string) bool {
	if username == "" || len(username) > maxUsernameLength {
		return false
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// generateAlphanumericSecret returns a cryptographically random alphanumeric string of the given length.
func generateAlphanumericSecret(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		if err != nil {
			return "", fmt.Errorf("crypto/rand: %w", err)
		}
		b[i] = alphanumeric[idx.Int64()]
	}
	return string(b), nil
}
