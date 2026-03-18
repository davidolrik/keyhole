package server

import (
	"bytes"
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
	"sync"
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
	defaultConnRateLimit           = 10
	defaultIdleTimeout             = 60 * time.Second
	defaultMaxTimeout              = 5 * time.Minute
	defaultReadLineTimeout         = 90 * time.Second
	defaultMaxConnections          = 256
	defaultInviteCodeTTL           = 72 * time.Hour
	defaultConsumedInviteRetention = 720 * time.Hour // 30 days
	inviteCleanupInterval          = 24 * time.Hour
)

// Config holds the runtime configuration for the server.
type Config struct {
	Listen                  string
	DataDir                 string
	Admins                  []string
	ServerSecret            []byte        // alphanumeric; if empty, loaded from {DataDir}/server_secret
	Version                 string
	ConnRateLimit           int           // max auth attempts per minute per IP; 0 = default (10)
	ReadLineTimeout         time.Duration // timeout for reading a line of input; 0 = default (60s)
	MaxConnections          int           // max concurrent SSH connections; 0 = default (256)
	InviteCodeTTL           time.Duration // how long invite codes are valid; 0 = default (72h)
	ConsumedInviteRetention time.Duration // how long to keep consumed invites; 0 = default (720h / 30 days)
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
	connSem      chan struct{} // semaphore to limit concurrent connections
	cleanupStop  chan struct{} // signals the invite cleanup goroutine to stop
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

	inviteCodeTTL := cfg.InviteCodeTTL
	if inviteCodeTTL == 0 {
		inviteCodeTTL = defaultInviteCodeTTL
	}
	consumedRetention := cfg.ConsumedInviteRetention
	if consumedRetention == 0 {
		consumedRetention = defaultConsumedInviteRetention
	}

	cleanupInvites(cfg.DataDir, inviteCodeTTL, consumedRetention)

	readLineTimeout := cfg.ReadLineTimeout
	if readLineTimeout == 0 {
		readLineTimeout = defaultReadLineTimeout
	}
	handler := command.NewHandler(store, store, enc, vaultMgr, serverSecret, cfg.DataDir, cfg.Admins, cfg.Version, auditLog, readLineTimeout, inviteCodeTTL)

	connLimit := cfg.ConnRateLimit
	if connLimit == 0 {
		connLimit = defaultConnRateLimit
	}

	maxConns := cfg.MaxConnections
	if maxConns == 0 {
		maxConns = defaultMaxConnections
	}

	cleanupStop := make(chan struct{})
	s := &Server{
		cfg:          cfg,
		store:        store,
		enc:          enc,
		serverSecret: serverSecret,
		hostKey:      hostKey,
		auditLog:     auditLog,
		connLimiter:  newRateLimiter(connLimit, time.Minute),
		connSem:      make(chan struct{}, maxConns),
		cleanupStop:  cleanupStop,
	}
	go s.runInviteCleanup(cfg.DataDir, inviteCodeTTL, consumedRetention)

	sshSrv := &ssh.Server{
		IdleTimeout: defaultIdleTimeout,
		MaxTimeout:  defaultMaxTimeout,
		HostSigners: []ssh.Signer{hostKey},
		ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
			select {
			case s.connSem <- struct{}{}:
				return &limitedConn{Conn: conn, sem: s.connSem}
			default:
				log.Printf("connection rejected: max connections (%d) reached", maxConns)
				conn.Close()
				return nil
			}
		},
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
	userDir := filepath.Join(s.cfg.DataDir, username)
	if isSymlink(userDir) {
		return fmt.Errorf("symlink detected at user directory for %q", username)
	}
	sshDir := filepath.Join(userDir, ".ssh")
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
	return storage.WriteFileNoFollow(authKeysPath, line, 0600)
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

// Close stops accepting connections, stops the invite cleanup goroutine,
// and closes the audit log.
func (s *Server) Close() error {
	close(s.cleanupStop)
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
	// Strip IPv6 zone identifiers (e.g. "%eth0") to prevent bypass via
	// different zone suffixes from the same address.
	if idx := strings.Index(ip, "%"); idx >= 0 {
		ip = ip[:idx]
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
	if isSymlink(filepath.Join(s.cfg.DataDir, username)) || isSymlink(filepath.Join(s.cfg.DataDir, username, ".ssh")) || isSymlink(authKeysPath) {
		log.Printf("auth: symlink detected in authorized_keys path for %q", username)
		s.auditLog.AuthDenied(username, remote, "symlink detected in authorized_keys path")
		return false
	}
	data, err := storage.ReadFileNoFollow(authKeysPath, 64*1024)
	if err == nil && checkAuthorizedKeys(data, key) {
		ctx.SetValue(keyVerifiedKey, true)
	}
	if err != nil && err != storage.ErrNotFound {
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
		errorf("%s", sanitizeError(err))
		sess.Exit(1)
		return
	}

	// Unverified sessions (wrong key or unregistered) may only use
	// allowlisted operations. Using an allowlist ensures that adding
	// operations in the future cannot accidentally expose them to
	// unauthenticated users.
	verified, _ := sess.Context().Value(keyVerifiedKey).(bool)
	if !verified {
		allowed := cmd.Op == command.OpRegister
		if !allowed {
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
		errorf("%s", sanitizeError(err))
		sess.Exit(1)
		return
	}

	cmdErr := handler.Handle(sess, username, sshPubKey, cmd)
	var auditAttrs []any
	if cmd.Op == command.OpMove {
		if cmd.Vault != "" {
			auditAttrs = append(auditAttrs, "source_vault", cmd.Vault)
		}
		auditAttrs = append(auditAttrs, "target_path", cmd.TargetPath)
		if cmd.TargetVault != "" {
			auditAttrs = append(auditAttrs, "target_vault", cmd.TargetVault)
		}
	}
	s.auditLog.Command(username, remote, cmd.Op.String(), cmd.Path, cmdErr, auditAttrs...)
	if cmdErr != nil {
		errorf("%s", sanitizeError(cmdErr))
		sess.Exit(1)
		return
	}
	sess.Exit(0)
}

// sanitizeError returns only the outermost error message, stripping wrapped
// internal details that could leak implementation information to SSH clients.
// For fmt.Errorf("context: %w", err) the outer context is the prefix before
// the ": " that precedes the wrapped error's text. If the wrapped text does
// not appear as a suffix (unexpected format), the full string is returned to
// avoid silently truncating useful information.
func sanitizeError(err error) string {
	wrapped := errors.Unwrap(err)
	if wrapped == nil {
		return err.Error()
	}
	full := err.Error()
	suffix := ": " + wrapped.Error()
	if strings.HasSuffix(full, suffix) {
		return full[:len(full)-len(suffix)]
	}
	return full
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
		if err := storage.WriteFileNoFollow(path, pemBytes, 0600); err != nil {
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
		crypto.Zeroize(configValue)
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
		if err := storage.WriteFileNoFollow(path, []byte(secret), 0600); err != nil {
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
	// Trim whitespace in-place to avoid creating a temporary string copy
	// that cannot be explicitly zeroed.
	secret := bytes.TrimSpace(data)
	crypto.Zeroize(data[len(secret):]) // zero any trailing whitespace bytes
	if len(secret) < minServerSecretLength {
		crypto.Zeroize(secret)
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

// limitedConn wraps a net.Conn and releases a semaphore slot on Close.
type limitedConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.sem })
	return err
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

// cleanupInvites removes expired invite codes and old consumed invites.
func cleanupInvites(dataDir string, codeExpiry, consumedRetention time.Duration) {
	cleanupDirByAge(filepath.Join(dataDir, "invites"), codeExpiry)
	cleanupDirByAge(filepath.Join(dataDir, "invites", "consumed"), consumedRetention)
}

// cleanupDirByAge removes regular files in dir whose modification time
// is older than maxAge. Directories are skipped. Missing dirs are ignored.
func cleanupDirByAge(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory may not exist yet
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > maxAge {
			path := filepath.Join(dir, e.Name())
			if err := os.Remove(path); err != nil {
				log.Printf("WARNING: failed to remove stale invite %s: %v", path, err)
			}
		}
	}
}

// runInviteCleanup periodically cleans up expired and consumed invites.
func (s *Server) runInviteCleanup(dataDir string, codeExpiry, consumedRetention time.Duration) {
	ticker := time.NewTicker(inviteCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.cleanupStop:
			return
		case <-ticker.C:
			cleanupInvites(dataDir, codeExpiry, consumedRetention)
		}
	}
}
