package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"go.olrik.dev/keyhole/internal/audit"
	"go.olrik.dev/keyhole/internal/command"
	"go.olrik.dev/keyhole/internal/crypto"
	"go.olrik.dev/keyhole/internal/storage"
	"go.olrik.dev/keyhole/internal/vault"
)

const serverSecretLength = 64

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Config holds the runtime configuration for the server.
type Config struct {
	Listen       string
	DataDir      string
	Admins       []string
	ServerSecret string // alphanumeric; if empty, loaded from {DataDir}/server_secret
	Version      string
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
}

// New creates a new Server, initializing host key and server secret on first run.
func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
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

	handler := command.NewHandler(store, store, enc, vaultMgr, serverSecret, cfg.DataDir, cfg.Admins, cfg.Version, auditLog)

	s := &Server{
		cfg:          cfg,
		store:        store,
		enc:          enc,
		serverSecret: serverSecret,
		hostKey:      hostKey,
		auditLog:     auditLog,
	}

	sshSrv := &ssh.Server{
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("create ssh dir: %w", err)
	}
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
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

// publicKeyHandler authenticates a connecting client.
// Only Ed25519 keys are accepted. For existing users, the key is checked against
// their authorized_keys. For new users (no authorized_keys), any Ed25519 key is
// allowed through — the command handler will require a valid invite code.
func (s *Server) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	username := ctx.User()
	remote := ctx.RemoteAddr().String()

	if key.Type() != gossh.KeyAlgoED25519 {
		reason := "non-Ed25519 key type " + key.Type()
		log.Printf("auth: rejecting %s for user %q", reason, username)
		s.auditLog.AuthDenied(username, remote, reason)
		return false
	}

	authKeysPath := filepath.Join(s.cfg.DataDir, username, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No authorized_keys — allow through; session handler will require register
			s.auditLog.Connect(username, remote, gossh.FingerprintSHA256(key))
			return true
		}
		log.Printf("auth: error reading authorized_keys for %q: %v", username, err)
		s.auditLog.AuthDenied(username, remote, "error reading authorized_keys")
		return false
	}

	if !checkAuthorizedKeys(data, key) {
		s.auditLog.AuthDenied(username, remote, "key not in authorized_keys")
		return false
	}

	s.auditLog.Connect(username, remote, gossh.FingerprintSHA256(key))
	return true
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

	argv := sess.Command()
	cmd, err := command.Parse(argv)
	if err != nil {
		s.auditLog.Command(username, remote, "unknown", "", err)
		errorf("%v", err)
		sess.Exit(1)
		return
	}

	// Users without authorized_keys may only register or ask for help
	authKeysPath := filepath.Join(s.cfg.DataDir, username, ".ssh", "authorized_keys")
	if _, statErr := os.Stat(authKeysPath); os.IsNotExist(statErr) {
		if cmd.Op != command.OpRegister && cmd.Op != command.OpHelp {
			regErr := fmt.Errorf("user %q not registered; use 'register <invite_code>'", username)
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
		errorf("%v", cmdErr)
		sess.Exit(1)
		return
	}
	sess.Exit(0)
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

// resolveServerSecret returns the server secret from the config value if provided,
// otherwise falls back to loading or generating from a file.
func resolveServerSecret(configValue, path string) ([]byte, error) {
	if configValue != "" {
		return []byte(strings.TrimSpace(configValue)), nil
	}
	return loadOrGenerateServerSecret(path)
}

// loadOrGenerateServerSecret loads the server secret from path, generating one if absent.
func loadOrGenerateServerSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		log.Printf("WARNING: generating new server secret at %s — back it up! Losing it makes all secrets unrecoverable.", path)
		secret := generateAlphanumericSecret(serverSecretLength)
		if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
			return nil, fmt.Errorf("write server secret: %w", err)
		}
		return []byte(secret), nil
	}

	return []byte(strings.TrimSpace(string(data))), nil
}

// generateAlphanumericSecret returns a cryptographically random alphanumeric string of the given length.
func generateAlphanumericSecret(length int) string {
	b := make([]byte, length)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		b[i] = alphanumeric[idx.Int64()]
	}
	return string(b)
}
