package audit

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
)

const maxLogSize = 10 * 1024 * 1024 // 10MB
const maxRotatedLogs = 5

// Logger writes structured audit events to {dataDir}/audit.log as JSON.
// All methods are goroutine-safe.
type Logger struct {
	l *slog.Logger
	f *os.File
}

// NewLogger opens (or creates) the audit log file in dataDir and returns a Logger.
// If the existing log exceeds 10MB, it is rotated to audit.log.1 before opening.
func NewLogger(dataDir string) (*Logger, error) {
	path := filepath.Join(dataDir, "audit.log")

	// Rotate if the log has grown too large, keeping up to maxRotatedLogs backups.
	if info, err := os.Stat(path); err == nil && info.Size() > maxLogSize {
		for i := maxRotatedLogs - 1; i >= 1; i-- {
			if err := os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1)); err != nil && !os.IsNotExist(err) {
				log.Printf("WARNING: audit log rotation step %d→%d failed: %v", i, i+1, err)
			}
		}
		if err := os.Rename(path, path+".1"); err != nil {
			log.Printf("WARNING: audit log rotation failed: %v", err)
			return nil, fmt.Errorf("audit log rotation failed: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	l := slog.New(slog.NewJSONHandler(f, nil))
	return &Logger{l: l, f: f}, nil
}

// Close closes the underlying log file.
func (lg *Logger) Close() error {
	return lg.f.Close()
}

// Connect logs a successful SSH authentication.
func (lg *Logger) Connect(username, remote, keyFingerprint string) {
	lg.l.Info("connect",
		"user", username,
		"remote", remote,
		"key", keyFingerprint,
	)
}

// AuthDenied logs a rejected authentication attempt.
func (lg *Logger) AuthDenied(username, remote, reason string) {
	lg.l.Warn("auth_denied",
		"user", username,
		"remote", remote,
		"reason", reason,
	)
}

// Registration logs a user registration event.
func (lg *Logger) Registration(username, remote, keyFingerprint, inviteCode string) {
	lg.l.Info("registration",
		"user", username,
		"remote", remote,
		"key", keyFingerprint,
		"invite_code", inviteCode,
	)
}

// VaultOp logs a vault operation (create, invite, accept, promote, destroy).
func (lg *Logger) VaultOp(op, actor, remote, vaultName string, attrs ...any) {
	args := []any{
		"actor", actor,
		"remote", remote,
		"vault", vaultName,
	}
	args = append(args, attrs...)
	lg.l.Info("vault_"+sanitizeLogValue(op), args...)
}

// VaultOpDenied logs a failed vault operation (permission denied, etc.).
func (lg *Logger) VaultOpDenied(op, actor, remote, vaultName, reason string, attrs ...any) {
	args := []any{
		"actor", actor,
		"remote", remote,
		"vault", vaultName,
		"reason", sanitizeLogValue(reason),
	}
	args = append(args, attrs...)
	lg.l.Warn("vault_"+sanitizeLogValue(op)+"_denied", args...)
}

// Command logs the result of an executed command.
func (lg *Logger) Command(username, remote, op, path string, err error) {
	if err == nil {
		lg.l.Info("command",
			"user", username,
			"remote", remote,
			"op", op,
			"path", path,
			"result", "ok",
		)
	} else {
		lg.l.Error("command",
			"user", username,
			"remote", remote,
			"op", op,
			"path", path,
			"result", "error",
			"err", sanitizeLogValue(err.Error()),
		)
	}
}

// sanitizeLogValue strips control characters (newlines, tabs, etc.) from a
// string before it is written to the audit log, preventing log injection.
func sanitizeLogValue(s string) string {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == '\t' {
			clean = append(clean, ' ')
		} else if c < 0x20 {
			continue
		} else {
			clean = append(clean, c)
		}
	}
	return string(clean)
}
