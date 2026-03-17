package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.olrik.dev/keyhole/internal/audit"
)

// logEntry represents a single JSON audit log line.
type logEntry struct {
	Time   string `json:"time"`
	Level  string `json:"level"`
	Msg    string `json:"msg"`
	User   string `json:"user"`
	Remote string `json:"remote"`
	Key    string `json:"key"`
	Op     string `json:"op"`
	Path   string `json:"path"`
	Result string `json:"result"`
	Err    string `json:"err"`
	Reason string `json:"reason"`
	Actor  string `json:"actor"`
	Vault  string `json:"vault"`
	Target string `json:"target"`
}

func TestLogFileCreated(t *testing.T) {
	dir := t.TempDir()
	_, err := audit.NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log")); err != nil {
		t.Errorf("audit.log not created: %v", err)
	}
}

func TestLogConnect(t *testing.T) {
	dir := t.TempDir()
	lg, err := audit.NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	lg.Connect("alice", "192.0.2.1:12345", "SHA256:abc123")

	entry := lastEntry(t, filepath.Join(dir, "audit.log"))
	if entry.Msg != "connect" {
		t.Errorf("msg = %q, want connect", entry.Msg)
	}
	if entry.User != "alice" {
		t.Errorf("user = %q, want alice", entry.User)
	}
	if entry.Remote != "192.0.2.1:12345" {
		t.Errorf("remote = %q, want 192.0.2.1:12345", entry.Remote)
	}
	if entry.Key != "SHA256:abc123" {
		t.Errorf("key = %q, want SHA256:abc123", entry.Key)
	}
	if entry.Time == "" {
		t.Error("time field is empty")
	}
	if entry.Level != "INFO" {
		t.Errorf("level = %q, want INFO", entry.Level)
	}
}

func TestLogCommand(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.Command("bob", "10.0.0.1:9999", "get", "account/github", nil)

	entry := lastEntry(t, filepath.Join(dir, "audit.log"))
	if entry.Msg != "command" {
		t.Errorf("msg = %q, want command", entry.Msg)
	}
	if entry.User != "bob" {
		t.Errorf("user = %q, want bob", entry.User)
	}
	if entry.Op != "get" {
		t.Errorf("op = %q, want get", entry.Op)
	}
	if entry.Path != "account/github" {
		t.Errorf("path = %q, want account/github", entry.Path)
	}
	if entry.Result != "ok" {
		t.Errorf("result = %q, want ok", entry.Result)
	}
}

func TestLogCommandError(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.Command("bob", "10.0.0.1:9999", "get", "account/github", os.ErrNotExist)

	entry := lastEntry(t, filepath.Join(dir, "audit.log"))
	if entry.Result != "error" {
		t.Errorf("result = %q, want error", entry.Result)
	}
	if entry.Err == "" {
		t.Error("err field is empty")
	}
	if entry.Level != "ERROR" {
		t.Errorf("level = %q, want ERROR", entry.Level)
	}
}

func TestLogAuthDenied(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.AuthDenied("mallory", "1.2.3.4:1234", "non-Ed25519 key type")

	entry := lastEntry(t, filepath.Join(dir, "audit.log"))
	if entry.Msg != "auth_denied" {
		t.Errorf("msg = %q, want auth_denied", entry.Msg)
	}
	if entry.User != "mallory" {
		t.Errorf("user = %q, want mallory", entry.User)
	}
	if entry.Reason != "non-Ed25519 key type" {
		t.Errorf("reason = %q, want 'non-Ed25519 key type'", entry.Reason)
	}
	if entry.Level != "WARN" {
		t.Errorf("level = %q, want WARN", entry.Level)
	}
}

func TestLogAppendsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	lg1, _ := audit.NewLogger(dir)
	lg1.Connect("alice", "1.2.3.4:1", "SHA256:aaa")
	lg1.Close()

	lg2, _ := audit.NewLogger(dir)
	lg2.Connect("bob", "5.6.7.8:2", "SHA256:bbb")
	lg2.Close()

	lines := allLines(t, filepath.Join(dir, "audit.log"))
	if len(lines) != 2 {
		t.Errorf("expected 2 lines after two loggers, got %d: %v", len(lines), lines)
	}
}

func TestLogIsConcurrentlySafe(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(i int) {
			lg.Connect("alice", "1.2.3.4:1234", "SHA256:abc")
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}

	lines := allLines(t, filepath.Join(dir, "audit.log"))
	if len(lines) != 20 {
		t.Errorf("expected 20 lines, got %d", len(lines))
	}
}

func TestLogVaultOpDenied(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.VaultOpDenied("promote", "mallory", "1.2.3.4:5678", "teamvault", "permission denied", "target", "alice")

	entry := lastEntry(t, filepath.Join(dir, "audit.log"))
	if entry.Msg != "vault_promote_denied" {
		t.Errorf("msg = %q, want vault_promote_denied", entry.Msg)
	}
	if entry.Actor != "mallory" {
		t.Errorf("actor = %q, want mallory", entry.Actor)
	}
	if entry.Vault != "teamvault" {
		t.Errorf("vault = %q, want teamvault", entry.Vault)
	}
	if entry.Reason != "permission denied" {
		t.Errorf("reason = %q, want 'permission denied'", entry.Reason)
	}
	if entry.Target != "alice" {
		t.Errorf("target = %q, want alice", entry.Target)
	}
	if entry.Level != "WARN" {
		t.Errorf("level = %q, want WARN", entry.Level)
	}
}

func TestLogLinesAreValidJSON(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.Connect("alice", "1.2.3.4:1", "SHA256:aaa")
	lg.Command("alice", "1.2.3.4:1", "get", "foo", nil)
	lg.AuthDenied("bob", "5.6.7.8:2", "bad key")

	lines := allLines(t, filepath.Join(dir, "audit.log"))
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", i, line)
		}
	}
}

// lastEntry returns the last log entry parsed from the audit log.
func lastEntry(t *testing.T, path string) logEntry {
	t.Helper()
	lines := allLines(t, path)
	if len(lines) == 0 {
		t.Fatal("audit.log is empty")
	}
	var entry logEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("failed to parse JSON log line: %v\nline: %s", err, lines[len(lines)-1])
	}
	return entry
}

// allLines returns all non-empty lines of a file.
func allLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit.log: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
