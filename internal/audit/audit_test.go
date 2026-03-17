package audit_test

import (
	"bufio"
	"encoding/json"
	"fmt"
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

func TestLogRotationOnStartup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Create a log file larger than the rotation threshold (10MB)
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write 11MB of data
	chunk := make([]byte, 1024*1024) // 1MB
	for i := range chunk {
		chunk[i] = 'x'
	}
	for i := 0; i < 11; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	// Opening a new logger should rotate the large file
	lg, err := audit.NewLogger(dir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	lg.Connect("alice", "1.2.3.4:1", "SHA256:aaa")
	lg.Close()

	// The old log should have been rotated
	rotatedPath := logPath + ".1"
	info, err := os.Stat(rotatedPath)
	if err != nil {
		t.Fatalf("rotated log not found: %v", err)
	}
	if info.Size() < 10*1024*1024 {
		t.Errorf("rotated log size = %d, expected >= 10MB", info.Size())
	}

	// The new log should be small (just the one entry we wrote)
	info, err = os.Stat(logPath)
	if err != nil {
		t.Fatalf("new log not found: %v", err)
	}
	if info.Size() > 1024*1024 {
		t.Errorf("new log size = %d, expected < 1MB", info.Size())
	}
}

func TestLogRotationErrorReturned(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Create a log file larger than the rotation threshold
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1024*1024)
	for i := 0; i < 11; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	// Create non-empty directories at all rotation slots so the shift
	// loop cannot move any of them, leaving .1 in place and blocking
	// the final rename of audit.log → audit.log.1.
	for i := 1; i <= 5; i++ {
		d := fmt.Sprintf("%s.%d", logPath, i)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "blocker"), []byte("x"), 0600)
	}

	// NewLogger should return an error because rotation failed
	_, err = audit.NewLogger(dir)
	if err == nil {
		t.Fatal("expected error when rotation fails")
	}
}

func TestLogCommandWithAttrs(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.Command("alice", "10.0.0.1:9999", "move", "db/password", nil,
		"source_vault", "teamvault",
		"target_path", "production/db",
		"target_vault", "ops")

	entry := lastEntryRaw(t, filepath.Join(dir, "audit.log"))
	if entry["op"] != "move" {
		t.Errorf("op = %q, want move", entry["op"])
	}
	if entry["path"] != "db/password" {
		t.Errorf("path = %q, want db/password", entry["path"])
	}
	if entry["source_vault"] != "teamvault" {
		t.Errorf("source_vault = %q, want teamvault", entry["source_vault"])
	}
	if entry["target_path"] != "production/db" {
		t.Errorf("target_path = %q, want production/db", entry["target_path"])
	}
	if entry["target_vault"] != "ops" {
		t.Errorf("target_vault = %q, want ops", entry["target_vault"])
	}
}

func TestLogSanitizesAttrsInVaultOp(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.VaultOp("invite", "alice", "1.2.3.4:5678", "myvault",
		"target", "evil\nuser attacker level CRITICAL vault_destroy vault_important")

	entry := lastEntryRaw(t, filepath.Join(dir, "audit.log"))
	target, ok := entry["target"].(string)
	if !ok {
		t.Fatal("target field missing or not a string")
	}
	if target != "evil user attacker level CRITICAL vault_destroy vault_important" {
		t.Errorf("target not sanitized: %q", target)
	}
}

func TestLogSanitizesAttrsInVaultOpDenied(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.VaultOpDenied("promote", "mallory", "1.2.3.4:5678", "teamvault", "denied",
		"target", "evil\ruser\tattack")

	entry := lastEntryRaw(t, filepath.Join(dir, "audit.log"))
	target, ok := entry["target"].(string)
	if !ok {
		t.Fatal("target field missing or not a string")
	}
	if target != "evil user attack" {
		t.Errorf("target not sanitized: %q", target)
	}
}

func TestLogSanitizesAttrsInCommand(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.NewLogger(dir)
	lg.Command("alice", "10.0.0.1:9999", "move", "db/password", nil,
		"target_vault", "evil\nvault\x01injection")

	entry := lastEntryRaw(t, filepath.Join(dir, "audit.log"))
	tv, ok := entry["target_vault"].(string)
	if !ok {
		t.Fatal("target_vault field missing or not a string")
	}
	if tv != "evil vaultinjection" {
		t.Errorf("target_vault not sanitized: %q", tv)
	}
}

// lastEntryRaw returns the last log entry as a raw map for testing dynamic keys.
func lastEntryRaw(t *testing.T, path string) map[string]any {
	t.Helper()
	lines := allLines(t, path)
	if len(lines) == 0 {
		t.Fatal("audit.log is empty")
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("failed to parse JSON log line: %v\nline: %s", err, lines[len(lines)-1])
	}
	return entry
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
