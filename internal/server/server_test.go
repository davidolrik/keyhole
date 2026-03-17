package server_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.olrik.dev/keyhole/internal/server"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing concurrent SSH I/O.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testUserSetup sets up a user with a fresh Ed25519 key and returns all the pieces.
type testUser struct {
	edPriv gossh.Signer
	sshPub gossh.PublicKey
	ag     agent.ExtendedAgent
	cfg    *gossh.ClientConfig
}

func newTestUser(t *testing.T, username string) *testUser {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: edPriv}); err != nil {
		t.Fatalf("agent.Add: %v", err)
	}
	extAgent := kr.(agent.ExtendedAgent)

	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	return &testUser{edPriv: signer, sshPub: sshPub, ag: extAgent, cfg: cfg}
}

// testServerSetup creates a server with alice as admin, registers alice, and returns the address and data directory.
func testServerSetup(t *testing.T) (addr, dataDir string, alice *testUser) {
	t.Helper()
	dataDir = t.TempDir()
	alice = newTestUser(t, "alice")

	cfg := server.Config{
		DataDir: dataDir,
		Admins:  []string{"alice"},
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.AddUserKey("alice", alice.sshPub); err != nil {
		t.Fatalf("AddUserKey alice: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	return ln.Addr().String(), dataDir, alice
}

// sshRunWithStdin runs a command over SSH with stdin and agent forwarding.
func sshRunWithStdin(t *testing.T, addr string, cfg *gossh.ClientConfig, ag agent.ExtendedAgent, command string, stdin string) (string, error) {
	t.Helper()
	conn, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	if ag != nil {
		if err := agent.ForwardToAgent(conn, ag); err != nil {
			return "", fmt.Errorf("ForwardToAgent: %w", err)
		}
		if err := agent.RequestAgentForwarding(sess); err != nil {
			return "", fmt.Errorf("RequestAgentForwarding: %w", err)
		}
	}

	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out

	if err := sess.Run(command); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// sshRunWithEnv runs a command over SSH with the given environment variables set on the session.
func sshRunWithEnv(t *testing.T, addr string, cfg *gossh.ClientConfig, ag agent.ExtendedAgent, command string, env map[string]string) (string, error) {
	t.Helper()
	conn, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	if ag != nil {
		if err := agent.ForwardToAgent(conn, ag); err != nil {
			return "", fmt.Errorf("ForwardToAgent: %w", err)
		}
		if err := agent.RequestAgentForwarding(sess); err != nil {
			return "", fmt.Errorf("RequestAgentForwarding: %w", err)
		}
	}

	for k, v := range env {
		if err := sess.Setenv(k, v); err != nil {
			return "", fmt.Errorf("Setenv %s: %w", k, err)
		}
	}

	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out

	if err := sess.Run(command); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// sshRun runs a command with agent forwarding and no stdin.
func sshRun(t *testing.T, addr string, cfg *gossh.ClientConfig, ag agent.ExtendedAgent, command string) (string, error) {
	t.Helper()
	return sshRunWithStdin(t, addr, cfg, ag, command, "")
}

func TestSetAndGet(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/github", "hunter2"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := sshRun(t, addr, alice.cfg, alice.ag, "get account/github")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("get = %q, want %q", got, "hunter2")
	}
}

func TestList(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	for _, path := range []string{"account/github", "account/twitter", "db/prod"} {
		if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set "+path, "value"); err != nil {
			t.Fatalf("set %s: %v", path, err)
		}
	}

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "list account")
	if err != nil {
		t.Fatalf("list account: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Errorf("list account = %q (%d lines), want 2", out, len(lines))
	}

	out, err = sshRun(t, addr, alice.cfg, alice.ag, "list")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	lines = strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Errorf("list all = %q (%d lines), want 3", out, len(lines))
	}
}

func TestGetNonExistent(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	_, err := sshRun(t, addr, alice.cfg, alice.ag, "get nonexistent/secret")
	if err == nil {
		t.Error("expected error getting nonexistent secret")
	}
}

func TestGetWithoutAgentFails(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	// No agent passed
	_, err := sshRun(t, addr, alice.cfg, nil, "get account/something")
	if err == nil {
		t.Error("expected error when getting without agent")
	}
}

func TestSetWithoutAgentFails(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	_, err := sshRunWithStdin(t, addr, alice.cfg, nil, "set account/something", "secret")
	if err == nil {
		t.Error("expected error when setting without agent")
	}
}

func TestUnknownCommandFails(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	_, err := sshRun(t, addr, alice.cfg, alice.ag, "delete account/github")
	if err == nil {
		t.Error("expected error for unknown command")
	}
}

func TestInviteAndRegister(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	// Admin generates invite
	inviteOut, err := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	inviteCode := strings.TrimSpace(inviteOut)
	if !strings.HasPrefix(inviteCode, "kh_") {
		t.Errorf("invite code = %q, expected kh_ prefix", inviteCode)
	}

	// New user registers
	bob := newTestUser(t, "bob")
	regOut, err := sshRunWithStdin(t, addr, bob.cfg, nil, "register "+inviteCode, "y\n")
	if err != nil {
		t.Fatalf("register: %v (output: %q)", err, regOut)
	}
	if !strings.Contains(regOut, "successful") {
		t.Errorf("register output = %q, expected 'successful'", regOut)
	}

	// Bob can now connect
	listOut, err := sshRun(t, addr, bob.cfg, bob.ag, "list")
	if err != nil {
		t.Fatalf("bob list: %v", err)
	}
	_ = listOut

	// Invite code should be consumed
	charlie := newTestUser(t, "charlie")
	_, err = sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+inviteCode, "y\n")
	if err == nil {
		t.Error("expected error reusing consumed invite code")
	}
}

func TestInviteRegistrationRejected(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	inviteOut, err := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	inviteCode := strings.TrimSpace(inviteOut)

	bob := newTestUser(t, "bob")
	regOut, err := sshRunWithStdin(t, addr, bob.cfg, nil, "register "+inviteCode, "n\n")
	if err != nil {
		t.Fatalf("register (reject): unexpected error %v (output: %q)", err, regOut)
	}
	if !strings.Contains(regOut, "cancelled") {
		t.Errorf("register reject output = %q, expected 'cancelled'", regOut)
	}

	// Invite code should still be valid (not consumed)
	charlie := newTestUser(t, "charlie")
	regOut2, err := sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+inviteCode, "y\n")
	if err != nil {
		t.Fatalf("charlie register after bob rejection: %v (output: %q)", err, regOut2)
	}
}

func TestNonAdminInviteFails(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")

	// Server with NO admins
	cfg := server.Config{DataDir: dataDir, Admins: nil}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.AddUserKey("alice", alice.sshPub)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	_, err = sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err == nil {
		t.Error("expected error for non-admin invite")
	}
}

func TestEd25519OnlyAuth(t *testing.T) {
	dataDir := t.TempDir()
	cfg := server.Config{DataDir: dataDir, Admins: nil}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaSigner, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	clientCfg := &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(rsaSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	_, err = gossh.Dial("tcp", addr, clientCfg)
	if err == nil {
		t.Error("expected RSA auth to fail")
	}
}

func TestPathTraversalRejected(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	_, err := sshRun(t, addr, alice.cfg, alice.ag, "get ../../../etc/passwd")
	if err == nil {
		t.Error("expected path traversal to be rejected")
	}
}

func TestSetOverwritesExistingSecret(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/key", "original"); err != nil {
		t.Fatalf("set original: %v", err)
	}
	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/key", "updated"); err != nil {
		t.Fatalf("set updated: %v", err)
	}

	got, err := sshRun(t, addr, alice.cfg, alice.ag, "get account/key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "updated" {
		t.Errorf("get = %q, want %q", got, "updated")
	}
}

func TestSecretIsolationBetweenUsers(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	cfg := server.Config{DataDir: dataDir, Admins: []string{"alice"}}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.AddUserKey("alice", alice.sshPub)
	srv.AddUserKey("bob", bob.sshPub)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set shared/path", "alice-secret"); err != nil {
		t.Fatalf("alice set: %v", err)
	}
	if _, err := sshRunWithStdin(t, addr, bob.cfg, bob.ag, "set shared/path", "bob-secret"); err != nil {
		t.Fatalf("bob set: %v", err)
	}

	aliceGot, err := sshRun(t, addr, alice.cfg, alice.ag, "get shared/path")
	if err != nil {
		t.Fatalf("alice get: %v", err)
	}
	if aliceGot != "alice-secret" {
		t.Errorf("alice get = %q, want alice-secret", aliceGot)
	}

	bobGot, err := sshRun(t, addr, bob.cfg, bob.ag, "get shared/path")
	if err != nil {
		t.Fatalf("bob get: %v", err)
	}
	if bobGot != "bob-secret" {
		t.Errorf("bob get = %q, want bob-secret", bobGot)
	}
}

func TestListGlob(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	for _, path := range []string{"account/github", "account/gitlab", "account/twitter", "db/prod"} {
		if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set "+path, "v"); err != nil {
			t.Fatalf("set %s: %v", path, err)
		}
	}

	cases := []struct {
		cmd      string
		wantN    int
		wantHits []string
	}{
		{"ls account/git*", 2, []string{"account/github", "account/gitlab"}},
		{"ls account/*", 3, []string{"account/github", "account/gitlab", "account/twitter"}},
		{"ls *", 4, nil},
		{"list db/*", 1, []string{"db/prod"}},
	}

	for _, tc := range cases {
		out, err := sshRun(t, addr, alice.cfg, alice.ag, tc.cmd)
		if err != nil {
			t.Fatalf("%q: %v", tc.cmd, err)
		}
		plain := stripANSI(out)
		lines := strings.Split(strings.TrimSpace(plain), "\n")
		if len(lines) != tc.wantN {
			t.Errorf("%q: got %d lines, want %d:\n%s", tc.cmd, len(lines), tc.wantN, plain)
		}
		for _, hit := range tc.wantHits {
			if !strings.Contains(plain, hit) {
				t.Errorf("%q: output missing %q:\n%s", tc.cmd, hit, plain)
			}
		}
	}
}

func TestLsAlias(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	for _, path := range []string{"account/github", "account/twitter"} {
		if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set "+path, "v"); err != nil {
			t.Fatalf("set %s: %v", path, err)
		}
	}

	lsOut, err := sshRun(t, addr, alice.cfg, alice.ag, "ls account")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	listOut, err := sshRun(t, addr, alice.cfg, alice.ag, "list account")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if lsOut != listOut {
		t.Errorf("ls output %q != list output %q", lsOut, listOut)
	}
}


func TestHelp(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"get", "set", "list", "ls", "invite", "register", "help"} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing %q; got:\n%s", want, out)
		}
	}
}

func TestHelpColors(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	// Default (colors on): output should contain ANSI codes
	colored, err := sshRun(t, addr, alice.cfg, alice.ag, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(colored, "\033[") {
		t.Errorf("help output missing ANSI codes: %q", colored)
	}

	// NO_COLOR: output should be plain
	plain, err := sshRunWithEnv(t, addr, alice.cfg, alice.ag, "help", map[string]string{"NO_COLOR": "1"})
	if err != nil {
		t.Fatalf("help NO_COLOR: %v", err)
	}
	if strings.Contains(plain, "\033[") {
		t.Errorf("help NO_COLOR output contains ANSI codes: %q", plain)
	}
}

func TestListColorDefault(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/github", "s"); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Colors are on by default (no TERM or NO_COLOR set)
	colored, err := sshRun(t, addr, alice.cfg, alice.ag, "list")
	if err != nil {
		t.Fatalf("list (default): %v", err)
	}
	if !strings.Contains(colored, "\033[") {
		t.Errorf("default list missing ANSI codes: %q", colored)
	}

	// NO_COLOR disables colors
	plain, err := sshRunWithEnv(t, addr, alice.cfg, alice.ag, "list", map[string]string{"NO_COLOR": "1"})
	if err != nil {
		t.Fatalf("list (NO_COLOR): %v", err)
	}
	if strings.Contains(plain, "\033[") {
		t.Errorf("NO_COLOR list contains ANSI codes: %q", plain)
	}

	// TERM=dumb also disables colors
	plain2, err := sshRunWithEnv(t, addr, alice.cfg, alice.ag, "list", map[string]string{"TERM": "dumb"})
	if err != nil {
		t.Fatalf("list (TERM=dumb): %v", err)
	}
	if strings.Contains(plain2, "\033[") {
		t.Errorf("TERM=dumb list contains ANSI codes: %q", plain2)
	}
}

func TestAuditLogWritten(t *testing.T) {
	addr, dataDir, alice := testServerSetup(t)

	// Run a set then a get to produce connect + command entries
	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set audit/test", "s3cr3t"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := sshRun(t, addr, alice.cfg, alice.ag, "get audit/test"); err != nil {
		t.Fatalf("get: %v", err)
	}

	logPath := filepath.Join(dataDir, "audit.log")

	lines := readLines(t, logPath)
	if len(lines) == 0 {
		t.Fatal("audit.log is empty")
	}

	var hasConnect, hasSet, hasGet bool
	for _, l := range lines {
		if strings.Contains(l, `"msg":"connect"`) && strings.Contains(l, `"user":"alice"`) {
			hasConnect = true
		}
		if strings.Contains(l, `"msg":"command"`) && strings.Contains(l, `"op":"set"`) {
			hasSet = true
		}
		if strings.Contains(l, `"msg":"command"`) && strings.Contains(l, `"op":"get"`) {
			hasGet = true
		}
	}
	if !hasConnect {
		t.Errorf("no connect event for alice in audit log; lines: %v", lines)
	}
	if !hasSet {
		t.Errorf("no set command event in audit log; lines: %v", lines)
	}
	if !hasGet {
		t.Errorf("no get command event in audit log; lines: %v", lines)
	}
}

func TestAuditLogAuthDenied(t *testing.T) {
	dataDir := t.TempDir()
	cfg := server.Config{DataDir: dataDir, Admins: nil}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	// Attempt connection with RSA key — should be denied
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaSigner, _ := gossh.NewSignerFromKey(rsaKey)
	clientCfg := &gossh.ClientConfig{
		User:            "attacker",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(rsaSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	gossh.Dial("tcp", addr, clientCfg) //nolint:errcheck // expected to fail

	lines := readLines(t, filepath.Join(dataDir, "audit.log"))
	var hasDenied bool
	for _, l := range lines {
		if strings.Contains(l, `"msg":"auth_denied"`) && strings.Contains(l, `"user":"attacker"`) {
			hasDenied = true
		}
	}
	if !hasDenied {
		t.Errorf("no auth_denied event for attacker in audit log; lines: %v", lines)
	}
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // skip 'm'
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// readLines returns all non-empty lines of a file.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// testServerSetupMultiUser creates a server with alice (admin) and bob registered.
func testServerSetupMultiUser(t *testing.T) (addr, dataDir string, alice, bob *testUser) {
	t.Helper()
	dataDir = t.TempDir()
	alice = newTestUser(t, "alice")
	bob = newTestUser(t, "bob")

	cfg := server.Config{
		DataDir: dataDir,
		Admins:  []string{"alice"},
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.AddUserKey("alice", alice.sshPub); err != nil {
		t.Fatalf("AddUserKey alice: %v", err)
	}
	if err := srv.AddUserKey("bob", bob.sshPub); err != nil {
		t.Fatalf("AddUserKey bob: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	return ln.Addr().String(), dataDir, alice, bob
}

func TestVaultCreateInviteAcceptSetGet(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	// Alice creates a vault
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault create teamvault")
	if err != nil {
		t.Fatalf("vault create: %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "created") {
		t.Errorf("vault create output = %q, expected 'created'", out)
	}

	// Alice invites bob
	tokenOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault invite teamvault bob")
	if err != nil {
		t.Fatalf("vault invite: %v (output: %q)", err, tokenOut)
	}
	token := strings.TrimSpace(tokenOut)

	// Bob accepts the invite
	acceptOut, err := sshRun(t, addr, bob.cfg, bob.ag, "vault accept teamvault "+token)
	if err != nil {
		t.Fatalf("vault accept: %v (output: %q)", err, acceptOut)
	}
	if !strings.Contains(acceptOut, "Joined") {
		t.Errorf("vault accept output = %q, expected 'Joined'", acceptOut)
	}

	// Alice sets a secret in the vault
	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set teamvault:db/password", "s3cr3t"); err != nil {
		t.Fatalf("vault set: %v", err)
	}

	// Alice can get it
	got, err := sshRun(t, addr, alice.cfg, alice.ag, "get teamvault:db/password")
	if err != nil {
		t.Fatalf("alice vault get: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("alice vault get = %q, want %q", got, "s3cr3t")
	}

	// Bob can get the same secret
	got, err = sshRun(t, addr, bob.cfg, bob.ag, "get teamvault:db/password")
	if err != nil {
		t.Fatalf("bob vault get: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("bob vault get = %q, want %q", got, "s3cr3t")
	}
}

func TestVaultListSecrets(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	for _, path := range []string{"db/prod", "db/staging", "api/key"} {
		if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set tv:"+path, "val"); err != nil {
			t.Fatalf("vault set %s: %v", path, err)
		}
	}

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "list tv:")
	if err != nil {
		t.Fatalf("list tv: %v", err)
	}
	plain := stripANSI(out)
	lines := strings.Split(strings.TrimSpace(plain), "\n")
	if len(lines) != 3 {
		t.Errorf("list tv: got %d lines, want 3:\n%s", len(lines), plain)
	}

	out, err = sshRun(t, addr, alice.cfg, alice.ag, "list tv:db")
	if err != nil {
		t.Fatalf("list tv:db: %v", err)
	}
	plain = stripANSI(out)
	lines = strings.Split(strings.TrimSpace(plain), "\n")
	if len(lines) != 2 {
		t.Errorf("list tv:db: got %d lines, want 2:\n%s", len(lines), plain)
	}
}

func TestVaultNonMemberCannotAccess(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create secret-vault")
	sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set secret-vault:key", "value")

	// Bob is not a member — should fail
	_, err := sshRun(t, addr, bob.cfg, bob.ag, "get secret-vault:key")
	if err == nil {
		t.Error("expected error when non-member accesses vault secret")
	}
}

func TestVaultMemberCannotInvite(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite bob, accept
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)

	// Bob (member, not admin) tries to invite charlie — should fail
	charlie := newTestUser(t, "charlie")
	// First register charlie through the server
	inviteOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	inviteCode := strings.TrimSpace(inviteOut)
	sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+inviteCode, "y\n")

	_, err := sshRun(t, addr, bob.cfg, bob.ag, "vault invite tv charlie")
	if err == nil {
		t.Error("expected error when member tries to invite")
	}
}

func TestVaultPromoteAndInvite(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite and accept bob
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)

	// Promote bob to admin
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault promote tv bob")
	if err != nil {
		t.Fatalf("vault promote: %v (output: %q)", err, out)
	}

	// Register charlie
	charlie := newTestUser(t, "charlie")
	inviteOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	inviteCode := strings.TrimSpace(inviteOut)
	sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+inviteCode, "y\n")

	// Bob (now admin) can invite charlie
	tokenOut2, err := sshRun(t, addr, bob.cfg, bob.ag, "vault invite tv charlie")
	if err != nil {
		t.Fatalf("admin bob invite charlie: %v (output: %q)", err, tokenOut2)
	}
}

func TestVaultDemote(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite and accept bob
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)

	// Promote bob to admin
	sshRun(t, addr, alice.cfg, alice.ag, "vault promote tv bob")

	// Verify bob is admin
	membersOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault members tv")
	if err != nil {
		t.Fatalf("vault members: %v", err)
	}
	if !strings.Contains(membersOut, "admin") {
		t.Fatalf("bob should be admin: %q", membersOut)
	}

	// Demote bob
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault demote tv bob")
	if err != nil {
		t.Fatalf("vault demote: %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "Demoted") {
		t.Errorf("vault demote output = %q, expected 'Demoted'", out)
	}

	// Verify bob is now member
	membersOut, err = sshRun(t, addr, alice.cfg, alice.ag, "vault members tv")
	if err != nil {
		t.Fatalf("vault members: %v", err)
	}
	// Bob should appear as member, not admin
	for _, line := range strings.Split(membersOut, "\n") {
		if strings.Contains(line, "bob") && strings.Contains(line, "admin") {
			t.Errorf("bob should be member, not admin: %q", membersOut)
		}
	}
}

func TestVaultDemoteNonAdminFails(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)

	// Bob (member) cannot demote alice
	_, err := sshRun(t, addr, bob.cfg, bob.ag, "vault demote tv alice")
	if err == nil {
		t.Error("expected error when member tries to demote")
	}
}

func TestVaultDemotedAdminCannotInvite(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite bob, accept, promote to admin
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)
	sshRun(t, addr, alice.cfg, alice.ag, "vault promote tv bob")

	// Register charlie
	charlie := newTestUser(t, "charlie")
	inviteOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	inviteCode := strings.TrimSpace(inviteOut)
	sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+inviteCode, "y\n")

	// Demote bob back to member
	sshRun(t, addr, alice.cfg, alice.ag, "vault demote tv bob")

	// Bob (now member) should NOT be able to invite
	_, err := sshRun(t, addr, bob.cfg, bob.ag, "vault invite tv charlie")
	if err == nil {
		t.Error("expected error when demoted admin tries to invite")
	}
}

func TestVaultRevoke(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite and accept bob
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+token)

	// Store a secret as bob
	sshRunWithStdin(t, addr, bob.cfg, bob.ag, "set tv:shared/secret", "mysecret\n")

	// Revoke bob
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault revoke tv bob")
	if err != nil {
		t.Fatalf("vault revoke: %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "Revoked") {
		t.Errorf("vault revoke output = %q, expected 'Revoked'", out)
	}

	// Bob should no longer be able to access vault secrets
	_, err = sshRun(t, addr, bob.cfg, bob.ag, "get tv:shared/secret")
	if err == nil {
		t.Error("expected error when revoked user accesses vault")
	}

	// Bob should not appear in members
	membersOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault members tv")
	if err != nil {
		t.Fatalf("vault members: %v", err)
	}
	if strings.Contains(membersOut, "bob") {
		t.Errorf("bob should not appear in members after revoke: %q", membersOut)
	}
}

func TestVaultRevokeNonAdminFails(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")

	// Invite bob and charlie
	tokenB, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+strings.TrimSpace(tokenB))

	charlie := newTestUser(t, "charlie")
	inviteOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+strings.TrimSpace(inviteOut), "y\n")

	tokenC, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv charlie")
	sshRun(t, addr, charlie.cfg, charlie.ag, "vault accept tv "+strings.TrimSpace(tokenC))

	// Bob (member) cannot revoke charlie
	_, err := sshRun(t, addr, bob.cfg, bob.ag, "vault revoke tv charlie")
	if err == nil {
		t.Error("expected error when member tries to revoke")
	}
}

func TestVaultRevokeOwnerFails(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+strings.TrimSpace(tokenOut))
	sshRun(t, addr, alice.cfg, alice.ag, "vault promote tv bob")

	// Bob (admin) cannot revoke alice (owner)
	_, err := sshRun(t, addr, bob.cfg, bob.ag, "vault revoke tv alice")
	if err == nil {
		t.Error("expected error when trying to revoke the owner")
	}
}

func TestVaultMembers(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite tv bob")
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept tv "+strings.TrimSpace(tokenOut))

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault members tv")
	if err != nil {
		t.Fatalf("vault members: %v", err)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "owner") {
		t.Errorf("vault members missing alice (owner): %q", out)
	}
	if !strings.Contains(out, "bob") || !strings.Contains(out, "member") {
		t.Errorf("vault members missing bob (member): %q", out)
	}
}

func TestVaultList(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create alpha")
	sshRun(t, addr, alice.cfg, alice.ag, "vault create beta")

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "vault list")
	if err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("vault list = %q, want alpha and beta", out)
	}
}

func TestPersonalVaultUnchanged(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	// Personal vault operations should work exactly as before
	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/github", "token123"); err != nil {
		t.Fatalf("personal set: %v", err)
	}
	got, err := sshRun(t, addr, alice.cfg, alice.ag, "get account/github")
	if err != nil {
		t.Fatalf("personal get: %v", err)
	}
	if got != "token123" {
		t.Errorf("personal get = %q, want %q", got, "token123")
	}

	// Explicit personal: prefix should work the same
	got2, err := sshRun(t, addr, alice.cfg, alice.ag, "get personal:account/github")
	if err != nil {
		t.Fatalf("personal: get: %v", err)
	}
	if got2 != "token123" {
		t.Errorf("personal: get = %q, want %q", got2, "token123")
	}
}

func TestMovePersonalToVault(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create tv")
	sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set mykey", "secret-value")

	// Move with confirmation
	out, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "move mykey tv:mykey", "y")
	if err != nil {
		t.Fatalf("move: %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "moved") && !strings.Contains(out, "Moved") && !strings.Contains(out, "Secret moved") {
		t.Errorf("move output = %q, expected confirmation", out)
	}

	// Secret should be in vault now
	got, err := sshRun(t, addr, alice.cfg, alice.ag, "get tv:mykey")
	if err != nil {
		t.Fatalf("vault get after move: %v", err)
	}
	if got != "secret-value" {
		t.Errorf("vault get after move = %q, want %q", got, "secret-value")
	}

	// Source should be gone
	_, err = sshRun(t, addr, alice.cfg, alice.ag, "get mykey")
	if err == nil {
		t.Error("expected error getting deleted source secret")
	}
}

func TestAgentTempDirCleanup(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	// Snapshot existing auth-agent dirs before our operations
	before, err := filepath.Glob(filepath.Join(os.TempDir(), "auth-agent*"))
	if err != nil {
		t.Fatalf("glob before: %v", err)
	}
	beforeSet := make(map[string]bool, len(before))
	for _, d := range before {
		beforeSet[d] = true
	}

	// Run set and get — both use agent forwarding which creates temp dirs
	if _, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set account/cleanup-test", "val"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := sshRun(t, addr, alice.cfg, alice.ag, "get account/cleanup-test"); err != nil {
		t.Fatalf("get: %v", err)
	}

	// Check for leftover auth-agent dirs that weren't there before
	after, err := filepath.Glob(filepath.Join(os.TempDir(), "auth-agent*"))
	if err != nil {
		t.Fatalf("glob after: %v", err)
	}
	var leftover []string
	for _, d := range after {
		if !beforeSet[d] {
			leftover = append(leftover, d)
		}
	}
	if len(leftover) > 0 {
		t.Errorf("agent temp dirs not cleaned up: %v", leftover)
	}
}

func TestHelpIncludesVersion(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")

	cfg := server.Config{
		DataDir: dataDir,
		Admins:  []string{"alice"},
		Version: "v1.2.3",
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.AddUserKey("alice", alice.sshPub)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	out, err := sshRun(t, ln.Addr().String(), alice.cfg, alice.ag, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	plain := stripANSI(out)
	if !strings.Contains(plain, "Keyhole") {
		t.Errorf("help output missing 'Keyhole'; got:\n%s", plain)
	}
	if !strings.Contains(plain, "v1.2.3") {
		t.Errorf("help output missing version 'v1.2.3'; got:\n%s", plain)
	}
}

func TestVaultDestroyByOwner(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	// Create vault and set a secret
	sshRun(t, addr, alice.cfg, alice.ag, "vault create doomed")
	sshRunWithStdin(t, addr, alice.cfg, alice.ag, "set doomed:secret/key", "value")

	// Destroy the vault — type vault name to confirm
	out, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "vault destroy doomed", "doomed\n")
	if err != nil {
		t.Fatalf("vault destroy: %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "destroyed") {
		t.Errorf("vault destroy output = %q, expected 'destroyed'", out)
	}

	// vault list should no longer include "doomed"
	listOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault list")
	if err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if strings.Contains(listOut, "doomed") {
		t.Errorf("vault list still contains 'doomed' after destroy: %q", listOut)
	}

	// get on the vault secret should fail
	_, err = sshRun(t, addr, alice.cfg, alice.ag, "get doomed:secret/key")
	if err == nil {
		t.Error("expected error getting secret from destroyed vault")
	}
}

func TestVaultDestroyNonOwnerFails(t *testing.T) {
	addr, _, alice, bob := testServerSetupMultiUser(t)

	// Alice creates vault and invites Bob
	sshRun(t, addr, alice.cfg, alice.ag, "vault create protected")
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite protected bob")
	token := strings.TrimSpace(tokenOut)
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept protected "+token)

	// Bob (member) attempts destroy — should fail
	_, err := sshRunWithStdin(t, addr, bob.cfg, bob.ag, "vault destroy protected", "protected\n")
	if err == nil {
		t.Error("expected error when non-owner tries to destroy vault")
	}

	// Vault should still exist
	listOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault list")
	if err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if !strings.Contains(listOut, "protected") {
		t.Errorf("vault list missing 'protected' after failed destroy: %q", listOut)
	}
}

func TestVaultDestroyCancelledOnMismatch(t *testing.T) {
	addr, _, alice, _ := testServerSetupMultiUser(t)

	sshRun(t, addr, alice.cfg, alice.ag, "vault create keepsafe")

	// Send wrong name at confirmation
	out, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "vault destroy keepsafe", "wrong-name\n")
	if err != nil {
		t.Fatalf("vault destroy (mismatch): %v (output: %q)", err, out)
	}
	if !strings.Contains(out, "cancelled") {
		t.Errorf("vault destroy mismatch output = %q, expected 'cancelled'", out)
	}

	// Vault should still exist
	listOut, err := sshRun(t, addr, alice.cfg, alice.ag, "vault list")
	if err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if !strings.Contains(listOut, "keepsafe") {
		t.Errorf("vault list missing 'keepsafe' after cancelled destroy: %q", listOut)
	}
}

func TestExpiredInviteCodeRejected(t *testing.T) {
	addr, dataDir, alice := testServerSetup(t)

	// Admin generates invite
	inviteOut, err := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	inviteCode := strings.TrimSpace(inviteOut)
	invitePath := filepath.Join(dataDir, "invites", inviteCode)
	expired := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(invitePath, []byte(expired), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Registration should fail with expired code
	bob := newTestUser(t, "bob")
	_, err = sshRunWithStdin(t, addr, bob.cfg, nil, "register "+inviteCode, "y\n")
	if err == nil {
		t.Error("expected error registering with expired invite code")
	}
}

func TestSanitizedErrorMessages(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	// Try to get a nonexistent secret — error should not leak internal details
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "get nonexistent/secret")
	if err == nil {
		t.Fatal("expected error getting nonexistent secret")
	}
	// The output should contain a sanitized error, not the full wrapped chain
	if strings.Contains(out, ".enc") || strings.Contains(out, "no such file") {
		t.Errorf("error message leaks internal details: %q", out)
	}
}

func TestAuditLogRegistration(t *testing.T) {
	addr, dataDir, alice := testServerSetup(t)

	inviteOut, err := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	inviteCode := strings.TrimSpace(inviteOut)

	bob := newTestUser(t, "bob")
	_, err = sshRunWithStdin(t, addr, bob.cfg, nil, "register "+inviteCode, "y\n")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	logPath := filepath.Join(dataDir, "audit.log")
	lines := readLines(t, logPath)

	var hasRegistration bool
	for _, l := range lines {
		if strings.Contains(l, `"msg":"registration"`) && strings.Contains(l, `"user":"bob"`) {
			hasRegistration = true
		}
	}
	if !hasRegistration {
		t.Errorf("no registration event for bob in audit log; lines: %v", lines)
	}
}

func TestAuditLogVaultOperations(t *testing.T) {
	addr, dataDir, alice, bob := testServerSetupMultiUser(t)

	// Create vault
	sshRun(t, addr, alice.cfg, alice.ag, "vault create auditv")

	// Invite bob
	tokenOut, _ := sshRun(t, addr, alice.cfg, alice.ag, "vault invite auditv bob")
	token := strings.TrimSpace(tokenOut)

	// Bob accepts
	sshRun(t, addr, bob.cfg, bob.ag, "vault accept auditv "+token)

	// Promote bob
	sshRun(t, addr, alice.cfg, alice.ag, "vault promote auditv bob")

	// Destroy vault
	sshRunWithStdin(t, addr, alice.cfg, alice.ag, "vault destroy auditv", "auditv\n")

	logPath := filepath.Join(dataDir, "audit.log")
	lines := readLines(t, logPath)

	checks := map[string]bool{
		"vault_create":  false,
		"vault_invite":  false,
		"vault_accept":  false,
		"vault_promote": false,
		"vault_destroy": false,
	}
	for _, l := range lines {
		for op := range checks {
			if strings.Contains(l, `"msg":"`+op+`"`) {
				checks[op] = true
			}
		}
	}
	for op, found := range checks {
		if !found {
			t.Errorf("no %s event in audit log", op)
		}
	}
}

func TestVaultDestroyPersonalRejected(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	_, err := sshRunWithStdin(t, addr, alice.cfg, alice.ag, "vault destroy personal", "personal\n")
	if err == nil {
		t.Error("expected error when trying to destroy personal vault")
	}
}

func TestWrongKeyCanStillConnect(t *testing.T) {
	addr, _, _ := testServerSetup(t)

	// Someone with a different Ed25519 key connecting as "alice" (who is registered).
	// Should get through SSH auth but be restricted to register only.
	imposter := newTestUser(t, "alice")

	// Even help should be rejected for unverified sessions
	_, err := sshRun(t, addr, imposter.cfg, imposter.ag, "help")
	if err == nil {
		t.Error("imposter should not be able to run help")
	}

	// Register should be allowed (though it will fail with bad invite code)
	out, err := sshRunWithStdin(t, addr, imposter.cfg, nil, "register kh_0000000000000000000000000000000000000000000000000000000000000000", "y\n")
	if err == nil {
		t.Fatal("register with bad code should fail")
	}
	// Should get through to the register handler (not "not authorized")
	if strings.Contains(out, "not authorized") {
		t.Error("register should be allowed for unverified sessions")
	}
}

func TestWrongKeyCannotRunCommands(t *testing.T) {
	addr, _, _ := testServerSetup(t)

	imposter := newTestUser(t, "alice")

	for _, cmd := range []string{"list", "help", "vault list"} {
		out, err := sshRun(t, addr, imposter.cfg, imposter.ag, cmd)
		if err == nil {
			t.Errorf("imposter should not be able to run %q", cmd)
		}
		if !strings.Contains(out, "not authorized") {
			t.Errorf("cmd %q: expected 'not authorized' error, got: %q", cmd, out)
		}
	}
}

func TestUnregisteredAndWrongKeyGetSameError(t *testing.T) {
	addr, _, _ := testServerSetup(t)

	imposter := newTestUser(t, "alice")
	stranger := newTestUser(t, "nobody")

	outImposter, _ := sshRun(t, addr, imposter.cfg, imposter.ag, "list")
	outStranger, _ := sshRun(t, addr, stranger.cfg, stranger.ag, "list")

	if outImposter != outStranger {
		t.Errorf("different error messages leak username existence:\n  wrong key: %q\n  unregistered: %q", outImposter, outStranger)
	}
}

func TestRegisterWithBadCodeDoesNotLeakUsername(t *testing.T) {
	addr, _, _ := testServerSetup(t)

	// Try registering as "alice" (who exists) with a bad invite code
	imposter := newTestUser(t, "alice")
	out, err := sshRunWithStdin(t, addr, imposter.cfg, nil, "register kh_0000000000000000000000000000000000000000000000000000000000000000", "y\n")
	if err == nil {
		t.Fatal("register with bad code should fail")
	}
	// Should say "invalid invite code", NOT "username already exists"
	if strings.Contains(out, "already exists") {
		t.Error("error message leaks that username exists")
	}
}

func TestExpiredAndNonExistentInviteReturnSameError(t *testing.T) {
	addr, dataDir, alice := testServerSetup(t)

	// Generate a real invite and expire it
	inviteOut, err := sshRun(t, addr, alice.cfg, alice.ag, "invite")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	inviteCode := strings.TrimSpace(inviteOut)
	invitePath := filepath.Join(dataDir, "invites", inviteCode)
	expired := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(invitePath, []byte(expired), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Try with expired code
	bob := newTestUser(t, "bob")
	expiredOut, _ := sshRunWithStdin(t, addr, bob.cfg, nil, "register "+inviteCode, "y\n")

	// Try with non-existent code
	fakeCode := "kh_0000000000000000000000000000000000000000000000000000000000000000"
	charlie := newTestUser(t, "charlie")
	nonExistOut, _ := sshRunWithStdin(t, addr, charlie.cfg, nil, "register "+fakeCode, "y\n")

	// Both should return the same error message
	if expiredOut != nonExistOut {
		t.Errorf("error messages differ:\n  expired:     %q\n  non-existent: %q", expiredOut, nonExistOut)
	}
}

func TestConnectionRateLimit(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")

	cfg := server.Config{
		DataDir:       dataDir,
		Admins:        []string{"alice"},
		ConnRateLimit: 5,
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.AddUserKey("alice", alice.sshPub); err != nil {
		t.Fatalf("AddUserKey: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	addr := ln.Addr().String()

	var rejected bool
	for i := 0; i < 10; i++ {
		_, err := sshRun(t, addr, alice.cfg, alice.ag, "help")
		if err != nil {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Error("expected rate limit to reject connections after limit exceeded")
	}
}

func TestReadLineTimeout(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")

	cfg := server.Config{
		DataDir:         dataDir,
		Admins:          []string{"alice"},
		ReadLineTimeout: 200 * time.Millisecond,
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.AddUserKey("alice", alice.sshPub); err != nil {
		t.Fatalf("AddUserKey: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	addr := ln.Addr().String()

	// Run "set" with a blocking stdin — should timeout, not hang
	start := time.Now()

	conn, err := gossh.Dial("tcp", addr, alice.cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err := agent.ForwardToAgent(conn, alice.ag); err != nil {
		t.Fatalf("ForwardToAgent: %v", err)
	}
	if err := agent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("RequestAgentForwarding: %v", err)
	}
	// Stdin that never sends data — blocks forever without timeout
	pr, _ := io.Pipe()
	sess.Stdin = pr
	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	err = sess.Run("set test/key")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from read timeout")
	}
	if elapsed > 5*time.Second {
		t.Errorf("readLine took %v, expected timeout around 200ms", elapsed)
	}
}

func TestHelpIncludesVaultCommands(t *testing.T) {
	addr, _, alice := testServerSetup(t)

	out, err := sshRun(t, addr, alice.cfg, alice.ag, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"vault create", "vault invite", "vault accept", "vault promote", "vault demote", "vault revoke", "vault members", "vault destroy", "vault list", "move"} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing %q", want)
		}
	}
}

func TestShortServerSecretRejected(t *testing.T) {
	dataDir := t.TempDir()

	// 63 characters — one short of the 64-character minimum
	secret63 := strings.Repeat("a", 63)
	cfg := server.Config{
		DataDir:      dataDir,
		ServerSecret: secret63,
	}
	_, err := server.New(cfg)
	if err == nil {
		t.Fatal("expected error for 63-character server secret")
	}
	if !strings.Contains(err.Error(), "at least 64") {
		t.Errorf("error = %q, expected message about minimum 64 characters", err)
	}
}

func TestValidServerSecretAccepted(t *testing.T) {
	dataDir := t.TempDir()

	// Exactly 64 characters — meets the minimum
	secret64 := strings.Repeat("a", 64)
	cfg := server.Config{
		DataDir:      dataDir,
		ServerSecret: secret64,
	}
	_, err := server.New(cfg)
	if err != nil {
		t.Fatalf("64-character secret should be accepted, got: %v", err)
	}
}

func TestSymlinkedAuthorizedKeysRejected(t *testing.T) {
	dataDir := t.TempDir()
	alice := newTestUser(t, "alice")

	cfg := server.Config{DataDir: dataDir, Admins: []string{"alice"}}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// Set up alice's key normally first
	if err := srv.AddUserKey("alice", alice.sshPub); err != nil {
		t.Fatalf("AddUserKey: %v", err)
	}

	// Replace authorized_keys with a symlink
	authKeysPath := filepath.Join(dataDir, "alice", ".ssh", "authorized_keys")
	tmpFile := filepath.Join(dataDir, "real_keys")
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	os.Remove(authKeysPath)
	if err := os.Symlink(tmpFile, authKeysPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	time.Sleep(10 * time.Millisecond)

	// Alice should not be able to run commands (key not verified due to symlink)
	_, err = sshRun(t, addr, alice.cfg, alice.ag, "help")
	if err == nil {
		t.Error("expected error when authorized_keys is a symlink")
	}
}

func TestSanitizeErrorStripsInternalDetails(t *testing.T) {
	// sanitizeError is tested indirectly — errors returned by handler.Handle
	// go through sanitizeError in sessionHandler before reaching the client.
	// This test verifies that errors with wrapped details (like file paths)
	// are stripped to just the outermost message.

	// The move error "secret copied to destination but source could not be deleted: remove /path/to/file: permission denied"
	// should be sanitized to just "secret copied to destination but source could not be deleted"
	// by sessionHandler's sanitizeError. We verify this by attempting an operation
	// that returns a wrapped error and checking the SSH output.

	addr, _, alice := testServerSetup(t)

	// Try to get a non-existent secret — the error will be wrapped
	out, err := sshRun(t, addr, alice.cfg, alice.ag, "get nonexistent/secret")
	if err == nil {
		t.Fatal("expected error for non-existent secret")
	}
	// The output should not contain internal path details
	if strings.Contains(out, ".enc") || strings.Contains(out, "keyhole") {
		t.Errorf("error output leaks internal details: %q", out)
	}
}

func TestEmptyServerSecretFileRejected(t *testing.T) {
	dataDir := t.TempDir()

	// Write an empty server_secret file
	secretPath := filepath.Join(dataDir, "server_secret")
	if err := os.WriteFile(secretPath, []byte(""), 0600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	cfg := server.Config{DataDir: dataDir}
	_, err := server.New(cfg)
	if err == nil {
		t.Fatal("expected error for empty server secret file")
	}
	if !strings.Contains(err.Error(), "at least 64") {
		t.Errorf("error = %q, expected message about minimum 64 characters", err)
	}
}
