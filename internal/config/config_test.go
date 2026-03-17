package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `
listen   = ":3333"
data_dir = "/var/lib/keyhole"
admins   = ["alice", "bob"]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Listen != ":3333" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":3333")
	}
	if cfg.DataDir != "/var/lib/keyhole" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/var/lib/keyhole")
	}
	if len(cfg.Admins) != 2 || cfg.Admins[0] != "alice" || cfg.Admins[1] != "bob" {
		t.Errorf("Admins = %v, want [alice bob]", cfg.Admins)
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	cfg, err := LoadFile("/nonexistent/path/keyhole.hcl")
	if err != nil {
		t.Fatalf("LoadFile on missing file should not error, got: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for missing file, got %+v", cfg)
	}
}

func TestLoadFile_Partial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `listen = ":4444"`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Listen != ":4444" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":4444")
	}
	if cfg.DataDir != "" {
		t.Errorf("DataDir = %q, want empty", cfg.DataDir)
	}
	if cfg.Admins != nil {
		t.Errorf("Admins = %v, want nil", cfg.Admins)
	}
}

func TestLoadEnv(t *testing.T) {
	t.Setenv("KEYHOLE_LISTEN", ":5555")
	t.Setenv("KEYHOLE_DATA_DIR", "/tmp/keyhole-env")
	t.Setenv("KEYHOLE_ADMINS", "carol, dave")

	cfg := LoadEnv()
	if cfg.Listen != ":5555" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":5555")
	}
	if cfg.DataDir != "/tmp/keyhole-env" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/tmp/keyhole-env")
	}
	if len(cfg.Admins) != 2 || cfg.Admins[0] != "carol" || cfg.Admins[1] != "dave" {
		t.Errorf("Admins = %v, want [carol dave]", cfg.Admins)
	}
}

func TestLoadEnv_Unset(t *testing.T) {
	// Ensure env vars are not set (t.Setenv restores after test)
	t.Setenv("KEYHOLE_LISTEN", "")
	t.Setenv("KEYHOLE_DATA_DIR", "")
	t.Setenv("KEYHOLE_ADMINS", "")
	os.Unsetenv("KEYHOLE_LISTEN")
	os.Unsetenv("KEYHOLE_DATA_DIR")
	os.Unsetenv("KEYHOLE_ADMINS")

	cfg := LoadEnv()
	if cfg.Listen != "" {
		t.Errorf("Listen = %q, want empty", cfg.Listen)
	}
	if cfg.DataDir != "" {
		t.Errorf("DataDir = %q, want empty", cfg.DataDir)
	}
	if cfg.Admins != nil {
		t.Errorf("Admins = %v, want nil", cfg.Admins)
	}
}

func TestMerge_Precedence(t *testing.T) {
	defaults := Config{Listen: ":2222", DataDir: "/default", Admins: nil}
	file := Config{Listen: ":3333", DataDir: "", Admins: []string{"alice"}}
	env := Config{Listen: "", DataDir: "/env-dir", Admins: nil}
	cli := Config{Listen: "", DataDir: "", Admins: []string{"override"}}

	got := Merge(defaults, file, env, cli)

	// file overrides defaults for Listen
	if got.Listen != ":3333" {
		t.Errorf("Listen = %q, want %q (file override)", got.Listen, ":3333")
	}
	// env overrides defaults for DataDir
	if got.DataDir != "/env-dir" {
		t.Errorf("DataDir = %q, want %q (env override)", got.DataDir, "/env-dir")
	}
	// cli overrides everything for Admins
	if len(got.Admins) != 1 || got.Admins[0] != "override" {
		t.Errorf("Admins = %v, want [override] (cli override)", got.Admins)
	}
}

func TestMerge_CLIOverridesAll(t *testing.T) {
	defaults := Config{Listen: ":2222", DataDir: "/default"}
	file := Config{Listen: ":3333", DataDir: "/file"}
	env := Config{Listen: ":4444", DataDir: "/env"}
	cli := Config{Listen: ":5555", DataDir: "/cli"}

	got := Merge(defaults, file, env, cli)

	if got.Listen != ":5555" {
		t.Errorf("Listen = %q, want %q", got.Listen, ":5555")
	}
	if got.DataDir != "/cli" {
		t.Errorf("DataDir = %q, want %q", got.DataDir, "/cli")
	}
}

func TestMerge_DefaultsUsedWhenNothingOverrides(t *testing.T) {
	defaults := Config{Listen: ":2222", DataDir: "/default", Admins: []string{"root"}}
	empty := Config{}

	got := Merge(defaults, empty, empty, empty)

	if got.Listen != ":2222" {
		t.Errorf("Listen = %q, want %q", got.Listen, ":2222")
	}
	if got.DataDir != "/default" {
		t.Errorf("DataDir = %q, want %q", got.DataDir, "/default")
	}
	if len(got.Admins) != 1 || got.Admins[0] != "root" {
		t.Errorf("Admins = %v, want [root]", got.Admins)
	}
}

func TestLoadFile_WorldReadableWithSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `server_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for world-readable config containing server_secret")
	}
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("error = %q, expected to mention 'permission'", err)
	}
}

func TestLoadFile_RestrictedWithSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `server_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.ServerSecret == "" {
		t.Error("expected server_secret to be loaded")
	}
}

func TestLoadFile_WorldReadableWithoutSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `listen = ":3333"`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for world-readable config file")
	}
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("error = %q, expected to mention 'permission'", err)
	}
}

func TestLoadFile_InviteTTLFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyhole.hcl")
	content := `
invite_code_ttl            = "48h"
consumed_invite_retention  = "168h"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.InviteCodeTTL != "48h" {
		t.Errorf("InviteCodeTTL = %q, want %q", cfg.InviteCodeTTL, "48h")
	}
	if cfg.ConsumedInviteRetention != "168h" {
		t.Errorf("ConsumedInviteRetention = %q, want %q", cfg.ConsumedInviteRetention, "168h")
	}
}

func TestLoadEnv_InviteTTLFields(t *testing.T) {
	t.Setenv("KEYHOLE_INVITE_CODE_TTL", "24h")
	t.Setenv("KEYHOLE_CONSUMED_INVITE_RETENTION", "360h")

	cfg := LoadEnv()
	if cfg.InviteCodeTTL != "24h" {
		t.Errorf("InviteCodeTTL = %q, want %q", cfg.InviteCodeTTL, "24h")
	}
	if cfg.ConsumedInviteRetention != "360h" {
		t.Errorf("ConsumedInviteRetention = %q, want %q", cfg.ConsumedInviteRetention, "360h")
	}
}

func TestMerge_InviteTTLFields(t *testing.T) {
	defaults := Config{InviteCodeTTL: "72h", ConsumedInviteRetention: "720h"}
	file := Config{InviteCodeTTL: "48h"}
	env := Config{}
	cli := Config{ConsumedInviteRetention: "168h"}

	got := Merge(defaults, file, env, cli)

	if got.InviteCodeTTL != "48h" {
		t.Errorf("InviteCodeTTL = %q, want %q (file override)", got.InviteCodeTTL, "48h")
	}
	if got.ConsumedInviteRetention != "168h" {
		t.Errorf("ConsumedInviteRetention = %q, want %q (cli override)", got.ConsumedInviteRetention, "168h")
	}
}

func TestDefault_InviteTTLFields(t *testing.T) {
	cfg := Default()
	if cfg.InviteCodeTTL != "72h" {
		t.Errorf("InviteCodeTTL = %q, want %q", cfg.InviteCodeTTL, "72h")
	}
	if cfg.ConsumedInviteRetention != "720h" {
		t.Errorf("ConsumedInviteRetention = %q, want %q", cfg.ConsumedInviteRetention, "720h")
	}
}

func TestLoadEnv_ServerSecretClearedFromEnv(t *testing.T) {
	t.Setenv("KEYHOLE_SERVER_SECRET", "test-secret-value-that-is-long-enough-for-the-minimum-length-check-ok")

	cfg := LoadEnv()
	if cfg.ServerSecret == "" {
		t.Fatal("expected server secret to be loaded")
	}

	// The environment variable should be cleared after loading
	if val := os.Getenv("KEYHOLE_SERVER_SECRET"); val != "" {
		t.Errorf("KEYHOLE_SERVER_SECRET still set in environment after LoadEnv: %q", val)
	}
}

func TestParseAdmins(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"alice", []string{"alice"}},
		{"alice,bob", []string{"alice", "bob"}},
		{" alice , bob , ", []string{"alice", "bob"}},
	}
	for _, tt := range tests {
		got := ParseAdmins(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("ParseAdmins(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParseAdmins(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
