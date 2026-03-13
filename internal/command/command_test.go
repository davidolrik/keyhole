package command_test

import (
	"strings"
	"testing"

	"go.olrik.dev/keyhole/internal/command"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		want    command.Command
		wantErr bool
	}{
		{
			name: "get command",
			argv: []string{"get", "account/github"},
			want: command.Command{Op: command.OpGet, Path: "account/github"},
		},
		{
			name: "set command",
			argv: []string{"set", "account/twitter"},
			want: command.Command{Op: command.OpSet, Path: "account/twitter"},
		},
		{
			name: "list with prefix",
			argv: []string{"list", "account"},
			want: command.Command{Op: command.OpList, Path: "account"},
		},
		{
			name: "list without prefix",
			argv: []string{"list"},
			want: command.Command{Op: command.OpList, Path: ""},
		},
		{
			name: "invite command",
			argv: []string{"invite"},
			want: command.Command{Op: command.OpInvite},
		},
		{
			name: "register command",
			argv: []string{"register", "kh_abc123"},
			want: command.Command{Op: command.OpRegister, InviteCode: "kh_abc123"},
		},
		{
			name: "ls alias",
			argv: []string{"ls"},
			want: command.Command{Op: command.OpList, Path: ""},
		},
		{
			name: "ls alias with prefix",
			argv: []string{"ls", "account"},
			want: command.Command{Op: command.OpList, Path: "account"},
		},
		{
			name: "ls glob wildcard only",
			argv: []string{"ls", "*"},
			want: command.Command{Op: command.OpList, Path: "", GlobMatch: true},
		},
		{
			name: "ls glob prefix",
			argv: []string{"ls", "account/g*"},
			want: command.Command{Op: command.OpList, Path: "account/g", GlobMatch: true},
		},
		{
			name: "ls glob directory slash",
			argv: []string{"ls", "account/*"},
			want: command.Command{Op: command.OpList, Path: "account/", GlobMatch: true},
		},
		{
			name: "list glob prefix",
			argv: []string{"list", "foo/bar*"},
			want: command.Command{Op: command.OpList, Path: "foo/bar", GlobMatch: true},
		},
		{
			name: "help command",
			argv: []string{"help"},
			want: command.Command{Op: command.OpHelp},
		},
		{
			name:    "unknown command",
			argv:    []string{"delete", "account/github"},
			wantErr: true,
		},
		{
			name:    "empty argv",
			argv:    []string{},
			wantErr: true,
		},
		{
			name:    "get without path",
			argv:    []string{"get"},
			wantErr: true,
		},
		{
			name:    "set without path",
			argv:    []string{"set"},
			wantErr: true,
		},
		{
			name:    "register without invite code",
			argv:    []string{"register"},
			wantErr: true,
		},
		{
			name:    "path with dot prefix component",
			argv:    []string{"get", ".hidden/secret"},
			wantErr: true,
		},
		{
			name:    "path with double dot traversal",
			argv:    []string{"get", "../etc/passwd"},
			wantErr: true,
		},
		{
			name:    "path with internal dot-prefix component",
			argv:    []string{"get", "account/.ssh/key"},
			wantErr: true,
		},
		{
			name:    "get with extra args",
			argv:    []string{"get", "account/github", "extra"},
			wantErr: true,
		},
		{
			name:    "invite with extra args",
			argv:    []string{"invite", "extra"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := command.Parse(tt.argv)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse(%v) expected error, got nil", tt.argv)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v) unexpected error: %v", tt.argv, err)
			}
			if got.Op != tt.want.Op {
				t.Errorf("Op = %v, want %v", got.Op, tt.want.Op)
			}
			if got.Path != tt.want.Path {
				t.Errorf("Path = %q, want %q", got.Path, tt.want.Path)
			}
			if got.InviteCode != tt.want.InviteCode {
				t.Errorf("InviteCode = %q, want %q", got.InviteCode, tt.want.InviteCode)
			}
			if got.GlobMatch != tt.want.GlobMatch {
				t.Errorf("GlobMatch = %v, want %v", got.GlobMatch, tt.want.GlobMatch)
			}
			if got.Vault != tt.want.Vault {
				t.Errorf("Vault = %q, want %q", got.Vault, tt.want.Vault)
			}
		})
	}
}

func TestParseVaultSyntax(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		want    command.Command
		wantErr bool
	}{
		// Colon syntax for get/set/list
		{
			name: "get with vault prefix",
			argv: []string{"get", "tv:foo/bar"},
			want: command.Command{Op: command.OpGet, Path: "foo/bar", Vault: "tv"},
		},
		{
			name: "set with vault prefix",
			argv: []string{"set", "tv:secret"},
			want: command.Command{Op: command.OpSet, Path: "secret", Vault: "tv"},
		},
		{
			name: "list vault all",
			argv: []string{"list", "tv:"},
			want: command.Command{Op: command.OpList, Vault: "tv"},
		},
		{
			name: "list vault prefix",
			argv: []string{"list", "tv:db"},
			want: command.Command{Op: command.OpList, Path: "db", Vault: "tv"},
		},
		{
			name: "list vault glob",
			argv: []string{"ls", "tv:db/*"},
			want: command.Command{Op: command.OpList, Path: "db/", Vault: "tv", GlobMatch: true},
		},
		{
			name: "personal vault explicit",
			argv: []string{"get", "personal:foo"},
			want: command.Command{Op: command.OpGet, Path: "foo", Vault: ""},
		},
		// Vault management commands
		{
			name: "vault create",
			argv: []string{"vault", "create", "teamvault"},
			want: command.Command{Op: command.OpVaultCreate, Vault: "teamvault"},
		},
		{
			name: "vault invite",
			argv: []string{"vault", "invite", "tv", "bob"},
			want: command.Command{Op: command.OpVaultInvite, Vault: "tv", TargetUser: "bob"},
		},
		{
			name: "vault accept",
			argv: []string{"vault", "accept", "tv", "abc123"},
			want: command.Command{Op: command.OpVaultAccept, Vault: "tv", InviteCode: "abc123"},
		},
		{
			name: "vault promote",
			argv: []string{"vault", "promote", "tv", "bob"},
			want: command.Command{Op: command.OpVaultPromote, Vault: "tv", TargetUser: "bob"},
		},
		{
			name: "vault members",
			argv: []string{"vault", "members", "tv"},
			want: command.Command{Op: command.OpVaultMembers, Vault: "tv"},
		},
		{
			name: "vault list",
			argv: []string{"vault", "list"},
			want: command.Command{Op: command.OpVaultList},
		},
		// Move command
		{
			name: "move personal to vault",
			argv: []string{"move", "foo/bar", "tv:foo/bar"},
			want: command.Command{Op: command.OpMove, Path: "foo/bar", TargetVault: "tv", TargetPath: "foo/bar"},
		},
		{
			name: "move vault to personal",
			argv: []string{"move", "tv:secret", "secret"},
			want: command.Command{Op: command.OpMove, Vault: "tv", Path: "secret", TargetPath: "secret"},
		},
		// Error cases
		{
			name:    "vault no subcommand",
			argv:    []string{"vault"},
			wantErr: true,
		},
		{
			name:    "vault unknown subcommand",
			argv:    []string{"vault", "delete", "tv"},
			wantErr: true,
		},
		{
			name:    "vault create no name",
			argv:    []string{"vault", "create"},
			wantErr: true,
		},
		{
			name:    "vault invite missing user",
			argv:    []string{"vault", "invite", "tv"},
			wantErr: true,
		},
		{
			name:    "move missing args",
			argv:    []string{"move", "foo"},
			wantErr: true,
		},
		{
			name:    "path with colon rejected",
			argv:    []string{"get", "foo:bar:baz"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := command.Parse(tt.argv)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse(%v) expected error, got nil", tt.argv)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v) unexpected error: %v", tt.argv, err)
			}
			if got.Op != tt.want.Op {
				t.Errorf("Op = %v, want %v", got.Op, tt.want.Op)
			}
			if got.Path != tt.want.Path {
				t.Errorf("Path = %q, want %q", got.Path, tt.want.Path)
			}
			if got.Vault != tt.want.Vault {
				t.Errorf("Vault = %q, want %q", got.Vault, tt.want.Vault)
			}
			if got.InviteCode != tt.want.InviteCode {
				t.Errorf("InviteCode = %q, want %q", got.InviteCode, tt.want.InviteCode)
			}
			if got.TargetUser != tt.want.TargetUser {
				t.Errorf("TargetUser = %q, want %q", got.TargetUser, tt.want.TargetUser)
			}
			if got.TargetPath != tt.want.TargetPath {
				t.Errorf("TargetPath = %q, want %q", got.TargetPath, tt.want.TargetPath)
			}
			if got.TargetVault != tt.want.TargetVault {
				t.Errorf("TargetVault = %q, want %q", got.TargetVault, tt.want.TargetVault)
			}
			if got.GlobMatch != tt.want.GlobMatch {
				t.Errorf("GlobMatch = %v, want %v", got.GlobMatch, tt.want.GlobMatch)
			}
		})
	}
}

func TestFormatPath(t *testing.T) {
	tests := []struct {
		path      string
		color     bool
		wantColor bool // does the output contain ANSI codes?
		wantSlash bool // does the directory part end with /?
	}{
		{path: "mytoken", color: true, wantColor: false},
		{path: "mytoken", color: false, wantColor: false},
		{path: "account/github", color: false, wantColor: false},
		{path: "account/github", color: true, wantColor: true, wantSlash: true},
		{path: "prod/database/password", color: true, wantColor: true, wantSlash: true},
	}

	for _, tt := range tests {
		t.Run(tt.path+"/color="+boolStr(tt.color), func(t *testing.T) {
			got := command.FormatPath(tt.path, tt.color)
			hasAnsi := strings.Contains(got, "\033[")
			if hasAnsi != tt.wantColor {
				t.Errorf("FormatPath(%q, %v) = %q: ANSI codes present=%v, want %v",
					tt.path, tt.color, got, hasAnsi, tt.wantColor)
			}
			if tt.wantSlash {
				// The raw path without ANSI codes should end at the same leaf,
				// and the colored prefix must include the trailing slash in blue.
				plain := stripANSI(got)
				if plain != tt.path {
					t.Errorf("FormatPath plain text = %q, want %q", plain, tt.path)
				}
				// The blue segment must end with /
				// Find the reset code; everything before it is the blue segment.
				reset := "\033[0m"
				idx := strings.Index(got, reset)
				if idx == -1 {
					t.Fatalf("no reset code in colored output %q", got)
				}
				blueSegment := got[:idx]
				if !strings.HasSuffix(blueSegment, "/") {
					t.Errorf("blue segment %q does not end with /", blueSegment)
				}
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// skip until 'm'
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func TestParsePathNormalization(t *testing.T) {
	// Paths with redundant slashes should be cleaned
	got, err := command.Parse([]string{"get", "account//github"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Path != "account/github" {
		t.Errorf("path = %q, want %q", got.Path, "account/github")
	}
}
