package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Config holds the server configuration.
type Config struct {
	Listen                  string   `hcl:"listen,optional"`                    // address to listen on (e.g. ":2222")
	DataDir                 string   `hcl:"data_dir,optional"`                  // root data directory
	Admins                  []string `hcl:"admins,optional"`                    // usernames allowed to run admin commands
	ServerSecret            string   `hcl:"server_secret,optional"`             // alphanumeric server secret
	InviteCodeTTL           string   `hcl:"invite_code_ttl,optional"`           // how long invite codes are valid (e.g. "72h")
	ConsumedInviteRetention string   `hcl:"consumed_invite_retention,optional"` // how long to keep consumed invites (e.g. "720h")
}

// LoadFile reads and decodes an HCL config file. Returns (nil, nil) if the file doesn't exist.
// If the config contains a server_secret, the file must not be group- or world-readable.
func LoadFile(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	// Check permissions before reading so that sensitive values (e.g.
	// server_secret) are never loaded from a world-readable file.
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return nil, fmt.Errorf("config file %s has permission %04o; must not be group- or world-readable (try: chmod 600 %s)", path, mode, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := hclsimple.Decode(path, data, nil, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadEnv reads KEYHOLE_* environment variables into a Config.
// Unset variables result in zero values.
//
// SECURITY: KEYHOLE_SERVER_SECRET via environment is discouraged —
// environment variables are visible through /proc, ps, and are
// inherited by child processes. Prefer storing the server secret
// in a file with 0600 permissions (either in the config file or
// the auto-generated server_secret file in the data directory).
func LoadEnv() Config {
	var cfg Config
	cfg.Listen = os.Getenv("KEYHOLE_LISTEN")
	cfg.DataDir = os.Getenv("KEYHOLE_DATA_DIR")
	cfg.ServerSecret = os.Getenv("KEYHOLE_SERVER_SECRET")
	if cfg.ServerSecret != "" {
		// Clear the environment variable to reduce the exposure window.
		os.Unsetenv("KEYHOLE_SERVER_SECRET")
		log.Printf("WARNING: server secret loaded from KEYHOLE_SERVER_SECRET environment variable; prefer using a config file or server_secret file with 0600 permissions")
	}
	cfg.InviteCodeTTL = os.Getenv("KEYHOLE_INVITE_CODE_TTL")
	cfg.ConsumedInviteRetention = os.Getenv("KEYHOLE_CONSUMED_INVITE_RETENTION")
	if admins := os.Getenv("KEYHOLE_ADMINS"); admins != "" {
		cfg.Admins = ParseAdmins(admins)
	}
	return cfg
}

// Merge applies configuration precedence: each subsequent Config's non-zero
// values override the previous. Intended order: defaults, file, env, cli.
func Merge(configs ...Config) Config {
	var result Config
	for _, c := range configs {
		if c.Listen != "" {
			result.Listen = c.Listen
		}
		if c.DataDir != "" {
			result.DataDir = c.DataDir
		}
		if c.ServerSecret != "" {
			result.ServerSecret = c.ServerSecret
		}
		if c.Admins != nil {
			result.Admins = c.Admins
		}
		if c.InviteCodeTTL != "" {
			result.InviteCodeTTL = c.InviteCodeTTL
		}
		if c.ConsumedInviteRetention != "" {
			result.ConsumedInviteRetention = c.ConsumedInviteRetention
		}
	}
	return result
}

// Default returns a Config with default values.
func Default() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return Config{
		Listen:                  ":2222",
		DataDir:                 filepath.Join(home, ".keyhole"),
		Admins:                  nil,
		InviteCodeTTL:           "72h",
		ConsumedInviteRetention: "720h",
	}
}

// ParseAdmins splits a comma-separated admin list into a slice of usernames.
func ParseAdmins(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
