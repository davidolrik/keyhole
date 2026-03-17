package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Config holds the server configuration.
type Config struct {
	Listen       string   `hcl:"listen,optional"`        // address to listen on (e.g. ":2222")
	DataDir      string   `hcl:"data_dir,optional"`      // root data directory
	Admins       []string `hcl:"admins,optional"`        // usernames allowed to run admin commands
	ServerSecret string   `hcl:"server_secret,optional"` // alphanumeric server secret
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

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := hclsimple.Decode(path, data, nil, &cfg); err != nil {
		return nil, err
	}

	if cfg.ServerSecret != "" {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return nil, fmt.Errorf("config file %s has permission %04o; must not be group- or world-readable when it contains server_secret (try: chmod 600 %s)", path, mode, path)
		}
	}

	return &cfg, nil
}

// LoadEnv reads KEYHOLE_* environment variables into a Config.
// Unset variables result in zero values.
func LoadEnv() Config {
	var cfg Config
	cfg.Listen = os.Getenv("KEYHOLE_LISTEN")
	cfg.DataDir = os.Getenv("KEYHOLE_DATA_DIR")
	cfg.ServerSecret = os.Getenv("KEYHOLE_SERVER_SECRET")
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
		Listen:  ":2222",
		DataDir: filepath.Join(home, ".keyhole"),
		Admins:  nil,
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
