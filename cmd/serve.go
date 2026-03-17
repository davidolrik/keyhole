package cmd

import (
	"fmt"
	"log"
	"net"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"go.olrik.dev/keyhole/internal/config"
	"go.olrik.dev/keyhole/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the keyhole SSH server",
	RunE:  runServe,
}

var (
	flagListen       string
	flagDataDir      string
	flagAdmins       string
	flagConfigPath string
)

func init() {
	serveCmd.Flags().StringVarP(&flagListen, "listen", "L", "", "Address to listen on")
	serveCmd.Flags().StringVarP(&flagDataDir, "data", "D", "", "Data directory")
	serveCmd.Flags().StringVar(&flagAdmins, "admin", "", "Comma-separated list of admin usernames")
serveCmd.Flags().StringVarP(&flagConfigPath, "config", "C", "", "Path to HCL config file")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	defaults := config.Default()

	// Load environment variables once — LoadEnv clears sensitive env vars
	// (e.g. KEYHOLE_SERVER_SECRET) after reading them, so it must not be
	// called more than once.
	envCfg := config.LoadEnv()

	// Resolve config file path: explicit flag, or derive from data_dir
	configPath := flagConfigPath
	if configPath == "" {
		// We need data_dir to find the config file, so do a preliminary
		// resolve: CLI > env > default
		dataDir := defaults.DataDir
		if envCfg.DataDir != "" {
			dataDir = envCfg.DataDir
		}
		if flagDataDir != "" {
			dataDir = flagDataDir
		}
		configPath = filepath.Join(dataDir, "keyhole.hcl")
	}

	// Load HCL config file (nil if not found)
	var fileCfg config.Config
	if loaded, err := config.LoadFile(configPath); err != nil {
		return err
	} else if loaded != nil {
		fileCfg = *loaded
	}

	// Build CLI config from flags
	cliCfg := config.Config{
		Listen:       flagListen,
		DataDir:      flagDataDir,
		Admins:       config.ParseAdmins(flagAdmins),
	}

	// Merge: defaults < file < env < cli
	cfg := config.Merge(defaults, fileCfg, envCfg, cliCfg)

	serverSecret := []byte(cfg.ServerSecret)
	cfg.ServerSecret = ""

	var inviteCodeTTL time.Duration
	if cfg.InviteCodeTTL != "" {
		var err error
		inviteCodeTTL, err = time.ParseDuration(cfg.InviteCodeTTL)
		if err != nil {
			return fmt.Errorf("invalid invite_code_ttl %q: %w", cfg.InviteCodeTTL, err)
		}
	}
	var consumedInviteRetention time.Duration
	if cfg.ConsumedInviteRetention != "" {
		var err error
		consumedInviteRetention, err = time.ParseDuration(cfg.ConsumedInviteRetention)
		if err != nil {
			return fmt.Errorf("invalid consumed_invite_retention %q: %w", cfg.ConsumedInviteRetention, err)
		}
	}

	srv, err := server.New(server.Config{
		Listen:                  cfg.Listen,
		DataDir:                 cfg.DataDir,
		Admins:                  cfg.Admins,
		ServerSecret:            serverSecret,
		Version:                 Version,
		InviteCodeTTL:           inviteCodeTTL,
		ConsumedInviteRetention: consumedInviteRetention,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("keyhole listening on %s", cfg.Listen)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		srv.Close()
	}()

	err = srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
