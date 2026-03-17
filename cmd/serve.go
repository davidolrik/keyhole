package cmd

import (
	"log"
	"net"
	"os/signal"
	"path/filepath"
	"syscall"

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

	// Resolve config file path: explicit flag, or derive from data_dir
	configPath := flagConfigPath
	if configPath == "" {
		// We need data_dir to find the config file, so do a preliminary
		// resolve: CLI > env > default
		dataDir := defaults.DataDir
		if envDir := config.LoadEnv().DataDir; envDir != "" {
			dataDir = envDir
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

	// Load environment variables
	envCfg := config.LoadEnv()

	// Build CLI config from flags
	cliCfg := config.Config{
		Listen:       flagListen,
		DataDir:      flagDataDir,
		Admins:       config.ParseAdmins(flagAdmins),
	}

	// Merge: defaults < file < env < cli
	cfg := config.Merge(defaults, fileCfg, envCfg, cliCfg)

	srv, err := server.New(server.Config{
		Listen:       cfg.Listen,
		DataDir:      cfg.DataDir,
		Admins:       cfg.Admins,
		ServerSecret: cfg.ServerSecret,
		Version:      Version,
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
