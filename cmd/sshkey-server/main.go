package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/brushtailmedia/sshkey/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sshkey-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configDir := flag.String("config", "/etc/sshkey-chat", "config directory path")
	dataDir := flag.String("data", "/var/sshkey-chat", "data directory path")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	logger.Info("loading config", "dir", *configDir)
	cfg, err := config.Load(*configDir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if err := config.EnsureDataDir(*dataDir); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	logger.Info("config loaded",
		"users", len(cfg.Users),
		"rooms", len(cfg.Rooms),
		"port", cfg.Server.Server.Port,
	)

	srv, err := server.New(cfg, logger, *dataDir)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received, reloading config")
				srv.Reload()
			default:
				logger.Info("shutdown signal received", "signal", sig.String())
				srv.Close()
				return
			}
		}
	}()

	return srv.ListenAndServe()
}
