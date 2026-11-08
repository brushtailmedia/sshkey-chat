package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/server"
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
		"port", cfg.Server.Server.Port,
	)

	srv, err := server.New(cfg, logger, *dataDir)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	var shuttingDown atomic.Bool
	closed := make(chan struct{}) // closed once a signalled Close has finished
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received, reloading config")
				srv.Reload()
			default:
				logger.Info("shutdown signal received", "signal", sig.String())
				shuttingDown.Store(true)
				if err := srv.Close(); err != nil {
					logger.Error("shutdown", "error", err)
				}
				close(closed)
				return
			}
		}
	}()

	err = srv.ListenAndServe()
	// ListenAndServe returns the moment Close shuts the listener, while the
	// rest of Close — the grace period, the store checkpoint and close, the
	// lockfile removal — is still running on the signal goroutine. Returning
	// here would exit the process mid-shutdown, leaving the lockfile behind
	// and the databases unflushed; wait for the shutdown to finish.
	if shuttingDown.Load() {
		<-closed
	}
	return err
}
