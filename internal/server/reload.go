package server

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// watchConfig starts watching config files for changes and reloads on modification.
// Also handles SIGHUP reload (called from main).
func (s *Server) watchConfig() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.logger.Error("failed to create file watcher", "error", err)
		return
	}

	go func() {
		defer watcher.Close()

		// Debounce: editors often write multiple events for one save
		var debounceTimer *time.Timer

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
						s.reloadConfig(event.Name)
					})
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				s.logger.Error("file watcher error", "error", err)
			}
		}
	}()

	// Watch the config directory
	if err := watcher.Add(s.cfg.Dir); err != nil {
		s.logger.Error("failed to watch config dir", "dir", s.cfg.Dir, "error", err)
	}

	s.logger.Info("watching config directory", "dir", s.cfg.Dir)
}

// Reload reloads config files. Can be called from SIGHUP handler.
func (s *Server) Reload() {
	s.reloadConfig("")
}

// reloadConfig reloads the appropriate config file(s) based on which file changed.
func (s *Server) reloadConfig(changedFile string) {
	base := filepath.Base(changedFile)
	s.logger.Info("config change detected", "file", base)

	switch base {
	case "users.toml":
		// Phase 16 Gap 4: users.toml has been removed. If the file
		// still exists in the config dir from a pre-Phase-16 install,
		// log a warning so the operator knows it's no longer doing
		// anything and can safely delete it.
		s.logger.Warn("users.toml is no longer supported and is ignored — delete the file. Use `sshkey-ctl bootstrap-admin` to create the first admin on a fresh deployment.")
	case "server.toml":
		s.reloadServerConfig()
	default:
		// Full reload (SIGHUP or unknown file)
		s.reloadServerConfig()
	}
}

// reloadServerConfig reloads server.toml (hot-reloadable fields only).
func (s *Server) reloadServerConfig() {
	serverPath := filepath.Join(s.cfg.Dir, "server.toml")
	newCfg, err := config.LoadServerConfig(serverPath)
	if err != nil {
		s.logger.Error("failed to reload server.toml", "error", err)
		return
	}

	s.cfg.Lock()
	// Only update hot-reloadable fields (admin status is in users.db, not server.toml)
	s.cfg.Server.Server.AutoRevoke = newCfg.Server.AutoRevoke
	s.cfg.Server.Server.Quotas = newCfg.Server.Quotas
	s.cfg.Server.Retention = newCfg.Retention
	s.cfg.Server.Files = newCfg.Files
	s.cfg.Server.RateLimits = newCfg.RateLimits
	s.cfg.Server.Messages = newCfg.Messages
	s.cfg.Server.Sync = newCfg.Sync
	s.cfg.Server.Devices = newCfg.Devices
	s.cfg.Server.Logging = newCfg.Logging
	// port and bind are NOT reloaded (require restart)
	s.cfg.Unlock()

	s.logger.Info("server.toml reloaded (hot-reloadable fields)")
}
