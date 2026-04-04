package server

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/brushtailmedia/sshkey/internal/protocol"
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
		s.reloadUsers()
	case "rooms.toml":
		s.reloadRooms()
	case "server.toml":
		s.reloadServerConfig()
	default:
		// Full reload (SIGHUP or unknown file)
		s.reloadUsers()
		s.reloadRooms()
		s.reloadServerConfig()
	}
}

// reloadUsers reloads users.toml and handles membership changes.
func (s *Server) reloadUsers() {
	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newUsers, err := config.LoadUsers(usersPath)
	if err != nil {
		s.logger.Error("failed to reload users.toml", "error", err)
		return
	}

	s.cfg.Lock()
	oldUsers := s.cfg.Users
	s.cfg.Users = newUsers
	s.cfg.Unlock()

	// Detect changes
	var added, removed []string
	var roomChanges []roomChange

	for username := range newUsers {
		if _, existed := oldUsers[username]; !existed {
			added = append(added, username)
		}
	}
	for username := range oldUsers {
		if _, exists := newUsers[username]; !exists {
			removed = append(removed, username)
		}
	}

	// Detect room membership changes for existing users
	for username, newUser := range newUsers {
		oldUser, existed := oldUsers[username]
		if !existed {
			continue
		}

		oldRooms := toSet(oldUser.Rooms)
		newRooms := toSet(newUser.Rooms)

		for r := range newRooms {
			if !oldRooms[r] {
				roomChanges = append(roomChanges, roomChange{username, r, "join"})
			}
		}
		for r := range oldRooms {
			if !newRooms[r] {
				roomChanges = append(roomChanges, roomChange{username, r, "leave"})
			}
		}
	}

	// Notify connected clients of changes
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Send updated room_list to users whose rooms changed
	affectedUsers := make(map[string]bool)
	for _, rc := range roomChanges {
		affectedUsers[rc.user] = true

		// Broadcast join/leave events to the room
		event := protocol.RoomEvent{
			Type:  "room_event",
			Room:  rc.room,
			Event: rc.event,
			User:  rc.user,
		}
		s.broadcastToRoom(rc.room, event)
	}

	for _, username := range added {
		affectedUsers[username] = true
	}

	for _, client := range s.clients {
		if affectedUsers[client.Username] {
			s.sendRoomList(client)
		}
	}

	// Disconnect removed users
	for _, username := range removed {
		for _, client := range s.clients {
			if client.Username == username {
				client.Encoder.Encode(protocol.Error{
					Type:    "error",
					Code:    protocol.ErrNotAuthorized,
					Message: "Your account has been removed",
				})
				client.Channel.Close()
			}
		}
	}

	s.logger.Info("users.toml reloaded",
		"added", len(added),
		"removed", len(removed),
		"room_changes", len(roomChanges),
	)
}

// reloadRooms reloads rooms.toml.
func (s *Server) reloadRooms() {
	roomsPath := filepath.Join(s.cfg.Dir, "rooms.toml")
	newRooms, err := config.LoadRooms(roomsPath)
	if err != nil {
		s.logger.Error("failed to reload rooms.toml", "error", err)
		return
	}

	s.cfg.Lock()
	s.cfg.Rooms = newRooms
	s.cfg.Unlock()

	// Send updated room_list to all connected clients
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		s.sendRoomList(client)
	}

	s.logger.Info("rooms.toml reloaded", "rooms", len(newRooms))
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
	// Only update hot-reloadable fields
	s.cfg.Server.Server.Admins = newCfg.Server.Admins
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

type roomChange struct {
	user  string
	room  string
	event string // "join" or "leave"
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
