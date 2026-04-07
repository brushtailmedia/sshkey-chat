package server

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
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
	var retirements []retirementTransition

	for username, newUser := range newUsers {
		if _, existed := oldUsers[username]; !existed {
			if newUser.Retired {
				// Admin added a retired entry directly — no join events, no rotation.
				s.logger.Info("loaded retired user (new entry)", "user", username)
				continue
			}
			// Check if this username was previously retired — v1 rule: retired names cannot be reused
			if oldUser, wasRetired := oldUsers[username]; wasRetired && oldUser.Retired {
				s.logger.Error("rejected new user: username belongs to a retired account",
					"user", username,
					"retired_at", oldUser.RetiredAt,
				)
				// Restore the old retired entry — don't allow the new one
				s.cfg.Lock()
				s.cfg.Users[username] = oldUser
				s.cfg.Unlock()
				continue
			}
			added = append(added, username)
		}
	}
	for username, oldUser := range oldUsers {
		if _, exists := newUsers[username]; !exists {
			// Skip users that were already retired — they weren't active anyway.
			if oldUser.Retired {
				continue
			}
			removed = append(removed, username)
		}
	}

	// Detect retirement transitions (user flipped to retired via admin edit)
	// and room membership changes for existing users.
	for username, newUser := range newUsers {
		oldUser, existed := oldUsers[username]
		if !existed {
			continue
		}

		// Reject un-retiring: v1 rule — retired accounts cannot be reactivated
		if oldUser.Retired && !newUser.Retired {
			s.logger.Error("rejected reactivation: retired accounts cannot be un-retired",
				"user", username,
				"retired_at", oldUser.RetiredAt,
			)
			s.cfg.Lock()
			s.cfg.Users[username] = oldUser
			s.cfg.Unlock()
			continue
		}

		// Transition to retired: handled separately, skip room-diff for this user.
		if newUser.Retired && !oldUser.Retired {
			retirements = append(retirements, retirementTransition{
				username: username,
				oldRooms: oldUser.Rooms,
				reason:   newUser.RetiredReason,
			})
			continue
		}

		// Un-retirement via admin edit (unusual — retirement is meant to be
		// monotonic, but admins can override). Log and proceed normally.
		if oldUser.Retired && !newUser.Retired {
			s.logger.Warn("user un-retired by admin edit",
				"user", username,
			)
		}

		// Skip room diff for users that are retired on both sides
		// (their rooms list should stay empty).
		if newUser.Retired {
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

	// Process retirement transitions first. handleRetirement fires its own
	// broadcasts and acquires its own locks, so we call it before holding s.mu
	// to avoid lock contention with the diff-broadcasting block below.
	for _, r := range retirements {
		s.handleRetirement(r.username, r.oldRooms, r.reason)
	}

	// Notify connected clients of changes
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Send updated room_list to users whose rooms changed
	affectedUsers := make(map[string]bool)
	rotationRooms := make(map[string]string) // room -> reason ("join" or "leave")
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

		// Mark room for epoch rotation
		rotationRooms[rc.room] = rc.event
	}

	for _, username := range added {
		affectedUsers[username] = true
		// New users joining rooms need epoch rotation for each room
		if newUser, ok := newUsers[username]; ok {
			for _, room := range newUser.Rooms {
				rotationRooms[room] = "join"
			}
		}
	}

	for _, client := range s.clients {
		if affectedUsers[client.UserID] {
			s.sendRoomList(client)
		}
	}

	// Trigger epoch rotation for rooms with membership changes
	// For joins: the joining user should trigger rotation
	// For leaves: next sender triggers (mark rotation pending)
	for room, reason := range rotationRooms {
		if reason == "join" {
			// Find the joining user's connected client and trigger
			for _, rc := range roomChanges {
				if rc.room == room && rc.event == "join" {
					for _, client := range s.clients {
						if client.UserID == rc.user {
							s.triggerEpochRotation(client, room, "member_join")
							break
						}
					}
					break
				}
			}
			// Also check newly added users
			for _, username := range added {
				for _, client := range s.clients {
					if client.UserID == username {
						if newUser, ok := newUsers[username]; ok {
							for _, r := range newUser.Rooms {
								if r == room {
									s.triggerEpochRotation(client, room, "member_join")
								}
							}
						}
						break
					}
				}
			}
		} else {
			// Leave: mark rotation pending, next sender triggers
			s.epochs.getOrCreate(room, s.epochs.currentEpochNum(room))
			s.logger.Info("epoch rotation pending (member left)",
				"room", room,
			)
		}
	}

	// Disconnect removed users
	for _, username := range removed {
		for _, client := range s.clients {
			if client.UserID == username {
				client.Encoder.Encode(protocol.Error{
					Type:    "error",
					Code:    protocol.ErrNotAuthorized,
					Message: "Your account has been removed",
				})
				client.Channel.Close()
			}
		}
	}

	if s.audit != nil {
		s.audit.Log("server", "reload", fmt.Sprintf("file=users.toml added=%d removed=%d room_changes=%d retired=%d", len(added), len(removed), len(roomChanges), len(retirements)))
	}

	s.logger.Info("users.toml reloaded",
		"added", len(added),
		"removed", len(removed),
		"room_changes", len(roomChanges),
		"retired", len(retirements),
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

// retirementTransition captures a user flipping from active to retired,
// carrying the rooms they were in before retirement so handleRetirement can
// fire leave events and mark those rooms for epoch rotation.
type retirementTransition struct {
	username string
	oldRooms []string
	reason   string // self_compromise | admin | key_lost
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
