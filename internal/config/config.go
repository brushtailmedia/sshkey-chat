// Package config handles parsing of server.toml, users.toml, and rooms.toml.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// ParseSize parses a human-readable size string like "50MB", "256KB", "1GB"
// into bytes. Supports KB, MB, GB suffixes (case-insensitive). Plain numbers
// are treated as bytes.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	s = strings.ToUpper(s)
	var multiplier int64 = 1
	if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size: %q", s)
	}
	return n * multiplier, nil
}

// ServerConfig represents server.toml.
type ServerConfig struct {
	Server     ServerSection     `toml:"server"`
	Messages   MessagesSection   `toml:"messages"`
	Retention  RetentionSection  `toml:"retention"`
	Sync       SyncSection       `toml:"sync"`
	Files      FilesSection      `toml:"files"`
	Devices    DevicesSection    `toml:"devices"`
	RateLimits RateLimitsSection `toml:"rate_limits"`
	Shutdown   ShutdownSection   `toml:"shutdown"`
	Logging    LoggingSection    `toml:"logging"`
	Push       PushSection       `toml:"push"`
}

type ServerSection struct {
	Port int    `toml:"port"`
	Bind string `toml:"bind"`

	// AllowSelfLeaveRooms controls whether users can voluntarily leave
	// active rooms via /leave. Default false preserves the admin-managed
	// membership model — when disabled, room membership is changed only
	// via sshkey-ctl add-to-room / remove-from-room. When enabled, users
	// can self-leave and the server broadcasts a room_event leave to
	// remaining members. Hot-reloadable.
	AllowSelfLeaveRooms bool `toml:"allow_self_leave_rooms"`

	// AllowSelfLeaveRetiredRooms controls whether users can clean up
	// retired rooms from their sidebar via /leave or /delete. Default true
	// because retired rooms are dead — there's no membership decision to
	// preserve, just sidebar housekeeping. Inert until Phase 12 introduces
	// room retirement. Hot-reloadable.
	AllowSelfLeaveRetiredRooms bool `toml:"allow_self_leave_retired_rooms"`
}

type MessagesSection struct {
	MaxBodySize string `toml:"max_body_size"`
}

type RetentionSection struct {
	PurgeDays int `toml:"purge_days"` // 0 = keep forever
}

type SyncSection struct {
	WindowMessages  int `toml:"window_messages"`
	WindowDays      int `toml:"window_days"`
	HistoryPageSize int `toml:"history_page_size"`
}

type FilesSection struct {
	MaxFileSize       string   `toml:"max_file_size"`
	MaxAvatarSize     string   `toml:"max_avatar_size"`
	AllowedAvatarTypes []string `toml:"allowed_avatar_types"`
}

type DevicesSection struct {
	MaxPerUser int `toml:"max_per_user"`
}

type RateLimitsSection struct {
	MessagesPerSecond    int `toml:"messages_per_second"`
	UploadsPerMinute     int `toml:"uploads_per_minute"`
	ConnectionsPerMinute int `toml:"connections_per_minute"`
	FailedAuthPerMinute  int `toml:"failed_auth_per_minute"`
	TypingPerSecond      int `toml:"typing_per_second"`
	HistoryPerMinute     int `toml:"history_per_minute"`
	DeletesPerMinute      int `toml:"deletes_per_minute"`
	AdminDeletesPerMinute int `toml:"admin_deletes_per_minute"`
	ReactionsPerMinute    int `toml:"reactions_per_minute"`
	DMCreatesPerMinute   int `toml:"dm_creates_per_minute"`
	ProfilesPerMinute    int `toml:"profiles_per_minute"`
	PinsPerMinute        int `toml:"pins_per_minute"`
}

type ShutdownSection struct {
	GracePeriod string `toml:"grace_period"`
}

type LoggingSection struct {
	Level     string `toml:"level"`
	File      string `toml:"file"`
	MaxSizeMB int    `toml:"max_size_mb"`
	MaxFiles  int    `toml:"max_files"`
	Format    string `toml:"format"`
}

type PushSection struct {
	APNs APNsConfig `toml:"apns"`
	FCM  FCMConfig  `toml:"fcm"`
}

type APNsConfig struct {
	Enabled  bool   `toml:"enabled"`
	KeyPath  string `toml:"key_path"`
	KeyID    string `toml:"key_id"`
	TeamID   string `toml:"team_id"`
	BundleID string `toml:"bundle_id"`
	Sandbox  bool   `toml:"sandbox"`
}

type FCMConfig struct {
	Enabled         bool   `toml:"enabled"`
	CredentialsPath string `toml:"credentials_path"`
	ProjectID       string `toml:"project_id"`
}

// User represents a single user entry from users.toml.
//
// Retirement: When Retired is true, the account is permanently ended. The key
// no longer authenticates, the user is removed from all rooms and DMs, and
// other users see their messages in history marked [retired]. Retirement is
// monotonic and irreversible at the protocol level — a retired account can
// only be succeeded by a new account (same or different username) added by
// an admin. See PROJECT.md "Account Retirement" for the full model.
type User struct {
	Key            string   `toml:"key"`
	DisplayName    string   `toml:"display_name"`
	Rooms          []string `toml:"rooms"`
	Retired        bool     `toml:"retired,omitempty"`
	RetiredAt      string   `toml:"retired_at,omitempty"`      // RFC3339 timestamp
	RetiredReason  string   `toml:"retired_reason,omitempty"`  // self_compromise | admin | key_lost
}

// Room represents a single room entry from rooms.toml.
type Room struct {
	DisplayName string `toml:"display_name,omitempty"` // human-visible name (populated from TOML section key on seed)
	Topic       string `toml:"topic"`
}

// DefaultServerConfig returns a ServerConfig with all defaults applied.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerSection{
			Port:                       2222,
			Bind:                       "0.0.0.0",
			AllowSelfLeaveRooms:        false, // explicit: admin-managed by default
			AllowSelfLeaveRetiredRooms: true,  // explicit: retired-room cleanup allowed
		},
		Messages: MessagesSection{
			MaxBodySize: "16KB",
		},
		Retention: RetentionSection{
			PurgeDays: 0, // keep forever by default
		},
		Sync: SyncSection{
			WindowMessages:  200,
			WindowDays:      7,
			HistoryPageSize: 100,
		},
		Files: FilesSection{
			MaxFileSize:       "50MB",
			MaxAvatarSize:     "256KB",
			AllowedAvatarTypes: []string{"image/png", "image/jpeg"},
		},
		Devices: DevicesSection{
			MaxPerUser: 10,
		},
		RateLimits: RateLimitsSection{
			MessagesPerSecond:    5,
			UploadsPerMinute:     60,
			ConnectionsPerMinute: 20,
			FailedAuthPerMinute:  5,
			TypingPerSecond:      1,
			HistoryPerMinute:     50,
			DeletesPerMinute:      10,
			AdminDeletesPerMinute: 50,
			ReactionsPerMinute:    30,
			DMCreatesPerMinute:   5,
			ProfilesPerMinute:    5,
			PinsPerMinute:        10,
		},
		Shutdown: ShutdownSection{
			GracePeriod: "10s",
		},
		Logging: LoggingSection{
			Level:     "info",
			File:      "/var/sshkey-chat/server.log",
			MaxSizeMB: 100,
			MaxFiles:  5,
			Format:    "json",
		},
	}
}

// LoadServerConfig reads and parses server.toml, applying defaults for missing fields.
func LoadServerConfig(path string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("load server.toml: %w", err)
	}
	return cfg, nil
}

// LoadUsers reads and parses users.toml. Returns a map of userID -> User.
func LoadUsers(path string) (map[string]User, error) {
	var raw map[string]User
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, fmt.Errorf("load users.toml: %w", err)
	}
	return raw, nil
}

// LoadRooms reads and parses rooms.toml. Returns a map of room name -> Room.
func LoadRooms(path string) (map[string]Room, error) {
	var raw map[string]Room
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, fmt.Errorf("load rooms.toml: %w", err)
	}
	return raw, nil
}

// Config holds all loaded configuration. Safe for concurrent reads via RLock/RUnlock.
type Config struct {
	sync.RWMutex
	Server ServerConfig
	Users  map[string]User
	Rooms  map[string]Room
	Dir    string // config directory path
}

// Load reads all config files from the given directory.
func Load(dir string) (*Config, error) {
	serverPath := filepath.Join(dir, "server.toml")
	usersPath := filepath.Join(dir, "users.toml")
	roomsPath := filepath.Join(dir, "rooms.toml")

	server, err := LoadServerConfig(serverPath)
	if err != nil {
		return nil, err
	}

	users, err := LoadUsers(usersPath)
	if err != nil {
		return nil, err
	}

	rooms, err := LoadRooms(roomsPath)
	if err != nil {
		return nil, err
	}

	// Validate: all user room assignments reference existing rooms.
	// Retired users' room lists are ignored (should be empty; stale entries
	// are tolerated so admin mis-edits don't block server startup).
	for username, user := range users {
		if user.Retired {
			continue
		}
		for _, room := range user.Rooms {
			if _, ok := rooms[room]; !ok {
				return nil, fmt.Errorf("user %q references unknown room %q", username, room)
			}
		}
	}



	// Validate: all user keys are Ed25519 and parseable
	// (retired users are still required to have a valid key — it's preserved
	// for historical attribution and auditability; it just doesn't authenticate)
	for username, user := range users {
		if len(user.Key) == 0 {
			return nil, fmt.Errorf("user %q has no key", username)
		}
		if !isEd25519Key(user.Key) {
			return nil, fmt.Errorf("user %q: only Ed25519 keys are supported (got %q)", username, keyType(user.Key))
		}
		if err := validateSSHKey(user.Key); err != nil {
			return nil, fmt.Errorf("user %q: invalid SSH key: %w", username, err)
		}
	}

	return &Config{
		Server: server,
		Users:  users,
		Rooms:  rooms,
		Dir:    dir,
	}, nil
}

// isEd25519Key checks if the key string starts with ssh-ed25519.
func isEd25519Key(key string) bool {
	return len(key) > 11 && key[:11] == "ssh-ed25519"
}

// keyType extracts the key type prefix from an SSH public key string.
func keyType(key string) string {
	for i, c := range key {
		if c == ' ' {
			return key[:i]
		}
	}
	return key
}

// validateSSHKey checks that the key string can be parsed as a valid SSH public key.
func validateSSHKey(key string) error {
	_, err := parseSSHKey(key)
	return err
}

// parseSSHKey parses an SSH authorized_key format string.
func parseSSHKey(key string) ([]byte, error) {
	fields := splitFields(key)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid key format")
	}
	// Decode the base64 key data to validate it
	data, err := base64Decode(fields[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in key: %w", err)
	}
	return data, nil
}

// splitFields splits a string on whitespace (simple, no allocation for small fields).
func splitFields(s string) []string {
	var fields []string
	start := -1
	for i, c := range s {
		if c == ' ' || c == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}

// base64Decode decodes standard base64.
func base64Decode(s string) ([]byte, error) {
	return base64Std.DecodeString(s)
}

var base64Std = base64.StdEncoding

// EnsureDataDir creates the data directory if it doesn't exist.
func EnsureDataDir(path string) error {
	return os.MkdirAll(path, 0750)
}
