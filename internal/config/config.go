// Package config handles parsing of server.toml, users.toml, and rooms.toml.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
)

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
	Port   int      `toml:"port"`
	Bind   string   `toml:"bind"`
	Admins []string `toml:"admins"`
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
	Topic string `toml:"topic"`
}

// DefaultServerConfig returns a ServerConfig with all defaults applied.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerSection{
			Port: 2222,
			Bind: "0.0.0.0",
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
			ConnectionsPerMinute: 10,
			FailedAuthPerMinute:  5,
			TypingPerSecond:      1,
			HistoryPerMinute:     50,
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

// LoadUsers reads and parses users.toml. Returns a map of username -> User.
func LoadUsers(path string) (map[string]User, error) {
	var raw map[string]User
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, fmt.Errorf("load users.toml: %w", err)
	}
	return raw, nil
}

// WriteUsers writes the users map back to users.toml atomically (write to
// temp file, then rename). Used by the retirement flow when the server needs
// to persist a retirement flag set via the protocol.
//
// Because the config directory is watched via fsnotify, this write will
// trigger a reload. The reload is idempotent: the in-memory state is updated
// first, so the reload loads the same state it finds in memory and computes
// an empty diff.
func WriteUsers(path string, users map[string]User) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	enc := toml.NewEncoder(f)
	if err := enc.Encode(users); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encode users.toml: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
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

	// Validate: all admin users exist and are not retired
	for _, admin := range server.Server.Admins {
		u, ok := users[admin]
		if !ok {
			return nil, fmt.Errorf("admin %q not found in users.toml", admin)
		}
		if u.Retired {
			return nil, fmt.Errorf("admin %q is retired — remove from server.toml admins or un-retire", admin)
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
