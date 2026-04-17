// Package config handles parsing of server.toml and rooms.toml.
//
// Phase 16 Gap 4 removed users.toml support entirely. Users are now
// created exclusively via `sshkey-ctl approve` (for users who SSH in
// with their own key) or `sshkey-ctl bootstrap-admin` (for admin
// keypair generation on the server side). The TOML file no longer
// exists in any role.
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
	// AdminActionsPerMinute caps the rate at which a single user can issue
	// in-group admin verbs (add_to_group, remove_from_group, promote_group_admin,
	// demote_group_admin, rename_group) against a single group. Scoped per
	// user per group so one noisy admin can't starve another group. Default
	// 20/min is generous enough for any realistic kick-spree but tight enough
	// to bound abuse. Server-initiated paths (retirement cascade, last-member
	// cleanup) are exempt — this limit only applies to wire-level verbs.
	AdminActionsPerMinute int `toml:"admin_actions_per_minute"`
	// EditsPerMinute caps the rate at which a single user can issue
	// message-edit verbs (edit, edit_group, edit_dm). Shared bucket per
	// user across all three contexts — one bucket, not three — so a
	// user can't bypass the limit by interleaving edits across rooms
	// and DMs. Default 10/min is tight enough to bound abuse while
	// generous enough for realistic typo fixes. Phase 15.
	EditsPerMinute int `toml:"edits_per_minute"`
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
			DeletesPerMinute:       10,
			AdminDeletesPerMinute:  50,
			ReactionsPerMinute:     30,
			DMCreatesPerMinute:     5,
			ProfilesPerMinute:      5,
			PinsPerMinute:          10,
			AdminActionsPerMinute:  20, // Phase 14: per user per group
			EditsPerMinute:         10, // Phase 15: shared bucket per user across edit/edit_group/edit_dm
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

// LoadRooms reads and parses rooms.toml. Returns a map of room name -> Room.
func LoadRooms(path string) (map[string]Room, error) {
	var raw map[string]Room
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return nil, fmt.Errorf("load rooms.toml: %w", err)
	}
	return raw, nil
}

// Config holds all loaded configuration. Safe for concurrent reads via RLock/RUnlock.
//
// Phase 16 Gap 4 removed the `Users map[string]User` field — users.toml
// is no longer supported. Operators must use `sshkey-ctl bootstrap-admin`
// to create the first admin on a fresh deployment, and the normal approve
// flow for everyone else.
type Config struct {
	sync.RWMutex
	Server ServerConfig
	Rooms  map[string]Room
	Dir    string // config directory path
}

// Load reads all config files from the given directory.
//
// Phase 16 Gap 4: users.toml support has been removed entirely. Only
// server.toml and rooms.toml are loaded here. The first admin on a
// fresh server is created via `sshkey-ctl bootstrap-admin`, NOT by
// editing a TOML file.
func Load(dir string) (*Config, error) {
	serverPath := filepath.Join(dir, "server.toml")
	roomsPath := filepath.Join(dir, "rooms.toml")

	server, err := LoadServerConfig(serverPath)
	if err != nil {
		return nil, err
	}

	rooms, err := LoadRooms(roomsPath)
	if err != nil {
		return nil, err
	}

	return &Config{
		Server: server,
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
