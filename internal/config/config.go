// Package config handles parsing of server.toml.
//
// Phase 16 Gap 4 removed users.toml support entirely. Users are now
// created exclusively via `sshkey-ctl approve` (for users who SSH in
// with their own key) or `sshkey-ctl bootstrap-admin` (for admin
// keypair generation on the server side). The TOML file no longer
// exists in any role.
//
// Phase 23 removes rooms.toml support entirely. Rooms are created and
// managed through store-backed CLI commands (init/add-room/etc), not
// seed files.
package config

import (
	"fmt"
	"log/slog"
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
	Groups     GroupsSection     `toml:"groups"`
	RateLimits RateLimitsSection `toml:"rate_limits"`
	Shutdown   ShutdownSection   `toml:"shutdown"`
	Logging    LoggingSection    `toml:"logging"`
	Push       PushSection       `toml:"push"`
	Backup     BackupSection     `toml:"backup"` // Phase 19 — scheduled backup + retention
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

	// AutoRevoke configures Phase 17b auto-revoke on sustained
	// misbehavior. See internal/config/autorevoke.go for the full
	// schema + validation rules. Nested as [server.auto_revoke] in
	// server.toml.
	AutoRevoke AutoRevokeSection `toml:"auto_revoke"`

	// Quotas configures per-user daily upload caps (originally
	// designed as Phase 25, shipped 2026-04-19 as out-of-phase fix).
	// Default-on: DefaultServerConfig populates [server.quotas.user]
	// with Enabled = true and 1GB warn / 5GB block / 30-day retention.
	// Operators opt out with `[server.quotas.user] enabled = false`.
	// Mirrors the Phase 17b auto-revoke + Phase 19 backup default-on
	// pattern. See internal/config/quotas.go for the schema +
	// validation. Nested as [server.quotas] in server.toml.
	Quotas QuotasSection `toml:"quotas"`
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
	MaxFileSize        string   `toml:"max_file_size"`
	MaxAvatarSize      string   `toml:"max_avatar_size"`
	AllowedAvatarTypes []string `toml:"allowed_avatar_types"`

	// MaxFileIDsPerMessage bounds the envelope-level file_ids[] array
	// at message-send time (handleSend / handleSendGroup / handleSendDM).
	// Phase 17 Step 4c DoS defense; also fires SignalFileIDsOverCap for
	// Phase 17b auto-revoke observability. Default 20 — matches the
	// WhatsApp batch-send ceiling and sits comfortably above "here are
	// today's photos" use cases for chat. Terminal clients today only
	// exercise single-attach (/upload <path>), so this cap is primarily
	// protocol-layer defense against hostile crafted envelopes; a
	// deployment that grows a multi-attach UX may need to raise it.
	MaxFileIDsPerMessage int `toml:"max_file_ids_per_message"`
}

type DevicesSection struct {
	MaxPerUser int `toml:"max_per_user"`
}

// GroupsSection governs per-group policy knobs. Phase 17 Step 4d.
//
// MaxMembers is the hard cap on group-DM membership — enforced at
// create_group and add_to_group, and is the upper bound on the
// wrapped_keys envelope size (a 10M-entry map that passes the
// per-member ECDH check would otherwise exhaust memory). Default 150
// matches the pre-Phase-17 hardcoded value and PROTOCOL.md
// documentation. At 150 members, each send costs ~12KB of wrapped-key
// material on the wire and ~15ms of crypto. Operators running smaller
// deployments may tune down; operators with hardware to match may
// tune up.
type GroupsSection struct {
	MaxMembers int `toml:"max_members"`
}

type RateLimitsSection struct {
	MessagesPerSecond     int `toml:"messages_per_second"`
	UploadsPerMinute      int `toml:"uploads_per_minute"`
	ConnectionsPerMinute  int `toml:"connections_per_minute"`
	FailedAuthPerMinute   int `toml:"failed_auth_per_minute"`
	TypingPerSecond       int `toml:"typing_per_second"`
	HistoryPerMinute      int `toml:"history_per_minute"`
	DeletesPerMinute      int `toml:"deletes_per_minute"`
	AdminDeletesPerMinute int `toml:"admin_deletes_per_minute"`
	ReactionsPerMinute    int `toml:"reactions_per_minute"`
	DMCreatesPerMinute    int `toml:"dm_creates_per_minute"`
	ProfilesPerMinute     int `toml:"profiles_per_minute"`
	PinsPerMinute         int `toml:"pins_per_minute"`
	// Phase 17 Step 5: rate-limit coverage for 4 previously-unlimited
	// handlers.
	// RoomMembersPerMinute bounds info-panel room_members refreshes.
	// Default 6 (one per 10s) matches refresh-UX cadence; mashing
	// refresh is rate-limited.
	RoomMembersPerMinute int `toml:"room_members_per_minute"`
	// DeviceListPerMinute bounds settings-panel device_list refreshes.
	// Same 6/min default rationale as RoomMembersPerMinute.
	DeviceListPerMinute int `toml:"device_list_per_minute"`
	// DownloadRequestsPerMinute bounds per-user download verbs.
	// Default 60/min (1/sec) — higher than other refresh verbs
	// because attachment-heavy chat views legitimately fire many
	// requests when opened.
	DownloadRequestsPerMinute int `toml:"download_requests_per_minute"`

	// IdleTimeoutSeconds is the Phase 17b Step 5a NDJSON idle
	// watchdog threshold. If a client connection sends no complete
	// protocol frame for this many seconds, the server closes the
	// SSH channel. 0 disables (default) — operators tune post-launch
	// once legitimate user idle patterns are observed. Slow-loris
	// defense; SSH-layer keepalive (30s) already kills dead TCP
	// connections independently.
	IdleTimeoutSeconds int `toml:"idle_timeout_seconds"`

	// PerClientWriteBufferSize is the Phase 17b Step 5b per-connection
	// outbound message queue depth. fanOut broadcasts non-blocking-
	// enqueue into each recipient's queue; a slow reader whose queue
	// fills causes drops (counted as SignalBroadcastDropped) rather
	// than blocking the sender. Default 256 absorbs ~50 seconds of
	// a chatty room's worth of broadcasts. Raise for deployments
	// with very large rooms or sustained broadcast storms; lower
	// only if memory pressure demands it (size × active connections
	// is the memory budget).
	PerClientWriteBufferSize int `toml:"per_client_write_buffer_size"`

	// ConsecutiveDropDisconnectThreshold is the Phase 17b Step 5b
	// cutoff for "slow-reader" disconnects. After a client's
	// outbound queue has been full for this many consecutive
	// fanOut attempts, the server closes their SSH channel.
	// Disconnect (not auto-revoke) is the remedy — the client can
	// reconnect with a clean slate and sync-catchup. Default 10.
	// 0 disables disconnect-on-drops (drops still counted, but the
	// channel stays open — not recommended).
	ConsecutiveDropDisconnectThreshold int `toml:"consecutive_drop_disconnect_threshold"`

	// ErrorResponsesPerMinute is the Phase 17c Step 1 per-device cap
	// on outbound error response volume. respondError consults this
	// before sending; on exceed the error is silently dropped (no
	// wire bytes, no log) and the per-device SignalErrorFlood
	// counter increments — Phase 17b auto-revoke picks up
	// cross-connection abusers via `[server.auto_revoke.thresholds]
	// error_flood = "10:60"` (typical). Default 60 matches the
	// downloads_per_minute cadence; bounds a legitimate burst
	// (e.g. opening a busy room with stale epochs). 0 disables the
	// check entirely.
	ErrorResponsesPerMinute int `toml:"error_responses_per_minute"`
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

// DefaultServerConfig returns a ServerConfig with all defaults applied.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerSection{
			Port:                       2222,
			Bind:                       "0.0.0.0",
			AllowSelfLeaveRooms:        false, // explicit: admin-managed by default
			AllowSelfLeaveRetiredRooms: true,  // explicit: retired-room cleanup allowed
			AutoRevoke: AutoRevokeSection{
				// Phase 17b default-on. See refactor_plan.md
				// §Phase 17b for the "Single-stage shipping,
				// default-on" rationale — every auto-revoke
				// signal has a zero legitimate baseline so
				// enabling by default does not false-positive
				// legitimate clients. Operators disable via
				// enabled = false + restart if unusual
				// behavior occurs.
				Enabled:         true,
				PruneAfterHours: 168, // 7 days — comfortably exceeds the typical 60s window
				Thresholds:      nil, // operator populates via [server.auto_revoke.thresholds]
			},
			Quotas: QuotasSection{
				// Per-user upload quotas — default-on
				// (revised 2026-04-19 same day after
				// consistency review against Phase 17b
				// auto-revoke + Phase 19 backups, both of
				// which ship default-on with the same
				// asymmetry-of-harm argument). Operators
				// who don't want quotas set
				// `[server.quotas.user] enabled = false`.
				//
				// AllowExemptUsers default false — the
				// per-user `quota_exempt` escape hatch is
				// admin-managed-by-default. Set
				// `allow_exempt_users = true` in server.toml
				// to enable `sshkey-ctl user quota-exempt
				// <user> --on`. Mirrors the
				// AllowSelfLeaveRooms = false pattern.
				User: UserQuotaSection{
					Enabled:               true,
					AllowExemptUsers:      false,
					DailyUploadBytesWarn:  "1GB",
					DailyUploadBytesBlock: "5GB",
					FlagConsecutiveDays:   2,
					RetentionDays:         30,
				},
			},
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
			MaxFileSize:          "50MB",
			MaxAvatarSize:        "256KB",
			AllowedAvatarTypes:   []string{"image/png", "image/jpeg"},
			MaxFileIDsPerMessage: 20, // Phase 17 Step 4c: chat-app-appropriate ceiling
		},
		Devices: DevicesSection{
			MaxPerUser: 10,
		},
		Groups: GroupsSection{
			MaxMembers: 150, // Phase 17 Step 4d: matches pre-17 hardcoded cap + PROTOCOL.md
		},
		RateLimits: RateLimitsSection{
			MessagesPerSecond:     5,
			UploadsPerMinute:      60,
			ConnectionsPerMinute:  20,
			FailedAuthPerMinute:   5,
			TypingPerSecond:       1,
			HistoryPerMinute:      50,
			DeletesPerMinute:      10,
			AdminDeletesPerMinute: 50,
			ReactionsPerMinute:    30,
			DMCreatesPerMinute:    5,
			ProfilesPerMinute:     5,
			PinsPerMinute:         10,
			AdminActionsPerMinute: 20, // Phase 14: per user per group
			EditsPerMinute:        10, // Phase 15: shared bucket per user across edit/edit_group/edit_dm
			// Phase 17 Step 5: new rate-limit coverage
			RoomMembersPerMinute:      6,  // info-panel refresh cadence
			DeviceListPerMinute:       6,  // settings-panel refresh cadence
			DownloadRequestsPerMinute: 60, // attachment-heavy chat tolerance
			// Phase 17b Step 5b: per-client outbound queue
			PerClientWriteBufferSize:           256, // ~50s of chatty-room traffic
			ConsecutiveDropDisconnectThreshold: 10,  // disconnect slow readers
			// Phase 17c Step 1: error-response rate limit per device
			ErrorResponsesPerMinute: 60, // bounds legit error bursts; 0 disables
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
		Backup: BackupSection{
			// Phase 19 default-on. See refactor_plan.md §Phase 19
			// decision #11 for the asymmetry rationale — the cost
			// of "wrong default on" is ~30KB of disk on an unused
			// test server; the cost of "wrong default off" is
			// total data loss on disk failure in production.
			// skip_if_idle = true neutralizes the default-on
			// cost on truly-idle deployments.
			Enabled:            true,
			Interval:           "24h",
			DestDir:            "backups", // relative → <dataDir>/backups/
			RetentionCount:     10,
			RetentionAge:       "720h", // 30 days
			Compress:           true,
			SkipIfIdle:         true,
			IncludeConfigFiles: true,
		},
	}
}

// LoadServerConfig reads and parses server.toml, applying defaults for missing fields.
//
// Phase 17b Step 1: calls ServerConfig.Validate() after decode. Validation
// failures abort startup with a descriptive error; non-fatal warnings are
// emitted via slog.Warn so operators see misconfigurations without hard-
// failing startup.
func LoadServerConfig(path string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("load server.toml: %w", err)
	}
	warnings, err := cfg.Validate()
	if err != nil {
		return cfg, fmt.Errorf("validate server.toml: %w", err)
	}
	for _, w := range warnings {
		slog.Warn("server.toml validation warning", "message", w)
	}
	return cfg, nil
}

// Validate runs cross-section validation on a loaded ServerConfig.
// Returns startup warnings (non-fatal; caller should surface to
// operator) and hard errors (abort startup).
//
// Phase 17b Step 1 adds [server.auto_revoke] validation.
// Phase 19 Step 1 adds [backup] validation. Future cross-section
// checks land here too.
func (c ServerConfig) Validate() (warnings []string, err error) {
	_, warn, err := c.Server.AutoRevoke.ParseAndValidate()
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, warn...)

	_, warnBackup, err := c.Backup.ParseAndValidate()
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, warnBackup...)

	// Per-user upload quotas (out-of-phase 2026-04-19, default-on).
	// DefaultServerConfig populates Enabled=true + sensible defaults,
	// so even an operator who omits the section entirely gets a
	// validated config. Explicit `enabled = false` short-circuits
	// validation and disables the feature. Invalid fields under
	// Enabled=true → hard error.
	if _, err := c.Server.Quotas.User.ParseAndValidate(); err != nil {
		return nil, err
	}

	return warnings, nil
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
	Dir    string // config directory path
}

// Load reads all config files from the given directory.
//
// Phase 16 Gap 4: users.toml support has been removed entirely.
// Phase 23: rooms.toml support has been removed entirely.
// The first admin on a fresh server is created via `sshkey-ctl
// bootstrap-admin`, NOT by editing a TOML file.
func Load(dir string) (*Config, error) {
	serverPath := filepath.Join(dir, "server.toml")

	server, err := LoadServerConfig(serverPath)
	if err != nil {
		return nil, err
	}

	return &Config{
		Server: server,
		Dir:    dir,
	}, nil
}

// EnsureDataDir creates the data directory if it doesn't exist.
func EnsureDataDir(path string) error {
	return os.MkdirAll(path, 0750)
}
