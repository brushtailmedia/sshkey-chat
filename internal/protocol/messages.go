// Package protocol defines the sshkey-chat wire format message types.
// All messages are NDJSON (one JSON object per line) on SSH Channel 1.
package protocol

import "encoding/json"

// Handshake messages

type ServerHello struct {
	Type         string   `json:"type"`          // "server_hello"
	Protocol     string   `json:"protocol"`      // "sshkey-chat"
	Version      int      `json:"version"`       // 1
	ServerID     string   `json:"server_id"`     // e.g. "chat.example.com"
	Capabilities []string `json:"capabilities"`  // advertised capabilities
}

type ClientHello struct {
	Type          string   `json:"type"`           // "client_hello"
	Protocol      string   `json:"protocol"`       // "sshkey-chat"
	Version       int      `json:"version"`        // 1
	Client        string   `json:"client"`         // "terminal", "gui", etc.
	ClientVersion string   `json:"client_version"` // e.g. "0.1.0"
	DeviceID      string   `json:"device_id"`      // e.g. "dev_V1StGXR8_Z5jdHi6B-myT"
	LastSyncedAt  string   `json:"last_synced_at"` // ISO 8601 timestamp or empty
	Capabilities  []string `json:"capabilities"`   // requested capabilities
}

type Welcome struct {
	Type               string   `json:"type"`                // "welcome"
	User               string   `json:"user"`                // authenticated username
	DisplayName        string   `json:"display_name"`        // display name from config
	Admin              bool     `json:"admin"`               // true if user is a server admin
	Rooms              []string `json:"rooms"`               // rooms the user has access to
	Conversations      []string `json:"conversations"`       // DM conversation IDs
	PendingSync        bool     `json:"pending_sync"`        // true if sync batches follow
	ActiveCapabilities []string `json:"active_capabilities"` // negotiated capabilities
}

// Sync messages

type SyncBatch struct {
	Type      string          `json:"type"`       // "sync_batch"
	Messages  []RawMessage    `json:"messages"`   // mixed room + DM messages
	EpochKeys []SyncEpochKey  `json:"epoch_keys"` // room epoch keys needed for this batch
	Page      int             `json:"page"`
	HasMore   bool            `json:"has_more"`
}

type SyncEpochKey struct {
	Room       string `json:"room"`
	Epoch      int64  `json:"epoch"`
	WrappedKey string `json:"wrapped_key"` // base64, wrapped for the recipient
}

type SyncComplete struct {
	Type     string `json:"type"`      // "sync_complete"
	SyncedTo string `json:"synced_to"` // ISO 8601 timestamp
}

// Room messages

type Send struct {
	Type      string   `json:"type"`                // "send"
	Room      string   `json:"room"`
	Epoch     int64    `json:"epoch"`
	Payload   string   `json:"payload"`             // base64 encrypted
	FileIDs   []string `json:"file_ids,omitempty"`
	Signature string   `json:"signature"`           // base64 Ed25519 signature
}

type Message struct {
	Type      string   `json:"type"`                // "message"
	ID        string   `json:"id"`                  // server-assigned, msg_ prefix
	From      string   `json:"from"`
	Room      string   `json:"room"`
	TS        int64    `json:"ts"`                  // unix epoch seconds
	Epoch     int64    `json:"epoch"`
	Payload   string   `json:"payload"`             // base64 encrypted, pass-through
	FileIDs   []string `json:"file_ids,omitempty"`
	Signature string   `json:"signature"`           // base64, pass-through
}

// DM messages

type CreateDM struct {
	Type    string   `json:"type"`              // "create_dm"
	Members []string `json:"members"`           // other usernames (sender is implicit)
	Name    string   `json:"name,omitempty"`    // optional group name
}

type DMCreated struct {
	Type         string   `json:"type"`         // "dm_created"
	Conversation string   `json:"conversation"` // conv_ prefixed Nano ID
	Members      []string `json:"members"`      // all members including sender
	Name         string   `json:"name,omitempty"`
}

type RenameConversation struct {
	Type         string `json:"type"`         // "rename_conversation"
	Conversation string `json:"conversation"`
	Name         string `json:"name"`         // new name (empty to clear)
}

type ConversationRenamed struct {
	Type         string `json:"type"`         // "conversation_renamed"
	Conversation string `json:"conversation"`
	Name         string `json:"name"`
	RenamedBy    string `json:"renamed_by"`
}

type SendDM struct {
	Type         string            `json:"type"`                  // "send_dm"
	Conversation string            `json:"conversation"`
	WrappedKeys  map[string]string `json:"wrapped_keys"`          // username -> base64 wrapped key
	Payload      string            `json:"payload"`               // base64 encrypted
	FileIDs      []string          `json:"file_ids,omitempty"`
	Signature    string            `json:"signature"`             // base64 Ed25519 signature
}

type DM struct {
	Type         string            `json:"type"`                  // "dm"
	ID           string            `json:"id"`                    // server-assigned
	From         string            `json:"from"`
	Conversation string            `json:"conversation"`
	TS           int64             `json:"ts"`
	WrappedKeys  map[string]string `json:"wrapped_keys"`          // pass-through
	Payload      string            `json:"payload"`               // pass-through
	FileIDs      []string          `json:"file_ids,omitempty"`
	Signature    string            `json:"signature"`             // pass-through
}

// Leave conversation

type LeaveConversation struct {
	Type         string `json:"type"`         // "leave_conversation"
	Conversation string `json:"conversation"`
}

type ConversationEvent struct {
	Type         string `json:"type"`             // "conversation_event"
	Conversation string `json:"conversation"`
	Event        string `json:"event"`            // "leave"
	User         string `json:"user"`
	Reason       string `json:"reason,omitempty"` // optional: "retirement" (leave caused by account retirement)
}

// Message deletion

type Delete struct {
	Type string `json:"type"` // "delete"
	ID   string `json:"id"`  // message ID to delete
}

type Deleted struct {
	Type         string `json:"type"`                    // "deleted"
	ID           string `json:"id"`
	DeletedBy    string `json:"deleted_by"`
	TS           int64  `json:"ts"`
	Room         string `json:"room,omitempty"`          // set for room messages
	Conversation string `json:"conversation,omitempty"`  // set for DM messages
}

// Typing indicators (capability: typing)

type Typing struct {
	Type         string `json:"type"`                    // "typing"
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
	User         string `json:"user,omitempty"`          // set by server on broadcast
}

// Read receipts (capability: read_receipts)

type Read struct {
	Type         string `json:"type"`                    // "read"
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
	User         string `json:"user,omitempty"`          // set by server on broadcast
	LastRead     string `json:"last_read"`               // message ID
}

// Reactions (capability: reactions)

type React struct {
	Type         string            `json:"type"`                  // "react"
	ID           string            `json:"id"`                    // target message ID
	Room         string            `json:"room,omitempty"`
	Conversation string            `json:"conversation,omitempty"`
	Epoch        int64             `json:"epoch,omitempty"`       // rooms only
	WrappedKeys  map[string]string `json:"wrapped_keys,omitempty"` // DMs only
	Payload      string            `json:"payload"`               // base64 encrypted emoji
	Signature    string            `json:"signature"`
}

type Reaction struct {
	Type         string            `json:"type"`                  // "reaction"
	ReactionID   string            `json:"reaction_id"`           // server-assigned, react_ prefix
	ID           string            `json:"id"`                    // target message ID
	Room         string            `json:"room,omitempty"`
	Conversation string            `json:"conversation,omitempty"`
	User         string            `json:"user"`
	TS           int64             `json:"ts"`
	Epoch        int64             `json:"epoch,omitempty"`       // rooms only
	WrappedKeys  map[string]string `json:"wrapped_keys,omitempty"` // DMs only
	Payload      string            `json:"payload"`               // pass-through
	Signature    string            `json:"signature"`             // pass-through
}

type Unreact struct {
	Type       string `json:"type"`        // "unreact"
	ReactionID string `json:"reaction_id"`
}

type ReactionRemoved struct {
	Type         string `json:"type"`                    // "reaction_removed"
	ReactionID   string `json:"reaction_id"`
	ID           string `json:"id"`                      // target message ID
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
	User         string `json:"user"`
}

// Pinned messages (rooms only)

type Pin struct {
	Type string `json:"type"` // "pin"
	Room string `json:"room"`
	ID   string `json:"id"`  // message ID
}

type Pinned struct {
	Type     string `json:"type"` // "pinned"
	Room     string `json:"room"`
	ID       string `json:"id"`
	PinnedBy string `json:"pinned_by"`
	TS       int64  `json:"ts"`
}

type Unpin struct {
	Type string `json:"type"` // "unpin"
	Room string `json:"room"`
	ID   string `json:"id"`
}

type Unpinned struct {
	Type string `json:"type"` // "unpinned"
	Room string `json:"room"`
	ID   string `json:"id"`
}

type Pins struct {
	Type        string       `json:"type"` // "pins"
	Room        string       `json:"room"`
	Messages    []string     `json:"messages"`               // pinned message IDs
	MessageData []RawMessage `json:"message_data,omitempty"` // full message envelopes for decryption
}

// User profile

type SetProfile struct {
	Type        string `json:"type"`         // "set_profile"
	DisplayName string `json:"display_name"`
	AvatarID    string `json:"avatar_id,omitempty"`
}

type Profile struct {
	Type           string `json:"type"`            // "profile"
	User           string `json:"user"`
	DisplayName    string `json:"display_name"`
	AvatarID       string `json:"avatar_id,omitempty"`
	PubKey         string `json:"pubkey"`          // ssh-ed25519 public key
	KeyFingerprint string `json:"key_fingerprint"` // SHA256:...
	Retired        bool   `json:"retired,omitempty"`      // true if the account has been retired
	RetiredAt      string `json:"retired_at,omitempty"`   // RFC3339 timestamp of retirement
}

// User status

type SetStatus struct {
	Type string `json:"type"` // "set_status"
	Text string `json:"text"` // empty to clear
}

// Unread counts

type Unread struct {
	Type         string `json:"type"`                   // "unread"
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
	Count        int    `json:"count"`
	LastRead     string `json:"last_read"`
}

// Presence (capability: presence)

type Presence struct {
	Type        string `json:"type"`                   // "presence"
	User        string `json:"user"`
	Status      string `json:"status"`                 // "online", "offline"
	DisplayName string `json:"display_name"`
	AvatarID    string `json:"avatar_id,omitempty"`
	StatusText  string `json:"status_text,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`    // ISO 8601, offline only
}

// Room list

type RoomList struct {
	Type  string     `json:"type"`  // "room_list"
	Rooms []RoomInfo `json:"rooms"`
}

type RoomInfo struct {
	Name    string `json:"name"`
	Topic   string `json:"topic"`
	Members int    `json:"members"`
}

// Room events

type RoomEvent struct {
	Type  string `json:"type"`  // "room_event"
	Room  string `json:"room"`
	Event string `json:"event"` // "join", "leave"
	User  string `json:"user"`
}

// Conversation list

type ConversationList struct {
	Type          string             `json:"type"`          // "conversation_list"
	Conversations []ConversationInfo `json:"conversations"`
}

type ConversationInfo struct {
	ID      string   `json:"id"`
	Members []string `json:"members"`
	Name    string   `json:"name,omitempty"`
}

// History (lazy scroll-back)

type History struct {
	Type         string `json:"type"`                   // "history"
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
	Before       string `json:"before"`                 // message ID
	Limit        int    `json:"limit"`
}

type HistoryResult struct {
	Type         string         `json:"type"`                    // "history_result"
	Room         string         `json:"room,omitempty"`
	Conversation string         `json:"conversation,omitempty"`
	Messages     []RawMessage   `json:"messages"`
	EpochKeys    []SyncEpochKey `json:"epoch_keys,omitempty"`   // rooms only
	HasMore      bool           `json:"has_more"`
}

// Key exchange -- epoch keys (rooms)

type EpochKey struct {
	Type       string `json:"type"`        // "epoch_key"
	Room       string `json:"room"`
	Epoch      int64  `json:"epoch"`
	WrappedKey string `json:"wrapped_key"` // base64, wrapped for recipient
}

type EpochTrigger struct {
	Type     string        `json:"type"`      // "epoch_trigger"
	Room     string        `json:"room"`
	NewEpoch int64         `json:"new_epoch"`
	Members  []MemberKey   `json:"members"`
}

type MemberKey struct {
	User   string `json:"user"`
	PubKey string `json:"pubkey"` // ssh-ed25519 public key
}

type EpochRotate struct {
	Type        string            `json:"type"`        // "epoch_rotate"
	Room        string            `json:"room"`
	Epoch       int64             `json:"epoch"`
	WrappedKeys map[string]string `json:"wrapped_keys"` // username -> base64 wrapped key
	MemberHash  string            `json:"member_hash"`  // SHA256 of sorted member usernames
}

type EpochConfirmed struct {
	Type  string `json:"type"`  // "epoch_confirmed"
	Room  string `json:"room"`
	Epoch int64  `json:"epoch"`
}

// File transfer

type UploadStart struct {
	Type         string `json:"type"`                   // "upload_start"
	UploadID     string `json:"upload_id"`              // client-generated, up_ prefix
	Size         int64  `json:"size"`                   // bytes
	Room         string `json:"room,omitempty"`
	Conversation string `json:"conversation,omitempty"`
}

type UploadReady struct {
	Type     string `json:"type"`      // "upload_ready"
	UploadID string `json:"upload_id"`
}

type UploadComplete struct {
	Type     string `json:"type"`      // "upload_complete"
	UploadID string `json:"upload_id"`
	FileID   string `json:"file_id"`   // server-assigned, file_ prefix
}

type Download struct {
	Type   string `json:"type"`   // "download"
	FileID string `json:"file_id"`
}

type DownloadStart struct {
	Type   string `json:"type"`   // "download_start"
	FileID string `json:"file_id"`
	Size   int64  `json:"size"`
}

type DownloadComplete struct {
	Type   string `json:"type"`   // "download_complete"
	FileID string `json:"file_id"`
}

// Message signatures (capability: signatures)
// Signature field is on Send, SendDM, React, Message, DM, Reaction structs.

// Device revocation

type DeviceRevoked struct {
	Type     string `json:"type"`     // "device_revoked"
	DeviceID string `json:"device_id"`
	Reason   string `json:"reason"`   // "admin_action"
}

// Device management (user-scoped; admin uses sshkey-ctl instead)

// ListDevices requests the list of devices registered for the authenticated user.
type ListDevices struct {
	Type string `json:"type"` // "list_devices"
}

// DeviceList is the server's response to ListDevices, listing all devices
// for the requesting user.
type DeviceList struct {
	Type    string       `json:"type"`    // "device_list"
	Devices []DeviceInfo `json:"devices"`
}

type DeviceInfo struct {
	DeviceID     string `json:"device_id"`
	LastSyncedAt string `json:"last_synced_at,omitempty"`
	CreatedAt    string `json:"created_at"`
	Current      bool   `json:"current,omitempty"` // true if this is the requesting device
	Revoked      bool   `json:"revoked,omitempty"` // true if the device has been revoked
}

// RevokeDevice asks the server to revoke one of the authenticated user's
// own devices (not this one — for that, Close the client directly). The
// server rejects if the device_id doesn't belong to the authenticated user.
type RevokeDevice struct {
	Type     string `json:"type"`      // "revoke_device"
	DeviceID string `json:"device_id"` // device to revoke
}

// DeviceRevokeResult is the server's response to RevokeDevice.
type DeviceRevokeResult struct {
	Type     string `json:"type"`      // "device_revoke_result"
	DeviceID string `json:"device_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// Admin notifications

type AdminNotify struct {
	Type        string `json:"type"`        // "admin_notify"
	Event       string `json:"event"`       // "pending_key"
	Fingerprint string `json:"fingerprint"`
	Attempts    int    `json:"attempts"`
	FirstSeen   string `json:"first_seen"`  // ISO 8601
}

// Mobile push registration

type PushRegister struct {
	Type     string `json:"type"`      // "push_register"
	Platform string `json:"platform"`  // "ios", "android"
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`     // APNs/FCM token
}

type PushRegistered struct {
	Type     string `json:"type"`     // "push_registered"
	Platform string `json:"platform"`
}

// Server shutdown

type ServerShutdown struct {
	Type        string `json:"type"`         // "server_shutdown"
	Message     string `json:"message"`
	ReconnectIn int    `json:"reconnect_in"` // seconds
}

// Account retirement

// RetireMe is sent by a client to permanently retire their own account.
// The request is authenticated by the current SSH connection (the user is
// holding their key). Retirement is monotonic and irreversible: the key
// no longer authenticates, the user is removed from rooms and group DMs,
// and other users are notified via user_retired.
type RetireMe struct {
	Type   string `json:"type"`   // "retire_me"
	Reason string `json:"reason"` // self_compromise | switching_key | other
}

// UserRetired is broadcast to peers sharing rooms or conversations with
// the retired user, so clients can update their UI (mark user inactive,
// render 1:1 DMs as read-only, add [retired] marker to historical messages).
type UserRetired struct {
	Type string `json:"type"` // "user_retired"
	User string `json:"user"`
	Ts   int64  `json:"ts"`   // unix seconds
}

// RetiredUsers is sent on connect (after welcome, alongside profiles) with
// the list of retired users visible to this client. Allows fresh clients to
// learn about retirements that happened while they were offline.
type RetiredUsers struct {
	Type  string        `json:"type"`  // "retired_users"
	Users []RetiredUser `json:"users"`
}

type RetiredUser struct {
	User      string `json:"user"`
	RetiredAt string `json:"retired_at"` // RFC3339
}

// Errors

type Error struct {
	Type    string `json:"type"`            // "error"
	Code    string `json:"code"`            // machine-readable error code
	Message string `json:"message"`         // human-readable description
	Ref     string `json:"ref,omitempty"`   // message ID that caused the error
}

// Error codes
const (
	ErrNotAuthorized     = "not_authorized"
	ErrRateLimited       = "rate_limited"
	ErrMessageTooLarge   = "message_too_large"
	ErrUploadTooLarge    = "upload_too_large"
	ErrEpochConflict     = "epoch_conflict"
	ErrStaleMemberList   = "stale_member_list"
	ErrInvalidWrappedKeys = "invalid_wrapped_keys"
	ErrDeviceLimitExceeded = "device_limit_exceeded"
	ErrInvalidEpoch      = "invalid_epoch"
	ErrUnknownConversation = "unknown_conversation"
	ErrUnknownRoom       = "unknown_room"
	ErrUserRetired       = "user_retired"
)

// RawMessage is a JSON object that hasn't been decoded into a specific type yet.
// Used in sync batches and history results which contain mixed message types.
type RawMessage = json.RawMessage
