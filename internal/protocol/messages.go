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
	Rooms              []string `json:"rooms"`               // room nanoid IDs the user has access to
	Groups             []string `json:"groups"`              // group DM IDs the user is a member of
	PendingSync        bool     `json:"pending_sync"`        // true if sync batches follow
	ActiveCapabilities []string `json:"active_capabilities"` // negotiated capabilities
}

// Sync messages

type SyncBatch struct {
	Type      string          `json:"type"`                 // "sync_batch"
	Messages  []RawMessage    `json:"messages"`             // mixed room + DM messages
	Reactions []RawMessage    `json:"reactions,omitempty"`  // reactions on the synced messages
	Events    []RawMessage    `json:"events,omitempty"`     // Phase 14: group admin events (join/leave/promote/demote/rename) for offline replay
	EpochKeys []SyncEpochKey  `json:"epoch_keys"`           // room epoch keys needed for this batch
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
	EditedAt  int64    `json:"edited_at,omitempty"` // Phase 15: server sets on edit, absent on unedited messages
}

// Edit is the client → server envelope for replacing a room message's
// encrypted payload (Phase 15). Intentionally omits FileIDs and any
// reply/mention/attachment metadata — those are immutable under the
// plan's split-enforcement model. FileIDs is envelope-level and
// preserved by the server from the stored row on replace. ReplyTo,
// Mentions, and Attachments live inside the encrypted payload and are
// preserved by the client via the preserve-and-replace pattern before
// re-encrypting (see message_editing.md Chunk 6).
type Edit struct {
	Type      string `json:"type"`      // "edit"
	ID        string `json:"id"`        // msg ID of the message being edited
	Room      string `json:"room"`      // room nanoid
	Epoch     int64  `json:"epoch"`     // current epoch (grace window same as send)
	Payload   string `json:"payload"`   // base64 encrypted new payload
	Signature string `json:"signature"` // base64 Ed25519 signature over canonical form
}

// Edited is the server → client broadcast shape after a successful
// room-message edit. Carries the original `ts` preserved from the
// stored row plus the authoritative `edited_at` timestamp set at the
// moment the server processed the edit. `file_ids` is the preserved
// list from the original row. Clients unconditionally clear their
// locally-cached reactions for this message ID when they process this
// event (see message_editing.md Decision log Q12).
type Edited struct {
	Type      string   `json:"type"`                // "edited"
	ID        string   `json:"id"`
	From      string   `json:"from"`
	Room      string   `json:"room"`
	TS        int64    `json:"ts"`                  // ORIGINAL send time, preserved
	Epoch     int64    `json:"epoch"`
	Payload   string   `json:"payload"`             // new encrypted payload
	FileIDs   []string `json:"file_ids,omitempty"`  // preserved from stored row
	Signature string   `json:"signature"`
	EditedAt  int64    `json:"edited_at"`           // server-authoritative edit wall clock
}

// Group DM messages
//
// (Pre-Phase-11 comment about 1:1 DMs being unsupported has been deleted —
// they shipped in Phase 11 with their own type family: `CreateDM`, `SendDM`,
// `DM`, `LeaveDM`, `DMInfo`, etc. See the DM section further down.)

type CreateGroup struct {
	Type    string   `json:"type"`              // "create_group"
	Members []string `json:"members"`           // other usernames (sender is implicit)
	Name    string   `json:"name,omitempty"`    // optional group name
}

type GroupCreated struct {
	Type    string   `json:"type"`              // "group_created"
	Group   string   `json:"group"`             // group_ prefixed Nano ID
	Members []string `json:"members"`           // all members including sender
	Admins  []string `json:"admins,omitempty"`  // Phase 14: admin user IDs (includes creator)
	Name    string   `json:"name,omitempty"`
}

type RenameGroup struct {
	Type  string `json:"type"`             // "rename_group"
	Group string `json:"group"`
	Name  string `json:"name"`             // new name (empty to clear)
	Quiet bool   `json:"quiet,omitempty"`  // Phase 14: suppress inline system message
}

type GroupRenamed struct {
	Type      string `json:"type"`       // "group_renamed"
	Group     string `json:"group"`
	Name      string `json:"name"`
	RenamedBy string `json:"renamed_by"`
}

type SendGroup struct {
	Type        string            `json:"type"`                  // "send_group"
	Group       string            `json:"group"`
	WrappedKeys map[string]string `json:"wrapped_keys"`          // userID -> base64 wrapped key
	Payload     string            `json:"payload"`               // base64 encrypted
	FileIDs     []string          `json:"file_ids,omitempty"`
	Signature   string            `json:"signature"`             // base64 Ed25519 signature
}

type GroupMessage struct {
	Type        string            `json:"type"`                  // "group_message"
	ID          string            `json:"id"`                    // server-assigned
	From        string            `json:"from"`
	Group       string            `json:"group"`
	TS          int64             `json:"ts"`
	WrappedKeys map[string]string `json:"wrapped_keys"`          // pass-through
	Payload     string            `json:"payload"`               // pass-through
	FileIDs     []string          `json:"file_ids,omitempty"`
	Signature   string            `json:"signature"`             // pass-through
	EditedAt    int64             `json:"edited_at,omitempty"`   // Phase 15
}

// EditGroup is the client → server envelope for replacing a group DM
// message's encrypted payload (Phase 15). Fresh K_msg wrapped for the
// CURRENT group member set (not the set at original send time — the
// server validates against GetGroupMembers at edit time). FileIDs is
// omitted; the server preserves file_ids from the stored row.
type EditGroup struct {
	Type        string            `json:"type"`        // "edit_group"
	ID          string            `json:"id"`
	Group       string            `json:"group"`
	WrappedKeys map[string]string `json:"wrapped_keys"`
	Payload     string            `json:"payload"`
	Signature   string            `json:"signature"`
}

// GroupEdited is the server → client broadcast for a successful group
// DM edit. Shape mirrors GroupMessage plus EditedAt.
type GroupEdited struct {
	Type        string            `json:"type"`                // "group_edited"
	ID          string            `json:"id"`
	From        string            `json:"from"`
	Group       string            `json:"group"`
	TS          int64             `json:"ts"`                  // ORIGINAL send time
	WrappedKeys map[string]string `json:"wrapped_keys"`
	Payload     string            `json:"payload"`
	FileIDs     []string          `json:"file_ids,omitempty"`  // preserved from stored row
	Signature   string            `json:"signature"`
	EditedAt    int64             `json:"edited_at"`
}

// Leave group

type LeaveGroup struct {
	Type  string `json:"type"`  // "leave_group"
	Group string `json:"group"`
}

// GroupEvent is the generic broadcast envelope for every admin-initiated
// group mutation and self-leave. Phase 14 extended it significantly:
//
//   - Event values: "leave" (unchanged), "join", "promote", "demote", "rename"
//     (added). A group_event{leave} carries optional Reason; the other event
//     types use dedicated fields (Name for rename, By for the acting admin).
//   - By: the user ID of the admin that triggered this event. Required
//     (non-empty) for admin-initiated events (join, promote, demote, rename,
//     and leave with reason="removed"). Empty for self-leave, retirement,
//     and retirement-succession promote.
//   - Quiet: when true, clients MUST still update member/admin lists and
//     persist the event to the local group_events table, but MUST suppress
//     the inline system message in the message view. Always false for kicks
//     (leave with reason="removed") — being removed is high-consequence and
//     clients should always surface it loudly.
//   - Name: new name value for rename events.
//
// Reason values for Event="leave":
//   - ""             self-leave via /leave
//   - "removed"      admin-initiated removal via handleRemoveFromGroup; By required
//   - "retirement"   caller account was retired; By empty
//
// Reason values for Event="promote":
//   - ""                        normal admin promote; By required
//   - "retirement_succession"   auto-promote of oldest member when the last
//                               admin retires their account; By empty
type GroupEvent struct {
	Type   string `json:"type"`             // "group_event"
	Group  string `json:"group"`
	Event  string `json:"event"`            // "leave" | "join" | "promote" | "demote" | "rename"
	User   string `json:"user"`             // target user (the one being removed/added/promoted/demoted)
	By     string `json:"by,omitempty"`     // Phase 14: acting admin (required when Reason="removed" or Event in {join,promote,demote,rename})
	Reason string `json:"reason,omitempty"` // "" | "removed" | "retirement" | "retirement_succession"
	Name   string `json:"name,omitempty"`   // Phase 14: new name for Event="rename"
	Quiet  bool   `json:"quiet,omitempty"`  // Phase 14: suppress inline system message (never true for kicks)
}

// GroupLeft confirms to the leaving user that their leave_group request
// succeeded. The server sends this to every active session of the leaving
// user (the leaver is not in group_event broadcasts because they have
// already been removed from the member list).
//
// Reason distinguishes self-leave from admin-triggered removal:
//   - "" (empty): the user ran /leave themselves
//   - "removed": an admin removed the user via handleRemoveFromGroup (Phase 14).
//                By carries the kicking admin's user ID so the client can
//                render "You were removed from the group by alice" instead of
//                the generic "You were removed from the group by an admin".
//   - "retirement": the user's account was retired
//
// Phase 14 historical note: "admin" was the reason code used by the
// pre-Phase-14 CLI escape hatch. That path was deleted entirely in Phase 14
// (see refactor_plan.md Phase 14 entry). Clients should treat "admin" as
// equivalent to "removed" for any persisted rows they might encounter, but
// no new rows with reason="admin" should appear in v1.
//
// Clients use Reason + By to surface a specific status bar message — "Left
// group" vs "You were removed from group X by alice" — so the kicked user
// understands why they were ejected and by whom.
type GroupLeft struct {
	Type   string `json:"type"`             // "group_left"
	Group  string `json:"group"`
	Reason string `json:"reason,omitempty"` // "" | "removed" | "retirement"
	By     string `json:"by,omitempty"`     // Phase 14: kicking admin's user ID; required when Reason="removed", empty otherwise
}

// DeleteGroup is the client-initiated request to remove a group DM from
// every device on the user's account. Distinct from leave_group: leave is
// "I am leaving this group" (membership change, sidebar greys, history
// kept), delete is "I am leaving this group AND wiping my local copy on
// every device of mine" (sidebar entry gone, messages purged).
//
// The server runs the leave logic internally if the user is currently a
// member, then records the deletion intent in deleted_groups regardless,
// then echoes group_deleted to all of the user's connected sessions.
// Idempotent: re-running for the same group is safe.
type DeleteGroup struct {
	Type  string `json:"type"`  // "delete_group"
	Group string `json:"group"`
}

// GroupDeleted is the canonical echo of a successful delete_group. The
// server sends it to every connected session of the user that issued
// the delete (NOT to remaining group members — they receive a regular
// group_event{leave} from the inline leave logic, which is the right
// signal for them).
//
// Clients receiving group_deleted always purge the local message rows
// and drop the sidebar entry, regardless of whether THIS device was the
// one that initiated the delete. This is how multi-device propagation
// works for currently-connected devices. Offline devices catch up via
// deleted_groups during sync.
type GroupDeleted struct {
	Type  string `json:"type"`  // "group_deleted"
	Group string `json:"group"`
}

// DeletedGroupsList is sent during the connect handshake (BEFORE
// group_list) to catch up devices that were offline when a delete_group
// was issued from another session. Carries every group ID this user has
// previously /delete'd that has not yet been pruned.
//
// Clients process this by running the same purge path as group_deleted
// for each group ID. The list is deliberately sent first so the local
// state is reconciled before the sidebar is populated from group_list.
type DeletedGroupsList struct {
	Type   string   `json:"type"` // "deleted_groups"
	Groups []string `json:"groups"`
}

// Phase 14 — in-group admin verbs
//
// The handlers for these verbs enforce byte-identical privacy for the
// "unknown group / non-member / non-admin" triple: all three failure modes
// return an identical ErrUnknownGroup frame so a probing client cannot use
// these verbs to enumerate group membership or admin status. Only AFTER
// the caller has proven membership AND admin status does the server start
// returning more specific errors (ErrAlreadyMember, ErrAlreadyAdmin,
// ErrForbidden for last-admin rules, ErrUnknownUser for bad target).
//
// The Quiet flag on AddToGroup/PromoteGroupAdmin/DemoteGroupAdmin suppresses
// the inline system message on receiving clients while still persisting the
// event and updating member/admin lists. RemoveFromGroup deliberately does
// NOT have a Quiet flag — kicks are always loud.

// AddToGroup requests that an admin add a single new member to an existing
// group. The caller must be an admin of the group. Multi-target adds are
// done client-side by sending one AddToGroup per target.
type AddToGroup struct {
	Type  string `json:"type"`             // "add_to_group"
	Group string `json:"group"`
	User  string `json:"user"`             // target to add
	Quiet bool   `json:"quiet,omitempty"`  // suppress inline system message
}

// RemoveFromGroup requests that an admin remove a member from a group DM.
// Callers who pass their own user ID fall through to the self-leave path
// (handleLeaveGroup) rather than generating a "alice removed alice" event.
type RemoveFromGroup struct {
	Type  string `json:"type"`  // "remove_from_group"
	Group string `json:"group"`
	User  string `json:"user"`  // target to remove
}

// PromoteGroupAdmin requests that an admin promote a member to admin.
// Unilateral: any admin can promote any member, no cross-admin approval
// needed. Target must currently be a non-admin member.
type PromoteGroupAdmin struct {
	Type  string `json:"type"`             // "promote_group_admin"
	Group string `json:"group"`
	User  string `json:"user"`             // target to promote
	Quiet bool   `json:"quiet,omitempty"`  // suppress inline system message
}

// DemoteGroupAdmin requests that an admin demote another admin (or themselves)
// back to regular member. Rejected if the demotion would leave the group with
// zero admins — the caller must promote a successor first in that case.
type DemoteGroupAdmin struct {
	Type  string `json:"type"`             // "demote_group_admin"
	Group string `json:"group"`
	User  string `json:"user"`             // target to demote (may equal caller for self-demote)
	Quiet bool   `json:"quiet,omitempty"`  // suppress inline system message
}

// AddGroupResult echoes a successful add_to_group back to the calling admin.
type AddGroupResult struct {
	Type  string `json:"type"`  // "add_group_result"
	Group string `json:"group"`
	User  string `json:"user"`  // added user
}

// RemoveGroupResult echoes a successful remove_from_group back to the calling admin.
type RemoveGroupResult struct {
	Type  string `json:"type"`  // "remove_group_result"
	Group string `json:"group"`
	User  string `json:"user"`  // removed user
}

// PromoteAdminResult echoes a successful promote_group_admin back to the calling admin.
type PromoteAdminResult struct {
	Type  string `json:"type"`  // "promote_admin_result"
	Group string `json:"group"`
	User  string `json:"user"`  // promoted user
}

// DemoteAdminResult echoes a successful demote_group_admin back to the calling admin.
type DemoteAdminResult struct {
	Type  string `json:"type"`  // "demote_admin_result"
	Group string `json:"group"`
	User  string `json:"user"`  // demoted user
}

// GroupAddedTo is a direct notification sent to a user's sessions when an
// admin adds them to a group. Carries the full group metadata (name,
// members, admins, added_by) so the client can insert the group into its
// local store without waiting for a fresh group_list catchup.
//
// The added user receives no pre-join history — their first decryptable
// message is the next group_message broadcast after the add lands.
type GroupAddedTo struct {
	Type    string   `json:"type"`    // "group_added_to"
	Group   string   `json:"group"`
	Name    string   `json:"name,omitempty"`
	Members []string `json:"members"`
	Admins  []string `json:"admins"`
	AddedBy string   `json:"added_by"` // user ID of the admin who added the recipient
}

// Leave room
//
// Unlike groups, room leave is gated by the [server] allow_self_leave_rooms
// config flag (default false). The server returns ErrForbidden when the
// flag is disabled. Membership is checked first so non-members get a
// distinct ErrNotAuthorized error.

type LeaveRoom struct {
	Type string `json:"type"` // "leave_room"
	Room string `json:"room"`
}

// RoomLeft confirms to the leaving user that their leave_room request
// succeeded. Sent to every active session of the leaver, mirroring the
// GroupLeft echo pattern. The leaver is not in room_event broadcasts
// because they have already been removed from room_members.
//
// Reason distinguishes the trigger so the client can render an
// appropriate status message:
//   - "" (empty): self-leave via /leave command
//   - "admin": an admin removed the user via sshkey-ctl remove-from-room
//   - "retirement": the room itself was retired (Phase 12)
//   - "user_retired": the leaving user's account was retired
type RoomLeft struct {
	Type   string `json:"type"`             // "room_left"
	Room   string `json:"room"`
	Reason string `json:"reason,omitempty"` // "" | "admin" | "retirement" | "user_retired"
}

// Room retirement and delete (Phase 12)
//
// Retirement is an admin-initiated, server-wide state change that takes
// a room out of active service while preserving history. Writes are
// rejected, the display name is suffixed so the original can be reused,
// and connected members receive a room_retired broadcast. The CLI
// runs locally (see decision_no_remote_admin_commands.md memory note)
// and coordinates with the running server via the
// pending_room_retirements queue table + a polling goroutine.
//
// Delete is a client-initiated, per-user action that removes a room
// from the user's own view (sidebar entry + local history). It uses a
// dedicated delete_room protocol verb so all of the user's devices get
// a clean catchup signal, mirroring the group DM delete pattern from
// Phase 11.

// RoomRetired is broadcast to every connected member of a room at the
// moment the room is retired. Carries the post-retirement (suffixed)
// display name so clients can update their local cache immediately.
// Sent by the server's runRoomRetirementProcessor polling goroutine
// after consuming a pending_room_retirements queue row.
//
// Also used by the retired_rooms catchup list (RetiredRoomsList) sent
// during the connect handshake for offline devices.
type RoomRetired struct {
	Type        string `json:"type"`              // "room_retired"
	Room        string `json:"room"`              // room nanoid (unchanged by retirement)
	DisplayName string `json:"display_name"`      // post-retirement suffixed name
	RetiredAt   string `json:"retired_at"`        // RFC3339 timestamp
	RetiredBy   string `json:"retired_by"`        // admin user ID
	Reason      string `json:"reason,omitempty"`  // optional free-text reason
}

// RetiredRoomsList is sent during the connect handshake (BEFORE
// room_list) to catch up devices that were offline when a room was
// retired from the CLI. Carries every retired room where the user is
// still in room_members (Q8 filter: users who left before retirement
// don't see the room in this list).
//
// Clients process this by applying the same local effects as a live
// room_retired event for each entry: mark the room as retired in the
// local rooms table, update the display name to the suffixed version,
// and surface the read-only banner if the room is currently in view.
type RetiredRoomsList struct {
	Type  string        `json:"type"` // "retired_rooms"
	Rooms []RoomRetired `json:"rooms"`
}

// RoomUpdated is broadcast to connected members of a room when an
// admin updates its display name or topic via the CLI. Phase 16 Gap 1
// — backs both `sshkey-ctl update-topic` and `sshkey-ctl rename-room`
// via a shared protocol event.
//
// Carries the FULL post-change room state, not a diff: clients apply
// the event by upserting their local rooms-table row from the payload
// fields. Whichever field actually changed gets reflected on the next
// render; the unchanged field is overwritten with its current value
// (a no-op). One handler covers both verbs.
//
// Sent by the server's runRoomUpdatesProcessor polling goroutine
// after consuming a pending_room_updates queue row. Delivered ONLY
// to current members of the affected room (narrow broadcast — same
// pattern as room_retired).
type RoomUpdated struct {
	Type        string `json:"type"`         // "room_updated"
	Room        string `json:"room"`         // room nanoid
	DisplayName string `json:"display_name"` // post-change display name
	Topic       string `json:"topic"`        // post-change topic
}

// DeleteRoom is the client-initiated request to remove a room from the
// user's own view. The server runs the leave flow (remove from
// room_members, broadcast room_event{leave} to remaining members,
// mark for epoch rotation on active rooms), records a deleted_rooms
// sidecar row BEFORE the leave for multi-device catchup, and echoes
// RoomDeleted back to all of the caller's connected sessions.
//
// Policy-gated by allow_self_leave_rooms (for active rooms) or
// allow_self_leave_retired_rooms (for retired rooms); server picks
// which flag based on IsRoomRetired at the time of the request.
type DeleteRoom struct {
	Type string `json:"type"` // "delete_room"
	Room string `json:"room"`
}

// RoomDeleted confirms to the caller that their delete_room request
// succeeded. Sent to every active session of the caller so all of
// their devices can purge local state in lockstep. Client handlers
// must call PurgeRoomMessages (drop messages, reactions, pins,
// epoch keys, and the rooms table row) and remove the sidebar entry.
//
// Distinct from RoomLeft: RoomLeft is the leave echo (keeps local
// history), RoomDeleted is the delete echo (purges local history).
type RoomDeleted struct {
	Type string `json:"type"` // "room_deleted"
	Room string `json:"room"`
}

// DeletedRoomsList is sent during the connect handshake (BEFORE
// room_list AND retired_rooms) to catch up devices that were offline
// when a delete_room was issued from another session. Carries every
// room ID this user has previously /delete'd that has not yet been
// pruned from the deleted_rooms sidecar.
//
// Clients process this by running the same purge path as RoomDeleted
// for each room ID: drop all local state for the room. The list is
// deliberately sent first so the local state is reconciled before the
// sidebar is populated from room_list.
type DeletedRoomsList struct {
	Type  string   `json:"type"` // "deleted_rooms"
	Rooms []string `json:"rooms"`
}

// Phase 20: server-authoritative multi-device /leave catchup.
//
// When a user is removed from a room or group DM while their
// client is offline (self-leave on another device, admin removal,
// or retirement cascade), the server records a row in the
// user_left_rooms / user_left_groups history tables. On reconnect,
// the server sends LeftRoomsList and LeftGroupsList BEFORE
// RoomList / GroupList so the client has the full "left" picture
// before populating its sidebar.
//
// Each entry carries the reason code and initiating user so the
// client can render distinct system messages ("you were removed by
// admin" vs "you left on another device" vs "your account was
// retired") rather than a generic "(left)". Replaces the
// client-side reconciliation walk (diff local active IDs against
// server's list) with server-pushed state — the server is now
// authoritative for the "why did this room go away" dimension.

// LeftRoomEntry is one entry in a LeftRoomsList catchup message.
type LeftRoomEntry struct {
	Room        string `json:"room"`
	Reason      string `json:"reason"`                 // "" | "removed" | "user_retired"
	InitiatedBy string `json:"initiated_by,omitempty"` // admin user_id for "removed", "system" for retirement
	LeftAt      int64  `json:"left_at"`
}

// LeftRoomsList is sent on the connect handshake with the most
// recent leave per (user, room) that has not been superseded by a
// re-join. Sent BEFORE RoomList so the client has reason codes in
// hand before reconciling the sidebar.
type LeftRoomsList struct {
	Type  string          `json:"type"` // "left_rooms"
	Rooms []LeftRoomEntry `json:"rooms"`
}

// LeftGroupEntry is one entry in a LeftGroupsList catchup message.
type LeftGroupEntry struct {
	Group       string `json:"group"`
	Reason      string `json:"reason"`                 // "" | "removed" | "retirement"
	InitiatedBy string `json:"initiated_by,omitempty"` // admin user_id for "removed", "system" for retirement
	LeftAt      int64  `json:"left_at"`
}

// LeftGroupsList is the group DM analogue of LeftRoomsList. Sent
// BEFORE GroupList on the connect handshake.
type LeftGroupsList struct {
	Type   string           `json:"type"` // "left_groups"
	Groups []LeftGroupEntry `json:"groups"`
}

// 1:1 DM messages
//
// 1:1 DMs are fixed two-party conversations stored in the direct_messages
// table. They use a per-user history cutoff for the "silent leave" model:
// a user who leaves doesn't trigger a broadcast to the other party, and
// the server filters messages on read via the cutoff timestamp.

// CreateDM requests creation of a 1:1 DM with a single other user. The
// server canonicalizes the pair alphabetically and deduplicates: if a DM
// already exists between these two users, the existing row is returned
// via DMCreated. This enforces 1:1 at the wire level (no Members slice).
type CreateDM struct {
	Type  string `json:"type"`  // "create_dm"
	Other string `json:"other"` // the single other user ID
}

type DMCreated struct {
	Type    string   `json:"type"`    // "dm_created"
	DM      string   `json:"dm"`      // dm_ prefixed nanoid
	Members []string `json:"members"` // always [user_a, user_b]
}

type SendDM struct {
	Type        string            `json:"type"`                  // "send_dm"
	DM          string            `json:"dm"`
	WrappedKeys map[string]string `json:"wrapped_keys"`          // exactly 2 entries
	Payload     string            `json:"payload"`               // base64 encrypted
	FileIDs     []string          `json:"file_ids,omitempty"`
	Signature   string            `json:"signature"`
}

type DM struct {
	Type        string            `json:"type"`                  // "dm"
	ID          string            `json:"id"`                    // server-assigned msg ID
	From        string            `json:"from"`
	DM          string            `json:"dm"`                    // DM row ID
	TS          int64             `json:"ts"`
	WrappedKeys map[string]string `json:"wrapped_keys"`
	Payload     string            `json:"payload"`
	FileIDs     []string          `json:"file_ids,omitempty"`
	Signature   string            `json:"signature"`
	EditedAt    int64             `json:"edited_at,omitempty"`   // Phase 15
}

// EditDM is the client → server envelope for replacing a 1:1 DM
// message's encrypted payload (Phase 15). WrappedKeys must have
// exactly 2 entries matching the DM's two parties. Server rejects
// if the caller's per-user left_at ratchet is set (frozen view
// can't be mutated).
type EditDM struct {
	Type        string            `json:"type"`        // "edit_dm"
	ID          string            `json:"id"`
	DM          string            `json:"dm"`
	WrappedKeys map[string]string `json:"wrapped_keys"`
	Payload     string            `json:"payload"`
	Signature   string            `json:"signature"`
}

// DMEdited is the server → client broadcast for a successful 1:1 DM
// edit. Delivered to both parties' active sessions, provided neither
// has a frozen view on the affected message.
type DMEdited struct {
	Type        string            `json:"type"`                // "dm_edited"
	ID          string            `json:"id"`
	From        string            `json:"from"`
	DM          string            `json:"dm"`
	TS          int64             `json:"ts"`                  // ORIGINAL send time
	WrappedKeys map[string]string `json:"wrapped_keys"`
	Payload     string            `json:"payload"`
	FileIDs     []string          `json:"file_ids,omitempty"`  // preserved from stored row
	Signature   string            `json:"signature"`
	EditedAt    int64             `json:"edited_at"`
}

type LeaveDM struct {
	Type string `json:"type"` // "leave_dm"
	DM   string `json:"dm"`
}

// DMLeft confirms to the leaving user that their leave_dm request
// succeeded. Echoed to every active session of the leaver. No broadcast
// to the other party — 1:1 leave is silent. The per-user cutoff on the
// server row means the leaver's future reads see nothing past the cutoff.
type DMLeft struct {
	Type string `json:"type"` // "dm_left"
	DM   string `json:"dm"`
}

// DMList is sent during the connect flow (alongside group_list) to
// enumerate the user's 1:1 DM conversations.
type DMList struct {
	Type string   `json:"type"` // "dm_list"
	DMs  []DMInfo `json:"dms"`
}

type DMInfo struct {
	ID      string   `json:"id"`
	Members []string `json:"members"` // always [user_a, user_b]
	// LeftAtForCaller is the per-user history cutoff for the recipient of
	// this dm_list. 0 = the caller is an active party. >0 = the caller has
	// previously left this DM and the unix timestamp tells the client when.
	// Used by sync to propagate /delete state to other devices that were
	// offline when the leave happened.
	LeftAtForCaller int64 `json:"left_at_for_caller,omitempty"`
}

// Message deletion

type Delete struct {
	Type string `json:"type"` // "delete"
	ID   string `json:"id"`  // message ID to delete
}

type Deleted struct {
	Type      string `json:"type"`              // "deleted"
	ID        string `json:"id"`
	DeletedBy string `json:"deleted_by"`
	TS        int64  `json:"ts"`
	Room      string `json:"room,omitempty"`    // set for room messages
	Group     string `json:"group,omitempty"`   // set for group DM messages
	DM        string `json:"dm,omitempty"`      // set for 1:1 DM messages
}

// Typing indicators (capability: typing)

type Typing struct {
	Type  string `json:"type"`           // "typing"
	Room  string `json:"room,omitempty"`
	Group string `json:"group,omitempty"`
	DM    string `json:"dm,omitempty"`
	User  string `json:"user,omitempty"` // set by server on broadcast
}

// Read receipts (capability: read_receipts)

type Read struct {
	Type     string `json:"type"`              // "read"
	Room     string `json:"room,omitempty"`
	Group    string `json:"group,omitempty"`
	DM       string `json:"dm,omitempty"`
	User     string `json:"user,omitempty"`    // set by server on broadcast
	LastRead string `json:"last_read"`         // message ID
}

// Reactions (capability: reactions)

type React struct {
	Type        string            `json:"type"`                   // "react"
	ID          string            `json:"id"`                     // target message ID
	Room        string            `json:"room,omitempty"`
	Group       string            `json:"group,omitempty"`
	DM          string            `json:"dm,omitempty"`
	Epoch       int64             `json:"epoch,omitempty"`        // rooms only
	WrappedKeys map[string]string `json:"wrapped_keys,omitempty"` // DMs (group + 1:1)
	Payload     string            `json:"payload"`                // base64 encrypted emoji
	Signature   string            `json:"signature"`
}

type Reaction struct {
	Type        string            `json:"type"`                   // "reaction"
	ReactionID  string            `json:"reaction_id"`            // server-assigned, react_ prefix
	ID          string            `json:"id"`                     // target message ID
	Room        string            `json:"room,omitempty"`
	Group       string            `json:"group,omitempty"`
	DM          string            `json:"dm,omitempty"`
	User        string            `json:"user"`
	TS          int64             `json:"ts"`
	Epoch       int64             `json:"epoch,omitempty"`        // rooms only
	WrappedKeys map[string]string `json:"wrapped_keys,omitempty"` // DMs (group + 1:1)
	Payload     string            `json:"payload"`                // pass-through
	Signature   string            `json:"signature"`              // pass-through
}

type Unreact struct {
	Type       string `json:"type"`        // "unreact"
	ReactionID string `json:"reaction_id"`
}

type ReactionRemoved struct {
	Type       string `json:"type"`             // "reaction_removed"
	ReactionID string `json:"reaction_id"`
	ID         string `json:"id"`               // target message ID
	Room       string `json:"room,omitempty"`
	Group      string `json:"group,omitempty"`
	DM         string `json:"dm,omitempty"`
	User       string `json:"user"`
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
	Admin          bool   `json:"admin,omitempty"`        // true if user is a server admin
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
	Type     string `json:"type"`            // "unread"
	Room     string `json:"room,omitempty"`
	Group    string `json:"group,omitempty"`
	DM       string `json:"dm,omitempty"`
	Count    int    `json:"count"`
	LastRead string `json:"last_read"`
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
	ID          string `json:"id"`           // room nanoid
	Name        string `json:"name"`         // display name (human-visible)
	Topic       string `json:"topic"`
	Members     int    `json:"members"`
}

// Room events
//
// Reason on a "leave" event distinguishes the trigger so client UIs can
// render different system messages to remaining members:
//   - "" (empty): self-leave (the user ran /leave themselves)
//   - "removed": an admin removed the user via sshkey-ctl remove-from-room
//   - "user_retired": the leaving user's account was retired
//
// Phase 20 extended RoomEvent with By and Name fields to support the
// room event audit trail (bundled with the leave-catchup work). Rooms
// now write group_events rows for leave/join/topic/rename/retire
// events via RecordRoomEvent, mirroring Phase 14's group-side audit
// model. By carries the acting operator/admin; Name carries the new
// topic/display-name for topic/rename events.
type RoomEvent struct {
	Type   string `json:"type"`             // "room_event"
	Room   string `json:"room"`
	Event  string `json:"event"`            // "join" | "leave" | "topic" | "rename" | "retire"
	User   string `json:"user"`
	By     string `json:"by,omitempty"`     // Phase 20: acting admin/operator
	Reason string `json:"reason,omitempty"` // "" | "removed" | "user_retired"
	Name   string `json:"name,omitempty"`   // Phase 20: new value for "topic" / "rename" events
}

// Group list

type GroupList struct {
	Type   string      `json:"type"`   // "group_list"
	Groups []GroupInfo `json:"groups"`
}

type GroupInfo struct {
	ID      string   `json:"id"`
	Members []string `json:"members"`
	Admins  []string `json:"admins,omitempty"` // Phase 14: admin user IDs (subset of Members); empty on pre-14 servers
	Name    string   `json:"name,omitempty"`
}

// History (lazy scroll-back)

type History struct {
	Type   string `json:"type"`            // "history"
	Room   string `json:"room,omitempty"`
	Group  string `json:"group,omitempty"`
	DM     string `json:"dm,omitempty"`
	Before string `json:"before"`          // message ID
	Limit  int    `json:"limit"`
}

type HistoryResult struct {
	Type      string         `json:"type"`                  // "history_result"
	Room      string         `json:"room,omitempty"`
	Group     string         `json:"group,omitempty"`
	DM        string         `json:"dm,omitempty"`
	Messages  []RawMessage   `json:"messages"`
	Reactions []RawMessage   `json:"reactions,omitempty"`   // reactions on the returned messages
	EpochKeys []SyncEpochKey `json:"epoch_keys,omitempty"`  // rooms only
	HasMore   bool           `json:"has_more"`
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
	WrappedKeys map[string]string `json:"wrapped_keys"` // userID -> base64 wrapped key
	MemberHash  string            `json:"member_hash"`  // SHA256 of sorted member usernames
}

type EpochConfirmed struct {
	Type  string `json:"type"`  // "epoch_confirmed"
	Room  string `json:"room"`
	Epoch int64  `json:"epoch"`
}

// File transfer

type UploadStart struct {
	Type        string `json:"type"`             // "upload_start"
	UploadID    string `json:"upload_id"`        // client-generated, up_ prefix
	Size        int64  `json:"size"`             // bytes (encrypted)
	ContentHash string `json:"content_hash"`     // "blake2b-256:<hex>" of encrypted bytes
	Room        string `json:"room,omitempty"`
	Group       string `json:"group,omitempty"`
	DM          string `json:"dm,omitempty"`
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

// UploadError is sent when the server rejects an upload_start (rate limit,
// size limit, etc.). Clients match on UploadID to fail the pending upload
// instead of waiting forever for upload_ready. Code matches the protocol
// error codes (Err* constants).
type UploadError struct {
	Type         string `json:"type"`                      // "upload_error"
	UploadID     string `json:"upload_id"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	RetryAfterMs int64  `json:"retry_after_ms,omitempty"`  // Phase 17 Step 6: populated on rate-limit rejections
}

type Download struct {
	Type   string `json:"type"`   // "download"
	FileID string `json:"file_id"`
}

type DownloadStart struct {
	Type        string `json:"type"`                    // "download_start"
	FileID      string `json:"file_id"`
	Size        int64  `json:"size"`
	ContentHash string `json:"content_hash"`  // "blake2b-256:<hex>" of encrypted bytes
}

type DownloadComplete struct {
	Type   string `json:"type"`   // "download_complete"
	FileID string `json:"file_id"`
}

// DownloadError is sent when the server rejects a download request (file
// not found, storage failure, missing channel, etc.). Clients match on
// FileID to fail the pending download instead of waiting forever for
// binary frames on Channel 2.
type DownloadError struct {
	Type    string `json:"type"`    // "download_error"
	FileID  string `json:"file_id"`
	Code    string `json:"code"`
	Message string `json:"message"`
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

// Pending keys management (admin-only)

type ListPendingKeys struct {
	Type string `json:"type"` // "list_pending_keys"
}

type PendingKeyEntry struct {
	Fingerprint string `json:"fingerprint"`
	Attempts    int    `json:"attempts"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

type PendingKeysList struct {
	Type string            `json:"type"` // "pending_keys_list"
	Keys []PendingKeyEntry `json:"keys"`
}

// Room membership

type RoomMembers struct {
	Type string `json:"type"` // "room_members"
	Room string `json:"room"`
}

type RoomMembersList struct {
	Type    string   `json:"type"` // "room_members_list"
	Room    string   `json:"room"`
	Members []string `json:"members"`
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

// UserUnretired is the inverse of UserRetired — broadcast when an
// admin runs `sshkey-ctl unretire-user` to reverse a mistaken
// retirement. Connected clients should DELETE the user from their
// retired cache so the [retired] marker is flushed from sidebar
// labels, info panels, and message headers. Phase 16 Gap 1.
//
// What this does NOT signal: that the user has been re-added to any
// rooms or groups. The retirement cascade removed the user from
// every shared context, and unretirement is intentionally minimal —
// it only flips the flag. Operators must manually re-add the user
// via add-to-room or in-group /add. The broadcast simply tells
// clients to stop rendering the [retired] decoration.
type UserUnretired struct {
	Type string `json:"type"` // "user_unretired"
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
	Type         string `json:"type"`                      // "error"
	Code         string `json:"code"`                      // machine-readable error code
	Message      string `json:"message"`                   // human-readable description
	Ref          string `json:"ref,omitempty"`             // message ID that caused the error
	RetryAfterMs int64  `json:"retry_after_ms,omitempty"`  // Phase 17: populated on rate-limit rejections; client backoff hint
	CorrID       string `json:"corr_id,omitempty"`         // Phase 17c: echoed from the inbound request so clients correlate errors to their send queue entries
}

// Error codes
const (
	ErrNotAuthorized       = "not_authorized"
	ErrForbidden           = "forbidden" // policy denied (e.g., allow_self_leave_rooms = false)
	ErrRateLimited         = "rate_limited"
	ErrMessageTooLarge     = "message_too_large"
	ErrUploadTooLarge      = "upload_too_large"
	ErrEpochConflict       = "epoch_conflict"
	ErrStaleMemberList     = "stale_member_list"
	ErrInvalidWrappedKeys  = "invalid_wrapped_keys"
	ErrDeviceLimitExceeded = "device_limit_exceeded"
	ErrInvalidEpoch        = "invalid_epoch"
	ErrUnknownGroup        = "unknown_group"
	ErrUnknownRoom         = "unknown_room"
	ErrUnknownDM           = "unknown_dm"
	ErrUnknownUser         = "unknown_user"   // Phase 14: add_to_group target not found
	ErrAlreadyMember       = "already_member" // Phase 14: add_to_group target already in group
	ErrAlreadyAdmin        = "already_admin"  // Phase 14: promote_group_admin target already admin
	ErrUserRetired         = "user_retired"
	ErrRoomRetired         = "room_retired" // room has been retired — writes rejected
	ErrServerBusy          = "server_busy"
	// Phase 15: message editing error codes. ErrEditNotAuthorized and
	// ErrEditDeletedMessage are byte-identical to ErrUnknownX on the
	// wire per the privacy rule (non-authors and not-deleted-check
	// failures collapse into the unknown-context response so probing
	// clients can't enumerate authorship). They exist as named constants
	// for internal logging and future hardening. ErrEditNotMostRecent
	// and ErrEditWindowExpired are surfaced to the caller because by
	// the time those checks run the caller has already proven
	// membership and authorship.
	ErrEditNotAuthorized  = "edit_not_authorized"  // internal only — wire response is ErrUnknownX
	ErrEditNotMostRecent  = "edit_not_most_recent" // surfaced
	ErrEditWindowExpired  = "edit_window_expired"  // surfaced
	ErrEditDeletedMessage = "edit_deleted_message" // internal only — wire response is ErrUnknownX
)

// Phase 17 Step 2 wire codes — stable protocol tokens for the Phase 17c
// centralized error helper + constructors below. These are deliberately a
// separate vocabulary from the internal `counters.Signal*` names, which are
// observability identifiers and may evolve independently. A caller building
// a protocol.Error picks from this Code* set; counters package picks from
// its Signal* set. The two never share symbol identities.
//
// Adding a new wire code means: add the constant here, document in
// PROTOCOL.md if client-facing, and use in handler rejection sites.
const (
	CodeDenied      = "denied"            // Phase 14 privacy-opaque rejection
	CodeRateLimit   = "rate_limited"      // rate-limit rejection (carries RetryAfterMs)
	CodeMalformed   = "malformed"         // client-facing validation failure with public field name
	CodeInvalidID   = "invalid_id"        // shape rejection (malformed nanoid etc.)
	CodeTooLarge    = "payload_too_large" // oversized-input rejection
	CodeUnknownVerb = "unknown_verb"      // unrecognized type (reserved; currently silent)
	CodeInternal    = "internal_error"    // server-internal failure (client handles as Category A retry)
)

// OpaqueReject returns a byte-identical opaque rejection suitable for
// Category D (privacy-identical) rejections: non-member sends, unknown-room
// lookups, deleted-row access. The response shape is fixed by the Phase 14
// privacy invariant — do not customize per callsite, or probing clients can
// distinguish "not a member" from "room doesn't exist."
//
// Usage (from a Step 4-6 rejection site):
//
//	s.rejectAndLog(c, counters.SignalInvalidNanoID, "send",
//	    fmt.Sprintf("non-member send attempt on %s", roomID),
//	    protocol.OpaqueReject())
func OpaqueReject() *Error {
	return &Error{
		Type:    "error",
		Code:    CodeDenied,
		Message: "operation rejected",
	}
}

// RateLimit returns a rate-limit rejection error with the given backoff hint
// in milliseconds. Clients handling Category A (retriable transient) use the
// hint for exponential-backoff seeding; refresh-verb clients (A-silent) drop
// the error silently and leave cached data on screen.
//
// retryAfterMs may be 0 if no specific backoff is suggested — the
// RetryAfterMs field uses `omitempty` so zero is elided from the wire.
func RateLimit(retryAfterMs int64) *Error {
	return &Error{
		Type:         "error",
		Code:         CodeRateLimit,
		Message:      "please slow down",
		RetryAfterMs: retryAfterMs,
	}
}

// MalformedField returns a malformed-field rejection naming the public field
// and a reason string. Use for client-facing validation failures where the
// field name is public knowledge (payload size, file_ids cap, wrapped_keys
// cap, content_hash format, etc.).
//
// Do NOT use for privacy-sensitive fields — a malformed-field message with
// a private field name leaks server state. Use OpaqueReject() instead.
func MalformedField(field, reason string) *Error {
	return &Error{
		Type:    "error",
		Code:    CodeMalformed,
		Message: field + ": " + reason,
	}
}

// RawMessage is a JSON object that hasn't been decoded into a specific type yet.
// Used in sync batches and history results which contain mixed message types.
type RawMessage = json.RawMessage
