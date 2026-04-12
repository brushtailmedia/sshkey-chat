# Message Editing (Phase 15) — Design + Plan

This document is the working plan for message editing. It lifts the design from PROJECT.md's "Future: Message Editing" section, updates it for the post-Phase-11 / post-Phase-12 codebase, and chunks the implementation into a reviewable order. Open questions are tracked inline in a Decision log at the bottom.

> The original design in PROJECT.md was drafted pre-Phase-11 with a two-verb model (`Edit` / `EditDM`) and used `"conversation":"conv_abc"` with display-name-keyed `wrapped_keys`. That shape no longer matches the protocol after Phase 11 split 1:1 and group DMs into distinct type families and Phase 7a switched rooms to nanoids. This document is the updated design; PROJECT.md's Future section has been refreshed to match.

---

## Status

- **Design:** complete (this document)
- **Implementation:** not started
- **Prerequisites:** Phase 11 (three-verb send/receive split, reaction clearing helper), Phase 12 (retired-room gate pattern, `IsLeft || IsRoomRetired` input block)

---

## Why editing, not "delete and resend"

Earlier drafts of PROJECT.md stated "no message editing — delete and resend" as a permanent design decision. That was before we reversed the call. The reasons for adding it:

1. **UX parity with the rest of the ecosystem.** Signal, WhatsApp, Slack, Discord, Matrix all support editing. Delete-and-resend is a worse experience: it breaks reply chains, loses reactions, and bumps the message's position in the stream. Users expect edit.
2. **Reply stability.** If Alice's message `msg_abc` has five replies, deleting and re-sending produces `msg_xyz` with no replies — the thread fractures. Editing `msg_abc` in place preserves the whole structure.
3. **Reaction preservation is NOT a goal.** We deliberately clear reactions on edit (Signal does the same) because reactions were for the original content. This is a design choice, not an implementation limitation.
4. **It's a bounded change.** Edit is structurally similar to send — same envelope, same signature pattern, same rate-limit shape. The code paths are mostly copy-paste from send with an extra author-check upfront.

---

## Constraints (design invariants)

These are the rules the implementation must enforce. They came from the original PROJECT.md design and have been extended for the post-Phase-11 / post-Phase-12 codebase.

- **Three context-specific verb families**, mirroring the Phase 11 send/receive split:
  - Rooms: `edit` / `edited` — uses `room` + `epoch`, no `wrapped_keys`
  - Group DMs: `edit_group` / `group_edited` — uses `group` + `wrapped_keys` over current group members
  - 1:1 DMs: `edit_dm` / `dm_edited` — uses `dm` + `wrapped_keys` over exactly 2 entries
- **Only the user's most recent message in the current context** can be edited. Server validates per-room / per-group / per-dm. "Most recent" includes thread replies — a reply IS the user's most recent in the parent's context if nothing followed it.
- **Room messages:** must be in the current or previous epoch (same grace window as sends). Epoch rotation naturally bounds the edit window (~100 messages or 1 hour, whichever comes first).
- **DM / group DM messages:** no epoch restriction (per-message keys are independent), but still gated by the "most recent" rule.
- **Retired rooms reject edits.** Same `IsRoomRetired` gate that Phase 12 added to `handleSend`, `handleReact`, `handlePin`, `handleUnpin`.
- **Left contexts block the edit shortcut at the client.** The existing `IsLeft || IsRoomRetired` input gate in `app.go` covers this. Edit mode entry routes through the same check.
- **Original content is replaced.** No edit history retained. Matches Signal behavior.
- **`edited_at` is set by the server.** Authoritative timestamp, lives in the envelope, never in the payload. Added to `Message`, `GroupMessage`, `DM` protocol types as an `omitempty` field.
- **Body-only edits.** Attachments are immutable. `Edit` / `EditGroup` / `EditDM` types do NOT carry `FileIDs` fields — structural enforcement. Server preserves the original row's `file_ids` on replace.
- **`reply_to` is immutable.** Same structural enforcement — the edit types don't carry `ReplyTo`. Thread structure stays stable.
- **No notifications on edit.** Mention extraction runs on the edited body for highlight rendering, but no push/notification fires. An edit is a correction, not a new message.
- **Cannot edit deleted messages.** Server rejects all three edit verbs if `deleted = 1`. Client does not offer the edit shortcut on deleted messages.
- **Byte-identical privacy.** New handlers join the list in the Conventions section. Non-author, non-member, unknown-context, and deleted-message all return the same wire bytes so a probing client can't enumerate authorship or context existence.

---

## Protocol types

### Rooms: `edit` / `edited`

```json
// Client -> Server
{"type":"edit","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B","epoch":3,
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast to all room members)
{"type":"edited","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B","from":"usr_alice",
 "ts":1712345680,"epoch":3,
 "payload":"base64...","signature":"base64...","edited_at":1712345690}
```

`ts` is the ORIGINAL send timestamp, preserved from the stored row. `edited_at` is the wall clock at the moment the server processed the edit. Both are delivered so clients can show "sent 3:04 PM (edited 3:06 PM)" if we ever want that detail — today's design only surfaces "(edited)" without the timestamp.

### Group DMs: `edit_group` / `group_edited`

```json
// Client -> Server
{"type":"edit_group","id":"msg_def456","group":"group_xK9mQ2pR",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast to all group members)
{"type":"group_edited","id":"msg_def456","group":"group_xK9mQ2pR","from":"usr_alice",
 "ts":1712345680,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64...","edited_at":1712345690}
```

`wrapped_keys` must match the CURRENT group member list at edit time, not the member list when the original was sent. This handles the case where members joined or left the group between send and edit — the new K_msg is wrapped for whoever's in the group now, not whoever was there before.

### 1:1 DMs: `edit_dm` / `dm_edited`

```json
// Client -> Server
{"type":"edit_dm","id":"msg_ghi789","dm":"dm_yL0nR3qS",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast to both parties)
{"type":"dm_edited","id":"msg_ghi789","dm":"dm_yL0nR3qS","from":"usr_alice",
 "ts":1712345680,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64...","edited_at":1712345690}
```

Exactly two `wrapped_keys` entries. Server rejects if the shape doesn't match the DM's two members. Server also rejects if either party has a non-zero `left_at` (the Phase 11 one-way ratchet) — you can't edit a message in a DM the other party already deleted from their side.

---

## Server handlers

Three new handlers mirroring the existing `handleSend` / `handleSendGroup` / `handleSendDM` shape:

### `handleEdit` (rooms)

1. Parse `Edit` envelope
2. **Membership + retired check first.** `IsRoomMemberByID(roomID, userID)` → false → return `ErrUnknownRoom` byte-identical to "unknown room". `IsRoomRetired(roomID)` → true → return `ErrRoomRetired`.
3. Rate limit: `EditsPerMinute` bucket for this user
4. **Fetch the stored row** by `id`. If not found → return same byte-identical "not found" response.
5. **Authorship check.** `row.From == c.UserID` → false → return byte-identical "not found" response. Non-authors can't even confirm the message exists.
6. **Deleted check.** `row.Deleted == true` → return byte-identical "not found" response. Same privacy rule.
7. **Context match.** `row.Room == msg.Room` → false → byte-identical "not found".
8. **Most-recent check.** Query: is there any message in this room by this user with `ts > row.ts`? If yes → `ErrEditNotMostRecent` (caller is proven author, safe to surface specifics).
9. **Epoch window check.** `msg.Epoch == currentEpoch(roomID) OR msg.Epoch == currentEpoch(roomID) - 1` → else `ErrEditWindowExpired`.
10. **Signature verification.** Canonical form = `msg.ID + "|" + msg.Room + "|" + strconv.FormatInt(msg.Epoch, 10) + "|" + msg.Payload`. Verify against the original author's pinned key (the stored row's `from`, which equals `c.UserID` by step 5).
11. **Replace payload.** `UPDATE messages SET payload = ?, signature = ?, edited_at = ? WHERE id = ?`. `file_ids` and `reply_to` untouched.
12. **Clear reactions.** `store.DeleteReactionsForMessage(row.ID)` — reuses the helper from `handleDelete`. Collect the cleared reaction IDs for step 13.
13. **Broadcast `reaction_removed` per cleared reaction** so connected clients drop them from UI.
14. **Broadcast `edited` full envelope** to all current room members via `broadcastToRoom`.
15. Info log.

### `handleEditGroup` (group DMs)

Same shape as `handleEdit` with these differences:

- No retired check (groups don't have a retired state)
- No epoch window check
- `wrapped_keys` must match the current group member set exactly (same check as `handleSendGroup`)
- Broadcast via `broadcastToGroup`
- Uses `GroupMessage` row lookup path instead of `Message`

### `handleEditDM` (1:1 DMs)

Same shape as `handleEditGroup` with these differences:

- `wrapped_keys` must have exactly 2 entries matching the DM's two parties
- Reject if either party's `left_at > 0` (Phase 11 cutoff) — `ErrDMLeft` or byte-identical to unknown per privacy rule
- Broadcast via both DM parties' sessions directly (DMs don't have a broadcast helper; mirror `handleSendDM`)

---

## Privacy matrix

The following table shows which server responses must be byte-identical to enforce the privacy invariant:

| Scenario | Response | Byte-identical to |
|---|---|---|
| Unknown room/group/dm | `ErrUnknownX` | (baseline) |
| Known context, not a member | `ErrUnknownX` | unknown |
| Member, but message ID not found | `ErrUnknownX` | unknown |
| Member, message found, not author | `ErrUnknownX` | unknown |
| Member, message found, author, deleted | `ErrUnknownX` | unknown |
| Member, author, not-deleted, not-most-recent | `ErrEditNotMostRecent` | (surfaced, caller is proven author) |
| Member, author, not-deleted, most-recent, bad epoch | `ErrEditWindowExpired` | (surfaced) |
| Room retired | `ErrRoomRetired` | (surfaced, same as other write handlers) |

The table collapses four different failure modes into the same wire bytes. The regression tests use `bytes.Equal` to assert this.

**Why retired is surfaced separately:** retirement is a public room state (broadcast via `room_retired`), so revealing it through an error doesn't leak information a member doesn't already have. Retired-room rejection matches the existing Phase 12 behavior for send/react/pin/unpin.

**Why not-most-recent and window-expired are surfaced:** by the time these checks run, the caller has already proven membership, authorship, and non-deletion. At that point, specific error messages help the user understand why their edit was rejected without leaking anything new.

---

## Rate limiting

- New field: `EditsPerMinute` on `config.RateLimits`, default 10/min
- New bucket: single shared bucket per user across all three edit verbs
- Documentation: `server.toml` example section updated
- Enforcement: top of each edit handler, same pattern as send rate limits

---

## Sync and history

- `Message`, `GroupMessage`, `DM` protocol types gain `EditedAt int64 \`json:"edited_at,omitempty"\``
- Store: `edited_at` column already planned for the client DB (see below); server side adds it to the same table
- Serialization: when building `sync_batch` and `history_result`, include `edited_at` on any envelope where the stored row's value is non-zero
- Old clients that don't recognize the field ignore it (forward compatibility rule)

---

## Client database

```sql
ALTER TABLE messages ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0;
```

Since there are no live users (per the project notes), we can edit the CREATE TABLE directly instead of running a migration — same approach as Phase 12's `retired_at` column.

Store helpers to update:

- `InsertMessage` — add `edited_at` to the INSERT and the `StoredMessage` struct
- `GetRoomMessages`, `GetGroupMessages`, `GetDMMessages` — SELECT the new column
- `UpdateMessageEdited(msgID string, body string, editedAt int64)` — new helper for the `edited` / `group_edited` / `dm_edited` dispatch path. Replaces `body` and sets `edited_at` in a single row update.

---

## Client dispatch

New cases in `client.go` `handleInternal`:

```go
case "edited":
    var m protocol.Edited
    if err := json.Unmarshal(raw, &m); err == nil {
        // decrypt payload with epoch key, extract body, update local DB
        c.applyEdit(m.ID, m.Room, "", "", m.Payload, m.Epoch, m.EditedAt, m.Signature)
    }
case "group_edited":
    var m protocol.GroupEdited
    if err := json.Unmarshal(raw, &m); err == nil {
        // decrypt with own wrapped key, extract body, update local DB
        c.applyEdit(m.ID, "", m.Group, "", m.Payload, 0, m.EditedAt, m.Signature)
    }
case "dm_edited":
    var m protocol.DMEdited
    if err := json.Unmarshal(raw, &m); err == nil {
        c.applyEdit(m.ID, "", "", m.DM, m.Payload, 0, m.EditedAt, m.Signature)
    }
```

`applyEdit` is a new client helper that:
1. Looks up the stored message by ID
2. Decrypts the new payload using the appropriate key (epoch key for rooms, own wrapped key for groups/DMs)
3. Verifies the signature against the stored `from` user's pinned key
4. Calls `store.UpdateMessageEdited(id, newBody, editedAt)`
5. If the message is currently in an open `MessagesModel`, updates the in-memory `DisplayMessage`

Signature verification failure = log + skip (same as normal sends).

---

## TUI rendering

### "(edited)" marker

`MessagesModel.View()` renders `"(edited)"` in `helpDescStyle` (dim timestamp style) after the timestamp when `msg.EditedAt > 0`. Matches the existing pattern for `"(retired)"` and `"(left)"`.

```
Alice  3:04 PM (edited)
  Hey, can you take a look at this when you get a chance?
```

### Edit mode entry

- **Trigger:** Up-arrow pressed when:
  - `a.focus == FocusInput` (input panel focused, not sidebar/messages)
  - `a.input.Value() == ""` (input is empty)
  - `!a.messages.IsLeft() && !a.messages.IsRoomRetired()` (not in an archived context)
  - The user has at least one non-deleted message in the current context
- **Action:**
  1. Find the user's most recent non-deleted message in the current context (scan backwards through `messages.messages`)
  2. Populate `a.input.value` with that message's body
  3. Set `a.input.editTarget = msg.ID` to track what's being edited
  4. Set `a.input.editMode = true`
  5. Show "Editing message" indicator in the input bar (same style as the reply indicator)

### Edit mode dispatch

When the user presses Enter in edit mode:

1. Grab `body = a.input.Value()`
2. Look up the edit target by ID in `messages.messages`
3. Based on active context, dispatch to the appropriate client method:
   - `messages.room != ""` → `a.client.EditMessage(target.ID, target.Room, target.Epoch, body)`
   - `messages.group != ""` → `a.client.EditGroupMessage(target.ID, target.Group, body)`
   - `messages.dm != ""` → `a.client.EditDMMessage(target.ID, target.DM, body)`
4. Clear the input, exit edit mode

Each client method:
- Fetches the current epoch key (rooms) or generates a fresh K_msg + wraps for current members (groups/DMs)
- Encrypts the new payload
- Signs it
- Sends the edit envelope
- Does NOT touch local state — wait for the server echo

### Edit mode cancel

`Esc` clears `editMode`, `editTarget`, and the input buffer. Returns to normal compose.

### Edit mode indicator

Input bar shows `"Editing message"` in a distinct style, similar to the existing `"Replying to @alice"` indicator.

### Stale epoch UX

When the server returns `ErrEditWindowExpired`:

- Status bar shows "Edit window expired — delete the message instead"
- Client exits edit mode (clears `editMode`, `editTarget`)
- Input buffer preserved so the user can paste/retype into a new message

---

## New error codes

Added to `protocol/messages.go` error constants:

```go
ErrEditNotAuthorized   = "edit_not_authorized"    // byte-identical to unknown per privacy
ErrEditNotMostRecent   = "edit_not_most_recent"   // surfaced, caller is proven author
ErrEditWindowExpired   = "edit_window_expired"    // surfaced, epoch rotated
ErrEditDeletedMessage  = "edit_deleted_message"   // byte-identical to unknown per privacy
```

Only `edit_not_most_recent` and `edit_window_expired` ever actually appear on the wire. The other two are used internally for logging/debugging; the actual wire response is the byte-identical unknown-context response. Listing them here so future maintainers understand the design.

---

## Chunked implementation order

Work the chunks in order. Each chunk is a complete unit of work with its own gate.

### Chunk 1 — Protocol types + error codes

**Server (`sshkey-chat/internal/protocol/messages.go`):**
1. Add `Edit`, `Edited`, `EditGroup`, `GroupEdited`, `EditDM`, `DMEdited` structs with field tags
2. Add `EditedAt int64 \`json:"edited_at,omitempty"\`` field to `Message`, `GroupMessage`, `DM`
3. Add error code constants: `ErrEditNotAuthorized`, `ErrEditNotMostRecent`, `ErrEditWindowExpired`, `ErrEditDeletedMessage`
4. Register the new types in `TypeOf` dispatch (if needed)

**Client (`sshkey-term/internal/protocol/messages.go`):** Mirror all of the above.

**Gate:** Both repos `go build ./...` clean.

### Chunk 2 — Server store helpers + schema

1. Add `edited_at` column to the server's message tables (one per room DB, per group DB, per DM DB). Phase 11 established the per-conversation DB pattern; each needs the new column.
2. `UpdateMessageEdited(msgID, body, editedAt, signature string)` — updates the row with the new encrypted payload + signature + edited_at timestamp. `file_ids`, `reply_to`, `ts` untouched.
3. `GetUserMostRecentMessageID(contextID, userID string) string` — returns the msg ID of the user's most recent message in the given room/group/dm. Used for the "most recent" validation. One function with context-sensitive dispatch or three separate functions — the cleaner option emerges during implementation.
4. Update `GetMessages` / sync helpers to SELECT and serialize the new `edited_at` column
5. Unit tests for each store helper

**Gate:** Server store builds + tests green.

### Chunk 3 — Server handlers

1. `handleEdit` in `session.go` — rooms variant. Mirror the handler shape from `handleSend` with the new author + most-recent + epoch-window + retired checks.
2. `handleEditGroup` in `session.go` — group DMs variant.
3. `handleEditDM` in `session.go` — 1:1 DMs variant.
4. Dispatcher cases added to the main message loop
5. Reaction-clearing integration: reuse `store.DeleteReactionsForMessage` and broadcast `reaction_removed` for each cleared reaction
6. Byte-identical privacy regression tests for each handler:
   - `TestHandleEdit_PrivacyResponsesIdentical` — unknown room, non-member, non-author, deleted, all return same wire bytes
   - `TestHandleEditGroup_PrivacyResponsesIdentical`
   - `TestHandleEditDM_PrivacyResponsesIdentical`
7. Functional tests per handler:
   - Happy path
   - Not author rejected
   - Not most recent rejected (`ErrEditNotMostRecent`)
   - Epoch window expired (rooms only)
   - Retired room rejected (rooms only)
   - Deleted message rejected
   - Reactions cleared on successful edit
   - `edited_at` set on the row

**Gate:** Server builds + tests green. Privacy matrix enforced.

### Chunk 4 — Rate limit wiring

1. Add `EditsPerMinute int \`toml:"edits_per_minute"\`` to `config.RateLimits` struct
2. Default value: 10
3. Document in `testdata/config/server.toml` and `docker/config/server.toml` (commented-out, default shown)
4. Plumb the bucket into each edit handler at the top, after membership check
5. Rate limit test per handler

**Gate:** Rate limit enforced.

### Chunk 5 — Client store + dispatch

1. `ALTER TABLE messages ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0` in the client's store schema (direct edit since no migration needed)
2. Update `StoredMessage` struct, `InsertMessage`, `GetRoomMessages`, `GetGroupMessages`, `GetDMMessages` to map the new column
3. `UpdateMessageEdited(msgID, body string, editedAt int64)` store helper
4. Store unit tests
5. New dispatch cases in `client.go` `handleInternal`: `edited`, `group_edited`, `dm_edited`
6. `applyEdit` helper that decrypts, verifies signature, and calls the store
7. Client dispatch tests

**Gate:** Client store + dispatch builds + tests green.

### Chunk 6 — Client send methods

1. `(c *Client) EditMessage(msgID, roomID string, epoch int64, body string) error` — encrypts with current epoch key, signs, sends `edit` envelope
2. `(c *Client) EditGroupMessage(msgID, groupID, body string) error` — fresh K_msg, wraps for current group members, signs, sends `edit_group` envelope
3. `(c *Client) EditDMMessage(msgID, dmID, body string) error` — fresh K_msg, wraps for both parties, signs, sends `edit_dm` envelope
4. Tests for each

**Gate:** Client send methods build + test green.

### Chunk 7 — TUI rendering

1. `DisplayMessage` struct gains `EditedAt int64` field (client repo)
2. `LoadFromDB` maps the column into the in-memory model
3. `MessagesModel.View()` renders `"(edited)"` in dim style when `EditedAt > 0`
4. Rendering tests for the edit marker

**Gate:** Edit marker visible in rendered output.

### Chunk 8 — TUI edit mode

1. `InputModel` gains `editMode bool` and `editTarget string` fields
2. Up-arrow handling in `app.go`:
   - Check focus, input emptiness, archived state, presence of editable messages
   - Scan backwards through `messages.messages` for the user's most recent non-deleted message
   - Populate input, set edit mode
3. Enter handling in edit mode:
   - Dispatch to the correct `client.EditX` method based on active context
   - Clear input, exit edit mode
4. Esc handling in edit mode: clear everything, return to compose
5. Input bar renders "Editing message" indicator when `editMode` is true
6. `handleServerMessage` case for `edit_window_expired` error: "Edit window expired — delete the message instead" in status bar, exit edit mode
7. TUI interaction tests:
   - Up-arrow enters edit mode with last message body
   - Up-arrow is a no-op on archived contexts
   - Up-arrow is a no-op when input has content
   - Esc cancels cleanly
   - Enter dispatches the correct verb per context

**Gate:** Edit mode works end-to-end in manual testing.

### Chunk 9 — Docs + cleanup

1. Update `PROTOCOL.md`:
   - Add new "Message Editing" section with the three verb families
   - Add new error codes to the errors table
2. Update `CHANGELOG.md` in both repos
3. Update `PROJECT.md` — move the "Future: Message Editing" section text into a "Message Editing" subsection under the main features area (no longer future). The design content stays, the "Status" line changes to "Shipped".
4. Mark this document as implemented: add `> **Shipped 2026-XX-XX** — Phase 15 complete.` to the top

**Gate:** All docs updated. Full test suite passes on both repos. Commit.

---

## Testing strategy

**Server unit tests** (per handler):

- `TestHandleEdit_HappyPath_ReplacesPayloadAndBroadcasts`
- `TestHandleEdit_NotAuthor_ReturnsUnknownBytes`
- `TestHandleEdit_NotMember_ReturnsUnknownBytes`
- `TestHandleEdit_DeletedMessage_ReturnsUnknownBytes`
- `TestHandleEdit_NotMostRecent_ReturnsNotMostRecentError`
- `TestHandleEdit_EpochTooOld_ReturnsWindowExpired`
- `TestHandleEdit_RetiredRoom_ReturnsRoomRetired`
- `TestHandleEdit_ClearsReactions`
- `TestHandleEdit_PrivacyResponsesIdentical` — the full byte-equal test
- (same set for Group and DM variants)

**Store tests:**

- `TestUpdateMessageEdited_ReplacesBodyAndSetsTimestamp`
- `TestUpdateMessageEdited_PreservesFileIDs`
- `TestUpdateMessageEdited_PreservesReplyTo`
- `TestGetUserMostRecentMessage_ReturnsLatest`
- `TestGetUserMostRecentMessage_ExcludesDeleted`

**Client dispatch tests:**

- `TestHandleEdited_UpdatesLocalDB`
- `TestHandleEdited_UpdatesInMemoryDisplayMessage`
- `TestHandleEdited_BadSignatureSkipped`

**TUI tests:**

- `TestInput_UpArrowEntersEditModeOnEmpty`
- `TestInput_UpArrowNoopWhenInputHasContent`
- `TestInput_UpArrowNoopOnLeftRoom`
- `TestInput_UpArrowNoopOnRetiredRoom`
- `TestInput_EscCancelsEditMode`
- `TestMessages_RendersEditedMarker`
- `TestApp_EditModeDispatchesCorrectVerbPerContext`
- `TestApp_EditWindowExpiredExitsEditMode`

**Integration (e2e main_test.go):**

- `TestEdit_RoomEndToEnd` — connect two clients, send, edit, verify second client sees the edit
- `TestEdit_GroupEndToEnd`
- `TestEdit_DMEndToEnd`
- `TestEdit_RateLimitEnforced` — 11 edits in 60s, 11th rejected

---

## Decision log

Open or recently-resolved design questions. Keep the resolution notes — they're more useful to future-you than the question alone.

- **Q1 — Do we track edit history?** No. Original content is replaced, matches Signal. An edit history would require `message_edit_history` table, `/edits <msg_id>` command, UI to view it, and raises delete-after-edit concerns (does deleting the message delete the edit history too?). Not worth the complexity.
- **Q2 — Do we allow editing across epochs for rooms?** No. Current or previous epoch only. Prevents a user from keeping an edit window open indefinitely by not rotating. Matches the send grace window.
- **Q3 — Do we allow editing 10-year-old DMs?** Gated by the "most recent" rule only — no time bound. In practice, users rarely want to edit old messages, and the "most recent" rule means they'd have to have sent nothing else in that DM since. If this becomes a problem, add a `most_recent_dm_edit_window_seconds` config later.
- **Q4 — Do edits bump the sort order?** No. `ts` is preserved from the original. The edited message stays in its original position in the stream. Matches Signal.
- **Q5 — Do other members see a "was edited" line inline, or just the marker?** Just the `(edited)` marker in the timestamp, no inline "edited at X" system message. Matches Signal.
- **Q6 — Last-write-wins on concurrent edits?** Yes. Two devices editing simultaneously: second one overwrites the first, server broadcasts the second. No merge, no lock. Devices see the final state via broadcast.
- **Q7 — Can admins edit other users' messages?** No. Edit is strictly authored-only. Admins can still delete (existing behavior), but the symmetry "admin can delete, therefore admin can edit" is NOT true. Editing someone else's words is a stronger action than deleting them and should not be delegated.
- **Q8 — What about editing in a thread view?** Same rules — the thread root or a reply can be edited if it's the user's most recent message in the context. The "most recent" scan includes thread replies naturally.
- **Q9 — What if the user edits a message to empty?** Same as sending an empty message: rejected with `invalid_payload`. Use delete instead.
- **Q10 — What happens to the edited message's `deleted_at` field?** Untouched. Edit and delete are orthogonal — edit doesn't un-delete, delete rejects edits.
- **Q11 — Fresh K_msg per edit for groups and DMs, or reuse?** Fresh K_msg. AES-GCM with same key and new nonce is technically safe, but the extra cost (one key generation + wraps) is trivial and it preserves the security model. Matches the PROJECT.md reasoning.

---

## Out of scope

These are explicitly NOT part of Phase 15:

- **Edit history viewer.** Matches Q1 — we don't store it.
- **Edit notifications / push.** An edit is a correction, not a new message.
- **Admin override for editing.** Q7 — no.
- **Editing across contexts.** You can't edit a room message from a DM or vice versa. The edit verb carries the context ID and the server validates it.
- **Partial edits / diff-based wire format.** Full envelope only.
- **Attachment edits.** Body-only, by design.
- **`reply_to` changes.** Body-only, by design.

---

## Cross-references

- **PROJECT.md → Future: Message Editing** — canonical design (kept in sync with this document)
- **refactor_plan.md → Phase 15** — high-level step summary pointing here
- **Conventions section** — byte-identical privacy pattern that edit handlers follow
- **Phase 11** — three-verb send/receive split that edit mirrors, reaction clearing helper
- **Phase 12** — `IsRoomRetired` gate pattern, `IsLeft || IsRoomRetired` input block
