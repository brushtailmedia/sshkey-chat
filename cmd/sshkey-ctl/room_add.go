package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// roomAddQueueResult reports the two independent outcomes of a room add:
// whether THIS call inserted the room_members row, and whether it wrote (or
// found an existing) pending_add_to_room side-effect queue row. Every helper
// return spells all three fields for grep-ability. See
// fix-pending-add-to-room-bypass-v3.md.
type roomAddQueueResult struct {
	Inserted      bool // true only when this call inserted room_members
	Queued        bool // true when this call wrote pending_add_to_room
	AlreadyQueued bool // an existing queue row already covers (user, room)
}

// addRoomMemberAndQueueSideEffects is the single source of truth for the
// membership-insert + live-side-effect-queue semantics shared by every CLI
// room-add path (add-to-room, approve --rooms, default-room auto-join +
// backfill). It is server-authoritative about retired rooms and retired users
// (third-party clients may attempt anything; the server must reject), and it
// uses the room_members insert result (RowsAffected) — not a pre-check — as the
// proof that a membership is new, so concurrent duplicate adds never produce
// fake join broadcasts or double epoch rotations.
//
// Callers format their own operator output from the returned result; the two
// warning checks are identical across sites:
//   - partial-failure: result.Inserted && err != nil && !result.AlreadyQueued
//   - insert-error:     !result.Inserted && err != nil
func addRoomMemberAndQueueSideEffects(st *store.Store, userID string, room store.RoomRecord, initiatedBy string) (roomAddQueueResult, error) {
	// 1. Retired rooms are read-only — never add or enqueue.
	if room.Retired {
		return roomAddQueueResult{}, fmt.Errorf("room %q is retired and cannot receive new members", room.DisplayName)
	}

	// 2. Server-authoritative retired-user gate — must not be bypassable by any
	//    CLI path. (cmdApprove / default-room paths add a freshly-approved user
	//    that can't be retired in the normal flow, but the gate closes the
	//    re-approval edge and keeps every path consistent.)
	u := st.GetUserByID(userID)
	if u == nil {
		return roomAddQueueResult{}, fmt.Errorf("user %q not found", userID)
	}
	if u.Retired {
		return roomAddQueueResult{}, fmt.Errorf("user %q is retired and cannot be added to rooms", userID)
	}

	// 3. Insert; RowsAffected is the source of truth for "new membership".
	inserted, err := st.AddRoomMemberIfMissing(room.ID, userID, 0)
	if err != nil {
		// 4. Insert error — nothing was written.
		return roomAddQueueResult{}, err
	}
	if !inserted {
		// 5. Already a member — no-op; no side effects should be queued.
		return roomAddQueueResult{}, nil
	}

	// 6. Re-adding is an affirmative undo of any prior leave OR delete.
	//    Clear both per-user sidecars so a stale row can't tell the user's
	//    devices to mark-as-left or purge a room they've just rejoined.
	//    Best-effort: warn but continue (the catchup send paths also filter
	//    out current members defensively). See
	//    stale-deleted-room-readd-fix.md.
	if err := st.DeleteUserLeftRoomRows(userID, room.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to clear prior leave history for %s in %s: %v\n", userID, room.DisplayName, err)
	}
	if err := st.ClearRoomDeletion(userID, room.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to clear prior delete record for %s in %s: %v\n", userID, room.DisplayName, err)
	}

	// 7. Enqueue live side effects for the running server.
	if err := st.RecordPendingAddToRoom(userID, room.ID, initiatedBy); err != nil {
		if errors.Is(err, store.ErrAlreadyQueued) {
			// 8. Defensive: an existing queue row already covers (user, room).
			//    Membership is durable; the existing row delivers side effects.
			return roomAddQueueResult{Inserted: true, AlreadyQueued: true}, nil
		}
		// 9. Real partial failure: membership inserted but queue write failed.
		return roomAddQueueResult{Inserted: true}, err
	}

	// 10. Fresh membership + fresh queue row.
	return roomAddQueueResult{Inserted: true, Queued: true}, nil
}
