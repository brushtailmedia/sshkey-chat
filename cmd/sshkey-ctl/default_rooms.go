package main

// Phase 16 — default rooms feature.
//
// Operators flag rooms as "default" so every new user approved
// lands in them automatically. When set-default-room runs against
// a room with existing users, the CLI ALSO backfills every active
// user as a member (Variant 2 chosen during planning: always
// backfill on flag set, not opt-in).
//
// CLI verbs:
//   set-default-room <name>    — flips is_default=1 + backfills
//                                 every active user as a member
//   unset-default-room <name>   — flips is_default=0; existing
//                                 members STAY (asymmetric on
//                                 purpose — operators rarely want
//                                 to mass-kick a whole room)
//   list-default-rooms          — show flagged non-retired rooms
//
// Approve-path integration: cmdApprove calls addUserToDefaultRooms(...)
// right after the user row insert, so brand-new users automatically
// appear in flagged rooms on first connect (no broadcast needed —
// they're connecting fresh and receive their full room_list during
// the handshake).
//
// Backfill broadcast story: existing connected users added during a
// set-default-room call now get live side effects through the shared
// pending_add_to_room queue. Existing room members see the join broadcast
// and epoch rotation, and newly-backfilled connected users receive the
// live-only room_added_to event within the add-to-room poll interval.

import (
	"fmt"
	"os"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func cmdSetDefaultRoom(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: set-default-room ROOM_NAME\n\n" +
			"Flags a room as 'default' AND backfills every active user\n" +
			"as a member. Every new user approved or bootstrapped after\n" +
			"this point will also auto-join the flagged room")
	}
	roomName := args[0]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	room, _ := st.GetRoomByDisplayName(roomName)
	if room == nil {
		return fmt.Errorf("room %q not found", roomName)
	}
	if room.Retired {
		return fmt.Errorf("room %q is retired — cannot flag as default", roomName)
	}
	if room.IsDefault {
		return fmt.Errorf("room %q is already a default room", roomName)
	}

	// Flip the flag first so the room is officially default before we
	// backfill (in case the backfill fails partway through, the flag
	// is already correct and a re-run will catch up).
	if err := st.SetRoomIsDefault(room.ID, true); err != nil {
		return fmt.Errorf("set is_default: %w", err)
	}

	// Backfill: walk every active (non-retired) user and add them through
	// the shared helper. The helper uses RowsAffected() as the source of
	// truth for new membership, so already-members are no-ops and only
	// genuine inserts enqueue live side effects.
	allUsers := st.GetAllUsersIncludingRetired()
	addedCount := 0
	skippedRetired := 0
	initiatedBy := fmt.Sprintf("os:%d", os.Getuid())
	for _, u := range allUsers {
		if u.Retired {
			skippedRetired++
			continue
		}
		// The shared helper is the source of truth for new-vs-existing
		// membership (via RowsAffected), so no separate IsRoomMemberByID
		// pre-check is needed: count only genuinely-new inserts; existing
		// members are a silent no-op. The helper also queues the live
		// join/epoch side effects that the old direct-insert path skipped.
		result, err := addRoomMemberAndQueueSideEffects(st, u.ID, *room, initiatedBy)
		if result.Inserted {
			addedCount++
		}
		if result.Inserted && err != nil && !result.AlreadyQueued {
			fmt.Fprintf(os.Stderr, "Warning: %s was added to %s, but live join/epoch side effects were not queued: %v\n", u.ID, roomName, err)
		}
		if !result.Inserted && err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add %s to %s: %v\n", u.ID, roomName, err)
		}
	}

	fmt.Printf("Flagged %q as a default room.\n", roomName)
	fmt.Printf("Backfill: added %d active user(s) as members (skipped %d retired).\n", addedCount, skippedRetired)
	if addedCount > 0 {
		fmt.Println("Note: existing room members will see join broadcasts within ~5 seconds.")
		fmt.Println("Newly-backfilled users who are connected will see the room in their sidebar within ~5 seconds.")
	}
	fmt.Println("New users approved after this point will auto-join.")
	return nil
}

func cmdUnsetDefaultRoom(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: unset-default-room ROOM_NAME\n\n" +
			"Clears the 'default' flag on a room. EXISTING members are\n" +
			"NOT removed — only future user approvals will skip this\n" +
			"room. To kick everyone, retire the room instead")
	}
	roomName := args[0]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	room, _ := st.GetRoomByDisplayName(roomName)
	if room == nil {
		return fmt.Errorf("room %q not found", roomName)
	}
	if !room.IsDefault {
		return fmt.Errorf("room %q is not a default room", roomName)
	}

	if err := st.SetRoomIsDefault(room.ID, false); err != nil {
		return fmt.Errorf("clear is_default: %w", err)
	}

	fmt.Printf("Cleared default flag on %q.\n", roomName)
	fmt.Println("Existing members remain. New users will no longer auto-join this room.")
	return nil
}

func cmdListDefaultRooms(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	defaults, err := st.GetDefaultRooms()
	if err != nil {
		return fmt.Errorf("list default rooms: %w", err)
	}
	if len(defaults) == 0 {
		fmt.Println("No default rooms configured.")
		fmt.Println("Use `sshkey-ctl set-default-room <name>` to flag a room.")
		return nil
	}
	fmt.Printf("Default rooms (%d):\n", len(defaults))
	for _, r := range defaults {
		fmt.Printf("  %s  (id=%s, topic=%q)\n", r.DisplayName, r.ID, r.Topic)
	}
	return nil
}

// addUserToDefaultRooms is the auto-join hook called from cmdApprove
// right after a new user row is inserted. Walks every flagged
// non-retired room and adds the user through the shared room-add helper
// so default-room joins queue the same live side effects as add-to-room.
//
// Errors are logged to stderr but don't fail the caller — the user
// row is already committed and the operator can manually re-run
// add-to-room for any room that failed.
//
// Returns the number of rooms the user was added to.
func addUserToDefaultRooms(st *store.Store, userID string) int {
	defaults, err := st.GetDefaultRooms()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to look up default rooms for auto-join: %v\n", err)
		return 0
	}
	count := 0
	initiatedBy := fmt.Sprintf("os:%d", os.Getuid())
	for _, r := range defaults {
		result, err := addRoomMemberAndQueueSideEffects(st, userID, r, initiatedBy)
		if result.Inserted {
			count++
		}
		if result.Inserted && err != nil && !result.AlreadyQueued {
			fmt.Fprintf(os.Stderr, "Warning: %s was added to default room %s, but live join/epoch side effects were not queued: %v\n", userID, r.DisplayName, err)
		}
		if !result.Inserted && err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to auto-add %s to default room %s: %v\n", userID, r.DisplayName, err)
		}
	}
	return count
}
