package main

// Phase 16 — default rooms feature.
//
// Operators flag rooms as "default" so every new user approved or
// bootstrapped lands in them automatically. When set-default-room
// runs against a room with existing users, the CLI ALSO backfills
// every active user as a member (Variant 2 chosen during planning:
// always backfill on flag set, not opt-in).
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
// Approve-path integration: cmdApprove and cmdBootstrapAdmin both
// call addUserToDefaultRooms(...) right after the user row insert,
// so brand-new users automatically appear in flagged rooms on first
// connect (no broadcast needed — they're connecting fresh and
// receive their full room_list during the handshake).
//
// Backfill broadcast story (worth flagging): existing connected
// users who are added as members during a set-default-room call do
// NOT receive a live broadcast about the new room. Their TUI picks
// the new room up on next reconnect via the standard room_list
// refresh. This matches the existing behavior of `add-to-room`
// (deferred as "optional polish" in the Phase 16 plan). A future
// polish phase can add a `room_added` protocol event that benefits
// both add-to-room and set-default-room backfills simultaneously.

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
			"this point will also auto-join the flagged room.")
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

	// Backfill: walk every active (non-retired) user and add them to
	// the room. AddRoomMember is idempotent (INSERT OR IGNORE) so
	// users already in the room are no-ops. We don't bother computing
	// the diff up front — INSERT OR IGNORE is cheaper than two
	// queries per user.
	allUsers := st.GetAllUsersIncludingRetired()
	addedCount := 0
	skippedRetired := 0
	for _, u := range allUsers {
		if u.Retired {
			skippedRetired++
			continue
		}
		// Pre-check membership to count "already in room" vs "newly
		// added" accurately for the operator output. Without this
		// check, INSERT OR IGNORE doesn't tell us which case fired.
		alreadyMember := st.IsRoomMemberByID(room.ID, u.ID)
		if alreadyMember {
			continue
		}
		if err := st.AddRoomMember(room.ID, u.ID, 0); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add %s to %s: %v\n", u.ID, roomName, err)
			continue
		}
		addedCount++
	}

	fmt.Printf("Flagged %q as a default room.\n", roomName)
	fmt.Printf("Backfill: added %d active user(s) as members (skipped %d retired).\n", addedCount, skippedRetired)
	if addedCount > 0 {
		fmt.Println("Note: connected users will see the new room in their sidebar on next reconnect.")
	}
	fmt.Println("New users approved after this point will auto-join.")
	return nil
}

func cmdUnsetDefaultRoom(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: unset-default-room ROOM_NAME\n\n" +
			"Clears the 'default' flag on a room. EXISTING members are\n" +
			"NOT removed — only future user approvals will skip this\n" +
			"room. To kick everyone, retire the room instead.")
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
// and cmdBootstrapAdmin right after a new user row is inserted.
// Walks every flagged non-retired room and adds the user as a
// member via AddRoomMember (idempotent).
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
	for _, r := range defaults {
		if err := st.AddRoomMember(r.ID, userID, 0); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to auto-add %s to default room %s: %v\n", userID, r.DisplayName, err)
			continue
		}
		count++
	}
	return count
}
