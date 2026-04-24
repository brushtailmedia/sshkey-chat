package main

// Phase 16 — inspection commands for operators.
//
//   show-user <id|display_name>   Full user details
//   show-room <display_name|id>   Full room details
//   list-admins                   Quick view of all admin users
//   search-users --name <query>   Fuzzy search by display name
//   search-users --fingerprint <fp>  Find user by SSH key fingerprint
//
// All four are pure read-only — they query users.db, rooms.db, and
// data.db (for devices and revocation status) without modifying
// anything. No broadcasts, no queue writes, no audit entries.

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// cmdShowUser prints comprehensive details for a single user:
// display name, user ID, SSH key fingerprint, admin status, retired
// status, room memberships, devices, and revocation status.
//
// Accepts either a user ID (usr_...) or a display name and
// resolves whichever it finds first. Case-insensitive on display
// name to match the existing search convention.
func cmdShowUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: show-user <user_id | display_name>")
	}
	query := args[0]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Try user ID first, then display name lookup.
	u := st.GetUserByID(query)
	if u == nil {
		all := st.GetAllUsersIncludingRetired()
		for i := range all {
			if strings.EqualFold(all[i].DisplayName, query) {
				u = &all[i]
				break
			}
		}
	}
	if u == nil {
		return fmt.Errorf("user %q not found (checked both ID and display name)", query)
	}

	// Compute fingerprint from the stored key.
	fingerprint := "(unknown)"
	if parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.Key)); err == nil {
		fingerprint = ssh.FingerprintSHA256(parsed)
	}

	fmt.Printf("User: %s\n", u.ID)
	fmt.Printf("  Display name:  %s\n", u.DisplayName)
	fmt.Printf("  Fingerprint:   %s\n", fingerprint)
	fmt.Printf("  Admin:         %v\n", u.Admin)
	fmt.Printf("  Retired:       %v\n", u.Retired)
	if u.Retired {
		fmt.Printf("  Retired at:    %s\n", u.RetiredAt)
		fmt.Printf("  Retired reason: %s\n", u.RetiredReason)
	}

	// Room memberships.
	roomIDs := st.GetUserRoomIDs(u.ID)
	if len(roomIDs) > 0 {
		fmt.Printf("  Rooms (%d):\n", len(roomIDs))
		for _, id := range roomIDs {
			room, _ := st.GetRoomByID(id)
			name := id
			if room != nil {
				name = room.DisplayName
			}
			fmt.Printf("    %s (%s)\n", name, id)
		}
	} else {
		fmt.Println("  Rooms:         (none)")
	}

	// Devices.
	devices, err := st.GetDevices(u.ID)
	if err == nil && len(devices) > 0 {
		fmt.Printf("  Devices (%d):\n", len(devices))
		for _, d := range devices {
			revoked, _ := st.IsDeviceRevoked(u.ID, d.DeviceID)
			status := ""
			if revoked {
				status = " [REVOKED]"
			}
			lastSync := d.LastSynced
			if lastSync == "" {
				lastSync = "(never)"
			}
			fmt.Printf("    %s  last_sync=%s  created=%s%s\n", d.DeviceID, lastSync, d.CreatedAt, status)
		}
	} else {
		fmt.Println("  Devices:       (none)")
	}

	return nil
}

// cmdShowRoom prints comprehensive details for a single room:
// display name, room ID, topic, member list (with display names),
// retired status, default flag, and creation date.
//
// Accepts either a room nanoid (room_...) or a display name.
func cmdShowRoom(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: show-room <display_name | room_id>")
	}
	query := args[0]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Try room ID first, then display name.
	var room *store.RoomRecord
	if strings.HasPrefix(query, "room_") {
		room, _ = st.GetRoomByID(query)
	}
	if room == nil {
		room, _ = st.GetRoomByDisplayName(query)
	}
	if room == nil {
		return fmt.Errorf("room %q not found (checked both ID and display name)", query)
	}

	fmt.Printf("Room: %s\n", room.ID)
	fmt.Printf("  Display name:  %s\n", room.DisplayName)
	fmt.Printf("  Topic:         %s\n", room.Topic)
	fmt.Printf("  Created at:    %s\n", room.CreatedAt)
	fmt.Printf("  Default:       %v\n", room.IsDefault)
	fmt.Printf("  Retired:       %v\n", room.Retired)
	if room.Retired {
		fmt.Printf("  Retired at:    %s\n", room.RetiredAt)
		fmt.Printf("  Retired by:    %s\n", room.RetiredBy)
	}

	// Members.
	memberIDs := st.GetRoomMemberIDsByRoomID(room.ID)
	if len(memberIDs) > 0 {
		fmt.Printf("  Members (%d):\n", len(memberIDs))
		for _, uid := range memberIDs {
			name := st.GetUserDisplayName(uid)
			admin := ""
			if st.IsAdmin(uid) {
				admin = " (admin)"
			}
			fmt.Printf("    %s — %s%s\n", uid, name, admin)
		}
	} else {
		fmt.Println("  Members:       (none)")
	}

	return nil
}

// cmdListAdmins prints a quick view of every user with admin=true.
// Retired admins are included (marked) because they still matter
// for audit trail — "who was an admin at the time of this action."
func cmdListAdmins(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	all := st.GetAllUsersIncludingRetired()
	var admins []store.UserRecord
	for _, u := range all {
		if u.Admin {
			admins = append(admins, u)
		}
	}

	if len(admins) == 0 {
		fmt.Println("No admin users.")
		fmt.Println("On a fresh deployment run `sshkey-ctl init` first, then `sshkey-ctl bootstrap-admin <name> [--out DIR]`.")
		fmt.Println("On an existing deployment, use `sshkey-ctl promote <user>` to grant admin.")
		return nil
	}

	fmt.Printf("Admins (%d):\n", len(admins))
	for _, u := range admins {
		status := ""
		if u.Retired {
			status = " [retired]"
		}
		fmt.Printf("  %-25s %s%s\n", u.DisplayName, u.ID, status)
	}
	return nil
}

// cmdSearchUsers searches for users by display name (fuzzy,
// case-insensitive substring) or by SSH key fingerprint (exact
// match). Searches across all users including retired.
//
// Flags:
//
//	--name <query>         case-insensitive substring match against
//	                        display names
//	--fingerprint <fp>     exact match against SSH key fingerprints
//	                        (accepts both SHA256:... and the bare
//	                        hash)
//
// Exactly one of --name or --fingerprint is required. Both can be
// combined in a future extension but the Phase 16 spec doesn't
// require it.
func cmdSearchUsers(dataDir string, args []string) error {
	var nameQuery, fpQuery string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				nameQuery = args[i+1]
				i++
			}
		case "--fingerprint":
			if i+1 < len(args) {
				fpQuery = args[i+1]
				i++
			}
		}
	}
	if nameQuery == "" && fpQuery == "" {
		return fmt.Errorf("usage: search-users --name <query>  OR  search-users --fingerprint <fingerprint>")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	all := st.GetAllUsersIncludingRetired()
	var matches []store.UserRecord
	for _, u := range all {
		if nameQuery != "" {
			if !strings.Contains(strings.ToLower(u.DisplayName), strings.ToLower(nameQuery)) {
				continue
			}
		}
		if fpQuery != "" {
			parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.Key))
			if err != nil {
				continue
			}
			fp := ssh.FingerprintSHA256(parsed)
			// Accept both "SHA256:abc..." and "abc..." (bare hash).
			if fp != fpQuery && !strings.HasSuffix(fp, fpQuery) {
				continue
			}
		}
		matches = append(matches, u)
	}

	if len(matches) == 0 {
		if nameQuery != "" {
			fmt.Printf("No users matching name %q.\n", nameQuery)
		} else {
			fmt.Printf("No users matching fingerprint %q.\n", fpQuery)
		}
		return nil
	}

	fmt.Printf("Found %d user(s):\n", len(matches))
	for _, u := range matches {
		status := ""
		if u.Admin {
			status += " (admin)"
		}
		if u.Retired {
			status += " [retired]"
		}
		fmt.Printf("  %-25s %s%s\n", u.DisplayName, u.ID, status)
	}
	return nil
}
