package store

// Phase 20 room_events helpers — parallel to group_events.go.
//
// The `group_events` table schema is defined in every per-context DB
// (see initMessageDB) — rooms, groups, and 1:1 DMs all get the same
// table. Phase 14 populates it for groups; Phase 20 populates it for
// rooms (closing the UX-parity gap with groups' inline system-message
// audit trail). The table name stays "group_events" despite the dual
// use to avoid a mechanical rename across protocol types, store
// helpers, and tests — room writes use the same table via RoomDB
// instead of GroupDB.
//
// Room event vocabulary: "leave" | "join" | "topic" | "rename" | "retire".
// Excluded (not room-scoped): promote/demote (user-level, covered by
// sendProfiles); delete (covered by deleted_rooms sidecar).
//
// Pre-join privacy gate: enforced at the sync layer by syncRoom which
// raises sinceTS to the user's joined_at via GetUserRoom. New members
// don't see pre-join audit events — mirrors Phase 14's group-side gate.

// RecordRoomEvent inserts an audit row into a per-room group_events
// table. Called from performRoomLeave (leave), cmdAddToRoom (join),
// processPendingRoomUpdates (topic, rename), and
// processPendingRoomRetirements (retire).
//
// Best-effort: failures are logged by the caller but do not block the
// originating action or broadcast.
//
// Note: the Quiet flag is unused for rooms (Phase 14 Quiet is a
// group-specific feature); always false. Kept on the signature for
// shape parity with RecordGroupEvent.
func (s *Store) RecordRoomEvent(roomID, event, user, by, reason, name string, quiet bool, ts int64) error {
	db, err := s.RoomDB(roomID)
	if err != nil {
		return err
	}
	quietFlag := 0
	if quiet {
		quietFlag = 1
	}
	_, err = db.Exec(`
		INSERT INTO group_events (event, user, by, reason, name, quiet, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event, user, by, reason, name, quietFlag, ts,
	)
	return err
}

// GetRoomEventsSince returns every group_events row in the given
// room's per-room DB with ts >= sinceTS, ordered by ts ascending.
// Mirrors GetGroupEventsSince's shape so syncRoom can pack events
// into SyncBatch.Events alongside messages, using the same sinceTS
// watermark (with syncRoom applying the first_seen/joined_at gate
// before calling this helper).
func (s *Store) GetRoomEventsSince(roomID string, sinceTS int64) ([]GroupEventRow, error) {
	db, err := s.RoomDB(roomID)
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`
		SELECT id, event, user, by, reason, name, quiet, ts
		FROM group_events WHERE ts >= ? ORDER BY ts ASC, id ASC`,
		sinceTS,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []GroupEventRow
	for rows.Next() {
		var r GroupEventRow
		var quietFlag int
		if err := rows.Scan(&r.ID, &r.Event, &r.User, &r.By, &r.Reason, &r.Name, &quietFlag, &r.TS); err != nil {
			return nil, err
		}
		r.Quiet = quietFlag == 1
		events = append(events, r)
	}
	return events, rows.Err()
}
