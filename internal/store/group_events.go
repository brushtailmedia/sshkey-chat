package store

// Phase 14 audit-trail store fns for the per-group group_events table.
//
// The table is defined inside each group-{id}.db file (see initMessageDB).
// Rooms and 1:1 DMs get an empty unused copy — the cost is one schema block,
// the benefit is automatic GC via DeleteGroupConversation (the per-group DB
// file unlink drops the events with it) and alignment with the DB-per-context
// invariant.
//
// Ownership contract (groups_admin.md "Audit recording contract"): each
// event type has exactly one recording site. RecordGroupEvent is best-effort
// from the handler — failures are logged but do not block the originating
// action or broadcast. GetGroupEventsSince uses the same sinceTS int64
// watermark as GetGroupMessagesSince so sync_batch can replay both streams
// through one client-side last_synced bump.

// GroupEventRow is a single row from the per-group group_events table,
// used by GetGroupEventsSince during sync replay.
type GroupEventRow struct {
	ID     int64
	Event  string // "join" | "leave" | "promote" | "demote" | "rename"
	User   string // the member this event is about
	By     string // the admin who triggered it; empty for self-leave, retirement, retirement_succession
	Reason string // "" | "removed" | "retirement" | "retirement_succession"
	Name   string // new name (for rename events only)
	Quiet  bool   // suppress inline system message on the client
	TS     int64  // unix seconds
}

// RecordGroupEvent inserts an audit row into the per-group group_events
// table. Called from performGroupLeave, handleAddToGroup, handleRemoveFromGroup,
// handlePromoteGroupAdmin, handleDemoteGroupAdmin, handleRenameGroup, and
// the per-group branch of handleRetirement. Ordering in each caller is
// mutation → audit → broadcast → echo.
//
// Failures do not block the originating action — handlers log the error
// and continue to the broadcast step. A persistent failure silently breaks
// /audit and sync replay for that one group; the error log is the canary.
func (s *Store) RecordGroupEvent(groupID, event, user, by, reason, name string, quiet bool, ts int64) error {
	db, err := s.GroupDB(groupID)
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

// GetGroupEventsSince returns every group_events row with ts >= sinceTS,
// ordered by ts ascending. Mirrors GetGroupMessagesSince's shape so
// syncGroup can pack both into a single SyncBatch with one sinceTS
// watermark.
func (s *Store) GetGroupEventsSince(groupID string, sinceTS int64) ([]GroupEventRow, error) {
	db, err := s.GroupDB(groupID)
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
