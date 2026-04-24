package protocol

// Phase 17c Step 3 — Error taxonomy classification (Activity 1).
//
// The four client-facing categories per refactor_plan.md §Phase 17c:
//
//   A-default : Retriable transient; auto-retry w/ exponential backoff,
//               surface to user on budget exhaustion. Used for
//               rate_limited on send/edit/react/admin verbs,
//               internal_error, server_busy.
//   A-silent  : Retriable transient; SILENT drop on client. No user-
//               visible error, cached data stays on screen. Used for
//               rate_limited on refresh verbs (room_members,
//               device_list).
//   B         : Retriable after state fix; server pushes fresh state
//               (epoch_key, group_list) alongside the error so the
//               client can resend with corrected payload. Used for
//               invalid_epoch, epoch_conflict, stale_member_list.
//   C         : Permanent user-action required; surface to UI, do NOT
//               auto-retry. Client presents the human-readable message.
//   D         : Privacy-identical rejection; byte-identical wire shape
//               regardless of underlying reason so probing clients
//               cannot enumerate (non-member vs unknown vs deleted row).
//               Client surfaces as generic "operation rejected".
//
// CategoryForCode is the authoritative mapping. Adding a new Code*
// constant MUST also add its category here, verified by
// TestCategoryForCode_ExhaustiveCoverage in categories_test.go.
//
// Note: rate_limited is A-default in this mapping. Refresh verbs
// (room_members, device_list) should use the A-silent variant instead
// by checking the verb at the call site — the Category function can't
// know the verb context.

// ErrorCategory identifies a client-response category for a given
// wire error code.
type ErrorCategory int

const (
	// CategoryUnknown is the zero value — returned for unrecognized
	// codes. Callers SHOULD treat this conservatively as
	// CategoryADefault (retry-and-surface) since that's the safest
	// default UX; the presence of an unknown code usually means a
	// newer server is talking to an older client or vice versa.
	CategoryUnknown ErrorCategory = iota

	// CategoryADefault: retriable transient, auto-retry + surface on
	// exhaust.
	CategoryADefault

	// CategoryASilent: retriable transient, NO user-visible error
	// (cached data still valid).
	CategoryASilent

	// CategoryB: retriable after server-pushed state fix.
	CategoryB

	// CategoryC: permanent user-action, surface to UI, no retry.
	CategoryC

	// CategoryD: privacy-identical rejection, surface as generic
	// "operation rejected", no retry.
	CategoryD
)

// String returns the human-readable category tag used in inline
// comments + debug output. Format matches the plan's examples:
// "A-default", "A-silent", "B", "C", "D", "unknown".
func (c ErrorCategory) String() string {
	switch c {
	case CategoryADefault:
		return "A-default"
	case CategoryASilent:
		return "A-silent"
	case CategoryB:
		return "B"
	case CategoryC:
		return "C"
	case CategoryD:
		return "D"
	default:
		return "unknown"
	}
}

// CategoryForCode returns the client-response category for the given
// wire error code. Single source of truth for Phase 17c Activity 1.
// Returns CategoryUnknown for unrecognized codes — callers should
// treat that as "retriable transient, surface on exhaust" (A-default).
//
// Note: rate_limited returns CategoryADefault here. Refresh-verb
// callers (handleRoomMembers, handleListDevices) should treat it as
// A-silent by verb context; this function can't see the verb.
func CategoryForCode(code string) ErrorCategory {
	switch code {
	// ── Category A — retriable transient ────────────────────────────
	// ErrRateLimited and CodeRateLimit are both "rate_limited" — a
	// single case covers both.
	case ErrRateLimited:
		return CategoryADefault
	case CodeInternal:
		return CategoryADefault
	case ErrServerBusy:
		return CategoryADefault

	// ── Category B — retriable after state fix ──────────────────────
	case ErrInvalidEpoch:
		return CategoryB
	case ErrEpochConflict:
		return CategoryB
	case ErrStaleMemberList:
		return CategoryB

	// ── Category C — permanent user-action ──────────────────────────
	case ErrMessageTooLarge, ErrUploadTooLarge:
		return CategoryC
	case ErrDailyQuotaExceeded:
		// Per-user daily upload quota — retry is "wait until UTC
		// midnight" which is closer to "permanent for now" than
		// "transient." Client surfaces the message directly without
		// auto-retry. Out-of-phase 2026-04-19.
		return CategoryC
	case ErrEditWindowExpired, ErrEditNotMostRecent:
		return CategoryC
	case ErrInvalidWrappedKeys:
		// Both "count mismatch" (send with wrong wrapped_keys) and
		// "stale member set" (group membership changed mid-send) surface
		// as this code today. The "stale member set" case is technically
		// a B (server could push fresh group_list), but the count-mismatch
		// case is C (client bug). Classifying as C for now — clients
		// should reconcile member list from broadcasts before resend.
		// Revisit if state-fix push lands for this code.
		return CategoryC
	case ErrUserRetired, ErrRoomRetired:
		return CategoryC
	case ErrForbidden:
		return CategoryC
	case ErrAlreadyMember, ErrAlreadyAdmin:
		return CategoryC
	case ErrDeviceLimitExceeded:
		return CategoryC
	case ErrNotAuthorized:
		// Typically used for post-membership authorization failures
		// (admin-only verbs, delete-own-message). Surfaced as C; the
		// privacy-identical variants collapse to ErrUnknownX instead.
		return CategoryC
	case "too_many_members", "username_taken", "invalid_profile":
		return CategoryC
	case "invalid_upload_id", "invalid_content_hash", "missing_hash", "invalid_context":
		return CategoryC
	case "invalid_file_id", "invalid_message":
		return CategoryC
	case ErrEditNotAuthorized, ErrEditDeletedMessage:
		// Internal-only codes — wire response is actually ErrUnknownX
		// (Category D). Mapped to C for completeness; not expected to
		// reach clients as-is.
		return CategoryC
	case CodeMalformed, CodeInvalidID, CodeTooLarge, CodeUnknownVerb:
		return CategoryC

	// ── Category D — privacy-identical rejection ────────────────────
	case CodeDenied:
		return CategoryD
	case ErrUnknownRoom, ErrUnknownGroup, ErrUnknownDM, ErrUnknownUser:
		return CategoryD
	case "unknown_file", "not_found":
		return CategoryD
	}
	return CategoryUnknown
}
