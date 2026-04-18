package protocol

// Phase 17c Step 3 — classification tests.

import (
	"strings"
	"testing"
)

func TestCategoryForCode_KnownCodes(t *testing.T) {
	cases := []struct {
		code     string
		want     ErrorCategory
		wantName string
	}{
		// A-default
		{ErrRateLimited, CategoryADefault, "A-default"},
		{CodeRateLimit, CategoryADefault, "A-default"},
		{CodeInternal, CategoryADefault, "A-default"},
		{ErrServerBusy, CategoryADefault, "A-default"},

		// B
		{ErrInvalidEpoch, CategoryB, "B"},
		{ErrEpochConflict, CategoryB, "B"},
		{ErrStaleMemberList, CategoryB, "B"},

		// C
		{ErrMessageTooLarge, CategoryC, "C"},
		{ErrUploadTooLarge, CategoryC, "C"},
		{ErrEditWindowExpired, CategoryC, "C"},
		{ErrEditNotMostRecent, CategoryC, "C"},
		{ErrInvalidWrappedKeys, CategoryC, "C"},
		{ErrUserRetired, CategoryC, "C"},
		{ErrRoomRetired, CategoryC, "C"},
		{ErrForbidden, CategoryC, "C"},
		{ErrAlreadyMember, CategoryC, "C"},
		{ErrAlreadyAdmin, CategoryC, "C"},
		{ErrNotAuthorized, CategoryC, "C"},
		{"too_many_members", CategoryC, "C"},
		{"invalid_upload_id", CategoryC, "C"},
		{CodeMalformed, CategoryC, "C"},
		{CodeInvalidID, CategoryC, "C"},
		{CodeTooLarge, CategoryC, "C"},

		// D
		{CodeDenied, CategoryD, "D"},
		{ErrUnknownRoom, CategoryD, "D"},
		{ErrUnknownGroup, CategoryD, "D"},
		{ErrUnknownDM, CategoryD, "D"},
		{ErrUnknownUser, CategoryD, "D"},
		{"unknown_file", CategoryD, "D"},
		{"not_found", CategoryD, "D"},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			got := CategoryForCode(tc.code)
			if got != tc.want {
				t.Errorf("CategoryForCode(%q) = %v, want %v", tc.code, got, tc.want)
			}
			if got.String() != tc.wantName {
				t.Errorf("CategoryForCode(%q).String() = %q, want %q", tc.code, got.String(), tc.wantName)
			}
		})
	}
}

func TestCategoryForCode_UnknownReturnsUnknown(t *testing.T) {
	got := CategoryForCode("totally_unheard_of_code_xyz")
	if got != CategoryUnknown {
		t.Errorf("unknown code = %v, want CategoryUnknown", got)
	}
	if got.String() != "unknown" {
		t.Errorf("CategoryUnknown.String() = %q, want %q", got.String(), "unknown")
	}
}

// TestCategoryForCode_ExhaustiveOverConstants — for every Err* and
// Code* constant declared in messages.go, assert CategoryForCode
// returns a non-Unknown category. Drift guard: a new code added to
// the protocol without a category entry fails this test.
func TestCategoryForCode_ExhaustiveOverConstants(t *testing.T) {
	// Maintained list of every wire code constant exported from the
	// protocol package. When a new code is added, append it here AND
	// classify it in categories.go.
	codes := []string{
		ErrNotAuthorized, ErrForbidden, ErrRateLimited, ErrMessageTooLarge,
		ErrUploadTooLarge, ErrEpochConflict, ErrStaleMemberList,
		ErrInvalidWrappedKeys, ErrDeviceLimitExceeded, ErrInvalidEpoch,
		ErrUnknownGroup, ErrUnknownRoom, ErrUnknownDM, ErrUnknownUser,
		ErrAlreadyMember, ErrAlreadyAdmin, ErrUserRetired, ErrRoomRetired,
		ErrServerBusy, ErrEditNotAuthorized, ErrEditNotMostRecent,
		ErrEditWindowExpired, ErrEditDeletedMessage,
		CodeDenied, CodeRateLimit, CodeMalformed, CodeInvalidID,
		CodeTooLarge, CodeUnknownVerb, CodeInternal,
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			got := CategoryForCode(code)
			if got == CategoryUnknown {
				t.Errorf("CategoryForCode(%q) returned Unknown — add to the taxonomy", code)
			}
		})
	}
}

// TestCategoryString_AllCategoriesHaveNames verifies each enum value
// has a human name (prevents a new category being added without a
// name in the String method).
func TestCategoryString_AllCategoriesHaveNames(t *testing.T) {
	for _, c := range []ErrorCategory{
		CategoryADefault, CategoryASilent, CategoryB, CategoryC, CategoryD,
	} {
		name := c.String()
		if name == "" || strings.Contains(name, "unknown") {
			t.Errorf("category %d has empty/unknown name: %q", c, name)
		}
	}
}
