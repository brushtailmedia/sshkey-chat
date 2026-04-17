package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Moved from rooms_test.go — co-located with the code they exercise.
// Behavior unchanged; this was a verbatim relocation in Phase 17 Step 1.

func TestGenerateRoomID(t *testing.T) {
	id := GenerateRoomID()
	if !strings.HasPrefix(id, "room_") {
		t.Errorf("room ID should start with room_, got %q", id)
	}
	if len(id) != 26 { // "room_" (5) + 21 chars
		t.Errorf("room ID length = %d, want 26", len(id))
	}

	// Should be unique
	id2 := GenerateRoomID()
	if id == id2 {
		t.Error("two generated IDs should not be equal")
	}
}

func TestGenerateID_Prefix(t *testing.T) {
	id := GenerateID("test_")
	if !strings.HasPrefix(id, "test_") {
		t.Errorf("should start with test_, got %q", id)
	}
}

// --- ValidateNanoID tests (Phase 17 Step 1) ---

// validBody is a 21-char string using only characters from idAlphabet.
// Useful for constructing valid-shape test ids.
const validBody = "V1StGXR8Z5jdHi6B-Mj_K"

func TestValidateNanoID_HappyPath(t *testing.T) {
	// Cover every production prefix currently in use across the codebase.
	// Known prefixes today: usr_, room_, group_, dm_, msg_, react_, file_,
	// plus corr_ (Phase 17c) and up_ (Phase 17 Step 4).
	knownPrefixes := []string{
		"usr_",
		"room_",
		"group_",
		"dm_",
		"msg_",
		"react_",
		"file_",
		"corr_",
		"up_",
	}
	for _, prefix := range knownPrefixes {
		t.Run(prefix, func(t *testing.T) {
			id := prefix + validBody
			if err := ValidateNanoID(id, prefix); err != nil {
				t.Errorf("ValidateNanoID(%q, %q) = %v, want nil", id, prefix, err)
			}
		})
	}
}

func TestValidateNanoID_UnusualButLegalPrefixes(t *testing.T) {
	// Per-spec happy-path edges: a prefix of just "_" or just "a" is legal.
	// Caller is trusted on what prefix to pass; validator only enforces
	// shape (non-empty, alphabet-only).
	cases := []string{"_", "a", "-", "aa_", "some-prefix_"}
	for _, prefix := range cases {
		t.Run(prefix, func(t *testing.T) {
			id := prefix + validBody
			if err := ValidateNanoID(id, prefix); err != nil {
				t.Errorf("ValidateNanoID(%q, %q) = %v, want nil", id, prefix, err)
			}
		})
	}
}

func TestValidateNanoID_LengthFailure(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"too_short", "room_short"},
		{"one_byte_short", "room_" + validBody[:20]},
		{"one_byte_long", "room_" + validBody + "x"},
		{"way_too_long", "room_" + strings.Repeat("a", 500)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNanoID(tc.id, "room_")
			if !errors.Is(err, ErrInvalidNanoIDLength) {
				t.Errorf("ValidateNanoID(%q, \"room_\") = %v, want ErrInvalidNanoIDLength", tc.id, err)
			}
		})
	}
}

func TestValidateNanoID_PrefixFailure(t *testing.T) {
	// Correct length, wrong prefix content.
	// "wrng_" + 21 chars is 26 bytes — same length as a room_-prefixed id.
	id := "wrng_" + validBody
	err := ValidateNanoID(id, "room_")
	if !errors.Is(err, ErrInvalidNanoIDPrefix) {
		t.Errorf("ValidateNanoID(%q, \"room_\") = %v, want ErrInvalidNanoIDPrefix", id, err)
	}
}

func TestValidateNanoID_EmptyExpectedPrefix(t *testing.T) {
	// Empty expectedPrefix is a programmer bug — must return prefix sentinel.
	err := ValidateNanoID("room_"+validBody, "")
	if !errors.Is(err, ErrInvalidNanoIDPrefix) {
		t.Errorf("ValidateNanoID(..., \"\") = %v, want ErrInvalidNanoIDPrefix", err)
	}
}

func TestValidateNanoID_MalformedExpectedPrefix(t *testing.T) {
	// expectedPrefix containing bytes outside the alphabet must return
	// ErrInvalidNanoIDPrefix (defensive check for caller bugs).
	cases := []struct {
		name   string
		prefix string
	}{
		{"slash", "rm/"},
		{"bang", "room!"},
		{"dot", "room."},
		{"space", "room "},
		{"null_byte", "room\x00"},
		{"newline", "room\n"},
		{"tab", "room\t"},
		{"quote", "room\""},
		{"apostrophe", "room'"},
		{"backslash", "room\\"},
		{"emoji", "🏠_"},
		{"unicode_latin", "rôom_"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build an id that would otherwise be valid-length.
			id := tc.prefix + validBody
			err := ValidateNanoID(id, tc.prefix)
			if !errors.Is(err, ErrInvalidNanoIDPrefix) {
				t.Errorf("ValidateNanoID(%q, %q) = %v, want ErrInvalidNanoIDPrefix", id, tc.prefix, err)
			}
		})
	}
}

func TestValidateNanoID_AlphabetFailure_InjectionClasses(t *testing.T) {
	// Each case injects exactly one invalid byte somewhere in an otherwise
	// valid nanoid body. Covers every major injection class the alphabet
	// restriction is designed to block.
	cases := []struct {
		name string
		bad  string // bad byte sequence to inject
	}{
		// SQL meta-chars
		{"sql_single_quote", "'"},
		{"sql_double_quote", "\""},
		{"sql_semicolon", ";"},
		{"sql_comment_dash", "."}, // `.` isn't a SQL meta strictly, but it's blocked
		{"sql_comment_hash", "#"},
		// Shell meta-chars
		{"shell_backtick", "`"},
		{"shell_dollar", "$"},
		{"shell_pipe", "|"},
		{"shell_amp", "&"},
		{"shell_space", " "},
		{"shell_gt", ">"},
		{"shell_lt", "<"},
		// Path traversal
		{"path_slash", "/"},
		{"path_backslash", "\\"},
		{"path_dot", "."},
		// Control characters
		{"ctrl_null", "\x00"},
		{"ctrl_newline", "\n"},
		{"ctrl_return", "\r"},
		{"ctrl_tab", "\t"},
		{"ctrl_esc", "\x1b"}, // ANSI escape
		// JSON envelope break-out
		{"json_quote", "\""},
		{"json_brace_open", "{"},
		{"json_brace_close", "}"},
		{"json_bracket_open", "["},
		{"json_bracket_close", "]"},
		{"json_backslash", "\\"},
		// Multi-byte UTF-8 / Unicode attacks
		{"utf8_latin_a_grave", "à"},
		{"utf8_emoji_house", "🏠"},
		{"utf8_rtl_override", "\u202e"}, // RTL override (bidi attack)
		{"utf8_zwj", "\u200d"},          // zero-width joiner (homograph)
		// High bytes (non-ASCII)
		{"high_byte_0x80", "\x80"},
		{"high_byte_0xff", "\xff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Replace the first byte of validBody with the bad sequence.
			// The id stays exactly the right byte-length when bad is 1 byte;
			// for multi-byte sequences we compensate to keep length correct
			// so the ALPHABET sentinel fires, not LENGTH.
			body := tc.bad + validBody
			// Trim to exactly 21 bytes if the bad sequence pushed us over.
			if len(body) > 21 {
				body = body[:21]
			}
			// Pad with valid chars if we're under 21 bytes.
			for len(body) < 21 {
				body += "a"
			}
			id := "room_" + body
			err := ValidateNanoID(id, "room_")
			if !errors.Is(err, ErrInvalidNanoIDAlphabet) {
				t.Errorf("ValidateNanoID(%q, \"room_\") = %v, want ErrInvalidNanoIDAlphabet", id, err)
			}
		})
	}
}

func TestValidateNanoID_MixedValidPlusOneInvalid(t *testing.T) {
	// An id with 20 valid chars and 1 invalid char buried in the middle
	// must still fail with the alphabet sentinel — the loop must visit
	// every byte, not short-circuit early.
	for _, pos := range []int{0, 5, 10, 15, 20} {
		t.Run(fmt.Sprintf("pos_%d", pos), func(t *testing.T) {
			body := []byte(validBody)
			body[pos] = '!' // not in alphabet
			id := "room_" + string(body)
			err := ValidateNanoID(id, "room_")
			if !errors.Is(err, ErrInvalidNanoIDAlphabet) {
				t.Errorf("ValidateNanoID(%q, \"room_\") = %v, want ErrInvalidNanoIDAlphabet", id, err)
			}
		})
	}
}

func TestValidateNanoID_OrderingAssertion(t *testing.T) {
	// When multiple failures coexist, the spec requires this order:
	//   length → prefix → alphabet
	// These tests confirm the ordering is a guarantee, not an accident.

	t.Run("length_trumps_prefix", func(t *testing.T) {
		// Wrong prefix AND wrong length — length must win.
		id := "wrong_toolong_" + validBody
		err := ValidateNanoID(id, "room_")
		if !errors.Is(err, ErrInvalidNanoIDLength) {
			t.Errorf("expected length sentinel to win, got %v", err)
		}
	})

	t.Run("length_trumps_alphabet", func(t *testing.T) {
		// Bad alphabet char AND wrong length — length must win.
		id := "room_" + validBody + "!extra" // too long + has '!'
		err := ValidateNanoID(id, "room_")
		if !errors.Is(err, ErrInvalidNanoIDLength) {
			t.Errorf("expected length sentinel to win, got %v", err)
		}
	})

	t.Run("prefix_trumps_alphabet", func(t *testing.T) {
		// Correct length, wrong prefix, AND bad alphabet in body —
		// prefix must win because it's checked before body alphabet.
		body := []byte(validBody)
		body[5] = '!' // not in alphabet
		id := "wrng_" + string(body)
		err := ValidateNanoID(id, "room_")
		if !errors.Is(err, ErrInvalidNanoIDPrefix) {
			t.Errorf("expected prefix sentinel to win, got %v", err)
		}
	})
}

func TestValidateNanoID_BoundedErrorMessageOnOversizedInput(t *testing.T) {
	// Spec requires ErrInvalidNanoIDLength error messages to NOT include
	// the full id value — so a giant bogus input must not produce a giant
	// error string.
	huge := strings.Repeat("a", 10_000)
	err := ValidateNanoID(huge, "room_")
	if err == nil {
		t.Fatal("expected error for oversized id")
	}
	if !errors.Is(err, ErrInvalidNanoIDLength) {
		t.Fatalf("expected length sentinel, got %v", err)
	}
	msg := err.Error()
	if len(msg) > 200 {
		t.Errorf("error message is %d bytes; must stay bounded (cap 200) even for giant inputs.\nmessage: %q",
			len(msg), msg)
	}
	if strings.Contains(msg, huge) {
		t.Error("error message must NOT include the full id value")
	}
}

func TestValidateNanoID_GeneratedIDsAreValid(t *testing.T) {
	// Every id produced by GenerateID must pass ValidateNanoID with the
	// same prefix. This is the round-trip contract between generator and
	// validator.
	prefixes := []string{"usr_", "room_", "group_", "dm_", "msg_", "react_", "file_"}
	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				id := GenerateID(prefix)
				if err := ValidateNanoID(id, prefix); err != nil {
					t.Fatalf("iteration %d: generated id %q failed validation: %v", i, id, err)
				}
			}
		})
	}
}

// --- Benchmarks ---
//
// Purpose: baseline establishment for Phase 19 comparison. Not a pass/fail
// gate. Run with `go test -bench=BenchmarkValidateNanoID -benchmem`.

func BenchmarkValidateNanoID_Happy(b *testing.B) {
	id := "room_" + validBody
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateNanoID(id, "room_")
	}
}

func BenchmarkValidateNanoID_BadLength(b *testing.B) {
	id := "room_short"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateNanoID(id, "room_")
	}
}

func BenchmarkValidateNanoID_BadPrefix(b *testing.B) {
	id := "wrng_" + validBody
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateNanoID(id, "room_")
	}
}

func BenchmarkValidateNanoID_BadAlphabet(b *testing.B) {
	body := []byte(validBody)
	body[10] = '!'
	id := "room_" + string(body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateNanoID(id, "room_")
	}
}
