package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Conformance-vector loader test (displayname-validator-conformance.md, Option
// C). The canonical vector file lives here in the authoritative server repo;
// sshkey-term vendors a byte-identical copy and runs the equivalent test, and a
// repo-root drift check in the term repo guards the vendored copy. The contract:
// assert accept/reject and the trimmed return for valid cases — never error
// text. Length is bytes-after-trim, not rune count.

type dnVectorCase struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
	Want  string `json:"want"`
	Why   string `json:"why"`
}

type dnVectorFile struct {
	Version int            `json:"version"`
	Comment string         `json:"comment"`
	Cases   []dnVectorCase `json:"cases"`
}

// dnVectorsExpectedVersion is the only vector version this loader understands.
// A mismatch fails loudly rather than silently testing a stale/forward set.
const dnVectorsExpectedVersion = 1

func loadDisplayNameVectors(t *testing.T) dnVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/displayname_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf dnVectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vf
}

// checkDisplayNameVector returns "" if ValidateDisplayName matches the vector,
// else a mismatch description. Factored out so the negative-control test can
// prove the harness actually catches a wrong vector.
func checkDisplayNameVector(c dnVectorCase) string {
	got, err := ValidateDisplayName(c.Name)
	if (err == nil) != c.Valid {
		return fmt.Sprintf("validity mismatch for %q: got err=%v, want valid=%v", c.Name, err, c.Valid)
	}
	if c.Valid {
		want := c.Want
		if want == "" {
			want = strings.TrimSpace(c.Name) // default: the cleaned (trimmed) input, not raw JSON
		}
		if got != want {
			return fmt.Sprintf("trimmed-return mismatch for %q: got %q, want %q", c.Name, got, want)
		}
	}
	return ""
}

func TestDisplayNameConformanceVectors(t *testing.T) {
	vf := loadDisplayNameVectors(t)
	if vf.Version != dnVectorsExpectedVersion {
		t.Fatalf("vector version = %d, want %d (unknown version — refusing to test a stale/forward set)", vf.Version, dnVectorsExpectedVersion)
	}
	if len(vf.Cases) == 0 {
		t.Fatal("no vector cases loaded")
	}
	for _, c := range vf.Cases {
		if msg := checkDisplayNameVector(c); msg != "" {
			t.Error(msg)
		}
	}

	// Length-boundary sanity: every valid case is within 2..32 bytes after
	// trim, and the set includes at least one >32-byte invalid case. A
	// fat-fingered 32-byte literal in the over-cap vector would silently be
	// valid and quietly defeat the byte-vs-rune trap (the highest-value case),
	// so guard the byte length explicitly rather than trusting the literal.
	hasOverCap := false
	for _, c := range vf.Cases {
		trimmed := strings.TrimSpace(c.Name)
		if c.Valid {
			if len(trimmed) < 2 || len(trimmed) > 32 {
				t.Errorf("valid case %q is %d bytes after trim — outside the 2..32 bound", c.Name, len(trimmed))
			}
		} else if len(trimmed) > 32 {
			hasOverCap = true
		}
	}
	if !hasOverCap {
		t.Error("no >32-byte invalid case present — the byte-length over-cap boundary is not exercised")
	}
}

// TestDisplayNameConformanceVectors_HarnessBinds is the negative control: a
// deliberately-wrong vector MUST be reported by checkDisplayNameVector. If this
// passes silently the conformance test above is asserting nothing.
func TestDisplayNameConformanceVectors_HarnessBinds(t *testing.T) {
	if checkDisplayNameVector(dnVectorCase{Name: "Alice", Valid: false}) == "" {
		t.Error("harness failed to catch a wrong validity expectation (valid name claimed invalid)")
	}
	if checkDisplayNameVector(dnVectorCase{Name: "  Alice  ", Valid: true, Want: "WRONG"}) == "" {
		t.Error("harness failed to catch a wrong trimmed-return expectation")
	}
}
