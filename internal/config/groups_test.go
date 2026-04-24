package config

// Phase 17 Step 4d — GroupsSection config tests.
//
// Verifies:
//   - Missing [groups] section → default MaxMembers = 150 (matches the
//     pre-Phase-17 hardcoded value and PROTOCOL.md documentation).
//   - Present [groups] section with `max_members = N` → loads N.
//   - Explicit `max_members = 0` loads as 0 (caller must treat as
//     "use default"; the handler code carries a defensive fallback to
//     150 if it sees non-positive). This test locks in that the parser
//     does NOT silently coerce 0 → 150 — the coercion is a handler-side
//     safety net, not a parser feature.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGroupsSection_DefaultWhenAbsent(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Groups.MaxMembers; got != 150 {
		t.Errorf("Groups.MaxMembers default = %d, want 150", got)
	}
}

func TestGroupsSection_LoadedFromTOML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[groups]
max_members = 200
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Groups.MaxMembers; got != 200 {
		t.Errorf("Groups.MaxMembers = %d, want 200", got)
	}
}

func TestGroupsSection_ExplicitZeroLoadsAsZero(t *testing.T) {
	// Parser is not allowed to silently coerce 0 → 150 — the "use
	// default when non-positive" behavior is enforced at the call site
	// (handleCreateGroup / handleAddToGroup) as a defensive fallback,
	// not here. An operator who writes `max_members = 0` gets 0
	// through the parser. If they want the default, they should omit
	// the field entirely (which hits the DefaultServerConfig path).
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[groups]
max_members = 0
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Groups.MaxMembers; got != 0 {
		t.Errorf("Groups.MaxMembers = %d, want 0 (parser must not coerce)", got)
	}
}

func TestDefaultServerConfig_GroupsSection(t *testing.T) {
	// Direct API check — bypasses TOML load. Future refactors that
	// move defaults around shouldn't accidentally drop this one.
	cfg := DefaultServerConfig()
	if got := cfg.Groups.MaxMembers; got != 150 {
		t.Errorf("DefaultServerConfig Groups.MaxMembers = %d, want 150", got)
	}
}
