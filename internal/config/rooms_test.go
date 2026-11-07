package config

// RoomsSection config tests — the [rooms] typing_max_members knob.
//
// Verifies:
//   - Missing [rooms] section → DefaultRoomTypingMaxMembers (100).
//   - Present section with `typing_max_members = N` → loads N.
//   - Explicit 0 loads as 0 and is VALID: it means typing off in every
//     room, not "use the default".
//   - A negative value is a hard config error naming the key.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRoomsConfig(t *testing.T, typingMaxMembers string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[rooms]
typing_max_members = `+typingMaxMembers+`
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
}

func TestRoomsSection_DefaultWhenAbsent(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Rooms.TypingMaxMembers; got != DefaultRoomTypingMaxMembers {
		t.Errorf("Rooms.TypingMaxMembers default = %d, want %d", got, DefaultRoomTypingMaxMembers)
	}
}

func TestRoomsSection_LoadedFromTOML(t *testing.T) {
	cfg, err := Load(writeRoomsConfig(t, "250"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Rooms.TypingMaxMembers; got != 250 {
		t.Errorf("Rooms.TypingMaxMembers = %d, want 250", got)
	}
}

func TestRoomsSection_ExplicitZeroIsTypingOff(t *testing.T) {
	cfg, err := Load(writeRoomsConfig(t, "0"))
	if err != nil {
		t.Fatalf("load: zero must be a valid value (typing off), got %v", err)
	}
	if got := cfg.Server.Rooms.TypingMaxMembers; got != 0 {
		t.Errorf("Rooms.TypingMaxMembers = %d, want 0 (parser must not coerce to the default)", got)
	}
}

func TestRoomsSection_NegativeRejected(t *testing.T) {
	_, err := Load(writeRoomsConfig(t, "-1"))
	if err == nil {
		t.Fatal("load: a negative typing_max_members must be a config error")
	}
	if !strings.Contains(err.Error(), "[rooms] typing_max_members") {
		t.Errorf("error should name the key, got %q", err.Error())
	}
}

func TestRoomsSection_ValidateDirect(t *testing.T) {
	for _, n := range []int{0, 1, 100, 100000} {
		if err := (RoomsSection{TypingMaxMembers: n}).Validate(); err != nil {
			t.Errorf("Validate(%d) = %v, want nil", n, err)
		}
	}
	if err := (RoomsSection{TypingMaxMembers: -5}).Validate(); err == nil {
		t.Error("Validate(-5) = nil, want error")
	}
}

func TestDefaultServerConfig_RoomsSection(t *testing.T) {
	cfg := DefaultServerConfig()
	if got := cfg.Rooms.TypingMaxMembers; got != DefaultRoomTypingMaxMembers {
		t.Errorf("DefaultServerConfig Rooms.TypingMaxMembers = %d, want %d", got, DefaultRoomTypingMaxMembers)
	}
}
