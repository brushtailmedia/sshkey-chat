package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func TestCmdInitWithIO_InteractiveDefaults(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	var out bytes.Buffer
	// Prompts: config, data, bind, port, create starter rooms,
	// starter rooms, mark starter rooms default.
	input := strings.NewReader(strings.Repeat("\n", 8))
	if err := cmdInitWithIO(configDir, dataDir, nil, input, &out, true); err != nil {
		t.Fatalf("cmdInitWithIO: %v", err)
	}

	if !strings.Contains(out.String(), "Press Enter to accept defaults shown in [brackets].") {
		t.Fatalf("missing defaults banner in output: %q", out.String())
	}

	if _, err := os.Stat(filepath.Join(configDir, "server.toml")); err != nil {
		t.Fatalf("server.toml missing: %v", err)
	}
	for _, db := range []string{"data.db", "users.db", "rooms.db"} {
		if _, err := os.Stat(filepath.Join(dataDir, "data", db)); err != nil {
			t.Fatalf("%s missing: %v", db, err)
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	general, err := st.GetRoomByDisplayName("general")
	if err != nil || general == nil {
		t.Fatalf("general room missing: %v", err)
	}
	if !general.IsDefault {
		t.Fatalf("general should be default-flagged")
	}
	support, err := st.GetRoomByDisplayName("support")
	if err != nil || support == nil {
		t.Fatalf("support room missing: %v", err)
	}
	if !support.IsDefault {
		t.Fatalf("support should be default-flagged")
	}
}

func TestCmdInitWithIO_NonTTYRequiresYes(t *testing.T) {
	err := cmdInitWithIO(
		filepath.Join(t.TempDir(), "config"),
		filepath.Join(t.TempDir(), "data"),
		nil,
		strings.NewReader(""),
		io.Discard,
		false,
	)
	if err == nil {
		t.Fatal("expected non-tty error without --yes")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected actionable --yes guidance, got: %v", err)
	}
}

func TestCmdInitWithIO_Yes_CustomStarterRoomsNoDefault(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	err := cmdInitWithIO(configDir, dataDir, []string{
		"--yes",
		"--starter-rooms", "engineering,random",
		"--no-default-starter-rooms",
	}, strings.NewReader(""), io.Discard, false)
	if err != nil {
		t.Fatalf("cmdInitWithIO: %v", err)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	for _, name := range []string{"engineering", "random"} {
		r, getErr := st.GetRoomByDisplayName(name)
		if getErr != nil || r == nil {
			t.Fatalf("room %q missing: %v", name, getErr)
		}
		if r.IsDefault {
			t.Fatalf("room %q should not be default-flagged", name)
		}
	}
	if r, _ := st.GetRoomByDisplayName("general"); r != nil {
		t.Fatalf("general should not be auto-created when starter-rooms override is provided")
	}
}

func TestCmdInitWithIO_IdempotentKeepsExistingServerToml(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	if err := cmdInitWithIO(configDir, dataDir, []string{"--yes"}, strings.NewReader(""), io.Discard, false); err != nil {
		t.Fatalf("first init: %v", err)
	}

	serverPath := filepath.Join(configDir, "server.toml")
	custom := []byte("# custom config\n[server]\nport = 9999\nbind = \"127.0.0.1\"\n")
	if err := os.WriteFile(serverPath, custom, 0640); err != nil {
		t.Fatalf("write custom server.toml: %v", err)
	}

	var out bytes.Buffer
	if err := cmdInitWithIO(configDir, dataDir, []string{"--yes"}, strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("second init: %v", err)
	}

	got, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("read server.toml: %v", err)
	}
	if string(got) != string(custom) {
		t.Fatalf("server.toml was overwritten on idempotent run")
	}
	if !strings.Contains(out.String(), "already exists") {
		t.Fatalf("expected idempotency message, got: %q", out.String())
	}
}

func TestCmdInitWithIO_DockerPresetWithYes(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	if err := cmdInitWithIO(configDir, dataDir, []string{"--docker", "--yes"}, strings.NewReader(""), io.Discard, false); err != nil {
		t.Fatalf("cmdInitWithIO --docker --yes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "server.toml")); err != nil {
		t.Fatalf("server.toml missing: %v", err)
	}
}
