package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
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

func TestCmdInitWithIO_DefaultWritesRecommendedTemplate(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	if err := cmdInitWithIO(configDir, dataDir, []string{"--yes"}, strings.NewReader(""), io.Discard, false); err != nil {
		t.Fatalf("cmdInitWithIO --yes: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(configDir, "server.toml"))
	if err != nil {
		t.Fatalf("read server.toml: %v", err)
	}
	got := string(content)
	if !strings.Contains(got, "recommended full template") {
		t.Fatalf("expected recommended template header, got:\n%s", got)
	}
	if !strings.Contains(got, "[backup]") || !strings.Contains(got, "[server.auto_revoke]") {
		t.Fatalf("expected full template sections in server.toml")
	}
}

func TestCmdInitWithIO_MinimalFlagWritesMinimalConfig(t *testing.T) {
	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	if err := cmdInitWithIO(configDir, dataDir, []string{"--yes", "--minimal"}, strings.NewReader(""), io.Discard, false); err != nil {
		t.Fatalf("cmdInitWithIO --yes --minimal: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(configDir, "server.toml"))
	if err != nil {
		t.Fatalf("read server.toml: %v", err)
	}
	got := string(content)
	if !strings.Contains(got, "# Generated by sshkey-ctl init.") {
		t.Fatalf("expected minimal header, got:\n%s", got)
	}
	if strings.Contains(got, "[backup]") || strings.Contains(got, "[server.auto_revoke]") {
		t.Fatalf("unexpected full-template sections in minimal server.toml")
	}
}

func TestCmdInitWithIO_ProfileDevUsesHomeDefaults(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", home)

	if err := cmdInitWithIO(defaultConfigDir, defaultDataDir, []string{"--yes", "--profile", "dev"}, strings.NewReader(""), io.Discard, false); err != nil {
		t.Fatalf("cmdInitWithIO --profile dev --yes: %v", err)
	}

	serverPath := filepath.Join(home, ".sshkey-chat", "config", "server.toml")
	if _, err := os.Stat(serverPath); err != nil {
		t.Fatalf("expected dev profile server.toml at %s: %v", serverPath, err)
	}
	content, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("read server.toml: %v", err)
	}
	if !strings.Contains(string(content), `bind = "127.0.0.1"`) {
		t.Fatalf("expected dev profile bind=127.0.0.1")
	}
}

func TestCmdInitWithIO_DockerAliasConflictsWithExplicitNonDockerProfile(t *testing.T) {
	err := cmdInitWithIO(
		filepath.Join(t.TempDir(), "config"),
		filepath.Join(t.TempDir(), "data"),
		[]string{"--yes", "--docker", "--profile", "dev"},
		strings.NewReader(""),
		io.Discard,
		false,
	)
	if err == nil {
		t.Fatal("expected profile conflict error")
	}
	if !strings.Contains(err.Error(), "--docker cannot be combined") {
		t.Fatalf("expected actionable conflict error, got: %v", err)
	}
}

func TestCmdInitWithIO_InvalidProfileRejected(t *testing.T) {
	err := cmdInitWithIO(
		filepath.Join(t.TempDir(), "config"),
		filepath.Join(t.TempDir(), "data"),
		[]string{"--yes", "--profile", "weird"},
		strings.NewReader(""),
		io.Discard,
		false,
	)
	if err == nil {
		t.Fatal("expected invalid profile error")
	}
	if !strings.Contains(err.Error(), "invalid --profile") {
		t.Fatalf("expected invalid profile message, got: %v", err)
	}
}

func TestRenderInitRecommendedServerToml_LoadsAsConfig(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	content, err := renderInitRecommendedServerToml("127.0.0.1", 4242, dataDir, initProfileDev)
	if err != nil {
		t.Fatalf("render template: %v", err)
	}
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}

	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatalf("load server.toml: %v", err)
	}
	if cfg.Server.Port != 4242 {
		t.Fatalf("port mismatch: got %d", cfg.Server.Port)
	}
	if cfg.Server.Bind != "127.0.0.1" {
		t.Fatalf("bind mismatch: got %q", cfg.Server.Bind)
	}
	if cfg.Logging.File != filepath.Join(dataDir, "server.log") {
		t.Fatalf("logging.file mismatch: got %q", cfg.Logging.File)
	}
}
