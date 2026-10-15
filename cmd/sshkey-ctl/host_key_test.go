package main

// `sshkey-ctl host-key` reads the relocated key at <dataDir>/data/host_key
// (relocate-host-key) — the same path the server and backup/restore use.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCmdHostKey_ReadsDataSubdir(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0750); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPath := filepath.Join(dataDir, "data", "host_key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out, err := captureStdoutErr(t, func() error { return cmdHostKey(dataDir) })
	if err != nil {
		t.Fatalf("cmdHostKey: %v", err)
	}
	if !strings.Contains(out, "Host key fingerprint: SHA256:") {
		t.Fatalf("output missing fingerprint line:\n%s", out)
	}
	if !strings.Contains(out, keyPath) {
		t.Fatalf("output must print the data-dir key path %q:\n%s", keyPath, out)
	}
}

func TestCmdHostKey_MissingKeyErrors(t *testing.T) {
	dataDir := t.TempDir()
	err := cmdHostKey(dataDir)
	if err == nil {
		t.Fatal("expected an error with no host key")
	}
	if !strings.Contains(err.Error(), filepath.Join("data", "host_key")) {
		t.Fatalf("error must name the data-dir location, got %q", err)
	}
}
