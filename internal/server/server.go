// Package server implements the sshkey-chat SSH server.
package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/brushtailmedia/sshkey/internal/protocol"
	"github.com/brushtailmedia/sshkey/internal/store"
)

// Server is the sshkey-chat SSH server.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	epochs   *epochManager
	limiter  *rateLimiter
	files    *fileManager
	audit    *auditLog
	typing   *typingTracker
	sshCfg   *ssh.ServerConfig
	hostKey  ssh.Signer
	logger   *slog.Logger
	listener net.Listener
	dataDir  string

	mu       sync.RWMutex
	clients  map[string]*Client // device_id -> Client
}

// New creates a new server with the given config and data directory.
func New(cfg *config.Config, logger *slog.Logger, dataDir ...string) (*Server, error) {
	dir := ""
	if len(dataDir) > 0 {
		dir = dataDir[0]
	}

	s := &Server{
		cfg:     cfg,
		logger:  logger,
		epochs:  newEpochManager(),
		limiter: newRateLimiter(),
		clients: make(map[string]*Client),
		dataDir: dir,
	}

	// Open storage if data directory provided
	if dir != "" {
		st, err := store.Open(dir)
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		s.store = st
		s.files = newFileManager(dir)
		s.audit = newAuditLog(dir)
	}

	// Typing tracker doesn't need expiry broadcast for now — the client handles display timeout.
	// Server-side expiry is informational only.
	s.typing = newTypingTracker(nil)

	hostKey, err := s.loadOrGenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	s.hostKey = hostKey

	s.sshCfg = &ssh.ServerConfig{
		PublicKeyCallback: s.authenticateKey,
		ServerVersion:     "SSH-2.0-sshkey-server",
	}
	s.sshCfg.AddHostKey(hostKey)

	return s, nil
}

// ListenAndServe starts the SSH listener and accepts connections.
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Server.Bind, s.cfg.Server.Server.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln
	s.logger.Info("server listening", "addr", addr)

	// Start config file watcher
	s.watchConfig()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.listener == nil {
				return nil // shutdown
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// Close shuts down the server gracefully.
func (s *Server) Close() error {
	// Audit
	if s.audit != nil {
		s.mu.RLock()
		clientCount := len(s.clients)
		s.mu.RUnlock()
		s.audit.Log("server", "shutdown", fmt.Sprintf("clients=%d", clientCount))
	}

	// Broadcast shutdown to all connected clients
	s.mu.RLock()
	for _, client := range s.clients {
		client.Encoder.Encode(protocol.ServerShutdown{
			Type:        "server_shutdown",
			Message:     "Server shutting down",
			ReconnectIn: 10,
		})
	}
	s.mu.RUnlock()

	var firstErr error
	if s.listener != nil {
		ln := s.listener
		s.listener = nil
		if err := ln.Close(); err != nil {
			firstErr = err
		}
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// authenticateKey validates an SSH public key against users.toml.
// Only Ed25519 keys are accepted.
func (s *Server) authenticateKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if key.Type() != "ssh-ed25519" {
		s.logger.Warn("rejected non-Ed25519 key",
			"type", key.Type(),
			"remote", conn.RemoteAddr().String(),
		)
		return nil, fmt.Errorf("only Ed25519 keys are supported, got %s", key.Type())
	}

	s.cfg.RLock()
	defer s.cfg.RUnlock()

	for username, user := range s.cfg.Users {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
		if err != nil {
			continue
		}
		if bytes.Equal(key.Marshal(), parsed.Marshal()) {
			s.logger.Info("key authenticated",
				"user", username,
				"fingerprint", ssh.FingerprintSHA256(key),
				"remote", conn.RemoteAddr().String(),
			)
			return &ssh.Permissions{
				Extensions: map[string]string{
					"username": username,
				},
			}, nil
		}
	}

	// Unknown key -- log to pending
	fingerprint := ssh.FingerprintSHA256(key)
	s.logger.Info("unknown key rejected",
		"fingerprint", fingerprint,
		"remote", conn.RemoteAddr().String(),
	)
	s.logPendingKey(fingerprint, conn.RemoteAddr().String())

	return nil, fmt.Errorf("key not authorized")
}

// logPendingKey stores a pending key in the DB, logs to file, and notifies admins.
func (s *Server) logPendingKey(fingerprint, remote string) {
	// Store in DB for tracking attempts
	attempts := 1
	if s.store != nil {
		s.store.UsersDB().Exec(`
			INSERT INTO pending_keys (fingerprint, remote_addr)
			VALUES (?, ?)
			ON CONFLICT (fingerprint) DO UPDATE SET
				attempts = attempts + 1,
				last_seen = datetime('now'),
				remote_addr = excluded.remote_addr`,
			fingerprint, remote)

		var count int
		var firstSeen string
		s.store.UsersDB().QueryRow(
			`SELECT attempts, first_seen FROM pending_keys WHERE fingerprint = ?`,
			fingerprint).Scan(&count, &firstSeen)
		if count > 0 {
			attempts = count
			// Notify connected admin clients
			s.notifyAdmins(protocol.AdminNotify{
				Type:        "admin_notify",
				Event:       "pending_key",
				Fingerprint: fingerprint,
				Attempts:    attempts,
				FirstSeen:   firstSeen,
			})
		}
	}

	// Also append to flat log file
	dataDir := filepath.Join(filepath.Dir(s.cfg.Dir), "data")
	logPath := filepath.Join(dataDir, "pending-keys.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		s.logger.Error("failed to open pending-keys.log", "error", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "fingerprint=%s remote=%s attempts=%d\n", fingerprint, remote, attempts)
}

// notifyAdmins sends a message to all connected admin clients.
func (s *Server) notifyAdmins(msg any) {
	s.cfg.RLock()
	adminSet := make(map[string]bool, len(s.cfg.Server.Server.Admins))
	for _, a := range s.cfg.Server.Server.Admins {
		adminSet[a] = true
	}
	s.cfg.RUnlock()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if adminSet[client.Username] {
			client.Encoder.Encode(msg)
		}
	}
}

// handleConnection processes a new SSH connection through the full lifecycle.
func (s *Server) handleConnection(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshCfg)
	if err != nil {
		s.logger.Debug("SSH handshake failed",
			"remote", conn.RemoteAddr().String(),
			"error", err,
		)
		conn.Close()
		return
	}

	username := sshConn.Permissions.Extensions["username"]
	s.logger.Info("connect",
		"user", username,
		"remote", sshConn.RemoteAddr().String(),
	)

	// Handle global requests (respond to keepalive, discard others)
	go func() {
		for req := range reqs {
			if req.WantReply {
				req.Reply(false, nil) // respond to keepalives
			}
		}
	}()

	// Start server-side keepalive (detect dead connections)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_, _, err := sshConn.SendRequest("keepalive@sshkey-chat", true, nil)
			if err != nil {
				return // connection dead
			}
		}
	}()

	// Handle channels: Channel 1 = NDJSON protocol, Channel 2 = binary file transfer
	channelNum := 0
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, chReqs, err := newCh.Accept()
		if err != nil {
			s.logger.Error("channel accept failed", "user", username, "error", err)
			continue
		}
		go ssh.DiscardRequests(chReqs)

		channelNum++
		if channelNum == 1 {
			// Channel 1: NDJSON protocol
			go s.handleSession(username, sshConn, ch)
		} else if channelNum == 2 {
			// Channel 2: binary file transfer
			go s.handleBinaryChannel(username, ch)
		} else {
			ch.Close()
		}
	}

	s.logger.Info("disconnect",
		"user", username,
		"remote", sshConn.RemoteAddr().String(),
	)
}

// loadOrGenerateHostKey loads the host key from disk or generates a new one.
func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := filepath.Join(s.cfg.Dir, "host_key")

	// Try to load existing key
	keyData, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse host key: %w", err)
		}
		s.logger.Info("loaded host key",
			"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()),
		)
		return signer, nil
	}

	// Generate new Ed25519 host key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	keyData = pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse generated host key: %w", err)
	}

	s.logger.Info("generated new host key",
		"path", keyPath,
		"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()),
	)
	return signer, nil
}
