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
	sshCfg   *ssh.ServerConfig
	hostKey  ssh.Signer
	logger   *slog.Logger
	listener net.Listener

	mu       sync.RWMutex
	clients  map[string]*Client // device_id -> Client
}

// New creates a new server with the given config and data directory.
func New(cfg *config.Config, logger *slog.Logger, dataDir ...string) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		logger:  logger,
		epochs:  newEpochManager(),
		limiter: newRateLimiter(),
		clients: make(map[string]*Client),
	}

	// Open storage if data directory provided
	if len(dataDir) > 0 && dataDir[0] != "" {
		st, err := store.Open(dataDir[0])
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		s.store = st
	}

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

// logPendingKey appends an entry to pending-keys.log.
func (s *Server) logPendingKey(fingerprint, remote string) {
	dataDir := filepath.Join(filepath.Dir(s.cfg.Dir), "data")
	logPath := filepath.Join(dataDir, "pending-keys.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		s.logger.Error("failed to open pending-keys.log", "error", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "fingerprint=%s remote=%s\n", fingerprint, remote)
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

	// Discard global requests (keepalive, etc.)
	go ssh.DiscardRequests(reqs)

	// Handle channels
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

		// Discard channel requests (pty, shell, exec, etc.)
		go ssh.DiscardRequests(chReqs)

		// Handle the protocol session on this channel
		go s.handleSession(username, sshConn, ch)
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
