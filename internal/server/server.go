// Package server implements the sshkey-chat SSH server.
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/push"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
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
	push     *push.Relay
	sshCfg   *ssh.ServerConfig
	hostKey  ssh.Signer
	logger   *slog.Logger
	listener net.Listener
	dataDir  string

	mu       sync.RWMutex
	clients  map[string]*Client // device_id -> Client

	// dmCleanupMu serializes 1:1 DM cleanup against handleCreateDM. When
	// both parties leave a DM, handleLeaveDM holds this mutex while it
	// deletes the row + dm-<id>.db file. Concurrent handleCreateDM calls
	// fail-fast with ErrServerBusy via TryLock so the client can retry,
	// avoiding the race where dedup returns a row that is about to be
	// (or has just been) deleted.
	dmCleanupMu sync.Mutex

	// adminKickStop signals the admin-kick processor goroutine to stop.
	// Closed by Close() during shutdown. The processor polls
	// pending_admin_kicks every adminKickPollInterval and dispatches
	// each row through performGroupLeave so the kicked user and the
	// remaining group members get live group_left / group_event echoes.
	adminKickStop chan struct{}

	// roomRetirementStop signals the room retirement processor goroutine
	// to stop. Closed by Close() during shutdown. The processor polls
	// pending_room_retirements every roomRetirementPollInterval and
	// broadcasts room_retired to connected members for each queued row.
	// Parallel to adminKickStop — same pattern for the same reason (no
	// IPC between sshkey-ctl and sshkey-server, table is the bridge).
	// Phase 12.
	roomRetirementStop chan struct{}
}

// adminKickPollInterval is how often the admin-kick processor checks
// the pending_admin_kicks queue. Five seconds is fine for an emergency
// moderation action — the kick takes effect at the data layer
// immediately (CLI mutates group_members directly), this just
// determines how soon the affected sessions see the live notification.
const adminKickPollInterval = 5 * time.Second

// roomRetirementPollInterval is how often the room retirement
// processor checks the pending_room_retirements queue. Same rationale
// as adminKickPollInterval — the retirement takes effect at the data
// layer immediately (CLI mutates rooms.db directly via SetRoomRetired),
// and this polling interval just determines the live-notification
// latency for connected members. Five seconds matches the admin kick
// processor for consistency.
const roomRetirementPollInterval = 5 * time.Second

// New creates a new server with the given config and data directory.
func New(cfg *config.Config, logger *slog.Logger, dataDir ...string) (*Server, error) {
	dir := ""
	if len(dataDir) > 0 {
		dir = dataDir[0]
	}

	s := &Server{
		cfg:                cfg,
		logger:             logger,
		epochs:             newEpochManager(),
		limiter:            newRateLimiter(),
		clients:            make(map[string]*Client),
		dataDir:            dir,
		adminKickStop:      make(chan struct{}),
		roomRetirementStop: make(chan struct{}),
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

		// Seed rooms.db from rooms.toml on first run
		if st.RoomsDBEmpty() && cfg.Rooms != nil {
			count, err := st.SeedRooms(cfg.Rooms)
			if err != nil {
				return nil, fmt.Errorf("seed rooms: %w", err)
			}
			if count > 0 {
				logger.Info("seeded rooms.db from rooms.toml", "rooms", count)
			}
		}

		// Seed room_members from users.toml on first run (after rooms are seeded)
		if st.RoomMembersEmpty() && cfg.Users != nil {
			count, err := st.SeedRoomMembers(cfg.Users)
			if err != nil {
				return nil, fmt.Errorf("seed room members: %w", err)
			}
			if count > 0 {
				logger.Info("seeded room_members from users.toml", "memberships", count)
			}
		}

		// Seed users.db from users.toml on first run
		if st.UsersDBEmpty() && cfg.Users != nil {
			count, err := st.SeedUsers(cfg.Users)
			if err != nil {
				return nil, fmt.Errorf("seed users: %w", err)
			}
			if count > 0 {
				logger.Info("seeded users.db from users.toml", "users", count)
			}
		}

		// Remove orphan files from crashed uploads (files on disk with
		// no hash record in the DB — they never completed successfully)
		s.cleanOrphanFiles()
	}

	// Initialize push relay (nil if not configured)
	s.push = push.NewRelay(cfg.Server.Push, logger)

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

	// Start the admin-kick processor — this is the bridge between the
	// CLI's pending_admin_kicks queue and the server's live broadcast
	// surface. Polls every adminKickPollInterval and dispatches each
	// queued kick through performGroupLeave.
	go s.runAdminKickProcessor()

	// Start the room retirement processor — Phase 12 parallel to the
	// admin kick processor. Polls pending_room_retirements every
	// roomRetirementPollInterval and broadcasts room_retired to
	// connected members of each newly-retired room. On startup, runs
	// one immediate consume pass before entering the ticker loop to
	// handle any rows that were queued while the server was down.
	s.processPendingRoomRetirements()
	go s.runRoomRetirementProcessor()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.listener == nil {
				return nil // shutdown
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}

		// Connection rate limiting per IP
		remoteIP := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(remoteIP); err == nil {
			remoteIP = host
		}
		connLimit := s.cfg.Server.RateLimits.ConnectionsPerMinute
		if connLimit == 0 {
			connLimit = 10
		}
		if !s.limiter.allowPerMinute("conn:"+remoteIP, connLimit) {
			s.logger.Warn("connection rate limited", "ip", remoteIP)
			conn.Close()
			continue
		}

		go s.handleConnection(conn)
	}
}

// Close shuts down the server gracefully.
// Store returns the underlying Store. Used by tests that need to seed
// or inspect persistent state directly without going through the
// protocol surface.
func (s *Server) Store() *store.Store {
	return s.store
}

func (s *Server) Close() error {
	// Audit
	if s.audit != nil {
		s.mu.RLock()
		clientCount := len(s.clients)
		s.mu.RUnlock()
		s.audit.Log("server", "shutdown", fmt.Sprintf("clients=%d", clientCount))
	}

	// Stop accepting new connections
	var firstErr error
	if s.listener != nil {
		ln := s.listener
		s.listener = nil
		if err := ln.Close(); err != nil {
			firstErr = err
		}
	}

	// Stop the admin-kick processor goroutine
	if s.adminKickStop != nil {
		select {
		case <-s.adminKickStop:
			// already closed
		default:
			close(s.adminKickStop)
		}
	}

	// Stop the room retirement processor goroutine
	if s.roomRetirementStop != nil {
		select {
		case <-s.roomRetirementStop:
			// already closed
		default:
			close(s.roomRetirementStop)
		}
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

	// Wait grace period for in-flight operations
	gracePeriod := 10 * time.Second
	if s.cfg.Server.Shutdown.GracePeriod != "" {
		if d, err := time.ParseDuration(s.cfg.Server.Shutdown.GracePeriod); err == nil {
			gracePeriod = d
		}
	}
	s.logger.Info("waiting for grace period", "duration", gracePeriod)
	time.Sleep(gracePeriod)

	// Close store (flushes WAL)
	if s.store != nil {
		if err := s.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// authenticateKey validates an SSH public key against users.db.
// Only Ed25519 keys are accepted.
func (s *Server) authenticateKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// Failed auth rate limiting per IP
	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}
	authLimit := s.cfg.Server.RateLimits.FailedAuthPerMinute
	if authLimit == 0 {
		authLimit = 5
	}
	if !s.limiter.allowPerMinute("auth:"+remoteIP, authLimit) {
		return nil, fmt.Errorf("too many authentication attempts")
	}

	if key.Type() != "ssh-ed25519" {
		s.logger.Warn("rejected non-Ed25519 key",
			"type", key.Type(),
			"remote", conn.RemoteAddr().String(),
		)
		return nil, fmt.Errorf("only Ed25519 keys are supported, got %s", key.Type())
	}

	// Look up user by SSH public key in users.db
	pubKeyStr := string(ssh.MarshalAuthorizedKey(key))
	pubKeyStr = strings.TrimSpace(pubKeyStr) // strip trailing newline

	if s.store != nil {
		userID := s.store.GetUserByKey(pubKeyStr)
		if userID != "" {
			if s.store.IsUserRetired(userID) {
				user := s.store.GetUserByID(userID)
				s.logger.Info("rejected retired account login",
					"user", userID,
					"fingerprint", ssh.FingerprintSHA256(key),
					"remote", conn.RemoteAddr().String(),
					"retired_at", user.RetiredAt,
					"retired_reason", user.RetiredReason,
				)
				return nil, fmt.Errorf("account retired")
			}
			s.logger.Info("key authenticated",
				"user", userID,
				"fingerprint", ssh.FingerprintSHA256(key),
				"remote", conn.RemoteAddr().String(),
			)
			return &ssh.Permissions{
				Extensions: map[string]string{
					"username": userID,
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
// Only notifies the admin on the first attempt — repeat attempts just update the counter.
func (s *Server) logPendingKey(fingerprint, remote string) {
	isFirstAttempt := true

	if s.store != nil {
		// Check if this key has been seen before
		var existing int
		s.store.DataDB().QueryRow(
			`SELECT attempts FROM pending_keys WHERE fingerprint = ?`,
			fingerprint).Scan(&existing)
		if existing > 0 {
			isFirstAttempt = false
		}

		// Upsert — increment attempt counter
		s.store.DataDB().Exec(`
			INSERT INTO pending_keys (fingerprint, remote_addr)
			VALUES (?, ?)
			ON CONFLICT (fingerprint) DO UPDATE SET
				attempts = attempts + 1,
				last_seen = datetime('now'),
				remote_addr = excluded.remote_addr`,
			fingerprint, remote)

		// Only notify admin on first attempt
		if isFirstAttempt {
			var firstSeen string
			s.store.DataDB().QueryRow(
				`SELECT first_seen FROM pending_keys WHERE fingerprint = ?`,
				fingerprint).Scan(&firstSeen)

			s.notifyAdmins(protocol.AdminNotify{
				Type:        "admin_notify",
				Event:       "pending_key",
				Fingerprint: fingerprint,
				Attempts:    1,
				FirstSeen:   firstSeen,
			})

			// Append to flat log file only on first attempt
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
	}
}

// notifyAdmins sends a message to all connected admin clients.
func (s *Server) notifyAdmins(msg any) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if s.store != nil && s.store.IsAdmin(client.UserID) {
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

	userID := sshConn.Permissions.Extensions["username"]
	s.logger.Info("connect",
		"user", userID,
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

	// Handle channels:
	//   Channel 1 = NDJSON protocol
	//   Channel 2 = downloads (server writes file bytes here)
	//   Channel 3 = uploads   (server reads file bytes here)
	// Download and upload are split onto separate SSH channels so a large
	// upload doesn't block concurrent downloads (and vice versa). The
	// download channel is handed to handleSession so handleDownload can
	// write to client.DownloadChannel.
	dlChanCh := make(chan ssh.Channel, 1)
	channelNum := 0
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, chReqs, err := newCh.Accept()
		if err != nil {
			s.logger.Error("channel accept failed", "user", userID, "error", err)
			continue
		}
		go ssh.DiscardRequests(chReqs)

		channelNum++
		switch channelNum {
		case 1:
			// Channel 1: NDJSON protocol
			go s.handleSession(userID, sshConn, ch, dlChanCh)
		case 2:
			// Channel 2: downloads — server writes here; no reader needed
			dlChanCh <- ch
		case 3:
			// Channel 3: uploads — server reads upload frames here
			go s.handleBinaryChannel(userID, ch)
		default:
			ch.Close()
		}
	}

	s.logger.Info("disconnect",
		"user", userID,
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
