// Package push implements APNs and FCM push notification senders.
// Push notifications are content-free wake signals — the app connects
// via SSH, syncs, and shows a local notification with real content.
package push

import (
	"log/slog"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// Sender sends a push notification to a device token.
type Sender interface {
	// Send sends a content-free wake push to the given token.
	// Returns true if the token is still valid, false if it should be deactivated.
	Send(token string) (valid bool, err error)

	// Platform returns "ios" or "android".
	Platform() string
}

// Relay manages push notification delivery.
type Relay struct {
	senders map[string]Sender // platform -> sender
	logger  *slog.Logger
}

// NewRelay creates a push relay from config. Returns nil if push is not configured.
func NewRelay(cfg config.PushSection, logger *slog.Logger) *Relay {
	senders := make(map[string]Sender)

	if cfg.APNs.Enabled {
		apns, err := NewAPNsSender(cfg.APNs, logger)
		if err != nil {
			logger.Error("failed to init APNs", "error", err)
		} else {
			senders["ios"] = apns
			logger.Info("APNs push enabled", "bundle", cfg.APNs.BundleID)
		}
	}

	if cfg.FCM.Enabled {
		fcm, err := NewFCMSender(cfg.FCM, logger)
		if err != nil {
			logger.Error("failed to init FCM", "error", err)
		} else {
			senders["android"] = fcm
			logger.Info("FCM push enabled", "project", cfg.FCM.ProjectID)
		}
	}

	if len(senders) == 0 {
		return nil
	}

	return &Relay{
		senders: senders,
		logger:  logger,
	}
}

// SendWake sends a content-free push to the given platform and token.
// Returns true if the token is valid.
func (r *Relay) SendWake(platform, token string) (bool, error) {
	sender, ok := r.senders[platform]
	if !ok {
		return false, nil
	}
	return sender.Send(token)
}

// HasPlatform returns true if the relay has a sender for the given platform.
func (r *Relay) HasPlatform(platform string) bool {
	_, ok := r.senders[platform]
	return ok
}
