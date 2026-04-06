package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// APNsSender sends push notifications via Apple Push Notification service.
type APNsSender struct {
	key      *ecdsa.PrivateKey
	keyID    string
	teamID   string
	bundleID string
	endpoint string
	client   *http.Client
	logger   *slog.Logger

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewAPNsSender creates an APNs sender from config.
func NewAPNsSender(cfg config.APNsConfig, logger *slog.Logger) (*APNsSender, error) {
	keyData, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read APNs key: %w", err)
	}

	key, err := parseAPNsKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse APNs key: %w", err)
	}

	endpoint := "https://api.push.apple.com"
	if cfg.Sandbox {
		endpoint = "https://api.sandbox.push.apple.com"
	}

	return &APNsSender{
		key:      key,
		keyID:    cfg.KeyID,
		teamID:   cfg.TeamID,
		bundleID: cfg.BundleID,
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		logger:   logger,
	}, nil
}

func (a *APNsSender) Platform() string { return "ios" }

// Send sends a content-free background push to the given device token.
func (a *APNsSender) Send(token string) (bool, error) {
	jwt, err := a.getJWT()
	if err != nil {
		return true, fmt.Errorf("generate JWT: %w", err)
	}

	// Content-available push — wakes the app without showing a notification
	payload := map[string]any{
		"aps": map[string]any{
			"content-available": 1,
		},
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/3/device/%s", a.endpoint, token)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return true, err
	}

	req.Header.Set("Authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", a.bundleID)
	req.Header.Set("apns-push-type", "background")
	req.Header.Set("apns-priority", "5") // low priority for background

	resp, err := a.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("APNs request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case 200:
		return true, nil
	case 410:
		// Gone — token is no longer valid
		a.logger.Info("APNs token expired", "token", token[:8]+"...")
		return false, nil
	case 400:
		a.logger.Warn("APNs bad request", "token", token[:8]+"...", "status", resp.StatusCode)
		return false, nil
	default:
		a.logger.Warn("APNs error", "status", resp.StatusCode, "token", token[:8]+"...")
		return true, fmt.Errorf("APNs status %d", resp.StatusCode)
	}
}

// getJWT returns a cached or fresh JWT for APNs authentication.
// APNs JWTs are valid for 1 hour; we refresh at 50 minutes.
func (a *APNsSender) getJWT() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Before(a.tokenExp) {
		return a.token, nil
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:   a.teamID,
		IssuedAt: jwt.NewNumericDate(now),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = a.keyID

	signed, err := t.SignedString(a.key)
	if err != nil {
		return "", err
	}

	a.token = signed
	a.tokenExp = now.Add(50 * time.Minute)
	return signed, nil
}

// parseAPNsKey parses a .p8 PKCS#8 private key file.
func parseAPNsKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}

	return ecKey, nil
}
