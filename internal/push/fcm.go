package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// FCMSender sends push notifications via Firebase Cloud Messaging v1 API.
type FCMSender struct {
	projectID  string
	serviceKey *rsa.PrivateKey
	clientEmail string
	endpoint   string
	client     *http.Client
	logger     *slog.Logger

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// serviceAccount represents the relevant fields from a Firebase service account JSON.
type serviceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	TokenURI    string `json:"token_uri"`
}

// NewFCMSender creates an FCM sender from config.
func NewFCMSender(cfg config.FCMConfig, logger *slog.Logger) (*FCMSender, error) {
	data, err := os.ReadFile(cfg.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("read FCM credentials: %w", err)
	}

	var sa serviceAccount
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("parse FCM credentials: %w", err)
	}

	key, err := parseRSAKey([]byte(sa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse FCM private key: %w", err)
	}

	projectID := cfg.ProjectID
	if projectID == "" {
		projectID = sa.ProjectID
	}

	return &FCMSender{
		projectID:   projectID,
		serviceKey:  key,
		clientEmail: sa.ClientEmail,
		endpoint:    fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", projectID),
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
	}, nil
}

func (f *FCMSender) Platform() string { return "android" }

// Send sends a data-only push (no notification) to wake the app.
func (f *FCMSender) Send(token string) (bool, error) {
	accessToken, err := f.getAccessToken()
	if err != nil {
		return true, fmt.Errorf("get access token: %w", err)
	}

	// Data-only message — no notification field, app handles display
	msg := map[string]any{
		"message": map[string]any{
			"token": token,
			"data": map[string]string{
				"type": "sync",
			},
		},
	}

	body, _ := json.Marshal(msg)

	req, err := http.NewRequest("POST", f.endpoint, bytes.NewReader(body))
	if err != nil {
		return true, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("FCM request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return true, nil
	}

	// Check for unregistered token
	var errResp struct {
		Error struct {
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	json.Unmarshal(respBody, &errResp)
	for _, d := range errResp.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			f.logger.Info("FCM token unregistered", "token", token[:8]+"...")
			return false, nil
		}
	}

	f.logger.Warn("FCM error", "status", resp.StatusCode, "body", string(respBody))
	return true, fmt.Errorf("FCM status %d", resp.StatusCode)
}

// getAccessToken returns a cached or fresh OAuth2 access token.
// Uses JWT to request a token from Google's OAuth2 endpoint.
func (f *FCMSender) getAccessToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.token != "" && time.Now().Before(f.tokenExp) {
		return f.token, nil
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    f.clientEmail,
		Audience:  jwt.ClaimStrings{"https://oauth2.googleapis.com/token"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}

	// Add scope claim
	type scopedClaims struct {
		jwt.RegisteredClaims
		Scope string `json:"scope"`
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, scopedClaims{
		RegisteredClaims: claims,
		Scope:            "https://www.googleapis.com/auth/firebase.messaging",
	})

	signed, err := t.SignedString(f.serviceKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	// Exchange JWT for access token
	payload := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s", signed)
	resp, err := f.client.Post(
		"https://oauth2.googleapis.com/token",
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(payload),
	)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	f.token = tokenResp.AccessToken
	// Refresh at 50 minutes (tokens last 60)
	f.tokenExp = now.Add(50 * time.Minute)
	return f.token, nil
}

func parseRSAKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaKey, nil
}
