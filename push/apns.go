package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/user"
)

const (
	apnsHost        = "https://api.push.apple.com"
	apnsSandboxHost = "https://api.sandbox.push.apple.com"
)

// APNsPushProvider delivers to raw APNs device tokens over HTTP/2 using
// token-based auth (.p8 key). Tokens Apple reports as gone are revoked.
type APNsPushProvider struct {
	client   *http.Client
	host     string
	keyID    string
	teamID   string
	bundleID string
	key      *ecdsa.PrivateKey
	tokenTTL time.Duration
	users    user.UserService
	journal  logger.ApplicationLogger

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

// NewAPNs reads the .p8 PEM from the secret named by apns_key_secret and
// the key / team / bundle ids from config.
func NewAPNs(ctx context.Context, secrets secret.SecretProvider, users user.UserService, journal logger.ApplicationLogger) (*APNsPushProvider, error) {
	cfg := config.Config()
	if cfg.APNsKeyID == "" || cfg.APNsTeamID == "" || cfg.APNsBundleID == "" {
		return nil, errors.New("push: apns_key_id, apns_team_id and apns_bundle_id are required")
	}
	if secrets == nil {
		return nil, errors.New("push: apns requires a secret provider")
	}
	pem, err := secrets.GetSecret(ctx, cfg.APNsKeySecret)
	if err != nil {
		return nil, fmt.Errorf("push: read secret %q: %w", cfg.APNsKeySecret, err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(pem))
	if err != nil {
		return nil, fmt.Errorf("push: parse APNs key: %w", err)
	}
	host := apnsHost
	if cfg.APNsSandbox {
		host = apnsSandboxHost
	}
	return &APNsPushProvider{
		client:   &http.Client{Timeout: 10 * time.Second},
		host:     host,
		keyID:    cfg.APNsKeyID,
		teamID:   cfg.APNsTeamID,
		bundleID: cfg.APNsBundleID,
		key:      key,
		tokenTTL: cfg.APNsTokenTTL,
		users:    users,
		journal:  journal,
	}, nil
}

func (p *APNsPushProvider) Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error {
	devices, err := p.users.ListActiveDeviceTokens(userID)
	if err != nil {
		return fmt.Errorf("push: list tokens for user %d: %w", userID, err)
	}
	return p.sendTokens(ctx, userID, devices, title, body, data)
}

func (p *APNsPushProvider) sendTokens(ctx context.Context, userID int, devices []model.DeviceToken, title, body string, data map[string]string) error {
	if len(devices) == 0 {
		return nil
	}
	payload, err := apnsPayload(title, body, data)
	if err != nil {
		return err
	}
	delivered, revoked := 0, 0
	var firstErr error
	for _, d := range devices {
		stale, err := p.post(ctx, d.Token, payload)
		switch {
		case err == nil:
			delivered++
		case stale:
			if revokeErr := p.users.RevokeDeviceToken(userID, d.Token); revokeErr != nil && p.journal != nil {
				p.journal.Info(fmt.Sprintf("push: failed to deactivate stale token for user %d: %v", userID, revokeErr))
			}
			revoked++
		default:
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if p.journal != nil {
		if revoked > 0 {
			p.journal.Info(fmt.Sprintf("push: deactivated %d stale APNs token(s) for user %d", revoked, userID))
		}
		p.journal.Info(fmt.Sprintf("push: APNs sent to user %d (%d/%d delivered)", userID, delivered, len(devices)))
	}
	return firstErr
}

// Send delivers to one explicit device token; stale tokens surface as an error.
func (p *APNsPushProvider) Send(ctx context.Context, to, title, body string, data map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	payload, err := apnsPayload(title, body, data)
	if err != nil {
		return err
	}
	_, err = p.post(ctx, to, payload)
	return err
}

// post returns stale=true when Apple says the token will never deliver again
// (410 Unregistered, or 400 BadDeviceToken / DeviceTokenNotForTopic).
func (p *APNsPushProvider) post(ctx context.Context, deviceToken string, payload []byte) (stale bool, err error) {
	bearer, err := p.providerToken()
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.host+"/3/device/"+deviceToken, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("authorization", "bearer "+bearer)
	req.Header.Set("apns-topic", p.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("push: APNs request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return false, nil
	}
	var apple struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&apple)
	stale = resp.StatusCode == http.StatusGone ||
		apple.Reason == "BadDeviceToken" || apple.Reason == "DeviceTokenNotForTopic"
	return stale, fmt.Errorf("push: APNs %d %s", resp.StatusCode, apple.Reason)
}

func (p *APNsPushProvider) providerToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Since(p.issuedAt) < p.tokenTTL {
		return p.token, nil
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": p.teamID, "iat": now.Unix()})
	tok.Header["kid"] = p.keyID
	signed, err := tok.SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("push: sign APNs token: %w", err)
	}
	p.token, p.issuedAt = signed, now
	return signed, nil
}

// apnsPayload builds {"aps":{"alert":{title,body},"sound":"default"}, data...}.
// Custom keys sit beside "aps" so the app reads them from userInfo.
func apnsPayload(title, body string, data map[string]string) ([]byte, error) {
	payload := make(map[string]any, len(data)+1)
	for k, v := range data {
		if k != "aps" {
			payload[k] = v
		}
	}
	payload["aps"] = map[string]any{
		"alert": map[string]string{"title": title, "body": body},
		"sound": "default",
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("push: encode APNs payload: %w", err)
	}
	return out, nil
}

var (
	_ port.MessageDispatcher = (*APNsPushProvider)(nil)
	_ tokenSender            = (*APNsPushProvider)(nil)
)
