package telephony

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/outbox"
)

const (
	quoLegacySignatureHeader   = "openphone-signature"
	quoStandardIDHeader        = "webhook-id"
	quoStandardTimestampHeader = "webhook-timestamp"
	quoStandardSignatureHeader = "webhook-signature"
)

// Quo reads Quo (formerly OpenPhone) webhooks: call.completed,
// message.received and message.delivered. It verifies both Standard Webhooks
// signatures (secret "whsec_<base64>") and the legacy openphone-signature
// header (secret is the base64 key).
type Quo struct {
	clock clock.Clock
}

var _ Provider = (*Quo)(nil)

// NewQuo uses clk for the replay window; a nil clk means the system clock.
func NewQuo(clk clock.Clock) *Quo { return &Quo{clock: clk} }

func (p *Quo) Name() string { return "quo" }

func (p *Quo) Ack() (string, string) { return "application/json", `{"ok":true}` }

type quoEvent struct {
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID           string          `json:"id"`
			Direction    string          `json:"direction"`
			From         string          `json:"from"`
			To           json.RawMessage `json:"to"`
			Participants []string        `json:"participants"`
			CreatedAt    time.Time       `json:"createdAt"`
			AnsweredAt   *time.Time      `json:"answeredAt"`
			CompletedAt  *time.Time      `json:"completedAt"`
			Media        []struct {
				URL string `json:"url"`
			} `json:"media"`
			Voicemail *struct {
				URL string `json:"url"`
			} `json:"voicemail"`
		} `json:"object"`
	} `json:"data"`
}

func (p *Quo) Events(webhook Webhook, signingSecret string) ([]Event, error) {
	if err := p.verify(webhook, signingSecret); err != nil {
		return nil, err
	}
	var payload quoEvent
	if err := json.Unmarshal(webhook.Body, &payload); err != nil {
		return nil, fmt.Errorf("%w: quo payload: %v", ErrPayload, err)
	}
	obj := payload.Data.Object
	event := Event{ExternalID: obj.ID, From: obj.From, At: obj.CreatedAt}
	switch payload.Type {
	case "call.completed":
		event.Kind = KindCall
		if obj.AnsweredAt != nil && obj.CompletedAt != nil && !obj.CompletedAt.Before(*obj.AnsweredAt) {
			event.Answered = true
			event.Duration = obj.CompletedAt.Sub(*obj.AnsweredAt).Truncate(time.Second)
		}
		if len(obj.Media) > 0 {
			event.RecordingURL = obj.Media[0].URL
		} else if obj.Voicemail != nil {
			event.RecordingURL = obj.Voicemail.URL
		}
	case "message.received":
		event.Kind, event.MessageStatus = KindMessage, MessageReceived
	case "message.delivered":
		event.Kind, event.MessageStatus = KindMessage, MessageDelivered
	default:
		return nil, nil
	}
	switch obj.Direction {
	case "incoming":
		event.Direction = DirectionInbound
	case "outgoing":
		event.Direction = DirectionOutbound
	default:
		return nil, fmt.Errorf("%w: quo %s has direction %q", ErrPayload, payload.Type, obj.Direction)
	}
	to, err := quoFirstNumber(obj.To)
	if err != nil {
		return nil, err
	}
	event.To = to
	if event.Kind == KindCall && len(obj.Participants) > 0 {
		if event.Direction == DirectionInbound {
			event.From = obj.Participants[0]
		} else {
			event.To = obj.Participants[0]
		}
	}
	if obj.ID == "" || event.Counterpart() == "" {
		return nil, fmt.Errorf("%w: quo %s without an id or number", ErrPayload, payload.Type)
	}
	if event.At.IsZero() {
		event.At = p.now()
	}
	return []Event{event}, nil
}

func (p *Quo) verify(webhook Webhook, signingSecret string) error {
	if signature := webhook.Header.Get(quoStandardSignatureHeader); signature != "" {
		return p.verifyStandard(webhook, signature, signingSecret)
	}
	return p.verifyLegacy(webhook, signingSecret)
}

func (p *Quo) verifyStandard(webhook Webhook, signature, signingSecret string) error {
	if err := checkSize(webhook, signature); err != nil {
		return err
	}
	id := webhook.Header.Get(quoStandardIDHeader)
	timestamp := webhook.Header.Get(quoStandardTimestampHeader)
	if id == "" || strings.Contains(id, ".") || timestamp == "" {
		return fmt.Errorf("%w: malformed standard webhook headers", ErrSignature)
	}
	if !strings.HasPrefix(signingSecret, "whsec_") {
		return fmt.Errorf("%w: standard webhook secret has no whsec_ prefix", ErrSignature)
	}
	if err := outbox.VerifyWebhookSignature(signingSecret, id, timestamp, webhook.Body, signature, config.Config().TelephonySignatureTolerance, p.now()); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// verifyLegacy checks "hmac;1;<unix ms>;<base64 HMAC-SHA256(key, ms + "." + body)>".
func (p *Quo) verifyLegacy(webhook Webhook, signingSecret string) error {
	header := webhook.Header.Get(quoLegacySignatureHeader)
	if err := checkSize(webhook, header); err != nil {
		return err
	}
	parts := strings.Split(header, ";")
	if len(parts) != 4 || parts[0] != "hmac" || parts[1] != "1" {
		return fmt.Errorf("%w: malformed %s header", ErrSignature, quoLegacySignatureHeader)
	}
	key, err := base64.StdEncoding.DecodeString(signingSecret)
	if err != nil || len(key) == 0 {
		return fmt.Errorf("%w: quo signing key is not base64", ErrSignature)
	}
	sentMs, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: timestamp %q", ErrSignature, parts[2])
	}
	// telephony_signature_tolerance applies both ways: too old is a replay, too new a forgery.
	if age, tolerance := p.now().Sub(time.UnixMilli(sentMs)), config.Config().TelephonySignatureTolerance; age > tolerance || age < -tolerance {
		return fmt.Errorf("%w: timestamp outside tolerance", ErrSignature)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[2] + "."))
	mac.Write(webhook.Body)
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(strings.TrimSpace(parts[3]))) {
		return ErrSignature
	}
	return nil
}

func (p *Quo) now() time.Time {
	if p.clock == nil {
		return time.Now()
	}
	return p.clock.Now()
}

// quoFirstNumber reads "to", a number for a call and a list for a message.
func quoFirstNumber(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return "", fmt.Errorf("%w: quo \"to\" is neither a number nor a list", ErrPayload)
	}
	if len(many) == 0 {
		return "", nil
	}
	return many[0], nil
}
