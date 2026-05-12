package payout

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"

	"github.com/nauticana/keel/logger"
)

// WiseProvider implements PayoutProvider against Wise Platform. Wise
// (formerly TransferWise) uses recipient accounts rather than connected
// accounts; KYC for the recipient is collected via Wise's hosted
// "recipient creation" page.
//
// Like StripeConnectProvider, this is a partial impl: webhook signature
// verification + event mapping are wired (Wise uses
// X-Signature-SHA256 HMAC), but StartOnboarding and RequestInstantPayout
// return ErrNotImplemented — wire them when the Wise Platform contract
// is live.
type WiseProvider struct {
	apiKey        string
	webhookSecret string
	journal       logger.ApplicationLogger
}

const wiseCode = "WI"

func NewWiseProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*WiseProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("wise: API key is required")
	}
	return &WiseProvider{apiKey: apiKey, webhookSecret: webhookSecret, journal: journal}, nil
}

func (p *WiseProvider) Code() string { return wiseCode }

func (p *WiseProvider) StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error) {
	return nil, ErrNotImplemented
}

func (p *WiseProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	return nil, ErrNotImplemented
}

type wiseWebhookEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Data      struct {
		Resource struct {
			ID     string `json:"id"`
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"resource"`
	} `json:"data"`
}

func (p *WiseProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	sig := firstHeader(headers, "x-signature-sha256")
	if sig == "" {
		return nil, fmt.Errorf("wise: missing X-Signature-SHA256 header")
	}
	if p.webhookSecret == "" {
		return nil, fmt.Errorf("wise: webhook secret not configured")
	}
	sum := sha256.Sum256(append([]byte(p.webhookSecret), rawBody...))
	expected := fmt.Sprintf("%x", sum[:])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return nil, fmt.Errorf("wise: invalid signature")
	}

	var ev wiseWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("wise: parse: %w", err)
	}
	mapped, ok := mapWiseEvent(ev.EventType, ev.Data.Resource.Status)
	if !ok {
		return nil, fmt.Errorf("wise: unhandled event %q", ev.EventType)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: ev.Data.Resource.ID,
		Activated:         mapped == PayoutEventAccountActivated,
		RawEventID:        ev.EventID,
	}, nil
}

func mapWiseEvent(name, status string) (PayoutWebhookEventType, bool) {
	switch name {
	case "recipients#created":
		return PayoutEventAccountCreated, true
	case "recipients#updated":
		if status == "ACTIVE" {
			return PayoutEventAccountActivated, true
		}
		return PayoutEventAccountUpdated, true
	case "recipients#deleted":
		return PayoutEventAccountRejected, true
	}
	return "", false
}

var _ PayoutProvider = (*WiseProvider)(nil)
