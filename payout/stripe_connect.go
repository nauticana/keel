package payout

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nauticana/keel/logger"
)

// StripeConnectProvider implements PayoutProvider against Stripe
// Connect. Connected accounts are Express type; the application hands
// the user Stripe's hosted-onboarding URL and Stripe posts back via
// account.updated when `details_submitted=true` and `payouts_enabled=true`.
//
// This is a partial implementation: webhook signature verification is
// wired (Stripe-Signature: t=...,v1=...) and event mapping is in place,
// but StartOnboarding + RequestInstantPayout are not yet wired against
// the Stripe API. Both return ErrNotImplemented; wire them when the
// Stripe Connect contract is live.
type StripeConnectProvider struct {
	apiKey        string
	webhookSecret string
	journal       logger.ApplicationLogger
}

const stripeConnectCode = "SC"

func NewStripeConnectProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*StripeConnectProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("stripe connect: API key is required")
	}
	return &StripeConnectProvider{apiKey: apiKey, webhookSecret: webhookSecret, journal: journal}, nil
}

func (p *StripeConnectProvider) Code() string { return stripeConnectCode }

func (p *StripeConnectProvider) StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error) {
	return nil, ErrNotImplemented
}

func (p *StripeConnectProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	return nil, ErrNotImplemented
}

type stripeWebhookEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID               string `json:"id"`
			DetailsSubmitted bool   `json:"details_submitted"`
			ChargesEnabled   bool   `json:"charges_enabled"`
			PayoutsEnabled   bool   `json:"payouts_enabled"`
		} `json:"object"`
	} `json:"data"`
}

func (p *StripeConnectProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	header := firstHeader(headers, "stripe-signature")
	if header == "" {
		return nil, fmt.Errorf("stripe connect: missing Stripe-Signature header")
	}
	if p.webhookSecret == "" {
		return nil, fmt.Errorf("stripe connect: webhook secret not configured")
	}
	ts, sig, err := parseStripeSignature(header)
	if err != nil {
		return nil, fmt.Errorf("stripe connect: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(p.webhookSecret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, fmt.Errorf("stripe connect: invalid signature")
	}

	var ev stripeWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("stripe connect: parse: %w", err)
	}
	mapped, ok := mapStripeEvent(ev.Type, ev.Data.Object.DetailsSubmitted && ev.Data.Object.PayoutsEnabled)
	if !ok {
		return nil, fmt.Errorf("stripe connect: unhandled event %q", ev.Type)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: ev.Data.Object.ID,
		Activated:         ev.Data.Object.DetailsSubmitted && ev.Data.Object.PayoutsEnabled,
		RawEventID:        ev.ID,
	}, nil
}

func parseStripeSignature(header string) (ts, sig string, err error) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sig = kv[1]
		}
	}
	if ts == "" || sig == "" {
		return "", "", fmt.Errorf("malformed Stripe-Signature header")
	}
	return ts, sig, nil
}

func mapStripeEvent(name string, fullyActivated bool) (PayoutWebhookEventType, bool) {
	switch name {
	case "account.created":
		return PayoutEventAccountCreated, true
	case "account.updated":
		if fullyActivated {
			return PayoutEventAccountActivated, true
		}
		return PayoutEventAccountUpdated, true
	case "account.application.deauthorized":
		return PayoutEventAccountRejected, true
	}
	return "", false
}

var _ PayoutProvider = (*StripeConnectProvider)(nil)
