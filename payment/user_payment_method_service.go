package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
)

// SetupIntentCardClient is the Stripe (or compatible) API hop used to
// look up card metadata (brand/last4/expiry) attached to a SetupIntent.
// Returns the card details + true when populated; false on any failure
// so callers can persist the bare provider_token even without details.
type SetupIntentCardClient interface {
	GetSetupIntentCard(ctx context.Context, setupIntentID string) (last4, brand string, expMonth, expYear int, ok bool)
}

// UserPaymentMethodService owns the two operations on basis
// user_payment_method that can't be served by abstract REST CRUD:
//
//   - SetDefault: atomic multi-row UPDATE — flips the chosen row to
//     is_default and clears every other row owned by the same user
//     in a single statement. Abstract single-row UPDATE would race
//     two-step "clear all + set one" against rapid taps.
//   - RecordFromSetupIntent: invoked by downstream PaymentEventHandler
//     impls when a Stripe (or compatible) SetupIntent.succeeded webhook
//     lands. Pulls card metadata via CardClient (optional) and inserts.
//
// List + Delete are served by keel's generic REST CRUD against the
// UserSpecific basis table — no service method needed.
//
// CardClient is optional — when nil, RecordFromSetupIntent persists the
// provider_token alone and the UI degrades to "Card on file".
type UserPaymentMethodService struct {
	DB         data.DatabaseRepository
	CardClient SetupIntentCardClient
	Journal    logger.ApplicationLogger
}

const (
	qUPMInsert     = "qUPMInsert"
	qUPMSetDefault = "qUPMSetDefault"
)

var userPaymentMethodQueries = map[string]string{
	qUPMInsert: `
INSERT INTO user_payment_method
 (id, user_id, method_type, provider, provider_token, last_four, brand,
  expiry_month, expiry_year, currency, is_default, created_at)
VALUES
 (nextval('user_payment_method_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, CURRENT_TIMESTAMP)`,

	// Atomic "flip the chosen row to default, clear every other row" —
	// avoids the racy two-step clear-then-set pattern. The user_id pin
	// makes cross-user attempts a no-op.
	qUPMSetDefault: `
UPDATE user_payment_method
   SET is_default = (id = ?)
 WHERE user_id = ?`,
}

// SetDefault flips the chosen row to default and clears every other
// row in the same UPDATE. Passing a non-owned methodID just clears the
// caller's existing default — no side-channel signal about other users.
func (s *UserPaymentMethodService) SetDefault(ctx context.Context, userID int, methodID int64) error {
	qs := s.DB.GetQueryService(ctx, userPaymentMethodQueries)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	if _, err := qs.Query(ctx, qUPMSetDefault, methodID, userID); err != nil {
		return fmt.Errorf("set default user payment method: %w", err)
	}
	return nil
}

// RecordFromSetupIntent persists a new row from a Stripe (or compatible)
// SetupIntent succeeded event. The provider name is taken from the
// PaymentEvent.Provider; provider_token holds the SetupIntent id (the
// reusable handle for future PaymentIntents). When CardClient is wired
// the row also carries card metadata; otherwise it lands with just the
// token and the UI shows "Card on file".
//
// userID is supplied by the caller — typically extracted from the
// PaymentEvent.Metadata["user_id"] field that keel auto-injects on
// checkout-session creation. method_type defaults to "card" since
// SetupIntent flows are card-flow today.
func (s *UserPaymentMethodService) RecordFromSetupIntent(ctx context.Context, userID int, provider, setupIntentID, currency string) error {
	if userID <= 0 {
		return fmt.Errorf("RecordFromSetupIntent: userID required")
	}
	if setupIntentID == "" {
		return fmt.Errorf("RecordFromSetupIntent: setupIntentID required")
	}
	if currency == "" {
		currency = "USD"
	}
	last4, brand, expMonth, expYear := "", "", 0, 0
	if s.CardClient != nil {
		l, b, m, y, ok := s.CardClient.GetSetupIntentCard(ctx, setupIntentID)
		if ok {
			last4, brand, expMonth, expYear = l, b, m, y
		}
	}
	qs := s.DB.GetQueryService(ctx, userPaymentMethodQueries)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	if _, err := qs.Query(ctx, qUPMInsert,
		userID, "card", provider, setupIntentID, last4, brand, expMonth, expYear, currency,
	); err != nil {
		return fmt.Errorf("insert user_payment_method: %w", err)
	}
	return nil
}

// StripeSetupIntentCardClient is a thin adapter that wraps the keel
// StripeCheckoutClient.Get helper into the SetupIntentCardClient port.
// Use this when wiring UserPaymentMethodService against the keel
// Stripe client (matches what a consuming app's payment service used to do
// inline).
type StripeSetupIntentCardClient struct {
	Client interface {
		Get(ctx context.Context, path string, params url.Values) ([]byte, error)
	}
	Journal logger.ApplicationLogger
}

func (c *StripeSetupIntentCardClient) GetSetupIntentCard(ctx context.Context, setupIntentID string) (last4, brand string, expMonth, expYear int, ok bool) {
	if c.Client == nil {
		return
	}
	body, err := c.Client.Get(ctx, "/setup_intents/"+setupIntentID, url.Values{"expand[]": {"payment_method"}})
	if err != nil {
		if c.Journal != nil {
			c.Journal.Error("stripe setup_intent fetch: " + err.Error())
		}
		return
	}
	var parsed struct {
		PaymentMethod struct {
			Card struct {
				Last4    string `json:"last4"`
				Brand    string `json:"brand"`
				ExpMonth int    `json:"exp_month"`
				ExpYear  int    `json:"exp_year"`
			} `json:"card"`
		} `json:"payment_method"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		if c.Journal != nil {
			c.Journal.Error("stripe setup_intent fetch: parse: " + err.Error())
		}
		return
	}
	cd := parsed.PaymentMethod.Card
	return cd.Last4, cd.Brand, cd.ExpMonth, cd.ExpYear, true
}
