package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// payment_method_type codes for a saved card; the wallet ones mark a
// wallet-tokenized card.
const (
	MethodTypeCard      = "card"
	MethodTypeWallet    = "wallet"
	MethodTypeApplePay  = "apple_pay"
	MethodTypeGooglePay = "google_pay"
)

// SavedCard is the card metadata attached to a SetupIntent.
type SavedCard struct {
	MethodType string
	Last4      string
	Brand      string
	ExpMonth   int
	ExpYear    int
}

// SetupIntentCardClient looks up the card attached to a SetupIntent; ok is
// false on any failure so callers can persist the bare provider_token.
type SetupIntentCardClient interface {
	GetSetupIntentCard(ctx context.Context, setupIntentID string) (card SavedCard, ok bool)
}

// ErrPaymentMethodNotFound: no saved method with that id belongs to the user.
var ErrPaymentMethodNotFound = errors.New("payment: saved payment method not found")

// UserPaymentMethodService owns the operations on basis
// user_payment_method that can't be served by abstract REST CRUD:
//
//   - SetDefault: atomic multi-row UPDATE — flips the chosen row to
//     is_default and clears every other row owned by the same user
//     in a single statement. Abstract single-row UPDATE would race
//     two-step "clear all + set one" against rapid taps.
//   - Remove: detaches the method at the provider, then deletes the row.
//   - RecordFromSetupIntent: invoked by downstream PaymentEventHandler
//     impls when a Stripe (or compatible) SetupIntent.succeeded webhook
//     lands. Pulls card metadata via CardClient (optional) and inserts.
//
// List is served by keel's generic REST CRUD against the UserSpecific
// basis table.
//
// CardClient is optional — when nil, RecordFromSetupIntent persists the
// provider_token alone and the UI degrades to "Card on file". Detacher is
// required by Remove.
type UserPaymentMethodService struct {
	DB         port.DatabaseRepository
	CardClient SetupIntentCardClient
	Detacher   PaymentMethodDetacher
	Journal    logger.ApplicationLogger
}

const (
	qUPMInsert     = "qUPMInsert"
	qUPMSetDefault = "qUPMSetDefault"
	qUPMToken      = "qUPMToken"
	qUPMDelete     = "qUPMDelete"
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

	qUPMToken: `
SELECT provider_token FROM user_payment_method
 WHERE id = ? AND user_id = ?`,

	qUPMDelete: `
DELETE FROM user_payment_method
 WHERE id = ? AND user_id = ?`,
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

// Remove detaches the user's saved method at the provider, then deletes its
// row. A failed detach keeps the row so the removal can be retried. Removing
// the default leaves none; the charge path then takes the newest method.
func (s *UserPaymentMethodService) Remove(ctx context.Context, userID int, methodID int64) error {
	if s.Detacher == nil {
		return fmt.Errorf("remove user payment method: Detacher not configured")
	}
	qs := s.DB.GetQueryService(ctx, userPaymentMethodQueries)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	res, err := qs.Query(ctx, qUPMToken, methodID, userID)
	if err != nil {
		return fmt.Errorf("read user payment method: %w", err)
	}
	if len(res.Rows) == 0 {
		return ErrPaymentMethodNotFound
	}
	if err := s.Detacher.DetachPaymentMethod(ctx, common.AsString(res.Rows[0][0])); err != nil {
		return fmt.Errorf("detach user payment method: %w", err)
	}
	if _, err := qs.Query(ctx, qUPMDelete, methodID, userID); err != nil {
		return fmt.Errorf("delete user payment method: %w", err)
	}
	return nil
}

// RecordFromSetupIntent persists a new row from a Stripe (or compatible)
// SetupIntent succeeded event. The provider name is taken from the
// PaymentEvent.Provider; provider_token holds the SetupIntent id (the
// reusable handle for future PaymentIntents). When CardClient is wired
// the row also carries card metadata and wallet method_type; otherwise it
// lands as a card with just the token and the UI shows "Card on file".
//
// userID is supplied by the caller — typically extracted from the
// PaymentEvent.Metadata["user_id"] field that keel auto-injects on
// checkout-session creation.
func (s *UserPaymentMethodService) RecordFromSetupIntent(ctx context.Context, userID int, provider, setupIntentID, currency string) error {
	if userID <= 0 {
		return fmt.Errorf("RecordFromSetupIntent: userID required")
	}
	if setupIntentID == "" {
		return fmt.Errorf("RecordFromSetupIntent: setupIntentID required")
	}
	var card SavedCard
	if s.CardClient != nil {
		if c, ok := s.CardClient.GetSetupIntentCard(ctx, setupIntentID); ok {
			card = c
		}
	}
	if card.MethodType == "" {
		card.MethodType = MethodTypeCard
	}
	qs := s.DB.GetQueryService(ctx, userPaymentMethodQueries)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	if _, err := qs.Query(ctx, qUPMInsert,
		userID, card.MethodType, provider, setupIntentID, card.Last4, card.Brand, card.ExpMonth, card.ExpYear, common.NullIfEmpty(currency),
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

func (c *StripeSetupIntentCardClient) GetSetupIntentCard(ctx context.Context, setupIntentID string) (SavedCard, bool) {
	if c.Client == nil {
		return SavedCard{}, false
	}
	body, err := c.Client.Get(ctx, "/setup_intents/"+setupIntentID, url.Values{"expand[]": {"payment_method"}})
	if err != nil {
		if c.Journal != nil {
			c.Journal.Error("stripe setup_intent fetch: " + err.Error())
		}
		return SavedCard{}, false
	}
	var parsed struct {
		PaymentMethod struct {
			Card struct {
				Last4    string `json:"last4"`
				Brand    string `json:"brand"`
				ExpMonth int    `json:"exp_month"`
				ExpYear  int    `json:"exp_year"`
				Wallet   *struct {
					Type string `json:"type"`
				} `json:"wallet"`
			} `json:"card"`
		} `json:"payment_method"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		if c.Journal != nil {
			c.Journal.Error("stripe setup_intent fetch: parse: " + err.Error())
		}
		return SavedCard{}, false
	}
	cd := parsed.PaymentMethod.Card
	card := SavedCard{MethodType: MethodTypeCard, Last4: cd.Last4, Brand: cd.Brand, ExpMonth: cd.ExpMonth, ExpYear: cd.ExpYear}
	if cd.Wallet != nil {
		switch cd.Wallet.Type {
		case "apple_pay":
			card.MethodType = MethodTypeApplePay
		case "google_pay":
			card.MethodType = MethodTypeGooglePay
		default:
			card.MethodType = MethodTypeWallet
		}
	}
	return card, true
}

var _ SetupIntentCardClient = (*StripeSetupIntentCardClient)(nil)
