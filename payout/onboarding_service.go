package payout

import (
	"context"
	"fmt"
	"sync"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
)

// Named keys for the SQL statements OnboardingService uses. Mirrors the
// payment package's webhook_repository_sql shape — one map per package,
// built once, served by a sync.Once-cached QueryService accessor so the
// placeholder rewriter doesn't re-run per webhook event.
const (
	qPayoutReusableAccounts  = "payout_reusable_accounts"
	qPayoutVerifyReusable    = "payout_verify_reusable"
	qPayoutLinkExisting      = "payout_link_existing"
	qPayoutIsOnboarded       = "payout_is_onboarded"
	qPayoutBankInfo          = "payout_bank_info"
	qPayoutWriteExternal     = "payout_write_external"
	qPayoutBackFillExternal  = "payout_backfill_external"
	qPayoutClearExternal     = "payout_clear_external"
)

var onboardingQueries = map[string]string{
	qPayoutReusableAccounts: `
SELECT ubi.partner_id, bp.caption, ubi.provider, ubi.provider_account_id,
       ubi.country_code, ubi.currency, ubi.provider_onboarded_at
  FROM user_bank_info ubi
  JOIN business_partner bp ON bp.id = ubi.partner_id
 WHERE ubi.user_id = ?
   AND ubi.partner_id <> ?
   AND ubi.provider_account_id IS NOT NULL
   AND ubi.currency = (
       SELECT currency FROM user_bank_info
        WHERE user_id = ? AND partner_id = ?
   )`,
	qPayoutVerifyReusable: `
SELECT 1 FROM user_bank_info
 WHERE user_id = ? AND provider_account_id = ? AND partner_id <> ?
 LIMIT 1`,
	qPayoutLinkExisting: `
UPDATE user_bank_info
   SET provider_account_id = ?,
       provider_onboarded_at = CURRENT_TIMESTAMP,
       provider_agreement = TRUE,
       updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND partner_id = ?`,
	qPayoutIsOnboarded: `
SELECT 1 FROM user_bank_info
 WHERE user_id = ? AND partner_id = ?
   AND provider_account_id IS NOT NULL
 LIMIT 1`,
	qPayoutBankInfo: `
SELECT ubi.country_code, ubi.currency, ubi.account_holder_name, ubi.billing_address,
       ubi.provider, COALESCE(ubi.provider_account_id, ''),
       COALESCE(ua.email, '')
  FROM user_bank_info ubi
  LEFT JOIN user_account ua ON ua.id = ubi.user_id
 WHERE ubi.user_id = ? AND ubi.partner_id = ?`,
	qPayoutWriteExternal: `
UPDATE user_bank_info
   SET provider_account_id = ?,
       provider_onboarded_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE provider_onboarded_at END,
       provider_agreement = CASE WHEN ? THEN TRUE ELSE provider_agreement END,
       updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND partner_id = ?`,
	qPayoutBackFillExternal: `
UPDATE user_bank_info
   SET provider_onboarded_at = CASE WHEN ? AND provider_onboarded_at IS NULL THEN CURRENT_TIMESTAMP ELSE provider_onboarded_at END,
       provider_agreement = CASE WHEN ? THEN TRUE ELSE provider_agreement END,
       updated_at = CURRENT_TIMESTAMP
 WHERE provider_account_id = ?`,
	qPayoutClearExternal: `
UPDATE user_bank_info
   SET provider_account_id = NULL,
       provider_onboarded_at = NULL,
       provider_agreement = FALSE,
       updated_at = CURRENT_TIMESTAMP
 WHERE provider_account_id = ?`,
}

// OnboardingService orchestrates the user-side payout-provider
// onboarding flow. It owns:
//   - starting a hosted-KYC session against the configured PayoutProvider;
//   - persisting the returned external account id placeholder on
//     user_bank_info;
//   - handling the provider's webhook to back-fill activation;
//   - listing existing reusable provider accounts the same user already
//     has on OTHER partners so a multi-partner user can opt to share
//     one external account across partners rather than redo KYC per
//     partner;
//   - dispatching instant out-of-cycle payouts.
//
// All SQL targets the basis `user_bank_info` table keyed on
// (user_id, partner_id). PartnerSpecific auto-filter applies because
// user_bank_info.partner_id FKs business_partner; the service uses
// raw SQL for cross-actor flows where the auto-filter would block.
type OnboardingService struct {
	DB                  data.DatabaseRepository
	Provider            PayoutProvider // single active provider, picked at startup via PAYOUT_PROVIDER flag
	OnboardingReturnURL string         // deep-link the provider redirects back to
	WebhookCallbackURL  string         // public-facing URL the provider POSTs events to
	Journal             logger.ApplicationLogger

	// qsOnce / qs cache the package-level onboardingQueries map after the
	// first call so the data layer's placeholder rewriter only runs once
	// per process. Same shape as payment.SQLWebhookRepository — eliminates
	// the per-call rebuild that previously happened in every method.
	qsOnce sync.Once
	qs     data.QueryService
}

// queryService returns the cached data.QueryService, lazily constructing it
// on first call. Safe for concurrent callers — sync.Once guarantees a
// single underlying GetQueryService invocation.
func (s *OnboardingService) queryService(ctx context.Context) data.QueryService {
	s.qsOnce.Do(func() {
		s.qs = s.DB.GetQueryService(ctx, onboardingQueries)
	})
	return s.qs
}

// StartOnboardingResult is what the calling-application handler echoes
// back to the client.
type StartOnboardingResult struct {
	URL               string `json:"url"`
	ExternalAccountID string `json:"externalAccountId"`
	ExpiresAt         string `json:"expiresAt"`
}

// ReusableAccount is one provider account the calling user already
// has on a different (user, partner) pair. UI shows these so the user
// can pick "use my existing account" when onboarding into a new
// partner instead of starting fresh KYC.
type ReusableAccount struct {
	PartnerID         int64  `json:"partnerId"`
	PartnerCaption    string `json:"partnerCaption"`
	Provider          string `json:"provider"`
	ProviderAccountID string `json:"providerAccountId"`
	CountryCode       string `json:"countryCode"`
	Currency          string `json:"currency"`
	OnboardedAt       string `json:"onboardedAt"`
}

// StartOnboarding kicks off the provider's hosted KYC flow for the
// calling user on the given partner. Loads name + country + currency
// + billing address from the existing user_bank_info row (which the
// downstream's registration wizard filled in earlier), calls the
// provider, and persists the returned ExternalAccountID placeholder.
// Returns the URL the calling application should open.
func (s *OnboardingService) StartOnboarding(ctx context.Context, userID int, partnerID int64) (*StartOnboardingResult, error) {
	if s.Provider == nil {
		return nil, fmt.Errorf("payout provider not configured")
	}
	bank, err := s.loadBankInfo(ctx, userID, partnerID)
	if err != nil {
		return nil, err
	}
	if bank.ProviderAccountID != "" {
		return nil, fmt.Errorf("provider account already linked")
	}
	sess, err := s.Provider.StartOnboarding(ctx, StartOnboardingInput{
		UserID:         int64(userID),
		PartnerID:      partnerID,
		Email:          bank.Email,
		CountryCode:    bank.CountryCode,
		Currency:       bank.Currency,
		AccountHolder:  bank.AccountHolderName,
		BillingAddress: bank.BillingAddress,
		ReturnURL:      s.OnboardingReturnURL,
		NotifyURL:      s.WebhookCallbackURL,
	})
	if err != nil {
		return nil, fmt.Errorf("provider StartOnboarding: %w", err)
	}
	if sess.ExternalAccountID != "" {
		if err := s.writeExternalAccountID(ctx, int64(userID), partnerID, sess.ExternalAccountID, false); err != nil {
			return nil, fmt.Errorf("persist external account id: %w", err)
		}
	}
	return &StartOnboardingResult{
		URL:               sess.URL,
		ExternalAccountID: sess.ExternalAccountID,
		ExpiresAt:         sess.ExpiresAt,
	}, nil
}

// HandleWebhook is invoked by the provider-facing webhook handler.
// providerCode is taken from the URL path (e.g. POST
// /api/v1/webhook/payout/AW); it MUST match the active provider's
// Code() — otherwise stale-config-on-other-side or an attacker probing
// endpoints. Verifies signature + parses event via the provider impl,
// then back-fills user_bank_info.
func (s *OnboardingService) HandleWebhook(ctx context.Context, providerCode string, headers map[string][]string, rawBody []byte) error {
	if s.Provider == nil {
		return fmt.Errorf("payout provider not configured")
	}
	if providerCode != s.Provider.Code() {
		return fmt.Errorf("webhook provider %q does not match configured %q", providerCode, s.Provider.Code())
	}
	ev, err := s.Provider.VerifyAndParseWebhook(headers, rawBody)
	if err != nil {
		return err
	}
	return s.applyEvent(ctx, ev)
}

// ListReusableAccounts returns provider accounts already activated on
// OTHER (user, partner) pairs for the same user. The calling
// application surfaces these as a "reuse existing account" option
// during onboarding into a new partner.
//
// Currency match is enforced — sharing one account between two same-
// currency partners works, but a CAD account can't be reused on a
// partner asking for USD. Cross-currency reuse is provider-specific
// and an opt-in upgrade; out of scope.
func (s *OnboardingService) ListReusableAccounts(ctx context.Context, userID int, targetPartnerID int64) ([]ReusableAccount, error) {
	qs := s.queryService(ctx)
	if qs == nil {
		return nil, fmt.Errorf("query service not available")
	}
	res, err := qs.Query(ctx, qPayoutReusableAccounts, userID, targetPartnerID, userID, targetPartnerID)
	if err != nil {
		return nil, fmt.Errorf("list reusable accounts: %w", err)
	}
	out := make([]ReusableAccount, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, ReusableAccount{
			PartnerID:         kcommon.AsInt64(row[0]),
			PartnerCaption:    kcommon.AsString(row[1]),
			Provider:          kcommon.AsString(row[2]),
			ProviderAccountID: kcommon.AsString(row[3]),
			CountryCode:       kcommon.AsString(row[4]),
			Currency:          kcommon.AsString(row[5]),
			OnboardedAt:       kcommon.AsString(row[6]),
		})
	}
	return out, nil
}

// LinkReusableAccount copies an existing provider_account_id from one
// of the rows ListReusableAccounts returned over onto the target
// (user, partner) row. The provider does not need to be called —
// reusing an account is application-side bookkeeping; the provider
// already cleared this user's KYC under the shared account id.
func (s *OnboardingService) LinkReusableAccount(ctx context.Context, userID int, targetPartnerID int64, providerAccountID string) error {
	qs := s.queryService(ctx)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	res, err := qs.Query(ctx, qPayoutVerifyReusable, userID, providerAccountID, targetPartnerID)
	if err != nil || len(res.Rows) == 0 {
		return fmt.Errorf("provider account not reusable for this user")
	}
	if _, err := qs.Query(ctx, qPayoutLinkExisting, providerAccountID, userID, targetPartnerID); err != nil {
		return fmt.Errorf("link existing account: %w", err)
	}
	return nil
}

// IsOnboardingComplete answers the calling-application's dashboard
// banner: true when the calling user has a populated
// provider_account_id on the active partner row.
func (s *OnboardingService) IsOnboardingComplete(ctx context.Context, userID int, partnerID int64) (bool, error) {
	qs := s.queryService(ctx)
	if qs == nil {
		return false, fmt.Errorf("query service not available")
	}
	res, err := qs.Query(ctx, qPayoutIsOnboarded, userID, partnerID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0, nil
}

// RequestInstantPayout looks up the user's external account id and
// asks the provider to disburse Amount. The calling application is
// responsible for fee math, minimums, balance pre-checks, and
// recording the resulting ProviderPayoutID against its own ledger
// table — keel deliberately doesn't ship a generic payout ledger
// since the schema varies per downstream.
func (s *OnboardingService) RequestInstantPayout(ctx context.Context, userID int, partnerID int64, amount int64, currency, idempotencyKey string) (*InstantPayoutResult, error) {
	if s.Provider == nil {
		return nil, fmt.Errorf("payout provider not configured")
	}
	bank, err := s.loadBankInfo(ctx, userID, partnerID)
	if err != nil {
		return nil, err
	}
	if bank.ProviderAccountID == "" {
		return nil, fmt.Errorf("user has no linked provider account")
	}
	return s.Provider.RequestInstantPayout(ctx, InstantPayoutInput{
		UserID:            int64(userID),
		PartnerID:         partnerID,
		ProviderAccountID: bank.ProviderAccountID,
		Amount:            amount,
		Currency:          currency,
		IdempotencyKey:    idempotencyKey,
	})
}

// --- internals ---

type bankInfoRow struct {
	CountryCode       string
	Currency          string
	AccountHolderName string
	BillingAddress    string
	Provider          string
	ProviderAccountID string
	Email             string
}

func (s *OnboardingService) loadBankInfo(ctx context.Context, userID int, partnerID int64) (*bankInfoRow, error) {
	qs := s.queryService(ctx)
	if qs == nil {
		return nil, fmt.Errorf("query service not available")
	}
	res, err := qs.Query(ctx, qPayoutBankInfo, userID, partnerID)
	if err != nil || len(res.Rows) == 0 {
		return nil, fmt.Errorf("user_bank_info not found — complete the billing step first")
	}
	row := res.Rows[0]
	return &bankInfoRow{
		CountryCode:       kcommon.AsString(row[0]),
		Currency:          kcommon.AsString(row[1]),
		AccountHolderName: kcommon.AsString(row[2]),
		BillingAddress:    kcommon.AsString(row[3]),
		Provider:          kcommon.AsString(row[4]),
		ProviderAccountID: kcommon.AsString(row[5]),
		Email:             kcommon.AsString(row[6]),
	}, nil
}

func (s *OnboardingService) writeExternalAccountID(ctx context.Context, userID int64, partnerID int64, externalID string, activated bool) error {
	qs := s.queryService(ctx)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	_, err := qs.Query(ctx, qPayoutWriteExternal, externalID, activated, activated, userID, partnerID)
	return err
}

// applyEvent back-fills user_bank_info from a normalized webhook
// event. Activation sets provider_onboarded_at + provider_agreement;
// account.created sets only the id (the row may already have it from
// StartOnboarding — that's fine, the UPDATE is idempotent); rejection
// clears the id so the calling application can prompt the user to retry.
func (s *OnboardingService) applyEvent(ctx context.Context, ev *PayoutWebhookEvent) error {
	switch ev.Type {
	case PayoutEventAccountCreated, PayoutEventAccountUpdated:
		return s.backFillByExternalID(ctx, ev.ExternalAccountID, false)
	case PayoutEventAccountActivated:
		return s.backFillByExternalID(ctx, ev.ExternalAccountID, true)
	case PayoutEventAccountRejected:
		return s.clearByExternalID(ctx, ev.ExternalAccountID)
	default:
		return fmt.Errorf("applyEvent: unhandled event type %q", ev.Type)
	}
}

func (s *OnboardingService) backFillByExternalID(ctx context.Context, externalID string, activated bool) error {
	qs := s.queryService(ctx)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	if _, err := qs.Query(ctx, qPayoutBackFillExternal, activated, activated, externalID); err != nil {
		return fmt.Errorf("back-fill by external_id: %w", err)
	}
	return nil
}

func (s *OnboardingService) clearByExternalID(ctx context.Context, externalID string) error {
	qs := s.queryService(ctx)
	if qs == nil {
		return fmt.Errorf("query service not available")
	}
	_, err := qs.Query(ctx, qPayoutClearExternal, externalID)
	return err
}
