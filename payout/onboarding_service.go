package payout

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// Named keys for the SQL statements OnboardingService uses. Mirrors the
// payment package's webhook_repository_sql shape — one map per package,
// built once, served by a sync.Once-cached QueryService accessor so the
// placeholder rewriter doesn't re-run per webhook event.
const (
	qPayoutReusableAccounts = "payout_reusable_accounts"
	qPayoutLinkExisting     = "payout_link_existing"
	qPayoutIsOnboarded      = "payout_is_onboarded"
	qPayoutBankInfo         = "payout_bank_info"
	qPayoutWriteExternal    = "payout_write_external"
	qPayoutBackFillExternal = "payout_backfill_external"
	qPayoutClearExternal    = "payout_clear_external"
	qPayoutSupersede        = "payout_supersede_bank_info"
	qPayoutInsertBankInfo   = "payout_insert_bank_info"
	qPayoutClaimDestination = "payout_claim_destination"
	qPayoutVerifyActiveIdx  = "payout_verify_active_index"
)

// All statements target only the active version (status = 'A') of a
// (user, partner)'s user_bank_info. Superseded rows are history and are
// never read or mutated by the onboarding flow.
var onboardingQueries = map[string]string{
	qPayoutReusableAccounts: `
SELECT ubi.partner_id, bp.caption, ubi.provider, ubi.provider_account_id,
       ubi.country_code, ubi.currency, ubi.provider_onboarded_at
  FROM user_bank_info ubi
  JOIN business_partner bp ON bp.id = ubi.partner_id
 WHERE ubi.user_id = ?
   AND ubi.partner_id <> ?
   AND ubi.status = 'A'
   AND ubi.provider = ?
   AND ubi.provider_account_id IS NOT NULL
   AND ubi.provider_agreement = TRUE
   AND ubi.provider_onboarded_at IS NOT NULL
   AND ubi.currency = (
       SELECT currency FROM user_bank_info
        WHERE user_id = ? AND partner_id = ? AND status = 'A'
   )`,

	// One atomic, provider- and currency-scoped statement: the source row
	// must be the same user's activated account on the CONFIGURED provider
	// with the target row's currency, and the copy carries its real
	// provider state — linking must never manufacture provider_agreement
	// or an onboarding timestamp. RETURNING lets the caller verify a
	// target row was actually updated. UPDATE … FROM is PostgreSQL-only,
	// like the rest of keel's payout SQL surface (see VerifySchema).
	qPayoutLinkExisting: `
UPDATE user_bank_info t
   SET provider_account_id = s.provider_account_id,
       provider = s.provider,
       provider_onboarded_at = s.provider_onboarded_at,
       provider_agreement = s.provider_agreement,
       updated_at = CURRENT_TIMESTAMP
  FROM user_bank_info s
 WHERE t.user_id = ? AND t.partner_id = ? AND t.status = 'A'
   AND s.user_id = t.user_id AND s.partner_id <> t.partner_id
   AND s.provider_account_id = ?
   AND s.status = 'A'
   AND s.provider = ?
   AND s.provider_agreement = TRUE
   AND s.provider_onboarded_at IS NOT NULL
   AND s.currency = t.currency
RETURNING t.user_id`,

	qPayoutIsOnboarded: `
SELECT 1 FROM user_bank_info
 WHERE user_id = ? AND partner_id = ? AND status = 'A'
   AND provider_account_id IS NOT NULL
   AND provider_agreement = TRUE
   AND provider_onboarded_at IS NOT NULL
 LIMIT 1`,

	qPayoutBankInfo: `
SELECT ubi.id, ubi.country_code, ubi.currency, ubi.account_holder_name, ubi.billing_address,
       ubi.provider, COALESCE(ubi.provider_account_id, ''),
       COALESCE(ua.email, ''),
       ubi.provider_agreement,
       ubi.provider_onboarded_at
  FROM user_bank_info ubi
  LEFT JOIN user_account ua ON ua.id = ubi.user_id
 WHERE ubi.user_id = ? AND ubi.partner_id = ? AND ubi.status = 'A'`,

	qPayoutWriteExternal: `
UPDATE user_bank_info
   SET provider_account_id = ?,
       provider_onboarded_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE provider_onboarded_at END,
       provider_agreement = CASE WHEN ? THEN TRUE ELSE provider_agreement END,
       updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND partner_id = ? AND status = 'A' AND provider = ?
RETURNING user_id`,

	// Provider-scoped: provider-native account ids are only unique within
	// one provider — an id collision must never mutate another provider's
	// rows.
	qPayoutBackFillExternal: `
UPDATE user_bank_info
   SET provider_onboarded_at = CASE WHEN ? AND provider_onboarded_at IS NULL THEN CURRENT_TIMESTAMP ELSE provider_onboarded_at END,
       provider_agreement = CASE WHEN ? THEN TRUE ELSE provider_agreement END,
       updated_at = CURRENT_TIMESTAMP
 WHERE provider_account_id = ? AND provider = ? AND status = 'A'
RETURNING user_id`,

	qPayoutClearExternal: `
UPDATE user_bank_info
   SET provider_account_id = NULL,
       provider_onboarded_at = NULL,
       provider_agreement = FALSE,
       updated_at = CURRENT_TIMESTAMP
 WHERE provider_account_id = ? AND provider = ? AND status = 'A'
RETURNING user_id`,

	qPayoutInsertBankInfo: `
INSERT INTO user_bank_info
 (id, user_id, partner_id, country_code, currency, account_holder_name,
  billing_address, tax_id_type, tax_id_encrypted, provider, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'A')`,

	qPayoutClaimDestination: `
UPDATE user_bank_info
   SET provider_account_id = ?,
       provider_onboarded_at = CURRENT_TIMESTAMP,
       provider_agreement = TRUE,
       updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND user_id = ? AND partner_id = ? AND status = 'A' AND provider = ?
   AND provider_account_id IS NULL
RETURNING user_id`,

	qPayoutSupersede: `
UPDATE user_bank_info
   SET status = 'S',
       superseded_at = CURRENT_TIMESTAMP,
       updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND partner_id = ? AND status = 'A'`,

	// Boot-time invariant probe: the partial unique index guarding one
	// active row per (user, partner) exists only on PostgreSQL, and the
	// payout SQL surface is PostgreSQL-only. Failing this query at boot
	// (e.g. on MySQL, which has no pg_indexes) stops a deployment whose
	// database cannot enforce payout invariants before it moves money.
	qPayoutVerifyActiveIdx: `
SELECT indexdef
  FROM pg_indexes
 WHERE schemaname = current_schema()
   AND tablename = 'user_bank_info'
   AND indexname = 'user_bank_info_active_uq'
 LIMIT 1`,
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
	DB                  port.DatabaseRepository
	Provider            PayoutProvider // single active provider, picked at startup via PAYOUT_PROVIDER flag
	OnboardingReturnURL string         // deep-link the provider redirects back to
	WebhookCallbackURL  string         // public-facing URL the provider POSTs events to
	Journal             logger.ApplicationLogger

	// WebhookLog is the durable event-id dedup record (basis
	// payout_webhook_log). Nil disables dedup — acceptable only in tests;
	// production wiring must set it (financial events must never rely on
	// a process-local or expiring cache).
	WebhookLog WebhookLog

	// TransferSink receives normalized transfer-lifecycle events
	// (transfer.paid/failed/returned/reversed) so the downstream payout
	// ledger can apply authoritative provider outcomes. A nil sink is a
	// configuration error once transfer events arrive: they are logged
	// durably, reported as failures (claim stays retryable), and the
	// provider keeps retrying until a sink is wired.
	TransferSink TransferEventSink

	// qsOnce / qs cache the package-level onboardingQueries map after the
	// first call so the data layer's placeholder rewriter only runs once
	// per process. Same shape as payment.SQLWebhookRepository — eliminates
	// the per-call rebuild that previously happened in every method.
	qsOnce sync.Once
	qs     port.QueryService

	verifyMu sync.Mutex
	verified bool
}

// queryService returns the cached data.QueryService, lazily constructing it
// on first call. Safe for concurrent callers — sync.Once guarantees a
// single underlying GetQueryService invocation.
func (s *OnboardingService) queryService(ctx context.Context) port.QueryService {
	s.qsOnce.Do(func() {
		s.qs = s.DB.GetQueryService(ctx, onboardingQueries)
	})
	return s.qs
}

// ready gates every financial entry point on the schema verification.
// Only success is cached — a transient probe failure is retried on the
// next call, never pinned for the process lifetime.
func (s *OnboardingService) ready(ctx context.Context) (port.QueryService, error) {
	qs := s.queryService(ctx)
	if qs == nil {
		return nil, fmt.Errorf("query service not available")
	}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if s.verified {
		return qs, nil
	}
	res, err := qs.Query(ctx, qPayoutVerifyActiveIdx)
	if err != nil {
		return nil, fmt.Errorf("payout requires PostgreSQL (pg_indexes probe failed): %w", err)
	}
	if len(res.Rows) == 0 || !indexDefCovers(kcommon.AsString(res.Rows[0][0]), "(user_id, partner_id)", "status = 'A'") {
		return nil, fmt.Errorf("user_bank_info: unique index user_bank_info_active_uq missing or malformed; apply schema/payout/user_bank_info.yml")
	}
	s.verified = true
	return qs, nil
}

// indexDefCovers checks a pg_indexes.indexdef for uniqueness, the exact
// column list, and (when non-empty) the partial predicate.
func indexDefCovers(def, columns, predicate string) bool {
	d := strings.ToLower(def)
	if !strings.Contains(d, "unique") || !strings.Contains(d, strings.ToLower(columns)) {
		return false
	}
	return predicate == "" || strings.Contains(d, strings.ToLower(predicate))
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
// dedupes on the provider's raw event id via WebhookLog, then applies:
// account events back-fill user_bank_info; transfer events dispatch to
// TransferSink; Ignored events are ACKed.
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
	if ev.Type == PayoutEventIgnored {
		return nil
	}
	if s.WebhookLog == nil || ev.RawEventID == "" {
		return s.applyEvent(ctx, ev)
	}
	logID, duplicate, err := s.WebhookLog.Claim(ctx, providerCode, ev, rawBody)
	if err != nil {
		return err
	}
	if duplicate {
		return nil // processed or in flight — ACK without reapplying
	}
	// A failed apply is recorded 'F' and the claim above re-claims it on
	// the provider's next retry — a transient sink/database outage never
	// permanently swallows a financial event.
	if applyErr := s.applyEvent(ctx, ev); applyErr != nil {
		_ = s.WebhookLog.UpdateStatus(ctx, logID, WebhookStatusFailed, applyErr.Error())
		return applyErr
	}
	return s.WebhookLog.UpdateStatus(ctx, logID, WebhookStatusProcessed, "")
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
	if s.Provider == nil {
		return nil, fmt.Errorf("payout provider not configured")
	}
	qs, err := s.ready(ctx)
	if err != nil {
		return nil, err
	}
	res, err := qs.Query(ctx, qPayoutReusableAccounts, userID, targetPartnerID, s.Provider.Code(), userID, targetPartnerID)
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

// LinkReusableAccount copies an existing provider account from one of
// the rows ListReusableAccounts returned over onto the target
// (user, partner) row. The provider does not need to be called —
// reusing an account is application-side bookkeeping; the provider
// already cleared this user's KYC under the shared account id.
//
// One atomic statement validates and links: the source must be the same
// user's fully activated account on the CONFIGURED provider with the
// target row's currency, and the copy carries the source's real
// provider state — linking never manufactures provider_agreement or an
// onboarding timestamp. Zero affected rows (no valid source, no active
// target, currency/provider mismatch) is a loud error.
func (s *OnboardingService) LinkReusableAccount(ctx context.Context, userID int, targetPartnerID int64, providerAccountID string) error {
	if s.Provider == nil {
		return fmt.Errorf("payout provider not configured")
	}
	qs, err := s.ready(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, qPayoutLinkExisting,
		userID, targetPartnerID, providerAccountID, s.Provider.Code())
	if err != nil {
		return fmt.Errorf("link existing account: %w", err)
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("provider account not reusable for this user")
	}
	return nil
}

// IsOnboardingComplete answers the calling-application's dashboard
// banner: true only when the active row has a provider account id,
// provider_agreement, and a provider-confirmed onboarding timestamp —
// a populated account id alone is not completed onboarding.
func (s *OnboardingService) IsOnboardingComplete(ctx context.Context, userID int, partnerID int64) (bool, error) {
	qs, err := s.ready(ctx)
	if err != nil {
		return false, err
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
//
// Eligibility is enforced here: the amount must be positive, the
// currency must match the destination row (it drives the minor-unit
// exponent — a mismatch silently rescales the amount), and the active
// bank row must be on the configured provider with an account id,
// provider_agreement, and a provider-confirmed onboarding timestamp.
func (s *OnboardingService) RequestInstantPayout(ctx context.Context, userID int, partnerID int64, amount int64, currency, idempotencyKey string) (*InstantPayoutResult, error) {
	if s.Provider == nil {
		return nil, fmt.Errorf("payout provider not configured")
	}
	if amount <= 0 {
		return nil, fmt.Errorf("payout amount must be positive, got %d", amount)
	}
	bank, err := s.loadBankInfo(ctx, userID, partnerID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(currency, bank.Currency) {
		return nil, fmt.Errorf("payout currency %q does not match destination currency %q", currency, bank.Currency)
	}
	if bank.ProviderAccountID == "" {
		return nil, fmt.Errorf("user has no linked provider account")
	}
	if bank.Provider != s.Provider.Code() {
		return nil, fmt.Errorf("bank info provider %q does not match configured %q", bank.Provider, s.Provider.Code())
	}
	if !bank.ProviderAgreement || bank.OnboardedAt == "" {
		return nil, fmt.Errorf("provider onboarding not completed for this account")
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

// RegisterBeneficiary creates a provider Beneficiary from
// application-collected details and stores its id as the active row's
// payout destination — the Airwallex payout-onboarding path, where the
// hosted-KYC connected account (acct_…) is never a valid destination.
// A created beneficiary is immediately payable, so the row is marked
// onboarded.
func (s *OnboardingService) RegisterBeneficiary(ctx context.Context, userID int, partnerID int64, beneficiary json.RawMessage) (string, error) {
	if s.Provider == nil {
		return "", fmt.Errorf("payout provider not configured")
	}
	creator, ok := s.Provider.(BeneficiaryCreator)
	if !ok {
		return "", fmt.Errorf("provider %s does not support beneficiary registration", s.Provider.Code())
	}
	qs, err := s.ready(ctx)
	if err != nil {
		return "", err
	}
	// Validate before the external call: an occupied destination is an
	// identity-bearing change and must go through ReplaceBankInfo first.
	bank, err := s.loadBankInfo(ctx, userID, partnerID)
	if err != nil {
		return "", err
	}
	if bank.Provider != s.Provider.Code() {
		return "", fmt.Errorf("bank info provider %q does not match configured %q", bank.Provider, s.Provider.Code())
	}
	if bank.ProviderAccountID != "" {
		return "", fmt.Errorf("destination already registered — replace the bank info version first")
	}
	id, err := creator.CreateBeneficiary(ctx, beneficiary)
	if err != nil {
		return "", err
	}
	// Conditional claim pinned to the validated version id: a row
	// replaced while the provider call was in flight makes the claim
	// return zero rows instead of linking the new version.
	res, err := qs.Query(ctx, qPayoutClaimDestination, id, bank.ID, userID, partnerID, s.Provider.Code())
	if err != nil {
		return "", fmt.Errorf("persist beneficiary id: %w", err)
	}
	if len(res.Rows) == 0 {
		return "", fmt.Errorf("bank info changed during registration — beneficiary %s not linked", id)
	}
	return id, nil
}

// NewBankInfo is the identity payload for a replacement destination
// version. The provider account starts unlinked; onboarding fills it.
type NewBankInfo struct {
	CountryCode       string
	Currency          string
	AccountHolderName string
	BillingAddress    string
	TaxIDType         string
	TaxIDEncrypted    []byte
	Provider          string
}

// ReplaceBankInfo supersedes the active version and inserts the new one
// in a single transaction, so a failed insert never leaves the user
// without an active destination.
func (s *OnboardingService) ReplaceBankInfo(ctx context.Context, userID int, partnerID int64, info NewBankInfo) error {
	if _, err := s.ready(ctx); err != nil {
		return err
	}
	if info.CountryCode == "" || info.Currency == "" || info.Provider == "" || info.AccountHolderName == "" {
		return fmt.Errorf("replace bank info: country, currency, provider, and holder are required")
	}
	tx, err := s.DB.BeginTx(ctx, onboardingQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Query(ctx, qPayoutSupersede, userID, partnerID); err != nil {
		return fmt.Errorf("replace bank info: supersede: %w", err)
	}
	if _, err := tx.Query(ctx, qPayoutInsertBankInfo, tx.GenID(), userID, partnerID,
		info.CountryCode, info.Currency, info.AccountHolderName, info.BillingAddress,
		info.TaxIDType, info.TaxIDEncrypted, info.Provider); err != nil {
		return fmt.Errorf("replace bank info: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// SupersedeBankInfoTx closes the active version on a caller-owned tx;
// the caller inserts the replacement row in the same tx.
func (s *OnboardingService) SupersedeBankInfoTx(ctx context.Context, tx port.TxQueryService, userID int, partnerID int64) error {
	if _, err := tx.Query(ctx, qPayoutSupersede, userID, partnerID); err != nil {
		return fmt.Errorf("supersede bank info (tx): %w", err)
	}
	return nil
}

// TxQueries exposes the payout query map for caller-owned transactions.
func (s *OnboardingService) TxQueries() map[string]string {
	return onboardingQueries
}

// VerifySchema runs the mandatory schema check eagerly at boot; every
// financial entry point also runs it lazily via ready().
func (s *OnboardingService) VerifySchema(ctx context.Context) error {
	_, err := s.ready(ctx)
	return err
}

// --- internals ---

type bankInfoRow struct {
	ID                int64
	CountryCode       string
	Currency          string
	AccountHolderName string
	BillingAddress    string
	Provider          string
	ProviderAccountID string
	Email             string
	ProviderAgreement bool
	OnboardedAt       string
}

func (s *OnboardingService) loadBankInfo(ctx context.Context, userID int, partnerID int64) (*bankInfoRow, error) {
	qs, err := s.ready(ctx)
	if err != nil {
		return nil, err
	}
	res, err := qs.Query(ctx, qPayoutBankInfo, userID, partnerID)
	if err != nil || len(res.Rows) == 0 {
		return nil, fmt.Errorf("user_bank_info not found — complete the billing step first")
	}
	row := res.Rows[0]
	return &bankInfoRow{
		ID:                kcommon.AsInt64(row[0]),
		CountryCode:       kcommon.AsString(row[1]),
		Currency:          kcommon.AsString(row[2]),
		AccountHolderName: kcommon.AsString(row[3]),
		BillingAddress:    kcommon.AsString(row[4]),
		Provider:          kcommon.AsString(row[5]),
		ProviderAccountID: kcommon.AsString(row[6]),
		Email:             kcommon.AsString(row[7]),
		ProviderAgreement: kcommon.AsBool(row[8]),
		OnboardedAt:       kcommon.AsString(row[9]),
	}, nil
}

func (s *OnboardingService) writeExternalAccountID(ctx context.Context, userID int64, partnerID int64, externalID string, activated bool) error {
	qs, err := s.ready(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, qPayoutWriteExternal, externalID, activated, activated, userID, partnerID, s.Provider.Code())
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("no active %s bank row for user %d partner %d", s.Provider.Code(), userID, partnerID)
	}
	return nil
}

// applyEvent back-fills user_bank_info from a normalized webhook
// event. Activation sets provider_onboarded_at + provider_agreement;
// account.created sets only the id (the row may already have it from
// StartOnboarding — that's fine, the UPDATE is idempotent); rejection
// clears the id so the calling application can prompt the user to retry.
// Transfer events dispatch to TransferSink; with no sink wired the
// event stays durably logged and is ACKed for later reconciliation.
func (s *OnboardingService) applyEvent(ctx context.Context, ev *PayoutWebhookEvent) error {
	switch ev.Type {
	case PayoutEventAccountCreated, PayoutEventAccountUpdated:
		activated := ev.Activated
		if !activated && ev.ExternalAccountID != "" {
			// Providers whose events carry no activation flag are
			// reconciled against the live account state; an error keeps
			// the claim retryable.
			if c, ok := s.Provider.(AccountStatusChecker); ok {
				a, err := c.IsAccountActive(ctx, ev.ExternalAccountID)
				if err != nil {
					return err
				}
				activated = a
			}
		}
		return s.backFillByExternalID(ctx, ev.ExternalAccountID, activated)
	case PayoutEventAccountActivated:
		return s.backFillByExternalID(ctx, ev.ExternalAccountID, true)
	case PayoutEventAccountRejected:
		return s.clearByExternalID(ctx, ev.ExternalAccountID)
	case PayoutEventTransferPaid, PayoutEventTransferFailed,
		PayoutEventTransferReturned, PayoutEventTransferReversed:
		// A missing sink is a configuration error, not success: returning
		// nil would mark the durable claim processed and permanently lose
		// a terminal financial outcome. Failing keeps the claim retryable
		// (F → re-claimed) until a sink is wired.
		if s.TransferSink == nil {
			return fmt.Errorf("payout: %s for transfer %s received but no TransferSink is wired", ev.Type, ev.ProviderTransferID)
		}
		return s.TransferSink.ApplyTransferEvent(ctx, ev)
	default:
		return fmt.Errorf("applyEvent: unhandled event type %q", ev.Type)
	}
}

// Zero affected rows is an error so the webhook claim stays retryable
// instead of ACKing an update that landed nowhere.
func (s *OnboardingService) backFillByExternalID(ctx context.Context, externalID string, activated bool) error {
	qs, err := s.ready(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, qPayoutBackFillExternal, activated, activated, externalID, s.Provider.Code())
	if err != nil {
		return fmt.Errorf("back-fill by external_id: %w", err)
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("back-fill: no active %s row for account %s", s.Provider.Code(), externalID)
	}
	return nil
}

func (s *OnboardingService) clearByExternalID(ctx context.Context, externalID string) error {
	qs, err := s.ready(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, qPayoutClearExternal, externalID, s.Provider.Code())
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("clear: no active %s row for account %s", s.Provider.Code(), externalID)
	}
	return nil
}
