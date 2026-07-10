package user

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

const (
	qInsertConsentEvent = "insert_consent_event"
	qConsentHistory     = "consent_history"
	qLatestConsent      = "latest_consent"
	qLookupPolicyID     = "lookup_policy_id"
)

var ConsentQueries = map[string]string{
	qInsertConsentEvent: `
INSERT INTO consent_event
 (id, user_id, email_hash, phone_hash, consent_type, consented, policy_id,
  event_ref, region, client_ip, client_user_agent, created_at)
VALUES
 (nextval('consent_event_seq'), ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, CURRENT_TIMESTAMP)
RETURNING id`,

	qConsentHistory: `
SELECT ce.consent_type, ce.consented, cp.policy_type, cp.version, cp.region,
       cp.language, ce.region, ce.event_ref, ce.client_ip, ce.client_user_agent, ce.created_at
  FROM consent_event ce
  JOIN consent_policy cp ON cp.id = ce.policy_id
 WHERE (ce.user_id = ?    AND ? IS NOT NULL)
    OR (ce.email_hash = ? AND ? IS NOT NULL)
    OR (ce.phone_hash = ? AND ? IS NOT NULL)
 ORDER BY ce.created_at DESC`,

	qLatestConsent: `
SELECT consented, policy_id, created_at
  FROM consent_event
 WHERE consent_type = ?
   AND ((user_id = ? AND ? IS NOT NULL) OR (email_hash = ? AND ? IS NOT NULL))
 ORDER BY created_at DESC
 LIMIT 1`,

	qLookupPolicyID: `
SELECT id FROM consent_policy
 WHERE policy_type = ? AND region = ? AND version = ? AND language = ?
 LIMIT 1`,
}

// LocalConsentService is the default port.ConsentService implementation,
// backed by the consent_policy + consent_event tables in keel's schema.
//
// The optional pepper byte slice (set via WithEmailPepper) salts the
// email_hash column so a database exfiltration cannot be reversed via
// rainbow tables — a plain unsalted SHA-256 of an email is recoverable
// in seconds with a domain wordlist. Operators wire the pepper from
// the secret provider at startup; an unset pepper falls back to the
// previous unsalted SHA-256 behavior to preserve hash-stability with
// pre-v0.5 rows.
type LocalConsentService struct {
	database     port.DatabaseRepository
	queryService port.QueryService
	journal      logger.ApplicationLogger
	emailPepper  []byte
}

func NewLocalConsentService(ctx context.Context, database port.DatabaseRepository, journal logger.ApplicationLogger) (*LocalConsentService, error) {
	s := &LocalConsentService{
		database: database,
		journal:  journal,
	}
	s.queryService = database.GetQueryService(ctx, ConsentQueries)
	return s, nil
}

// WithEmailPepper enables HMAC-SHA-256 email hashing keyed on the
// supplied byte slice. Pass the bytes of a random server-side secret
// (16-32 bytes is plenty) loaded from the secret provider at startup.
// Returns the receiver for fluent construction.
//
// HASH-STABILITY WARNING: enabling the pepper changes the email_hash
// representation, so any legacy rows written before the switch
// retain their old unpeppered hashes. Either backfill the column
// (rehash from a known plaintext source — usually impossible for
// consent data) or accept that LatestConsent will not match across
// the boundary for email-only lookups. user_id-keyed lookups are
// unaffected.
func (s *LocalConsentService) WithEmailPepper(pepper []byte) *LocalConsentService {
	if len(pepper) == 0 {
		return s
	}
	cp := make([]byte, len(pepper))
	copy(cp, pepper)
	s.emailPepper = cp
	return s
}

// Record writes one consent event. History is preserved (no idempotency
// at the DB layer) so regulators can trace every decision. The latest
// row wins in downstream LatestConsent queries.
func (s *LocalConsentService) Record(ctx context.Context, req ConsentRequest) error {
	if req.ConsentType == "" {
		return fmt.Errorf("consent: consent_type is required")
	}
	if req.UserID <= 0 && req.Email == "" && req.Phone == "" {
		return fmt.Errorf("consent: user_id, email, or phone is required")
	}

	policyID, err := s.resolvePolicyID(ctx, req)
	if err != nil {
		return err
	}

	var userID any
	if req.UserID > 0 {
		userID = req.UserID
	}
	var emailHash any
	if req.Email != "" {
		emailHash = s.hashIdentifier(req.Email)
	}
	var phoneHash any
	if req.Phone != "" {
		phoneHash = s.hashIdentifier(req.Phone)
	}

	_, err = s.queryService.Query(ctx, qInsertConsentEvent,
		userID,
		emailHash,
		phoneHash,
		req.ConsentType,
		req.Consented,
		policyID,
		nullIfEmpty(req.EventRef),
		req.Region,
		nullIfEmpty(req.ClientIP),
		nullIfEmpty(req.ClientUserAgent),
	)
	if err != nil {
		return fmt.Errorf("consent: insert event: %w", err)
	}
	return nil
}

// RecordSignupConsents records a bag of consent decisions in one pass,
// all referencing the same user and signup policy version. Use from
// signup handlers after the user_account row has been created so every
// event references the user_id directly.
func (s *LocalConsentService) RecordSignupConsents(ctx context.Context, userID int, email string, consents map[string]bool, meta ConsentRequest) error {
	base := meta
	base.UserID = userID
	base.Email = email
	for consentType, consented := range consents {
		req := base
		req.ConsentType = consentType
		req.Consented = consented
		if err := s.Record(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// LatestConsent returns the most recent decision for a (user, consent_type)
// pair. consented=false is possible if the user revoked a prior consent.
// (false, false, nil) means no event exists — caller decides whether to prompt.
func (s *LocalConsentService) LatestConsent(ctx context.Context, userID int, email, consentType string) (bool, bool, error) {
	var userArg, emailArg any
	if userID > 0 {
		userArg = userID
	}
	if email != "" {
		emailArg = s.hashIdentifier(email)
	}
	if userArg == nil && emailArg == nil {
		return false, false, fmt.Errorf("consent: either user_id or email is required")
	}
	res, err := s.queryService.Query(ctx, qLatestConsent,
		consentType, userArg, userArg, emailArg, emailArg,
	)
	if err != nil {
		return false, false, fmt.Errorf("consent: query latest: %w", err)
	}
	if len(res.Rows) == 0 {
		return false, false, nil
	}
	return common.AsBool(res.Rows[0][0]), true, nil
}

// Withdraw records a first-class opt-out (Consented=false) for a consent type —
// the STOP/revocation half of the lifecycle. History is preserved.
func (s *LocalConsentService) Withdraw(ctx context.Context, req ConsentRequest) error {
	req.Consented = false
	return s.Record(ctx, req)
}

// History returns every consent event for the subject (user/email/phone),
// newest first — the exportable audit trail for carrier (10DLC) opt-in/opt-out
// proof and DSAR requests.
func (s *LocalConsentService) History(ctx context.Context, subject ConsentSubject) ([]ConsentEvent, error) {
	if subject.UserID <= 0 && subject.Email == "" && subject.Phone == "" {
		return nil, fmt.Errorf("consent: subject requires user_id, email, or phone")
	}
	var userArg, emailArg, phoneArg any
	if subject.UserID > 0 {
		userArg = subject.UserID
	}
	if subject.Email != "" {
		emailArg = s.hashIdentifier(subject.Email)
	}
	if subject.Phone != "" {
		phoneArg = s.hashIdentifier(subject.Phone)
	}
	res, err := s.queryService.Query(ctx, qConsentHistory,
		userArg, userArg, emailArg, emailArg, phoneArg, phoneArg,
	)
	if err != nil {
		return nil, fmt.Errorf("consent: history: %w", err)
	}
	out := make([]ConsentEvent, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, ConsentEvent{
			ConsentType:     common.AsString(r[0]),
			Consented:       common.AsBool(r[1]),
			PolicyType:      common.AsString(r[2]),
			PolicyVersion:   common.AsString(r[3]),
			PolicyRegion:    common.AsString(r[4]),
			PolicyLanguage:  common.AsString(r[5]),
			Region:          common.AsString(r[6]),
			EventRef:        common.AsString(r[7]),
			ClientIP:        common.AsString(r[8]),
			ClientUserAgent: common.AsString(r[9]),
			CreatedAt:       common.AsTime(r[10]),
		})
	}
	return out, nil
}

func (s *LocalConsentService) resolvePolicyID(ctx context.Context, req ConsentRequest) (int64, error) {
	if req.PolicyType == "" || req.PolicyVersion == "" {
		return 0, fmt.Errorf("consent: policy_type and policy_version are required")
	}
	region := req.PolicyRegion
	if region == "" {
		region = "global"
	}
	lang := req.PolicyLanguage
	if lang == "" {
		lang = "en"
	}
	res, err := s.queryService.Query(ctx, qLookupPolicyID,
		req.PolicyType, region, req.PolicyVersion, lang,
	)
	if err != nil {
		return 0, fmt.Errorf("consent: lookup policy: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, fmt.Errorf("consent: policy %s/%s/%s not registered", req.PolicyType, region, req.PolicyVersion)
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

// hashIdentifier returns the storage form of a personal identifier
// (email, in this codebase). Uses HMAC-SHA-256 keyed on the configured
// pepper when one is set; otherwise falls back to plain SHA-256 to
// stay hash-stable with rows written before WithEmailPepper was
// available.
//
// Constant-time HMAC vs SHA-256 cost is rounding-error in the
// per-request budget — the previous implementation already paid one
// SHA-256 per consent insert, and HMAC-SHA-256 is dominated by the
// same compress block.
func (s *LocalConsentService) hashIdentifier(in string) string {
	normalized := strings.ToLower(strings.TrimSpace(in))
	if len(s.emailPepper) > 0 {
		mac := hmac.New(sha256.New, s.emailPepper)
		mac.Write([]byte(normalized))
		return hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ ConsentService = (*LocalConsentService)(nil)
