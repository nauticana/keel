package user

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"golang.org/x/crypto/bcrypt"
)

// MailSender is the minimal mail-transport contract the registration
// flow needs. dispatcher.MailClient satisfies it; declaring it here
// rather than importing dispatcher keeps user/ free of the dispatcher
// package — dispatcher imports user (UserService) for SMS/email
// recipient resolution, and that direction must stay one-way.
type MailSender interface {
	SendEmail(ctx context.Context, subject string, body string, recipients []string) error
}

// confirmationRange is the count of distinct 8-digit confirmation
// codes keel emits in registration / password-reset flows. Codes are
// drawn from [10000000, 99999999] so the publicly-emitted token is
// always exactly 8 digits — no leading zero corner cases.
const confirmationRange = 90000000

// generateConfirmationCode returns a fresh 8-digit confirmation code
// drawn from crypto/rand, not math/rand. The code is publicly mailed
// and used as a one-shot security factor on the password-reset and
// account-confirm flows; using a CSPRNG closes the predictability
// gap that math/rand/v2 left wide open.
func generateConfirmationCode() (int, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(confirmationRange))
	if err != nil {
		return 0, fmt.Errorf("registration: rng: %w", err)
	}
	return int(n.Int64()) + 10000000, nil
}

const (
	qAddUserRegistration         = "add_user_registration"
	qGetUserRegistration         = "get_user_registration"
	qSetUserRegistration         = "set_user_registration"
	qBumpRegistrationAttempts    = "bump_registration_attempts"
	qExpireRegistration          = "expire_registration"
	qAddPartner                  = "add_partner"
	qAddAddress                  = "add_address"
	qAddDomain                   = "add_domain"
	qAddUserAccount              = "add_user_account"
	qAddPartnerUser              = "add_partner_user"
	qAddUserPermission           = "add_user_permission"
	qGetPlan                     = "get_plan"
	qAddSubscription             = "add_subscription"
	qActivateSubscription        = "activate_subscription"
	qActivateUserAccount         = "activate_user_account"
	qListActivePlans             = "list_active_plans"
)

// MaxRegistrationAttempts caps brute-force attempts on a pending
// registration / password-reset confirmation row. After this many
// mismatches the row is marked expired and the user must request a
// fresh confirmation. 5 mirrors MaxLoginTokenAttempts so a guessing
// attacker has at most 5 tries per minted code regardless of code
// length.
const MaxRegistrationAttempts = 5

// RegistrationConfirmationTTL is the lifetime of a pending registration
// row. Past this window the qGetUserRegistration query no longer
// returns the row, so a code that was minted but never used cannot be
// brute-forced indefinitely. The previous implementation had no TTL
// filter, leaving codes valid forever until consumed.
const RegistrationConfirmationTTL = 15 * time.Minute

var registerQueries = map[string]string{
	qAddUserRegistration: `
INSERT INTO user_registration
 (user_email, confirmation, payload)
VALUES
 (?, ?, ?)
`,
	// Returns (confirmation, payload, attempts) for the latest pending
	// row that's still inside the TTL. The TTL filter is what stops a
	// minted-but-unused code from being brute-forced indefinitely; the
	// attempts column is read so callers can decide whether to bump or
	// expire on mismatch.
	qGetUserRegistration: "SELECT confirmation, payload, attempts FROM user_registration WHERE user_email = ? AND status = 'P' AND created_at > ? ORDER BY created_at DESC LIMIT 1",
	qSetUserRegistration: "UPDATE user_registration SET confirmed_at = CURRENT_TIMESTAMP, status = 'C' WHERE user_email = ? AND status = 'P'",
	// Atomic-bump: returns post-increment attempts when a pending row
	// exists for (email, confirmation), or zero rows otherwise.
	qBumpRegistrationAttempts: `
UPDATE user_registration
   SET attempts = attempts + 1
 WHERE user_email = ?
   AND confirmation = ?
   AND status = 'P'
RETURNING attempts
`,
	// Expire all pending rows for an email. Called when MaxRegistration-
	// Attempts is crossed so the attacker cannot keep guessing.
	qExpireRegistration: "UPDATE user_registration SET status = 'X' WHERE user_email = ? AND status = 'P'",
	qAddPartner: `
INSERT INTO business_partner
 (id, caption)
VALUES
 (nextval('business_partner_seq'), ?)
RETURNING id
`,
	qAddAddress: `
INSERT INTO partner_address
 (partner_id, address, city, state, zipcode, country, phone, latitude, longitude)
VALUES
 (?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
	qAddDomain: `
INSERT INTO partner_domain
 (partner_id, domain_url, is_primary)
VALUES
 (?, ?, TRUE)
`,
	qAddUserAccount: `
INSERT INTO user_account
 (id, first_name, last_name, user_name, user_email, status, passtext, passdate, login_attempts)
VALUES
 (?, ?, ?, ?, ?, 'I', ?, CURRENT_TIMESTAMP, 0)
`,
	qAddPartnerUser: `
INSERT INTO partner_user
 (partner_id, user_id, begda)
VALUES
 (?, ?, CURRENT_TIMESTAMP)
`,
	qAddUserPermission: `
INSERT INTO user_permission
 (user_id, role_id, begda)
VALUES
 (?, 'PARTNER_ADMIN', CURRENT_TIMESTAMP)
`,
	qGetPlan: `
SELECT id, monthly_cost, currency FROM subscription_plan WHERE id = ?
`,
	qAddSubscription: `
INSERT INTO partner_plan_subscription
 (partner_id, plan_id, begda, status, monthly_cost, currency, auto_renew)
VALUES
 (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, TRUE)
`,
	qActivateSubscription: `
UPDATE partner_plan_subscription
   SET status = 'A'
 WHERE partner_id = ? AND plan_id = ? AND status = 'P'
`,
	qActivateUserAccount: `
UPDATE user_account
   SET status = 'A'
 WHERE id = ?
`,
	qListActivePlans: `
SELECT id, caption, monthly_cost, annual_cost
  FROM subscription_plan
 ORDER BY monthly_cost
`,
}

type PartnerRegistration struct {
	FirstName      string  `json:"firstName"`
	LastName       string  `json:"lastName"`
	UserName       string  `json:"userName"`
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	PartnerCaption string  `json:"partnerCaption"`
	Address        string  `json:"address"`
	City           string  `json:"city"`
	State          string  `json:"state"`
	Zipcode        string  `json:"zipcode"`
	Country        string  `json:"country"`
	Phone          string  `json:"phone"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	DomainURL      string  `json:"domainUrl"`
	PlanID         string  `json:"planId"`
}

// ConfirmRegisterResult tells the client how to route the user after a
// successful registration confirmation. For paid plans the subscription row
// is inserted with status='P' and the caller should send the user to the
// payment URL; on payment success, call ActivateSubscription to flip it to 'A'.
type ConfirmRegisterResult struct {
	PartnerID       int64  `json:"partnerId"`
	PlanID          string `json:"planId"`
	PaymentRequired bool   `json:"paymentRequired"`
	PaymentURL      string `json:"paymentUrl,omitempty"`
}

// PublicPlan is the reduced view of a subscription_plan surface-able to
// unauthenticated visitors on the registration page.
type PublicPlan struct {
	ID          string  `json:"id"`
	Caption     string  `json:"caption"`
	MonthlyCost float64 `json:"monthlyCost"`
	AnnualCost  float64 `json:"annualCost"`
}

type RegistrationService struct {
	Repo data.DatabaseRepository
	Mail MailSender
}

func (r *RegistrationService) SendConfirmation(ctx context.Context, data *PartnerRegistration) error {
	confirmation, err := generateConfirmationCode()
	if err != nil {
		return err
	}

	// Hash password before persisting in payload
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), EncryptionCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	payloadData := *data
	payloadData.Email = normalizeEmail(payloadData.Email)
	payloadData.Password = string(hashedPassword)
	bytes, err := json.Marshal(payloadData)
	if err != nil {
		return err
	}
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	_, err = qs.Query(ctx, qAddUserRegistration, payloadData.Email, confirmation, string(bytes))
	if err != nil {
		return err
	}

	subject := "Confirm your registration"
	body := fmt.Sprintf("Hello %s,\n\nPlease use the following confirmation code to complete your registration:\n\n%d\n", data.FirstName, confirmation)
	if err := r.Mail.SendEmail(ctx, subject, body, []string{data.Email}); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (r *RegistrationService) Register(ctx context.Context, email string, confirmation int) (*ConfirmRegisterResult, error) {
	// Validate confirmation code
	email = normalizeEmail(email)
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	cutoff := time.Now().Add(-RegistrationConfirmationTTL)
	res, err := qs.Query(ctx, qGetUserRegistration, email, cutoff)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		// Either no pending row, or the row is past TTL. Generic message
		// — never distinguish "expired" from "never existed" because that
		// leaks whether the email was registered.
		return nil, fmt.Errorf("invalid or expired confirmation")
	}
	expected := int(common.AsInt32(res.Rows[0][0]))
	attempts := int(common.AsInt32(res.Rows[0][2]))
	if attempts >= MaxRegistrationAttempts {
		_, _ = qs.Query(ctx, qExpireRegistration, email)
		return nil, fmt.Errorf("invalid or expired confirmation")
	}
	if confirmation != expected {
		// Atomic-bump the attempts counter on the row that ACTUALLY
		// matches the (email, expected) pair. If post-increment crosses
		// the cap, expire the row so the attacker cannot keep guessing
		// against fresh `attempts` reads.
		bumpRes, _ := qs.Query(ctx, qBumpRegistrationAttempts, email, expected)
		if bumpRes != nil && len(bumpRes.Rows) > 0 {
			if newAttempts := int(common.AsInt32(bumpRes.Rows[0][0])); newAttempts >= MaxRegistrationAttempts {
				_, _ = qs.Query(ctx, qExpireRegistration, email)
			}
		}
		return nil, fmt.Errorf("invalid or expired confirmation")
	}
	payload := []byte(common.AsString(res.Rows[0][1]))
	var data PartnerRegistration
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("failed to parse registration data: %w", err)
	}
	result, _, err := r.executeRegistration(ctx, &data, false)
	return result, err
}

// RegisterImmediately is the OAuth-verified-signup entry point: callers
// (e.g. Google Business Profile, Apple Sign-In) that have already verified
// the user's email skip the SendConfirmation/Register two-step and run the
// full transaction directly. Caller is responsible for bcrypt-hashing
// data.Password in advance (or passing empty if no password — passtext is
// nullable as of v0.5).
//
// The created user_account is left at status='I' (consistent with the
// email-confirmation flow). For an OAuth-verified flow that should land an
// already-active user with an in-memory session, use
// RegisterImmediatelyWithSession instead.
//
// No row is written to user_registration; if the user later tries to
// re-register via the standard email flow, GetUserByEmail / the unique
// index on user_email will short-circuit it cleanly.
func (r *RegistrationService) RegisterImmediately(ctx context.Context, data *PartnerRegistration) (*ConfirmRegisterResult, error) {
	if data == nil {
		return nil, fmt.Errorf("nil registration data")
	}
	normalized := *data
	normalized.Email = normalizeEmail(normalized.Email)
	result, _, err := r.executeRegistration(ctx, &normalized, true)
	return result, err
}

// RegisterImmediatelyWithSession is RegisterImmediately + activation +
// in-memory UserSession. Use this when the upstream OAuth provider has
// already authenticated the user and the caller wants to issue a JWT
// without a follow-up GetUserByLogin round-trip (which would require the
// caller to know data.Password — an obstacle for password-less social
// signups).
//
// Side effects beyond RegisterImmediately:
//   - user_account.status is flipped to 'A' (active) since OAuth-verified
//     signup has no email-confirmation gate.
//   - The returned UserSession is built from the freshly-inserted row and
//     is suitable for UserService.CreateJWT(session).
//
// data.Password may be empty for password-less providers — the session is
// authoritative for JWT, not the DB password column.
func (r *RegistrationService) RegisterImmediatelyWithSession(ctx context.Context, data *PartnerRegistration) (*ConfirmRegisterResult, *model.UserSession, error) {
	if data == nil {
		return nil, nil, fmt.Errorf("nil registration data")
	}
	normalized := *data
	normalized.Email = normalizeEmail(normalized.Email)

	result, userID, err := r.executeRegistration(ctx, &normalized, true)
	if err != nil {
		return nil, nil, err
	}

	// OAuth-verified signups land active immediately — no email confirmation
	// step to gate behind. We update via the existing query service rather
	// than spinning a new tx because the registration tx already committed.
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	if _, err := qs.Query(ctx, qActivateUserAccount, userID); err != nil {
		return nil, nil, fmt.Errorf("activate user_account: %w", err)
	}

	session := &model.UserSession{
		Id:          int(userID),
		Email:       normalized.Email,
		PartnerId:   result.PartnerID,
		FirstName:   normalized.FirstName,
		LastName:    normalized.LastName,
		PhoneNumber: normalized.Phone,
		Status:      "A",
	}
	return result, session, nil
}

// executeRegistration runs the full registration transaction (partner +
// address + domain + user_account + permission + subscription) given a
// fully-populated PartnerRegistration. When skipMarkRegistration is false,
// also writes qSetUserRegistration to mark the matching user_registration
// row confirmed; RegisterImmediately passes true to skip that since no
// user_registration row was ever written.
//
// Returns the freshly-created userID alongside the public result so callers
// like RegisterImmediatelyWithSession can build an in-memory UserSession
// without re-querying.
func (r *RegistrationService) executeRegistration(ctx context.Context, data *PartnerRegistration, skipMarkRegistration bool) (*ConfirmRegisterResult, int64, error) {
	qs := r.Repo.GetQueryService(ctx, registerQueries)

	// Resolve plan outside the transaction so a bad plan_id fails fast.
	planID := strings.ToUpper(strings.TrimSpace(data.PlanID))
	if planID == "" {
		planID = "FREE"
	}
	planRes, err := qs.Query(ctx, qGetPlan, planID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to look up plan %q: %w", planID, err)
	}
	if len(planRes.Rows) == 0 {
		return nil, 0, fmt.Errorf("unknown plan %q", planID)
	}
	monthlyCost := common.AsFloat64(planRes.Rows[0][1])
	currency := common.AsString(planRes.Rows[0][2])
	if currency == "" {
		currency = "USD"
	}
	paymentRequired := monthlyCost > 0
	subStatus := "A"
	if paymentRequired {
		subStatus = "P"
	}

	tx, err := r.Repo.BeginTx(ctx, registerQueries)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback(ctx)

	ids, err := tx.Query(ctx, qAddPartner, data.PartnerCaption)
	if err != nil {
		return nil, 0, fmt.Errorf("add partner: %w", err)
	}
	partnerID := common.AsInt64(ids.Rows[0][0])

	if _, err := tx.Query(ctx, qAddAddress, partnerID, data.Address, data.City, data.State, data.Zipcode, data.Country, data.Phone, data.Latitude, data.Longitude); err != nil {
		return nil, 0, fmt.Errorf("add address: %w", err)
	}
	if _, err := tx.Query(ctx, qAddDomain, partnerID, data.DomainURL); err != nil {
		return nil, 0, fmt.Errorf("add domain: %w", err)
	}

	// Password is already bcrypt-hashed in the payload (or empty for
	// password-less social signups).
	userID := tx.GenID()
	if _, err := tx.Query(ctx, qAddUserAccount, userID, data.FirstName, data.LastName, data.UserName, data.Email, data.Password); err != nil {
		return nil, 0, classifyUniqueViolation(err)
	}
	if _, err := tx.Query(ctx, qAddPartnerUser, partnerID, userID); err != nil {
		return nil, 0, fmt.Errorf("add partner_user: %w", err)
	}
	if _, err := tx.Query(ctx, qAddUserPermission, userID); err != nil {
		return nil, 0, fmt.Errorf("add user_permission: %w", err)
	}
	if _, err := tx.Query(ctx, qAddSubscription, partnerID, planID, subStatus, monthlyCost, currency); err != nil {
		return nil, 0, fmt.Errorf("add subscription: %w", err)
	}
	if !skipMarkRegistration {
		if _, err := tx.Query(ctx, qSetUserRegistration, data.Email); err != nil {
			return nil, 0, fmt.Errorf("mark user_registration: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}

	return &ConfirmRegisterResult{
		PartnerID:       partnerID,
		PlanID:          planID,
		PaymentRequired: paymentRequired,
		PaymentURL:      buildPaymentURL(partnerID, planID, paymentRequired),
	}, userID, nil
}

// buildPaymentURL is a stub that points to a frontend checkout route. When the
// payment integration lands (Stripe / similar), replace this with a real
// Checkout Session URL generated server-side.
func buildPaymentURL(partnerID int64, planID string, paymentRequired bool) string {
	if !paymentRequired {
		return ""
	}
	return fmt.Sprintf("/payment/checkout?partnerId=%d&planId=%s", partnerID, planID)
}

// ActivateSubscription flips a pending subscription to active. Call this from
// the payment success callback / webhook once funds have cleared.
func (r *RegistrationService) ActivateSubscription(ctx context.Context, partnerID int64, planID string) error {
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	_, err := qs.Query(ctx, qActivateSubscription, partnerID, strings.ToUpper(strings.TrimSpace(planID)))
	return err
}

// ListPlans returns the public view of all subscription plans. Used by the
// unauthenticated registration page to render a plan picker.
func (r *RegistrationService) ListPlans(ctx context.Context) ([]PublicPlan, error) {
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	res, err := qs.Query(ctx, qListActivePlans)
	if err != nil {
		return nil, err
	}
	out := make([]PublicPlan, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, PublicPlan{
			ID:          common.AsString(row[0]),
			Caption:     common.AsString(row[1]),
			MonthlyCost: common.AsFloat64(row[2]),
			AnnualCost:  common.AsFloat64(row[3]),
		})
	}
	return out, nil
}

func (r *RegistrationService) SendPasswordChangeConfirmation(ctx context.Context, email string) error {
	confirmation, err := generateConfirmationCode()
	if err != nil {
		return err
	}
	normalized := normalizeEmail(email)
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	_, err = qs.Query(ctx, qAddUserRegistration, normalized, confirmation, "")
	if err != nil {
		return err
	}

	subject := "Confirm your password change"
	body := fmt.Sprintf("Hello,\n\nPlease use the following confirmation code to complete your password change:\n\n%d\n\nIf you did not request this change, please ignore this email.\n", confirmation)
	if err := r.Mail.SendEmail(ctx, subject, body, []string{email}); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (r *RegistrationService) ConfirmPasswordChange(ctx context.Context, email string, confirmation int) error {
	email = normalizeEmail(email)
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	cutoff := time.Now().Add(-RegistrationConfirmationTTL)
	res, err := qs.Query(ctx, qGetUserRegistration, email, cutoff)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("invalid or expired confirmation")
	}
	expected := int(common.AsInt32(res.Rows[0][0]))
	attempts := int(common.AsInt32(res.Rows[0][2]))
	if attempts >= MaxRegistrationAttempts {
		_, _ = qs.Query(ctx, qExpireRegistration, email)
		return fmt.Errorf("invalid or expired confirmation")
	}
	if confirmation != expected {
		bumpRes, _ := qs.Query(ctx, qBumpRegistrationAttempts, email, expected)
		if bumpRes != nil && len(bumpRes.Rows) > 0 {
			if newAttempts := int(common.AsInt32(bumpRes.Rows[0][0])); newAttempts >= MaxRegistrationAttempts {
				_, _ = qs.Query(ctx, qExpireRegistration, email)
			}
		}
		return fmt.Errorf("invalid or expired confirmation")
	}
	_, err = qs.Query(ctx, qSetUserRegistration, email)
	return err
}
