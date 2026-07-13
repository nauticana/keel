package user

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
	"golang.org/x/crypto/bcrypt"
)

// MailSender is the minimal mail-transport contract the registration
// flow needs. dispatcher.MailClient satisfies it; declaring it here
// rather than importing dispatcher keeps user/ free of the dispatcher
// package — dispatcher imports user (UserService) for SMS/email
// recipient resolution, and that direction must stay one-way.
type MailSender interface {
	SendEmail(ctx context.Context, subject string, body string, recipients []string, headers map[string]string) error
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
	qAddUserRegistration      = "add_user_registration"
	qGetUserRegistration      = "get_user_registration"
	qSetUserRegistration      = "set_user_registration"
	qBumpRegistrationAttempts = "bump_registration_attempts"
	qExpireRegistration       = "expire_registration"
	qAddPartner               = "add_partner"
	qAddAddress               = "add_address"
	qAddDomain                = "add_domain"
	qAddUserAccount           = "add_user_account"
	qAddPartnerUser           = "add_partner_user"
	qAddUserPermission        = "add_user_permission"
	qGetPlan                  = "get_plan"
	qPlanPrices               = "plan_prices"
	qAddSubscription          = "add_subscription"
	qActivateSubscription     = "activate_subscription"
	qActivateUserAccount      = "activate_user_account"
	qListActivePlans          = "list_active_plans"
)

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
SELECT currency FROM subscription_plan WHERE id = ? AND is_active = TRUE
`,
	qPlanPrices: `
SELECT billing_cycle, term_type, term_count, amount_minor, currency
  FROM subscription_plan_price WHERE plan_id = ?
`,
	qAddSubscription: `
INSERT INTO partner_plan_subscription
 (partner_id, plan_id, begda, status, monthly_cost, currency, auto_renew,
  billing_cycle, term_count, term_type, amount_minor, renewal_date, next_charge_date)
VALUES
 (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, TRUE, ?, ?, ?, ?, ?, ?)
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
SELECT sp.id, sp.caption, sp.activation_mode, sp.trial_days,
       pp.billing_cycle, pp.term_count, pp.term_type, pp.amount_minor, pp.currency, pp.provider_price_id
  FROM subscription_plan sp
  LEFT JOIN subscription_plan_price pp ON pp.plan_id = sp.id
 WHERE sp.is_active = TRUE
 ORDER BY sp.id, pp.term_type, pp.term_count, pp.billing_cycle
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
	// Chosen offer (optional; from the plan's subscription_plan_price rows). When
	// omitted, registration uses the plan's cheapest offer. PERIOD_TYPE codes.
	BillingCycle string `json:"billingCycle,omitempty"`
	TermType     string `json:"termType,omitempty"`
	TermCount    int    `json:"termCount,omitempty"`
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

// PublicPlan is the unauthenticated registration-page view of a plan. Prices is
// the same per-offer shape as billing.GetPlans so the shared sail price selector
// works without auth.
type PublicPlan struct {
	ID             string              `json:"id"`
	Caption        string              `json:"caption"`
	ActivationMode string              `json:"activationMode"` // drives the registration CTA (trial vs subscribe)
	TrialDays      int                 `json:"trialDays"`
	Prices         []billing.PlanPrice `json:"prices"`
}

// subscriptionOffer is the resolved price + schedule snapshot for the sub row a
// registration creates. The NULLable fields are nil for a free plan.
type subscriptionOffer struct {
	paymentRequired bool
	monthlyCost     float64 // per-installment display (major); 0 for free
	currency        string  // offer currency ("" for free → caller keeps plan currency)
	billingCycle    any
	termType        any
	termCount       any
	amountMinor     any
	renewalDate     any
	nextChargeDate  any
}

// resolveSubscriptionOffer picks the offer a registration should snapshot from a
// plan's subscription_plan_price rows. No rows (or a zero-priced match) → free.
// Requested terms must match an offer; with none requested, the cheapest is used.
// The first installment is collected via the checkout PaymentURL, so
// next_charge_date is the SECOND installment (the engine takes over from there).
func resolveSubscriptionOffer(rows [][]any, data *PartnerRegistration, currency string, now time.Time) (subscriptionOffer, error) {
	if len(rows) == 0 {
		return subscriptionOffer{}, nil // free plan
	}
	idx := -1
	if data.BillingCycle != "" || data.TermType != "" || data.TermCount > 0 {
		wc := billing.ParseBillingPeriod(data.BillingCycle).Code()
		wt := billing.ParseBillingPeriod(data.TermType).Code()
		wn := data.TermCount
		if wn < 1 {
			wn = 1
		}
		for i, row := range rows {
			if common.AsString(row[0]) == wc && common.AsString(row[1]) == wt && int(common.AsInt32(row[2])) == wn {
				idx = i
				break
			}
		}
		if idx < 0 {
			return subscriptionOffer{}, fmt.Errorf("plan does not offer the selected terms (%s/%d%s)", wc, wn, wt)
		}
	} else {
		for i := range rows {
			if idx < 0 || common.AsInt64(rows[i][3]) < common.AsInt64(rows[idx][3]) {
				idx = i
			}
		}
	}

	row := rows[idx]
	amount := common.AsInt64(row[3])
	if amount <= 0 {
		return subscriptionOffer{}, nil // zero-priced offer = free
	}
	terms := billing.BillingTerms{
		BillingCycle: billing.ParseBillingPeriod(common.AsString(row[0])),
		TermType:     billing.ParseBillingPeriod(common.AsString(row[1])),
		TermCount:    int(common.AsInt32(row[2])),
	}
	n, err := terms.TotalInstallments()
	if err != nil {
		return subscriptionOffer{}, err
	}
	tc := terms.TermCount
	if tc < 1 {
		tc = 1
	}
	return subscriptionOffer{
		paymentRequired: true,
		monthlyCost:     payment.MinorToMajor(billing.InstallmentMinor(terms.ContractTotalMinor(amount), n, 0), common.AsString(row[4])),
		currency:        common.AsString(row[4]),
		billingCycle:    terms.BillingCycle.Code(),
		termType:        terms.TermType.Code(),
		termCount:       tc,
		amountMinor:     amount,
		renewalDate:     terms.TermEnd(now),
		nextChargeDate:  terms.BillingCycle.NextRenewal(now),
	}, nil
}

type RegistrationService struct {
	Repo port.DatabaseRepository
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
	if err := r.Mail.SendEmail(ctx, subject, body, []string{data.Email}, nil); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (r *RegistrationService) Register(ctx context.Context, email string, confirmation int) (*ConfirmRegisterResult, error) {
	// Validate confirmation code
	email = normalizeEmail(email)
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	cutoff := time.Now().Add(-common.Config().RegistrationConfirmationTTL)
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
	if attempts >= common.Config().MaxRegistrationAttempts {
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
			if newAttempts := int(common.AsInt32(bumpRes.Rows[0][0])); newAttempts >= common.Config().MaxRegistrationAttempts {
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
	currency := common.AsString(planRes.Rows[0][0])
	if currency == "" {
		currency = "USD"
	}

	// Resolve the chosen offer from subscription_plan_price. A plan with no price
	// rows is free; otherwise pick the requested terms (or the cheapest offer).
	priceRes, err := qs.Query(ctx, qPlanPrices, planID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to look up prices for plan %q: %w", planID, err)
	}
	sub, err := resolveSubscriptionOffer(priceRes.Rows, data, currency, time.Now().UTC())
	if err != nil {
		return nil, 0, err
	}
	if sub.currency != "" {
		currency = sub.currency
	}
	subStatus := "A"
	if sub.paymentRequired {
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
	if _, err := tx.Query(ctx, qAddSubscription, partnerID, planID, subStatus, sub.monthlyCost, currency,
		sub.billingCycle, sub.termCount, sub.termType, sub.amountMinor, sub.renewalDate, sub.nextChargeDate); err != nil {
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
		PaymentRequired: sub.paymentRequired,
		PaymentURL:      buildPaymentURL(partnerID, planID, sub.paymentRequired),
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
	// One row per (plan, offer); group by plan id, preserving query order.
	order := make([]string, 0, len(res.Rows))
	byID := make(map[string]*PublicPlan, len(res.Rows))
	for _, row := range res.Rows {
		id := common.AsString(row[0])
		p, ok := byID[id]
		if !ok {
			p = &PublicPlan{
				ID:             id,
				Caption:        common.AsString(row[1]),
				ActivationMode: common.AsString(row[2]),
				TrialDays:      int(common.AsInt32(row[3])),
			}
			byID[id] = p
			order = append(order, id)
		}
		cycle := common.AsString(row[4]) // empty when the plan has no price rows (LEFT JOIN)
		if cycle == "" {
			continue
		}
		price := billing.PlanPrice{
			BillingCycle: cycle,
			TermCount:    int(common.AsInt32(row[5])),
			TermType:     common.AsString(row[6]),
			AmountMinor:  common.AsInt64(row[7]),
			Currency:     common.AsString(row[8]),
			PriceID:      common.AsString(row[9]),
		}
		price.Amount = payment.MinorToMajor(price.AmountMinor, price.Currency)
		p.Prices = append(p.Prices, price)
	}
	out := make([]PublicPlan, len(order))
	for i, id := range order {
		out[i] = *byID[id]
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
	if err := r.Mail.SendEmail(ctx, subject, body, []string{email}, nil); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (r *RegistrationService) ConfirmPasswordChange(ctx context.Context, email string, confirmation int) error {
	email = normalizeEmail(email)
	qs := r.Repo.GetQueryService(ctx, registerQueries)
	cutoff := time.Now().Add(-common.Config().RegistrationConfirmationTTL)
	res, err := qs.Query(ctx, qGetUserRegistration, email, cutoff)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("invalid or expired confirmation")
	}
	expected := int(common.AsInt32(res.Rows[0][0]))
	attempts := int(common.AsInt32(res.Rows[0][2]))
	if attempts >= common.Config().MaxRegistrationAttempts {
		_, _ = qs.Query(ctx, qExpireRegistration, email)
		return fmt.Errorf("invalid or expired confirmation")
	}
	if confirmation != expected {
		bumpRes, _ := qs.Query(ctx, qBumpRegistrationAttempts, email, expected)
		if bumpRes != nil && len(bumpRes.Rows) > 0 {
			if newAttempts := int(common.AsInt32(bumpRes.Rows[0][0])); newAttempts >= common.Config().MaxRegistrationAttempts {
				_, _ = qs.Query(ctx, qExpireRegistration, email)
			}
		}
		return fmt.Errorf("invalid or expired confirmation")
	}
	_, err = qs.Query(ctx, qSetUserRegistration, email)
	return err
}
