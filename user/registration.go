package user

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
	"golang.org/x/crypto/bcrypt"
)

// BusinessEmail is an EmailPolicy that refuses free consumer mailboxes.
func BusinessEmail(email string) error {
	at := domain.DomainFromEmail(email)
	if at == "" || domain.IsPublicDomain(at) {
		return ErrPublicEmail
	}
	return nil
}

// confirmationRange keeps emailed codes at exactly 8 digits.
const confirmationRange = 90000000

func generateConfirmationCode() (int, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(confirmationRange))
	if err != nil {
		return 0, fmt.Errorf("registration: rng: %w", err)
	}
	return int(n.Int64()) + 10000000, nil
}

// RegistrationService creates accounts and their partners: by emailed code,
// for a verified external identity, or for a signed-in user.
type RegistrationService struct {
	Repo port.DatabaseRepository
	Mail MailSender
	// Users applies the password and sign-in policies and builds sessions.
	Users UserService
	// Domains records a partner domain's evidence in the partner transaction.
	// Given no evidence, it proves the domain by the account's verified email
	// (VE) when that holds. RequireDomainProof refuses a domain left unproven.
	Domains            *domain.Service
	RequireDomainProof bool
	// Checkout opens the checkout of a plan that activates at checkout, priced
	// by the offer's provider_price_id. Nil leaves PaymentURL empty.
	Checkout           payment.CheckoutClient
	CheckoutSuccessURL string
	CheckoutCancelURL  string
	// Roles are granted to a partner's creator and must be partner-scoped.
	// Nil grants PARTNER_ADMIN.
	Roles []string
	// EmailPolicy screens the address of an emailed-code signup.
	EmailPolicy func(email string) error
	// OnPartnerTx writes the application's rows for a new partner in its
	// transaction; bind the application's query catalog with port.TxQueryCatalog.
	OnPartnerTx func(ctx context.Context, tx port.TxQueryService, partnerID, userID int64, setup *PartnerSetup) error

	once    sync.Once
	initErr error
	qs      port.QueryService
	txMap   map[string]string
}

var errNoUsers = errors.New("user: RegistrationService.Users is required")

func (r *RegistrationService) init(ctx context.Context) error {
	r.once.Do(func() {
		switch {
		case r.Repo == nil:
			r.initErr = errors.New("user: RegistrationService.Repo is required")
		case r.RequireDomainProof && r.Domains == nil:
			r.initErr = errors.New("user: RequireDomainProof needs Domains")
		case r.Checkout != nil && (r.CheckoutSuccessURL == "" || r.CheckoutCancelURL == ""):
			r.initErr = errors.New("user: Checkout needs CheckoutSuccessURL and CheckoutCancelURL")
		}
		if r.initErr != nil {
			return
		}
		r.txMap = common.MergeMaps(registerQueries, domain.TxQueries())
		r.qs = r.Repo.GetQueryService(ctx, registerQueries)
	})
	return r.initErr
}

// SendConfirmation stores a pending registration and emails its code.
func (r *RegistrationService) SendConfirmation(ctx context.Context, data *PartnerRegistration) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	if r.Users == nil || r.Mail == nil {
		return errors.New("user: SendConfirmation needs Users and Mail")
	}
	if data == nil {
		return model.NewBadRequest("registration is required")
	}
	if err := r.codeSignupAllowed(); err != nil {
		return err
	}
	reg := *data
	if err := r.validateAccount(&reg.AccountRegistration); err != nil {
		return err
	}
	if !reg.PartnerSetup.empty() {
		if err := reg.PartnerSetup.validate(); err != nil {
			return err
		}
		if err := r.checkRegion(ctx, &reg.PartnerSetup); err != nil {
			return err
		}
		if err := r.requireDomain(&reg.PartnerSetup); err != nil {
			return err
		}
		if r.RequireDomainProof {
			err := domain.MailboxOnDomain(reg.Email, reg.DomainURL)
			if errors.Is(err, domain.ErrRecipient) {
				return domain.ErrDomainNotProven
			}
			if err != nil {
				return err
			}
		}
	}
	if reg.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(reg.Password), EncryptionCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		reg.Password = string(hashed)
	}
	payload, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	confirmation, err := generateConfirmationCode()
	if err != nil {
		return err
	}
	if _, err := r.qs.Query(ctx, qAddUserRegistration, reg.Email, confirmation, string(payload)); err != nil {
		return err
	}
	body := fmt.Sprintf("Hello %s,\n\nPlease use the following confirmation code to complete your registration:\n\n%d\n", reg.FirstName, confirmation)
	if err := r.Mail.SendEmail(ctx, "Confirm your registration", body, []string{reg.Email}, nil); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}
	return nil
}

// codeSignupAllowed refuses an emailed-code signup the global sign-in policy
// would not let sign in, before an account is created.
func (r *RegistrationService) codeSignupAllowed() error {
	policies, err := r.Users.EffectivePolicies(0)
	if err != nil {
		return fmt.Errorf("user: sign-in policy lookup: %w", err)
	}
	if !ssoAdmits(policies[PolicySSORequired], SignInOTP) {
		return ErrSSORequired
	}
	return nil
}

func (r *RegistrationService) validateAccount(a *AccountRegistration) error {
	a.Email = normalizeEmail(a.Email)
	if strings.Count(a.Email, "@") != 1 || strings.ContainsAny(a.Email, " \r\n,;<>") {
		return model.NewBadRequest("a valid email is required")
	}
	if a.UserName = strings.TrimSpace(a.UserName); a.UserName == "" {
		a.UserName = a.Email
	}
	// Login resolves user_name before user_email, so a name shaped like an
	// address would shadow that address's owner.
	if strings.Contains(a.UserName, "@") && a.UserName != a.Email {
		return model.NewBadRequest("userName must not be another email address")
	}
	if r.EmailPolicy != nil {
		if err := r.EmailPolicy(a.Email); err != nil {
			return err
		}
	}
	if a.Password != "" {
		policy := r.Users.GetPasswordPolicy()
		if err := policy.Check(a.Password); err != nil {
			return model.NewBadRequest(err.Error())
		}
	}
	return nil
}

// Register confirms an emailed code and creates the active account, and its
// partner when the registration has one, in one transaction. The session
// signed in by one-time code.
func (r *RegistrationService) Register(ctx context.Context, email string, confirmation int) (*model.UserSession, *PartnerCreated, error) {
	if err := r.init(ctx); err != nil {
		return nil, nil, err
	}
	if r.Users == nil {
		return nil, nil, errNoUsers
	}
	if err := r.codeSignupAllowed(); err != nil {
		return nil, nil, err
	}
	email = normalizeEmail(email)
	payload, err := r.checkConfirmation(ctx, email, confirmation)
	if err != nil {
		return nil, nil, err
	}
	var reg PartnerRegistration
	if err := json.Unmarshal([]byte(payload), &reg); err != nil || reg.Email != email {
		return nil, nil, ErrInvalidConfirmation // a password-reset code
	}
	withPartner := !reg.PartnerSetup.empty()
	var plan *planChoice
	if withPartner {
		if plan, err = r.preparePartner(ctx, &reg.PartnerSetup, nil); err != nil {
			return nil, nil, err
		}
	}

	tx, err := r.Repo.BeginTx(ctx, r.txMap)
	if err != nil {
		return nil, nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	userID := tx.GenID()
	if _, err := tx.Query(ctx, qAddUserAccount, userID, reg.FirstName, reg.LastName, reg.UserName, email, nullIfEmpty(reg.Password)); err != nil {
		return nil, nil, classifyUniqueViolation(err)
	}
	var created *PartnerCreated
	if withPartner {
		if created, err = r.createPartnerTx(ctx, tx, userID, &reg.PartnerSetup, nil, plan); err != nil {
			return nil, nil, err
		}
	}
	if _, err := tx.Query(ctx, qSetUserRegistration, email); err != nil {
		return nil, nil, fmt.Errorf("mark user_registration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	committed = true

	session, err := signedIn(r.Users, int(userID), SignInOTP)
	if err != nil {
		return nil, nil, err
	}
	return session, created, r.checkout(ctx, created, plan, userID)
}

// RegisterWithIdentity creates the account of an external identity the
// caller verified and its partner in one transaction, and signs it in.
// evidence, from Domains.Check, proves setup's domain. An identity or email
// of an existing account returns ErrAccountExists.
func (r *RegistrationService) RegisterWithIdentity(ctx context.Context, identity ExternalIdentity, consent *SignupConsent,
	setup *PartnerSetup, evidence *domain.Evidence) (*model.UserSession, *PartnerCreated, error) {
	if err := r.init(ctx); err != nil {
		return nil, nil, err
	}
	if r.Users == nil {
		return nil, nil, errNoUsers
	}
	plan, err := r.preparePartner(ctx, setup, evidence)
	if err != nil {
		return nil, nil, err
	}
	creator, ok := r.Users.(IdentityAccountCreator)
	if !ok {
		return nil, nil, errors.New("user: RegisterWithIdentity needs IdentityAccountCreator")
	}
	tx, err := r.Repo.BeginTx(ctx, r.txMap)
	if err != nil {
		return nil, nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	account, err := creator.CreateIdentityAccountTx(ctx, tx, identity)
	if err != nil {
		return nil, nil, err
	}
	created, err := r.createPartnerTx(ctx, tx, int64(account.Id), setup, evidence, plan)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	committed = true
	var consentErr error
	if err := creator.RecordSignupConsent(account.Id, account.Email, consent); err != nil {
		consentErr = fmt.Errorf("%w: %w", ErrConsentNotRecorded, err)
	}
	method, err := r.Users.ExternalSignInMethod(created.PartnerID, identity)
	if err != nil {
		return nil, nil, errors.Join(consentErr, err)
	}
	session, err := signedIn(r.Users, account.Id, method)
	if err != nil {
		return nil, nil, errors.Join(consentErr, err)
	}
	return session, created, errors.Join(consentErr, r.checkout(ctx, created, plan, int64(account.Id)))
}

// CreatePartner creates a partner for a signed-in user who has none and makes
// the user its member with Roles. evidence, from Domains.Check, proves
// setup's domain. The user's next token refresh carries the partner.
func (r *RegistrationService) CreatePartner(ctx context.Context, userID int64, setup *PartnerSetup, evidence *domain.Evidence) (*PartnerCreated, error) {
	if err := r.init(ctx); err != nil {
		return nil, err
	}
	if userID <= 0 {
		return nil, errors.New("user: user id is required")
	}
	plan, err := r.preparePartner(ctx, setup, evidence)
	if err != nil {
		return nil, err
	}
	created, err := r.createPartner(ctx, userID, setup, evidence, plan)
	if err != nil {
		return nil, err
	}
	return created, r.checkout(ctx, created, plan, userID)
}

func (r *RegistrationService) preparePartner(ctx context.Context, setup *PartnerSetup, evidence *domain.Evidence) (*planChoice, error) {
	if setup == nil {
		return nil, model.NewBadRequest("partner setup is required")
	}
	if err := setup.validate(); err != nil {
		return nil, err
	}
	if err := r.checkRegion(ctx, setup); err != nil {
		return nil, err
	}
	if err := r.requireDomain(setup); err != nil {
		return nil, err
	}
	if evidence != nil && (r.Domains == nil || setup.DomainURL == "") {
		return nil, errors.New("user: domain evidence needs Domains and a partner domain")
	}
	return r.resolvePlan(ctx, setup)
}

// checkRegion refuses a country or state code the catalog does not hold,
// before any write.
func (r *RegistrationService) checkRegion(ctx context.Context, setup *PartnerSetup) error {
	country, state := setup.region()
	if country == "" {
		return nil
	}
	res, err := r.qs.Query(ctx, qCountryExists, country)
	if err != nil {
		return fmt.Errorf("failed to look up country %q: %w", country, err)
	}
	if len(res.Rows) == 0 {
		return model.NewBadRequest(fmt.Sprintf("unknown country %q", country))
	}
	if state == "" {
		return nil
	}
	if res, err = r.qs.Query(ctx, qStateExists, country, state); err != nil {
		return fmt.Errorf("failed to look up state %q of %q: %w", state, country, err)
	}
	if len(res.Rows) == 0 {
		return model.NewBadRequest(fmt.Sprintf("unknown state %q of country %q", state, country))
	}
	return nil
}

// resolvePlan resolves the plan and offer before any write, so a bad plan
// fails without an orphan account or partner. No plan selects FREE.
func (r *RegistrationService) resolvePlan(ctx context.Context, setup *PartnerSetup) (*planChoice, error) {
	planID := strings.ToUpper(strings.TrimSpace(setup.PlanID))
	if planID == "" {
		planID = "FREE"
	}
	res, err := r.qs.Query(ctx, qGetPlan, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up plan %q: %w", planID, err)
	}
	if len(res.Rows) == 0 {
		return nil, model.NewBadRequest(fmt.Sprintf("unknown plan %q", planID))
	}
	plan := &planChoice{id: planID, currency: common.AsString(res.Rows[0][0])}
	if plan.currency == "" {
		plan.currency = "USD"
	}
	prices, err := r.qs.Query(ctx, qPlanPrices, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up prices for plan %q: %w", planID, err)
	}
	if plan.offer, err = resolveSubscriptionOffer(prices.Rows, setup, common.AsString(res.Rows[0][1]), time.Now().UTC()); err != nil {
		return nil, err
	}
	if plan.offer.currency != "" {
		plan.currency = plan.offer.currency
	}
	if plan.offer.paymentRequired && r.Checkout != nil && plan.offer.providerPriceID == "" {
		return nil, fmt.Errorf("user: plan %q offer has no provider_price_id", planID)
	}
	return plan, nil
}

func (r *RegistrationService) createPartner(ctx context.Context, userID int64, setup *PartnerSetup, evidence *domain.Evidence, plan *planChoice) (*PartnerCreated, error) {
	tx, err := r.Repo.BeginTx(ctx, r.txMap)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	created, err := r.createPartnerTx(ctx, tx, userID, setup, evidence, plan)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return created, nil
}

func (r *RegistrationService) createPartnerTx(ctx context.Context, tx port.TxQueryService, userID int64, setup *PartnerSetup,
	evidence *domain.Evidence, plan *planChoice) (*PartnerCreated, error) {
	host, err := setup.host()
	if err != nil {
		return nil, err
	}
	ids, err := tx.Query(ctx, qAddPartner, strings.TrimSpace(setup.PartnerCaption))
	if err != nil {
		return nil, fmt.Errorf("add partner: %w", err)
	}
	if len(ids.Rows) == 0 {
		return nil, errors.New("add partner: no id returned")
	}
	partnerID := common.AsInt64(ids.Rows[0][0])
	country, state := setup.region()
	latitude, longitude := setup.coordinates()
	if _, err := tx.Query(ctx, qAddAddress, partnerID, setup.Address, nullIfBlank(setup.City), nullIfEmpty(state),
		nullIfBlank(setup.Zipcode), nullIfEmpty(country), nullIfBlank(setup.Phone), latitude, longitude); err != nil {
		return nil, fmt.Errorf("add address: %w", err)
	}
	if host != "" {
		if _, err := tx.Query(ctx, qAddDomain, partnerID, host); err != nil {
			return nil, fmt.Errorf("add domain: %w", err)
		}
	}
	if _, err := tx.Query(ctx, qAddPartnerUser, partnerID, userID); err != nil {
		if pgsql.IsExclusionViolation(err) {
			return nil, ErrAlreadyMember
		}
		return nil, fmt.Errorf("add partner_user: %w", err)
	}
	if err := r.grantRoles(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err := r.recordDomain(ctx, tx, partnerID, userID, host, evidence); err != nil {
		return nil, err
	}
	o := plan.offer
	if o.status != "" {
		if _, err := tx.Query(ctx, qAddSubscription, partnerID, plan.id, o.status, o.monthlyCost, plan.currency,
			o.billingCycle, o.termCount, o.termType, o.amountMinor, o.renewalDate, o.nextChargeDate); err != nil {
			return nil, fmt.Errorf("add subscription: %w", err)
		}
	}
	if r.OnPartnerTx != nil {
		if err := r.OnPartnerTx(ctx, tx, partnerID, userID, setup); err != nil {
			return nil, err
		}
	}
	return &PartnerCreated{PartnerID: partnerID, PlanID: plan.id, PaymentRequired: o.paymentRequired}, nil
}

func (r *RegistrationService) grantRoles(ctx context.Context, tx port.TxQueryService, userID int64) error {
	roles := r.Roles
	if roles == nil {
		roles = []string{"PARTNER_ADMIN"}
	}
	granted := map[string]bool{}
	for _, role := range roles {
		if granted[role] {
			continue
		}
		res, err := tx.Query(ctx, qAddPartnerRole, userID, role)
		if err != nil {
			return fmt.Errorf("grant role %s: %w", role, err)
		}
		if len(res.Rows) == 0 {
			return fmt.Errorf("user: role %q is not a partner-scoped role", role)
		}
		granted[role] = true
	}
	return nil
}

// requireDomain refuses a partner without a domain when RequireDomainProof is set.
func (r *RegistrationService) requireDomain(setup *PartnerSetup) error {
	if r.RequireDomainProof && strings.TrimSpace(setup.DomainURL) == "" {
		return model.NewBadRequest("domainUrl is required")
	}
	return nil
}

// recordDomain records evidence for the partner's domain: the given one, else
// the account's verified email when it proves the domain. With
// RequireDomainProof a partner without proven domain is refused.
func (r *RegistrationService) recordDomain(ctx context.Context, tx port.TxQueryService, partnerID, userID int64, host string, evidence *domain.Evidence) error {
	if host == "" {
		if r.RequireDomainProof {
			return domain.ErrDomainNotProven
		}
		return nil
	}
	if evidence == nil && r.Domains != nil {
		res, err := tx.Query(ctx, qRegistrantEmail, userID)
		if err != nil {
			return err
		}
		if len(res.Rows) > 0 {
			proof := domain.DomainProof{Email: common.AsString(res.Rows[0][0]), EmailVerified: common.AsBool(res.Rows[0][1])}
			evidence, err = r.Domains.Check(ctx, host, domain.MethodVerifiedEmail, proof)
			if err != nil && !errors.Is(err, domain.ErrDomainNotProven) && !errors.Is(err, domain.ErrInvalidDomain) && !errors.Is(err, domain.ErrUnknownMethod) {
				return err
			}
		}
	}
	if evidence == nil {
		if r.RequireDomainProof {
			return domain.ErrDomainNotProven
		}
		return nil
	}
	_, err := r.Domains.RecordTx(ctx, tx, partnerID, userID, host, evidence)
	return err
}

// checkout opens the checkout of a partner whose plan activates at checkout.
// Its metadata is what billing.NewProviderSubscriptionEventHandler reads.
func (r *RegistrationService) checkout(ctx context.Context, created *PartnerCreated, plan *planChoice, userID int64) error {
	if created == nil || !created.PaymentRequired || r.Checkout == nil {
		return nil
	}
	o := plan.offer
	url, err := r.Checkout.CreateCheckoutSession(ctx, payment.CheckoutRequest{
		Mode:       payment.ModeSubscription,
		PriceID:    o.providerPriceID,
		Quantity:   1,
		SuccessURL: r.CheckoutSuccessURL,
		CancelURL:  r.CheckoutCancelURL,
		Metadata: map[string]string{
			"partner_id":    strconv.FormatInt(created.PartnerID, 10),
			"plan_id":       plan.id,
			"user_id":       strconv.FormatInt(userID, 10),
			"billing_cycle": common.AsString(o.billingCycle),
			"term_type":     common.AsString(o.termType),
			"term_count":    strconv.Itoa(int(common.AsInt32(o.termCount))),
		},
		LineMetadata: map[string]string{"plan_id": plan.id},
	})
	if err != nil {
		return fmt.Errorf("%w: partner %d: %w", ErrCheckout, created.PartnerID, err)
	}
	created.PaymentURL = url
	return nil
}

func signedIn(users UserService, userID int, method string) (*model.UserSession, error) {
	if err := users.CheckSignInMethod(userID, method); err != nil {
		return nil, err
	}
	session, err := users.GetUserById(userID)
	if err != nil {
		return nil, err
	}
	session.SignInMethod = method
	return session, nil
}

// checkConfirmation returns the payload of the pending code for email. A
// wrong code counts against MaxRegistrationAttempts, and reaching it expires
// every pending code for the email.
func (r *RegistrationService) checkConfirmation(ctx context.Context, email string, confirmation int) (string, error) {
	cfg := config.Config()
	res, err := r.qs.Query(ctx, qGetUserRegistration, email, time.Now().Add(-cfg.RegistrationConfirmationTTL))
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", ErrInvalidConfirmation
	}
	expected := int(common.AsInt32(res.Rows[0][0]))
	if int(common.AsInt32(res.Rows[0][2])) >= cfg.MaxRegistrationAttempts {
		return "", r.expireConfirmation(ctx, email)
	}
	if confirmation != expected {
		bump, err := r.qs.Query(ctx, qBumpRegistrationAttempts, email, expected)
		if err != nil {
			return "", err
		}
		if len(bump.Rows) > 0 && int(common.AsInt32(bump.Rows[0][0])) >= cfg.MaxRegistrationAttempts {
			return "", r.expireConfirmation(ctx, email)
		}
		return "", ErrInvalidConfirmation
	}
	return common.AsString(res.Rows[0][1]), nil
}

func (r *RegistrationService) expireConfirmation(ctx context.Context, email string) error {
	if _, err := r.qs.Query(ctx, qExpireRegistration, email); err != nil {
		return err
	}
	return ErrInvalidConfirmation
}

// ActivateSubscription flips a pending subscription to active, for a payment
// confirmation outside billing.NewProviderSubscriptionEventHandler.
func (r *RegistrationService) ActivateSubscription(ctx context.Context, partnerID int64, planID string) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	_, err := r.qs.Query(ctx, qActivateSubscription, partnerID, strings.ToUpper(strings.TrimSpace(planID)))
	return err
}

// ListPlans returns the public view of all subscription plans. Used by the
// unauthenticated registration page to render a plan picker.
func (r *RegistrationService) ListPlans(ctx context.Context) ([]PublicPlan, error) {
	if err := r.init(ctx); err != nil {
		return nil, err
	}
	res, err := r.qs.Query(ctx, qListActivePlans)
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
		if err := price.FillAmount(); err != nil {
			return nil, err
		}
		p.Prices = append(p.Prices, price)
	}
	out := make([]PublicPlan, len(order))
	for i, id := range order {
		out[i] = *byID[id]
	}
	return out, nil
}

func (r *RegistrationService) SendPasswordChangeConfirmation(ctx context.Context, email string) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	confirmation, err := generateConfirmationCode()
	if err != nil {
		return err
	}
	if _, err := r.qs.Query(ctx, qAddUserRegistration, normalizeEmail(email), confirmation, ""); err != nil {
		return err
	}
	body := fmt.Sprintf("Hello,\n\nPlease use the following confirmation code to complete your password change:\n\n%d\n\nIf you did not request this change, please ignore this email.\n", confirmation)
	if err := r.Mail.SendEmail(ctx, "Confirm your password change", body, []string{email}, nil); err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}
	return nil
}

func (r *RegistrationService) ConfirmPasswordChange(ctx context.Context, email string, confirmation int) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	email = normalizeEmail(email)
	payload, err := r.checkConfirmation(ctx, email, confirmation)
	if err != nil {
		return err
	}
	if payload != "" {
		return ErrInvalidConfirmation // a registration code
	}
	if _, err := r.qs.Query(ctx, qSetUserRegistration, email); err != nil {
		return err
	}
	_, err = r.qs.Query(ctx, qMarkEmailVerifiedByEmail, email)
	return err
}
