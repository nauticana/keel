package user

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

// regStore stands in for the registration tables, driven by query name.
type regStore struct {
	pending     map[string]*pendingRow // email → latest pending code
	plans       map[string][]any       // plan → {currency, activation_mode}
	prices      map[string][][]any
	scoped      map[string]bool // partner-scoped roles
	emails      map[int64]string
	members     map[int64]int64 // user → partner
	domains     map[int64]string
	roles       []string
	subs        []string // subscription statuses
	evidence    []string // recorded domain verification methods
	calls       []string
	nextID      int64
	commits     int
	rollbacks   int
	memberFails bool // partner_user hits the one-partner exclusion
}

type pendingRow struct {
	code     int
	payload  string
	attempts int
	status   string
}

func newRegStore() *regStore {
	return &regStore{
		pending: map[string]*pendingRow{},
		plans:   map[string][]any{"FREE": {"USD", "A"}, "PRO": {"USD", "P"}},
		prices:  map[string][][]any{"PRO": {{"M", "M", int64(1), int64(1000), "USD", "price_pro"}}},
		scoped:  map[string]bool{"PARTNER_ADMIN": true, "AGENT_ADMIN": true},
		emails:  map[int64]string{}, members: map[int64]int64{}, domains: map[int64]string{},
		nextID: 100,
	}
}

func (s *regStore) GenID() int64                   { s.nextID++; return s.nextID }
func (s *regStore) Commit(context.Context) error   { s.commits++; return nil }
func (s *regStore) Rollback(context.Context) error { s.rollbacks++; return nil }

func (s *regStore) count(name string) int {
	n := 0
	for _, c := range s.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (s *regStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	s.calls = append(s.calls, name)
	out := &model.QueryResult{}
	switch name {
	case qAddUserRegistration:
		s.pending[args[0].(string)] = &pendingRow{code: args[1].(int), payload: args[2].(string), status: "P"}
	case qGetUserRegistration:
		if p := s.pending[args[0].(string)]; p != nil && p.status == "P" {
			out.Rows = [][]any{{int32(p.code), p.payload, int32(p.attempts)}}
		}
	case qBumpRegistrationAttempts:
		if p := s.pending[args[0].(string)]; p != nil && p.status == "P" {
			p.attempts++
			out.Rows = [][]any{{int32(p.attempts)}}
		}
	case qExpireRegistration:
		if p := s.pending[args[0].(string)]; p != nil {
			p.status = "X"
		}
	case qSetUserRegistration:
		if p := s.pending[args[0].(string)]; p != nil {
			p.status = "C"
		}
	case qGetPlan:
		if row, ok := s.plans[args[0].(string)]; ok {
			out.Rows = [][]any{row}
		}
	case qPlanPrices:
		out.Rows = s.prices[args[0].(string)]
	case qAddUserAccount:
		s.emails[args[0].(int64)] = args[4].(string)
	case qRegistrantEmail:
		if e, ok := s.emails[args[0].(int64)]; ok {
			out.Rows = [][]any{{e, true}}
		}
	case qAddPartner:
		out.Rows = [][]any{{s.GenID()}}
	case qAddDomain:
		s.domains[args[0].(int64)] = args[1].(string)
	case qAddPartnerUser:
		if s.memberFails {
			return nil, &pgconn.PgError{Code: "23P01"}
		}
		s.members[args[1].(int64)] = args[0].(int64)
	case qAddPartnerRole:
		if s.scoped[args[1].(string)] {
			s.roles = append(s.roles, args[1].(string))
			out.Rows = [][]any{{args[1]}}
		}
	case qAddSubscription:
		s.subs = append(s.subs, args[2].(string))
	case "dv_member":
		if s.members[args[1].(int64)] == args[0].(int64) {
			out.Rows = [][]any{{1}}
		}
	case "dv_domain":
		if s.domains[args[0].(int64)] == args[1].(string) {
			out.Rows = [][]any{{args[1]}}
		}
	case "dv_insert":
		s.evidence = append(s.evidence, args[3].(string))
	case "dv_get_current":
		out.Rows = [][]any{{args[0], args[1], time.Now(), args[1], args[2], int64(0), nil, nil, nil, nil, nil, nil, nil, time.Now()}}
	}
	return out, nil
}

type regRepo struct {
	port.DatabaseRepository
	store *regStore
}

func (r regRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.store
}
func (r regRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return r.store, nil
}

// regUsers is the part of UserService registration uses.
type regUsers struct {
	UserService
	store       *regStore
	refuse      string // sign-in method CheckSignInMethod refuses
	existing    bool   // GetOrCreateUserFromSocial matched an account
	method      string // ExternalSignInMethod result
	consentErr  error
	ssoRequired int // global SSO_REQUIRED
	policyErr   error
}

func (u *regUsers) EffectivePolicies(int64) (map[string]int, error) {
	return map[string]int{PolicySSORequired: u.ssoRequired}, u.policyErr
}

func (u *regUsers) GetPasswordPolicy() model.PasswordPolicy {
	return model.PasswordPolicy{MinPasswordLength: 8}
}

func (u *regUsers) CheckSignInMethod(_ int, method string) error {
	if method == u.refuse {
		return ErrSSORequired
	}
	return nil
}

func (u *regUsers) GetUserById(id int) (*model.UserSession, error) {
	return &model.UserSession{Id: id, PartnerId: u.store.members[int64(id)]}, nil
}

func (u *regUsers) CreateIdentityAccountTx(_ context.Context, tx port.TxQueryService, id ExternalIdentity) (*model.UserSession, error) {
	if tx != port.TxQueryService(u.store) {
		return nil, errors.New("account created outside the registration transaction")
	}
	if u.existing {
		return nil, ErrAccountExists
	}
	uid := u.store.GenID()
	u.store.emails[uid] = id.Email
	return &model.UserSession{Id: int(uid), Email: id.Email}, nil
}

func (u *regUsers) RecordSignupConsent(int, string, *SignupConsent) error { return u.consentErr }

func (u *regUsers) ExternalSignInMethod(int64, ExternalIdentity) (string, error) {
	return u.method, nil
}

type regMail struct{ sent []string }

func (m *regMail) SendEmail(_ context.Context, _, body string, to []string, _ map[string]string) error {
	m.sent = append(m.sent, to[0]+"|"+body)
	return nil
}

type regCheckout struct {
	payment.CheckoutClient
	req payment.CheckoutRequest
	err error
}

func (c *regCheckout) CreateCheckoutSession(_ context.Context, req payment.CheckoutRequest) (string, error) {
	c.req = req
	return "https://pay.example/session", c.err
}

func newRegistration(store *regStore) (*RegistrationService, *regUsers, *regMail) {
	users := &regUsers{store: store, method: SignInExternal}
	mail := &regMail{}
	return &RegistrationService{
		Repo: regRepo{store: store}, Mail: mail, Users: users,
		Domains: &domain.Service{Verifiers: []domain.DomainVerifier{domain.VerifiedEmailVerifier{}}},
	}, users, mail
}

func pendingCode(t *testing.T, store *regStore, email string) int {
	t.Helper()
	p := store.pending[email]
	if p == nil {
		t.Fatalf("no pending registration for %s", email)
	}
	return p.code
}

func isBadRequest(err error) bool {
	var appErr *model.AppError
	return errors.As(err, &appErr) && appErr.Status == 400
}

func TestRegisterCreatesAccountAndPartner(t *testing.T) {
	store := newRegStore()
	svc, _, mail := newRegistration(store)
	ctx := context.Background()
	reg := &PartnerRegistration{
		AccountRegistration: AccountRegistration{FirstName: "Ada", Email: " Ada@Example.com ", Password: "longenough"},
		PartnerSetup:        PartnerSetup{PartnerCaption: "Example", DomainURL: "https://www.Example.com/about"},
	}
	if err := svc.SendConfirmation(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if len(mail.sent) != 1 || !strings.HasPrefix(mail.sent[0], "ada@example.com|") {
		t.Fatalf("mail = %v", mail.sent)
	}
	stored := store.pending["ada@example.com"].payload
	if strings.Contains(stored, "longenough") || !strings.Contains(stored, `"password":"$2`) {
		t.Fatalf("payload must hold only the password hash: %s", stored)
	}

	session, created, err := svc.Register(ctx, "ADA@example.com", pendingCode(t, store, "ada@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if store.commits != 1 || store.rollbacks != 0 {
		t.Fatalf("commits %d rollbacks %d", store.commits, store.rollbacks)
	}
	if session.SignInMethod != SignInOTP || session.PartnerId != created.PartnerID {
		t.Fatalf("session = %+v, partner %d", session, created.PartnerID)
	}
	if created.PlanID != "FREE" || created.PaymentRequired || store.subs[0] != "A" {
		t.Fatalf("created = %+v subs %v", created, store.subs)
	}
	if store.domains[created.PartnerID] != "example.com" {
		t.Fatalf("domain = %q, want the normalized host", store.domains[created.PartnerID])
	}
	if len(store.evidence) != 1 || store.evidence[0] != domain.MethodVerifiedEmail {
		t.Fatalf("evidence = %v, want VE from the confirmed email", store.evidence)
	}
	if len(store.roles) != 1 || store.roles[0] != "PARTNER_ADMIN" {
		t.Fatalf("roles = %v", store.roles)
	}
	if store.pending["ada@example.com"].status != "C" {
		t.Fatal("the registration must be marked confirmed")
	}
}

func TestRegisterAccountOnlyThenCreatePartner(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	ctx := context.Background()
	if err := svc.SendConfirmation(ctx, &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "bo@shop.example"}}); err != nil {
		t.Fatal(err)
	}
	session, created, err := svc.Register(ctx, "bo@shop.example", pendingCode(t, store, "bo@shop.example"))
	if err != nil || created != nil || store.count(qAddPartner) != 0 {
		t.Fatalf("account-only registration: created %+v err %v", created, err)
	}

	got, err := svc.CreatePartner(ctx, int64(session.Id), &PartnerSetup{PartnerCaption: "Shop", DomainURL: "shop.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.members[int64(session.Id)] != got.PartnerID || len(store.evidence) != 1 {
		t.Fatalf("membership %v evidence %v", store.members, store.evidence)
	}

	store.memberFails = true
	if _, err := svc.CreatePartner(ctx, int64(session.Id), &PartnerSetup{PartnerCaption: "Second"}, nil); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("err = %v, want ErrAlreadyMember", err)
	}
}

func TestRegisterWrongCodeExpiresAtLimit(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	ctx := context.Background()
	if err := svc.SendConfirmation(ctx, &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "c@example.org"}}); err != nil {
		t.Fatal(err)
	}
	code := pendingCode(t, store, "c@example.org")
	for range 10 {
		if _, _, err := svc.Register(ctx, "c@example.org", code+1); !errors.Is(err, ErrInvalidConfirmation) {
			t.Fatalf("err = %v", err)
		}
		if store.pending["c@example.org"].status == "X" {
			break
		}
	}
	if store.pending["c@example.org"].status != "X" {
		t.Fatal("repeated wrong codes must expire the registration")
	}
	if _, _, err := svc.Register(ctx, "c@example.org", code); !errors.Is(err, ErrInvalidConfirmation) {
		t.Fatalf("an expired code must not register: %v", err)
	}
	if store.count(qAddUserAccount) != 0 {
		t.Fatal("no account may be created")
	}
}

func TestSendConfirmationValidates(t *testing.T) {
	store := newRegStore()
	svc, _, mail := newRegistration(store)
	svc.EmailPolicy = BusinessEmail
	svc.RequireDomainProof = true
	ctx := context.Background()
	account := AccountRegistration{Email: "dee@corp.example"}
	cases := map[string]struct {
		reg  PartnerRegistration
		want func(error) bool
	}{
		"public mailbox": {PartnerRegistration{AccountRegistration: AccountRegistration{Email: "dee@gmail.com"}},
			func(err error) bool { return errors.Is(err, ErrPublicEmail) }},
		"weak password":           {PartnerRegistration{AccountRegistration: AccountRegistration{Email: "dee@corp.example", Password: "short"}}, isBadRequest},
		"partner without caption": {PartnerRegistration{AccountRegistration: account, PartnerSetup: PartnerSetup{PlanID: "PRO"}}, isBadRequest},
		"bad domain":              {PartnerRegistration{AccountRegistration: account, PartnerSetup: PartnerSetup{PartnerCaption: "C", DomainURL: "://"}}, isBadRequest},
		"domain the email cannot prove": {PartnerRegistration{AccountRegistration: account, PartnerSetup: PartnerSetup{PartnerCaption: "C", DomainURL: "other.example"}},
			func(err error) bool { return errors.Is(err, domain.ErrDomainNotProven) }},
	}
	for name, tc := range cases {
		if err := svc.SendConfirmation(ctx, &tc.reg); !tc.want(err) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(mail.sent) != 0 || len(store.pending) != 0 {
		t.Fatal("a refused registration must not be stored or mailed")
	}
}

func TestCreatePartnerRequiresDomainProof(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	svc.RequireDomainProof = true
	store.emails[7] = "eve@elsewhere.example"
	_, err := svc.CreatePartner(context.Background(), 7, &PartnerSetup{PartnerCaption: "Eve", DomainURL: "target.example"}, nil)
	if !errors.Is(err, domain.ErrDomainNotProven) {
		t.Fatalf("err = %v, want ErrDomainNotProven", err)
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits %d rollbacks %d, want rollback", store.commits, store.rollbacks)
	}

	svc.RequireDomainProof = false
	store.rollbacks = 0
	if _, err := svc.CreatePartner(context.Background(), 8, &PartnerSetup{PartnerCaption: "Fay", DomainURL: "target.example"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(store.evidence) != 0 {
		t.Fatal("an unproven domain is recorded without evidence")
	}
}

func TestCreatePartnerGrantsOnlyPartnerScopedRoles(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	svc.Roles = []string{"PARTNER_ADMIN", "AGENT_ADMIN", "PARTNER_ADMIN"}
	if _, err := svc.CreatePartner(context.Background(), 7, &PartnerSetup{PartnerCaption: "G"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(store.roles, ",") != "PARTNER_ADMIN,AGENT_ADMIN" {
		t.Fatalf("roles = %v", store.roles)
	}

	svc.Roles = []string{"PARTNER_ADMIN", "SUPER"}
	if _, err := svc.CreatePartner(context.Background(), 8, &PartnerSetup{PartnerCaption: "H"}, nil); err == nil || !strings.Contains(err.Error(), "SUPER") {
		t.Fatalf("err = %v, want refusal of a global role", err)
	}
	if store.rollbacks != 1 {
		t.Fatal("a refused role must roll the partner back")
	}
}

func TestCreatePartnerRunsApplicationHook(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	var gotPartner, gotUser int64
	var extra struct{ Category string }
	svc.OnPartnerTx = func(_ context.Context, tx port.TxQueryService, partnerID, userID int64, setup *PartnerSetup) error {
		if tx != port.TxQueryService(store) {
			t.Error("the hook must run in the partner transaction")
		}
		gotPartner, gotUser = partnerID, userID
		return json.Unmarshal(setup.Extra, &extra)
	}
	created, err := svc.CreatePartner(context.Background(), 9, &PartnerSetup{PartnerCaption: "I", Extra: json.RawMessage(`{"category":"bakery"}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotPartner != created.PartnerID || gotUser != 9 || extra.Category != "bakery" {
		t.Fatalf("hook saw partner %d user %d extra %+v", gotPartner, gotUser, extra)
	}

	hookErr := errors.New("app row failed")
	svc.OnPartnerTx = func(context.Context, port.TxQueryService, int64, int64, *PartnerSetup) error { return hookErr }
	if _, err := svc.CreatePartner(context.Background(), 10, &PartnerSetup{PartnerCaption: "J"}, nil); !errors.Is(err, hookErr) {
		t.Fatalf("err = %v", err)
	}
	if store.rollbacks != 1 {
		t.Fatal("a failed hook must roll the partner back")
	}
}

func TestCreatePartnerOpensCheckout(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	checkout := &regCheckout{}
	svc.Checkout, svc.CheckoutSuccessURL, svc.CheckoutCancelURL = checkout, "https://app.example/ok", "https://app.example/cancel"
	created, err := svc.CreatePartner(context.Background(), 11, &PartnerSetup{PartnerCaption: "K", PlanID: "pro"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created.PaymentRequired || created.PaymentURL != "https://pay.example/session" || store.subs[0] != "P" {
		t.Fatalf("created = %+v subs %v", created, store.subs)
	}
	md := checkout.req.Metadata
	if checkout.req.PriceID != "price_pro" || md["plan_id"] != "PRO" || md["user_id"] != "11" || md["billing_cycle"] != "M" || md["term_count"] != "1" {
		t.Fatalf("checkout request = %+v", checkout.req)
	}

	checkout.err = errors.New("provider down")
	created, err = svc.CreatePartner(context.Background(), 12, &PartnerSetup{PartnerCaption: "L", PlanID: "PRO"}, nil)
	if !errors.Is(err, ErrCheckout) || created == nil || created.PartnerID == 0 || created.PaymentURL != "" {
		t.Fatalf("checkout failure: created %+v err %v", created, err)
	}

	store.prices["PRO"][0][5] = ""
	writes := store.count(qAddPartner)
	if _, err := svc.CreatePartner(context.Background(), 13, &PartnerSetup{PartnerCaption: "M", PlanID: "PRO"}, nil); err == nil || store.count(qAddPartner) != writes {
		t.Fatalf("an offer without a provider price must fail before any write: %v", err)
	}
}

func TestRegisterWithIdentity(t *testing.T) {
	store := newRegStore()
	svc, users, _ := newRegistration(store)
	id := ExternalIdentity{Provider: "google", Issuer: GoogleIssuer, Subject: "s1", Email: "gil@gmail.com", EmailVerified: true}
	users.method = SignInTenant
	session, created, err := svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{PartnerCaption: "N"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if session.SignInMethod != SignInTenant || session.PartnerId != created.PartnerID {
		t.Fatalf("session = %+v created %+v", session, created)
	}

	users.existing = true
	partners := store.count(qAddPartner)
	if _, _, err := svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{PartnerCaption: "O"}, nil); !errors.Is(err, ErrAccountExists) {
		t.Fatalf("err = %v, want ErrAccountExists", err)
	}
	if store.count(qAddPartner) != partners {
		t.Fatal("an existing account must not get a partner here")
	}

	users.existing, users.refuse = false, SignInTenant
	if _, _, err := svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{PartnerCaption: "P"}, nil); !errors.Is(err, ErrSSORequired) {
		t.Fatalf("err = %v, want the sign-in policy refusal", err)
	}

	users.refuse = ""
	if _, _, err := svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{}, nil); !isBadRequest(err) {
		t.Fatalf("err = %v, want 400 before the account is created", err)
	}

	users.consentErr = errors.New("consent store down")
	session, created, err = svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{PartnerCaption: "Q"}, nil)
	if !errors.Is(err, ErrConsentNotRecorded) || session == nil || created == nil {
		t.Fatalf("consent failure after commit: session %v created %v err %v", session, created, err)
	}
}

// A failed partner must not leave the identity's account behind.
func TestRegisterWithIdentityIsAtomic(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	hookErr := errors.New("app row failed")
	svc.OnPartnerTx = func(context.Context, port.TxQueryService, int64, int64, *PartnerSetup) error { return hookErr }
	id := ExternalIdentity{Provider: "google", Issuer: GoogleIssuer, Subject: "s2", Email: "hal@corp.example", EmailVerified: true}
	if _, _, err := svc.RegisterWithIdentity(context.Background(), id, nil, &PartnerSetup{PartnerCaption: "R"}, nil); !errors.Is(err, hookErr) {
		t.Fatalf("err = %v", err)
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits %d rollbacks %d, want the account rolled back with the partner", store.commits, store.rollbacks)
	}
}

func TestRequireDomainProofNeedsADomain(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	svc.RequireDomainProof = true
	ctx := context.Background()
	reg := &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "ivy@corp.example"}, PartnerSetup: PartnerSetup{PartnerCaption: "S"}}
	if err := svc.SendConfirmation(ctx, reg); !isBadRequest(err) {
		t.Fatalf("SendConfirmation err = %v, want 400", err)
	}
	if _, err := svc.CreatePartner(ctx, 7, &PartnerSetup{PartnerCaption: "S"}, nil); !isBadRequest(err) {
		t.Fatalf("CreatePartner err = %v, want 400", err)
	}
	if store.count(qAddPartner) != 0 {
		t.Fatal("a partner without a domain must be refused before any write")
	}

	// A code stored before the policy changed is still refused at commit.
	svc.RequireDomainProof = false
	if err := svc.SendConfirmation(ctx, reg); err != nil {
		t.Fatal(err)
	}
	svc.RequireDomainProof = true
	if _, _, err := svc.Register(ctx, "ivy@corp.example", pendingCode(t, store, "ivy@corp.example")); !isBadRequest(err) {
		t.Fatalf("Register err = %v, want 400", err)
	}
	if store.count(qAddUserAccount) != 0 {
		t.Fatal("no account may be created for a refused partner")
	}

	// Without the policy a partner may omit its domain.
	svc.RequireDomainProof = false
	if _, err := svc.CreatePartner(ctx, 8, &PartnerSetup{PartnerCaption: "T"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationServiceConfiguration(t *testing.T) {
	store := newRegStore()
	cases := map[string]*RegistrationService{
		"no repo":               {},
		"proof without domains": {Repo: regRepo{store: store}, RequireDomainProof: true},
		"checkout without urls": {Repo: regRepo{store: store}, Checkout: &regCheckout{}},
	}
	for name, svc := range cases {
		if _, err := svc.CreatePartner(context.Background(), 1, &PartnerSetup{PartnerCaption: "Q"}, nil); err == nil {
			t.Errorf("%s: want a configuration error", name)
		}
	}
	svc := &RegistrationService{Repo: regRepo{store: store}}
	if _, _, err := svc.Register(context.Background(), "x@example.com", 1); !errors.Is(err, errNoUsers) {
		t.Fatalf("err = %v, want errNoUsers", err)
	}
}

// An emailed-code signup could never sign in under a global SSO requirement,
// so it must not create an account.
func TestCodeSignupHonorsGlobalSSO(t *testing.T) {
	store := newRegStore()
	svc, users, mail := newRegistration(store)
	ctx := context.Background()
	reg := &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "jo@corp.example"}}
	if err := svc.SendConfirmation(ctx, reg); err != nil {
		t.Fatal(err)
	}
	code := pendingCode(t, store, "jo@corp.example")

	users.ssoRequired = SSOAnyIdentity
	if err := svc.SendConfirmation(ctx, reg); !errors.Is(err, ErrSSORequired) || len(mail.sent) != 1 {
		t.Fatalf("SendConfirmation err = %v, mails %d", err, len(mail.sent))
	}
	if _, _, err := svc.Register(ctx, "jo@corp.example", code); !errors.Is(err, ErrSSORequired) || store.count(qAddUserAccount) != 0 {
		t.Fatalf("Register err = %v, accounts %d", err, store.count(qAddUserAccount))
	}

	users.ssoRequired, users.policyErr = 0, errors.New("policy store down")
	if _, _, err := svc.Register(ctx, "jo@corp.example", code); err == nil || store.count(qAddUserAccount) != 0 {
		t.Fatalf("a failed policy lookup must refuse: %v", err)
	}
}

func TestUserNameCannotShadowAnotherEmail(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	reg := &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "kim@corp.example", UserName: "victim@corp.example"}}
	if err := svc.SendConfirmation(context.Background(), reg); !isBadRequest(err) {
		t.Fatalf("err = %v, want 400", err)
	}
	reg.UserName = "KIM@corp.example "
	if err := svc.SendConfirmation(context.Background(), reg); !isBadRequest(err) {
		t.Fatalf("a differently spelled address is still another login name: %v", err)
	}
	reg.UserName = "kim"
	if err := svc.SendConfirmation(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
}

// Login tokens and contact changes carry a user_id and share the table; they
// must never be read, counted or closed as registration or reset codes.
func TestRegistrationCodeQueriesSkipUserBoundRows(t *testing.T) {
	for _, name := range []string{qGetUserRegistration, qSetUserRegistration, qBumpRegistrationAttempts, qExpireRegistration} {
		if !strings.Contains(registerQueries[name], "user_id IS NULL") {
			t.Errorf("%s reads rows bound to a user", name)
		}
	}
}

func TestPasswordResetRefusesRegistrationCode(t *testing.T) {
	store := newRegStore()
	svc, _, _ := newRegistration(store)
	ctx := context.Background()
	if err := svc.SendConfirmation(ctx, &PartnerRegistration{AccountRegistration: AccountRegistration{Email: "lee@corp.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmPasswordChange(ctx, "lee@corp.example", pendingCode(t, store, "lee@corp.example")); !errors.Is(err, ErrInvalidConfirmation) {
		t.Fatalf("err = %v, want ErrInvalidConfirmation", err)
	}
	if store.pending["lee@corp.example"].status != "P" {
		t.Fatal("the registration must stay pending")
	}

	if err := svc.SendPasswordChangeConfirmation(ctx, "lee@corp.example"); err != nil {
		t.Fatal(err)
	}
	code := pendingCode(t, store, "lee@corp.example")
	if _, _, err := svc.Register(ctx, "lee@corp.example", code); !errors.Is(err, ErrInvalidConfirmation) {
		t.Fatalf("a reset code must not register: %v", err)
	}
	if err := svc.ConfirmPasswordChange(ctx, "lee@corp.example", code); err != nil {
		t.Fatal(err)
	}
}
