package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// store is an in-memory stand-in for the tables the sign-in service reads,
// answering keel's named queries by name.
type store struct {
	holders     map[string]int64 // domain name -> partner holding it by identity methods
	connections map[int64]*connection
	clients     map[int64]string
	nonces      map[string]string
	mappings    [][3]string // claim, value, role
	open        map[int][]string
	grants      map[int]map[string]time.Time
	partnerDoms map[int64][]string
	tSessions   []int64
	managed     map[int]bool // provisioned, active users
	scim        *scimStore
	onLock      func() // runs when connection rows are locked
	inserted    []any  // last connection insert args
	oidcRow     []any  // last oidc insert/update args
	committed   int
	rolledBack  int
}

func newStore() *store {
	return &store{holders: map[string]int64{}, connections: map[int64]*connection{}, clients: map[int64]string{},
		nonces: map[string]string{}, open: map[int][]string{}, grants: map[int]map[string]time.Time{}, partnerDoms: map[int64][]string{}, managed: map[int]bool{}}
}

type storeQS struct {
	port.TxQueryService
	s *store
}

func (q *storeQS) GenID() int64 { return 1 }

func (q *storeQS) QueryService(string, map[string]string) port.QueryService { return q }

func (q *storeQS) Commit(context.Context) error   { q.s.committed++; return nil }
func (q *storeQS) Rollback(context.Context) error { q.s.rolledBack++; return nil }

func rows(r ...[]any) (*model.QueryResult, error) { return &model.QueryResult{Rows: r}, nil }

func (q *storeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	s := q.s
	switch name {
	case "dv_identity_holders":
		if p, ok := s.holders[args[0].(string)]; ok {
			return rows([]any{p})
		}
		return rows()
	case "dv_partner_current":
		var out [][]any
		for d, p := range s.holders {
			if p == args[0].(int64) {
				out = append(out, []any{p, d, time.Now(), d, domain.MethodDNSTXT, int64(1), nil, time.Now(), nil, nil, nil, nil, nil, time.Now()})
			}
		}
		return rows(out...)
	case "nonce_insert":
		s.nonces[args[0].(string)] = args[2].(string)
		return rows()
	case "nonce_consume":
		p, ok := s.nonces[args[0].(string)]
		delete(s.nonces, args[0].(string))
		if !ok {
			return rows()
		}
		return rows([]any{p})
	case qActiveConnection:
		for _, c := range s.connections {
			if c.PartnerID == args[0].(int64) && c.Status == StatusActive {
				return rows(connRow(c))
			}
		}
		return rows()
	case qConnection:
		if c, ok := s.connections[args[1].(int64)]; ok && c.PartnerID == args[0].(int64) {
			return rows(connRow(c))
		}
		return rows()
	case qConnectionClient:
		return rows([]any{s.clients[args[1].(int64)]})
	case qInsertConnection:
		s.inserted = args
		id := int64(len(s.connections) + 100)
		s.connections[id] = &connection{IdentityConnection: port.IdentityConnection{ID: id, PartnerID: args[0].(int64), Protocol: args[2].(string), Issuer: args[3].(string)}, Status: StatusDraft}
		return rows([]any{id})
	case qInsertOIDC, qUpdateOIDC:
		s.oidcRow = args
		return rows()
	case qUpdateConnection:
		s.inserted = args
		return rows()
	case qMarkTested:
		s.connections[args[2].(int64)].Tested = true
		return rows()
	case qLockConnections:
		if s.onLock != nil {
			s.onLock()
		}
		return rows([]any{args[0]})
	case qDeactivateOthers:
		var out [][]any
		for id, c := range s.connections {
			if c.PartnerID == args[1].(int64) && id != args[2].(int64) && c.Status == StatusActive {
				c.Status = StatusDisabled
				out = append(out, []any{id})
			}
		}
		return rows(out...)
	case qActivate:
		c := s.connections[args[2].(int64)]
		if !c.Tested {
			return rows()
		}
		c.Status = StatusActive
		return rows([]any{c.ID})
	case qDisable:
		c := s.connections[args[2].(int64)]
		if c.Status == StatusDisabled {
			return rows()
		}
		c.Status = StatusDisabled
		return rows([]any{c.ID})
	case qPartnerDomains:
		var out [][]any
		for _, d := range s.partnerDoms[args[0].(int64)] {
			out = append(out, []any{d})
		}
		return rows(out...)
	case qTenantSessionUsers:
		var out [][]any
		for _, u := range s.tSessions {
			out = append(out, []any{u})
		}
		return rows(out...)
	case qSCIMManaged:
		uid := asInt(args[1])
		if s.managed[uid] || (s.scim != nil && s.scim.users[uid] != nil && s.scim.users[uid].active) {
			return rows([]any{1})
		}
		return rows()
	case qInsertSAML, qUpdateSAML:
		s.oidcRow = args
		return rows()
	case qRoleMappings:
		var out [][]any
		for _, m := range s.mappings {
			out = append(out, []any{m[0], m[1], m[2]})
		}
		return rows(out...)
	case qMappedGrants:
		var out [][]any
		for role, begda := range s.grants[asInt(args[2])] {
			out = append(out, []any{role, begda})
		}
		return rows(out...)
	case qOpenRoles:
		var out [][]any
		for _, r := range s.open[asInt(args[0])] {
			out = append(out, []any{r})
		}
		return rows(out...)
	case qGrantRole:
		if args[1].(string) == "SUPER" {
			return rows() // not partner-scoped
		}
		s.open[asInt(args[0])] = append(s.open[asInt(args[0])], args[1].(string))
		return rows([]any{time.Unix(1, 0)})
	case qRecordGrant:
		if s.grants[asInt(args[0])] == nil {
			s.grants[asInt(args[0])] = map[string]time.Time{}
		}
		s.grants[asInt(args[0])][args[1].(string)] = args[2].(time.Time)
		return rows()
	case qEndRole:
		delete(s.grants[asInt(args[0])], args[1].(string))
		var kept []string
		for _, r := range s.open[asInt(args[0])] {
			if r != args[1].(string) {
				kept = append(kept, r)
			}
		}
		s.open[asInt(args[0])] = kept
		return rows()
	case qEndProviderRoles:
		for userID, grants := range s.grants {
			for role := range grants {
				var kept []string
				for _, open := range s.open[userID] {
					if open != role {
						kept = append(kept, open)
					}
				}
				s.open[userID] = kept
			}
			delete(s.grants, userID)
		}
		return rows()
	}
	if s.scim != nil {
		if res, ok := s.scim.query(name, args); ok {
			return res, nil
		}
	}
	if name == qActiveSCIMUsers {
		return rows()
	}
	return nil, fmt.Errorf("unexpected query %s", name)
}

func connRow(c *connection) []any {
	return []any{c.ID, c.PartnerID, c.Protocol, c.Issuer, c.SubjectClaim, c.EmailClaim, c.RequireMFA, c.Status, c.Tested}
}

type storeDB struct {
	port.DatabaseRepository
	s *store
}

func (d *storeDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return &storeQS{s: d.s}
}

func (d *storeDB) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return &storeQS{s: d.s}, nil
}

// fakeUsers is the account side: accounts by id, links by issuer+subject.
type fakeUsers struct {
	user.UserService
	accounts   map[int]*model.UserSession
	links      map[string]int
	policies   map[string]int
	created    []user.ExternalIdentity
	joined     []int
	signedOut  []int
	revoked    []int
	checkedFor []string
	ended      []int
	endErr     error
}

func newUsers() *fakeUsers {
	return &fakeUsers{accounts: map[int]*model.UserSession{}, links: map[string]int{}, policies: map[string]int{}}
}

func (u *fakeUsers) GetUserFromExternal(id user.ExternalIdentity) (*model.UserSession, error) {
	if uid, ok := u.links[id.Issuer+"|"+id.Subject]; ok {
		s := *u.accounts[uid]
		return &s, nil
	}
	for _, a := range u.accounts {
		if a.Email == id.Email {
			return nil, user.ErrIdentityNotLinked
		}
	}
	return nil, user.ErrNoAccount
}

func (u *fakeUsers) GetUserByEmail(email string) (*model.UserSession, error) {
	for _, a := range u.accounts {
		if a.Email == email {
			s := *a
			return &s, nil
		}
	}
	return nil, user.ErrNoAccount
}

func (u *fakeUsers) EndMembership(partnerID int64, userID int, _ string) error {
	if u.endErr != nil {
		return u.endErr
	}
	a := u.accounts[userID]
	if a == nil || a.PartnerId != partnerID {
		return user.ErrNoMembership
	}
	a.PartnerId = 0
	u.ended = append(u.ended, userID)
	return nil
}

func (u *fakeUsers) GetUserById(id int) (*model.UserSession, error) {
	a, ok := u.accounts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	s := *a
	return &s, nil
}

func (u *fakeUsers) LinkExternalIdentity(userID int, id user.ExternalIdentity) error {
	u.links[id.Issuer+"|"+id.Subject] = userID
	return nil
}

func (u *fakeUsers) CheckSignInMethod(_ int, method string) error {
	u.checkedFor = append(u.checkedFor, method)
	return nil
}

func (u *fakeUsers) EffectivePolicies(int64) (map[string]int, error) { return u.policies, nil }

func (u *fakeUsers) LogoutEverywhere(id int) error   { u.signedOut = append(u.signedOut, id); return nil }
func (u *fakeUsers) RevokeAccessTokens(id int) error { u.revoked = append(u.revoked, id); return nil }

func (u *fakeUsers) CreateTenantAccountTx(_ context.Context, _ port.TxQueryService, partnerID int64, id user.ExternalIdentity) (*model.UserSession, error) {
	u.created = append(u.created, id)
	uid := 900 + len(u.created)
	u.accounts[uid] = &model.UserSession{Id: uid, Email: id.Email, PartnerId: partnerID}
	u.links[id.Issuer+"|"+id.Subject] = uid
	return u.accounts[uid], nil
}

func (u *fakeUsers) CreateTenantMemberTx(_ context.Context, _ port.TxQueryService, partnerID int64, m user.TenantMember, join bool) (int, error) {
	uid := 800 + len(u.accounts)
	a := &model.UserSession{Id: uid, Email: m.Email, FirstName: m.FirstName, LastName: m.LastName}
	if join {
		a.PartnerId = partnerID
	}
	u.accounts[uid] = a
	return uid, nil
}

func (u *fakeUsers) UpdateTenantMemberTx(_ context.Context, _ port.TxQueryService, userID int, m user.TenantMember) error {
	a := u.accounts[userID]
	a.Email, a.FirstName, a.LastName = m.Email, m.FirstName, m.LastName
	return nil
}

func (u *fakeUsers) JoinPartnerTx(_ context.Context, _ port.TxQueryService, partnerID int64, userID int) error {
	u.joined = append(u.joined, userID)
	u.accounts[userID].PartnerId = partnerID
	return nil
}

// fakeProvider returns the assertion the test sets.
type fakeProvider struct {
	assertion *port.IdentityAssertion
	err       error
	scopes    []string
}

func (p *fakeProvider) Protocol() string { return "O" }

func (p *fakeProvider) Begin(_ context.Context, conn port.IdentityConnection, req port.IdentityBegin) (*port.IdentityRedirect, error) {
	p.scopes = req.Scopes
	return &port.IdentityRedirect{URL: "https://idp.example/authorize?" + url.Values{"state": {req.State}, "login_hint": {req.LoginHint}}.Encode(), Pending: "p"}, nil
}

func (p *fakeProvider) Complete(context.Context, port.IdentityConnection, port.IdentityCallback) (*port.IdentityAssertion, error) {
	if p.err != nil {
		return nil, p.err
	}
	a := *p.assertion
	return &a, nil
}

const (
	acme    = int64(42)
	issuer  = "https://login.acme.example"
	connID  = int64(7)
	callbck = "https://api.example/public/sso/callback"
)

type fixture struct {
	svc      *Service
	store    *store
	users    *fakeUsers
	provider *fakeProvider
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := newStore()
	s.holders["acme.example"] = acme
	s.holders["other.example"] = 99
	s.connections[connID] = &connection{IdentityConnection: port.IdentityConnection{ID: connID, PartnerID: acme, Protocol: "O", Issuer: issuer}, Status: StatusActive, Tested: true}
	db := &storeDB{s: s}
	nonces := &connect.NonceService{DB: db}
	nonces.Init(context.Background())
	users := newUsers()
	provider := &fakeProvider{assertion: &port.IdentityAssertion{Issuer: issuer, Subject: "sub-1", Email: "ada@acme.example",
		AuthMethods: []string{"pwd"}, Claims: map[string][]string{"groups": {"admins"}}}}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	sealer, err := crypto.NewSealer(context.Background(), secretMap{"kek": base64.StdEncoding.EncodeToString(kek)}, "kek")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db, Users: users, Domains: &domain.Service{DB: db}, Providers: map[string]port.IdentityProvider{"O": provider},
		Nonces: nonces, Sealer: sealer}
	return &fixture{svc: svc, store: s, users: users, provider: provider}
}

type secretMap map[string]string

func (m secretMap) GetSecret(_ context.Context, name string) (string, error) { return m[name], nil }

// signIn runs Start for email and Complete with the provider's assertion.
func (f *fixture) signIn(t *testing.T, email string) (*Outcome, error) {
	t.Helper()
	_, key, err := f.svc.Start(context.Background(), email, callbck)
	if err != nil {
		return nil, err
	}
	return f.svc.Complete(context.Background(), key, callbck, url.Values{"state": {"s"}, "code": {"c"}})
}
