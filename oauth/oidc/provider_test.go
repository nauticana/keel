package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type fakeQS struct {
	port.QueryService
	rows [][]any
	args [][]any
}

func (q *fakeQS) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	q.args = append(q.args, args)
	return &model.QueryResult{Rows: q.rows}, nil
}

type fakeDB struct {
	port.DatabaseRepository
	qs *fakeQS
}

func (d *fakeDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d.qs }

type fakeSecrets map[string]string

func (s fakeSecrets) GetSecret(_ context.Context, name string) (string, error) {
	v, ok := s[name]
	if !ok {
		return "", errors.New("no secret")
	}
	return v, nil
}

func testSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	s, err := crypto.NewSealer(context.Background(), fakeSecrets{"kek": base64.StdEncoding.EncodeToString(kek)}, "kek")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func connection(idp *fakeIdP) port.IdentityConnection {
	return port.IdentityConnection{ID: 7, PartnerID: 42, Protocol: ProtocolOIDC, Issuer: idp.srv.URL}
}

func settingsRow(idp *fakeIdP, auth, secretName, sealed string) []any {
	return []any{idp.srv.URL + "/.well-known/openid-configuration", "client-1", auth, secretName, sealed, "openid email"}
}

func TestProviderSignsInWithStoredSettings(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	sealer := testSealer(t)
	sealed, err := sealer.Seal("sealed-secret")
	if err != nil {
		t.Fatal(err)
	}
	qs := &fakeQS{rows: [][]any{settingsRow(idp, "P", "", sealed)}}
	p := &Provider{DB: &fakeDB{qs: qs}, Sealer: sealer, Secrets: fakeSecrets{"op-secret": "operator-secret"}, HTTP: idp.srv.Client()}
	conn := connection(idp)
	ctx := context.Background()

	r, err := p.Begin(ctx, conn, port.IdentityBegin{State: "st", RedirectURI: testRedirect})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if qs.args[0][0] != int64(42) || qs.args[0][1] != int64(7) {
		t.Fatalf("settings must be read for the connection's own partner: %v", qs.args[0])
	}
	u, _ := url.Parse(r.URL)
	idp.claims = idp.baseClaims("client-1", u.Query().Get("nonce"))
	a, err := p.Complete(ctx, conn, port.IdentityCallback{RedirectURI: testRedirect, Params: callback("st"), Pending: r.Pending})
	if err != nil || a.Subject != "user-1" {
		t.Fatalf("Complete = %+v, %v", a, err)
	}
	if idp.lastReq.Get("client_secret") != "sealed-secret" {
		t.Fatalf("sealed credential not used: %v", idp.lastReq)
	}

	// An edited connection is rebuilt, not served from the cache.
	qs.rows = [][]any{settingsRow(idp, "P", "op-secret", "")}
	r, err = p.Begin(ctx, conn, port.IdentityBegin{State: "st", RedirectURI: testRedirect})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(r.URL)
	idp.claims = idp.baseClaims("client-1", u.Query().Get("nonce"))
	if _, err := p.Complete(ctx, conn, port.IdentityCallback{RedirectURI: testRedirect, Params: callback("st"), Pending: r.Pending}); err != nil {
		t.Fatal(err)
	}
	if idp.lastReq.Get("client_secret") != "operator-secret" {
		t.Fatalf("edited credential not used: %v", idp.lastReq)
	}
}

func TestProviderRefusals(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	sealer := testSealer(t)
	sealed, _ := sealer.Seal("x")
	conn := connection(idp)
	cases := map[string]struct {
		rows     [][]any
		conn     port.IdentityConnection
		noSealer bool
		secret   string
	}{
		"no settings row":    {},
		"unknown auth code":  {rows: [][]any{settingsRow(idp, "Z", "op", "")}},
		"both credentials":   {rows: [][]any{settingsRow(idp, "P", "op", sealed)}},
		"no credential":      {rows: [][]any{settingsRow(idp, "P", "", "")}},
		"missing secret":     {rows: [][]any{settingsRow(idp, "P", "absent", "")}},
		"sealed without key": {rows: [][]any{settingsRow(idp, "P", "", sealed)}, noSealer: true},
		"bad private key":    {rows: [][]any{settingsRow(idp, "J", "op", "")}, secret: "not a pem"},
		"SAML connection":    {rows: [][]any{settingsRow(idp, "P", "op", "")}, conn: port.IdentityConnection{ID: 7, PartnerID: 42, Protocol: "S", Issuer: idp.srv.URL}},
		"zero-value partner": {rows: [][]any{settingsRow(idp, "P", "op", "")}, conn: port.IdentityConnection{ID: 7, Protocol: ProtocolOIDC, Issuer: idp.srv.URL}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			secretValue := tc.secret
			if secretValue == "" {
				secretValue = "secret"
			}
			p := &Provider{DB: &fakeDB{qs: &fakeQS{rows: tc.rows}}, Secrets: fakeSecrets{"op": secretValue}, HTTP: idp.srv.Client()}
			if !tc.noSealer {
				p.Sealer = sealer
			}
			c := tc.conn
			if c.ID == 0 {
				c = conn
			}
			if _, err := p.Begin(context.Background(), c, port.IdentityBegin{State: "s", RedirectURI: testRedirect}); err == nil {
				t.Fatal("Begin must fail")
			}
		})
	}
	if _, err := (&Provider{}).Begin(context.Background(), conn, port.IdentityBegin{State: "s", RedirectURI: testRedirect}); err == nil {
		t.Fatal("a provider without a database must fail")
	}
}
