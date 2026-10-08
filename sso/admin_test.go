package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func validConfig() Configuration {
	return Configuration{Caption: "Acme", Issuer: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
		ClientID: "client-1", ClientAuth: ClientSecretPost, Credential: "s3cret"}
}

func TestConfigureSealsTheCredentialAndDerivesDefaults(t *testing.T) {
	f := newFixture(t)
	id, err := f.svc.Configure(context.Background(), acme, 5, validConfig())
	if err != nil || id == 0 {
		t.Fatalf("Configure = %d, %v", id, err)
	}
	// insert: partner, caption, protocol, issuer, subject_claim, email_claim, require_mfa, created_by
	if f.store.inserted[0] != acme || f.store.inserted[4] != "oid" || f.store.inserted[5] != "email" {
		t.Fatalf("connection row = %v; Entra defaults to oid", f.store.inserted)
	}
	// oidc: partner, id, discovery, client, auth, secret_name, sealed, scopes
	row := f.store.oidcRow
	sealed, _ := row[6].(string)
	if row[2] != validConfig().Issuer+"/.well-known/openid-configuration" || row[5] != nil || sealed == "" || strings.Contains(sealed, "s3cret") || row[7] != defaultScopes {
		t.Fatalf("settings row = %v", row)
	}
	if plain, err := f.svc.Sealer.Open(sealed); err != nil || plain != "s3cret" {
		t.Fatalf("sealed credential opens to %q, %v", plain, err)
	}
}

func TestConfigureRefusals(t *testing.T) {
	f := newFixture(t)
	f.svc.OperatorClients = map[string]OperatorClient{"entra": {ClientID: "op", ClientAuth: ClientSecretPost, SecretName: "entra_secret", IssuerPrefix: "https://login.microsoftonline.com/"}}
	edit := func(change func(*Configuration)) Configuration { c := validConfig(); change(&c); return c }
	for name, cfg := range map[string]Configuration{
		"no caption":          edit(func(c *Configuration) { c.Caption = "" }),
		"http issuer":         edit(func(c *Configuration) { c.Issuer = "http://idp.acme.example" }),
		"templated issuer":    edit(func(c *Configuration) { c.Issuer = "https://login.microsoftonline.com/{tenantid}/v2.0" }),
		"entra common":        edit(func(c *Configuration) { c.Issuer = "https://login.microsoftonline.com/common/v2.0" }),
		"entra organizations": edit(func(c *Configuration) { c.Issuer = "https://login.microsoftonline.com/organizations/v2.0" }),
		"entra consumers": edit(func(c *Configuration) {
			c.Issuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
		}),
		"issuer with query": edit(func(c *Configuration) { c.Issuer += "?x=1" }),
		"no client":         edit(func(c *Configuration) { c.ClientID = "" }),
		"no secret":         edit(func(c *Configuration) { c.Credential = "" }),
		"bad private key":   edit(func(c *Configuration) { c.ClientAuth = ClientPrivateKey; c.Credential = "not a pem" }),
		"unknown auth":      edit(func(c *Configuration) { c.ClientAuth = "N" }),
		"claim injection":   edit(func(c *Configuration) { c.SubjectClaim = "sub; drop" }),
		"unknown operator":  edit(func(c *Configuration) { c.OperatorClient = "okta"; c.ClientID, c.Credential = "", "" }),
		"operator elsewhere": edit(func(c *Configuration) {
			c.OperatorClient = "entra"
			c.Issuer = "https://evil.example"
			c.ClientID, c.Credential = "", ""
		}),
		"operator with secret": edit(func(c *Configuration) { c.OperatorClient = "entra" }),
		"operator host spoofed": edit(func(c *Configuration) {
			c.OperatorClient = "entra"
			c.Issuer = "https://login.microsoftonline.com.evil.example/x"
			c.ClientID, c.Credential = "", ""
		}),
	} {
		if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfigureOperatorClientAndPrivateKey(t *testing.T) {
	f := newFixture(t)
	f.svc.OperatorClients = map[string]OperatorClient{"entra": {ClientID: "op-client", ClientAuth: ClientSecretPost, SecretName: "entra_secret", IssuerPrefix: "https://login.microsoftonline.com/"}}
	cfg := validConfig()
	cfg.OperatorClient, cfg.ClientID, cfg.Credential = "entra", "", ""
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); err != nil {
		t.Fatal(err)
	}
	if row := f.store.oidcRow; row[3] != "op-client" || row[5] != "entra_secret" || row[6] != nil {
		t.Fatalf("operator settings = %v", row)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	cfg = validConfig()
	cfg.ClientAuth, cfg.Credential = ClientPrivateKey, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); err != nil {
		t.Fatalf("private key: %v", err)
	}
}

func TestConfigureActiveConnectionOnlyRotates(t *testing.T) {
	f := newFixture(t)
	f.store.clients[connID] = "client-1"
	cfg := validConfig()
	cfg.ID, cfg.Issuer = connID, issuer
	cfg.Credential = "rotated"
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if keep := f.store.inserted[5]; keep != true {
		t.Fatalf("rotation must keep the test: %v", f.store.inserted)
	}
	cfg.ClientID = "client-2"
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); !errors.Is(err, ErrConnectionActive) {
		t.Fatalf("client change on active = %v", err)
	}
	if _, err := f.svc.Configure(context.Background(), 99, 5, cfg); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("another partner's connection = %v", err)
	}
}

func TestTestSignInRecordsTestAndRequiresTheTester(t *testing.T) {
	f := newFixture(t)
	f.store.connections[connID].Status, f.store.connections[connID].Tested = StatusDraft, false
	f.users.accounts[5] = &model.UserSession{Id: 5, Email: "ada@acme.example", PartnerId: acme}
	ctx := context.Background()

	target, key, err := f.svc.BeginTest(ctx, acme, 5, connID, callbck)
	if err != nil || !strings.Contains(target, "login_hint=ada%40acme.example") {
		t.Fatalf("BeginTest = %q, %v", target, err)
	}
	out, err := f.svc.Complete(ctx, key, callbck, url.Values{})
	if err != nil || !out.Test || !f.store.connections[connID].Tested {
		t.Fatalf("test = %+v, %v", out, err)
	}

	f.provider.assertion.Email = "boss@acme.example"
	_, key, _ = f.svc.BeginTest(ctx, acme, 5, connID, callbck)
	if _, err := f.svc.Complete(ctx, key, callbck, url.Values{}); !errors.Is(err, ErrTestMismatch) {
		t.Fatalf("someone else = %v", err)
	}
	f.users.accounts[6] = &model.UserSession{Id: 6, Email: "eve@other.example", PartnerId: 99}
	if _, _, err := f.svc.BeginTest(ctx, acme, 6, connID, callbck); !errors.Is(err, ErrTestMismatch) {
		t.Fatalf("tester of another partner = %v", err)
	}
}

func TestTestSignInAsksEntraForDomainProof(t *testing.T) {
	f := newFixture(t)
	f.store.connections[connID].Issuer = "https://login.microsoftonline.com/1111/v2.0"
	f.users.accounts[5] = &model.UserSession{Id: 5, Email: "ada@acme.example", PartnerId: acme}
	if _, _, err := f.svc.BeginTest(context.Background(), acme, 5, connID, callbck); err != nil {
		t.Fatal(err)
	}
	if len(f.provider.scopes) == 0 || !strings.Contains(f.provider.scopes[0], "graph.microsoft.com") {
		t.Fatalf("scopes = %v", f.provider.scopes)
	}
}

func TestActivateAndDisable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	draft := &connection{IdentityConnection: port.IdentityConnection{ID: 8, PartnerID: acme, Protocol: "O", Issuer: issuer}, Status: StatusDraft}
	f.store.connections[8] = draft
	if err := f.svc.Activate(ctx, acme, 5, 8); !errors.Is(err, ErrNotTested) {
		t.Fatalf("untested = %v", err)
	}
	draft.Tested = true
	f.store.tSessions = []int64{11, 12}
	f.store.grants[21] = map[string]time.Time{"PARTNER_ADMIN": time.Unix(1, 0)}
	f.store.open[21] = []string{"PARTNER_ADMIN", "MANUAL"}
	if err := f.svc.Activate(ctx, acme, 5, 8); err != nil {
		t.Fatal(err)
	}
	if f.store.connections[connID].Status != StatusDisabled || draft.Status != StatusActive || len(f.users.signedOut) != 2 || len(f.users.revoked) != 2 {
		t.Fatalf("replacement: old %s new %s, signed out %v", f.store.connections[connID].Status, draft.Status, f.users.signedOut)
	}
	if len(f.store.grants[21]) != 0 || !slices.Equal(f.store.open[21], []string{"MANUAL"}) {
		t.Fatalf("replacement kept mapped roles: grants %v open %v", f.store.grants[21], f.store.open[21])
	}

	f.users.signedOut = nil
	if err := f.svc.Disable(ctx, acme, 5, connID); err != nil || len(f.users.signedOut) != 0 {
		t.Fatalf("disabling an inactive connection signed out %v, %v", f.users.signedOut, err)
	}
	f.store.grants[22] = map[string]time.Time{"BILLING": time.Unix(1, 0)}
	f.store.open[22] = []string{"BILLING"}
	if err := f.svc.Disable(ctx, acme, 5, 8); err != nil || len(f.users.signedOut) != 2 {
		t.Fatalf("disabling the active connection signed out %v, %v", f.users.signedOut, err)
	}
	if len(f.store.grants[22]) != 0 || len(f.store.open[22]) != 0 {
		t.Fatalf("disable kept mapped roles: grants %v open %v", f.store.grants[22], f.store.open[22])
	}
	if err := f.svc.Disable(ctx, 99, 5, 8); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("another partner = %v", err)
	}

	delete(f.store.holders, "acme.example")
	draft.Status = StatusDraft
	if err := f.svc.Activate(ctx, acme, 5, 8); !errors.Is(err, ErrNoIdentityDomain) {
		t.Fatalf("no held domain = %v", err)
	}
}

func TestTestProofFailureMattersOnlyWithoutHeldDomain(t *testing.T) {
	f := newFixture(t)
	f.store.connections[connID].Issuer = "https://login.microsoftonline.com/1111/v2.0"
	f.provider.assertion.Issuer, f.provider.assertion.AccessToken = f.store.connections[connID].Issuer, "graph-token"
	f.store.partnerDoms[acme] = []string{"acme.example"}
	f.users.accounts[5] = &model.UserSession{Id: 5, Email: "ada@acme.example", PartnerId: acme}
	ctx := context.Background()

	// No Entra verifier is wired, so the proof fails, but DNS evidence holds the domain.
	_, key, _ := f.svc.BeginTest(ctx, acme, 5, connID, callbck)
	if out, err := f.svc.Complete(ctx, key, callbck, url.Values{}); err != nil || !out.Test {
		t.Fatalf("held domain = %+v, %v", out, err)
	}
	delete(f.store.holders, "acme.example")
	_, key, _ = f.svc.BeginTest(ctx, acme, 5, connID, callbck)
	if _, err := f.svc.Complete(ctx, key, callbck, url.Values{}); err == nil || errors.Is(err, ErrEmailNotAllowed) {
		t.Fatalf("unheld domain must report the failed proof: %v", err)
	}
}

func TestConfigureSAMLConnection(t *testing.T) {
	f := newFixture(t)
	md := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exk1">` +
		`<IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://acme.okta.com/sso"/></IDPSSODescriptor></EntityDescriptor>`
	cfg := Configuration{Protocol: ProtocolSAML, Caption: "Okta", IdPMetadata: md}
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	// insert: partner, caption, protocol, issuer, subject_claim, email_claim, ...
	if f.store.inserted[2] != ProtocolSAML || f.store.inserted[3] != "http://www.okta.com/exk1" || f.store.inserted[4] != "NameID" {
		t.Fatalf("connection row = %v", f.store.inserted)
	}
	for name, bad := range map[string]Configuration{
		"no metadata":        {Protocol: ProtocolSAML, Caption: "x"},
		"malformed metadata": {Protocol: ProtocolSAML, Caption: "x", IdPMetadata: "<x"},
		"no sign-on service": {Protocol: ProtocolSAML, Caption: "x", IdPMetadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="e"/>`},
		"issuer mismatch":    {Protocol: ProtocolSAML, Caption: "x", IdPMetadata: md, Issuer: "http://other"},
		"client secret":      {Protocol: ProtocolSAML, Caption: "x", IdPMetadata: md, Credential: "s"},
		"unknown protocol":   {Protocol: "Z", Caption: "x"},
	} {
		if _, err := f.svc.Configure(context.Background(), acme, 5, bad); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg.ID = connID // an OpenID Connect connection
	if _, err := f.svc.Configure(context.Background(), acme, 5, cfg); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("protocol change = %v", err)
	}
}

func TestDisableDecidesUnderTheLock(t *testing.T) {
	f := newFixture(t)
	f.store.connections[connID].Status = StatusDraft
	f.store.tSessions = []int64{11}
	f.store.onLock = func() { f.store.connections[connID].Status = StatusActive } // activated concurrently
	if err := f.svc.Disable(context.Background(), acme, 5, connID); err != nil {
		t.Fatal(err)
	}
	if len(f.users.signedOut) != 1 {
		t.Fatalf("a connection active at the lock must have its sessions revoked: %v", f.users.signedOut)
	}
}
