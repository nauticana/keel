package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	spEntityID = "https://api.example/public/sso/saml"
	callback   = "https://api.example/public/sso/callback"
	idpEntity  = "https://idp.example/metadata"
)

type metadataQS struct {
	port.QueryService
	metadata string
}

func (q *metadataQS) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	if q.metadata == "" {
		return &model.QueryResult{}, nil
	}
	return &model.QueryResult{Rows: [][]any{{q.metadata}}}, nil
}

type metadataDB struct {
	port.DatabaseRepository
	qs *metadataQS
}

func (d *metadataDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d.qs
}

// spLookup answers the test identity provider with the service provider's metadata.
type spLookup struct{ md *crewjam.EntityDescriptor }

func (s spLookup) GetServiceProvider(*http.Request, string) (*crewjam.EntityDescriptor, error) {
	return s.md, nil
}

type fixture struct {
	idp      *crewjam.IdentityProvider
	provider *Provider
	conn     port.IdentityConnection
	// nameIDFormat and editAssertion shape the assertion before it is signed.
	nameIDFormat  string
	editAssertion func(*crewjam.Assertion)
}

func keyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, cert := keyPair(t)
	idp := &crewjam.IdentityProvider{Key: key, Signer: key, Certificate: cert, SignatureMethod: dsig.RSASHA256SignatureMethod,
		MetadataURL: mustURL(idpEntity), SSOURL: mustURL("https://idp.example/sso"), AssertionMaker: crewjam.DefaultAssertionMaker{}}
	idpMeta, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{DB: &metadataDB{qs: &metadataQS{metadata: string(idpMeta)}}, EntityID: spEntityID}
	spMeta := (&crewjam.ServiceProvider{EntityID: spEntityID, AcsURL: mustURL(callback), MetadataURL: mustURL(callback)}).Metadata()
	idp.ServiceProviderProvider = spLookup{md: spMeta}
	return &fixture{idp: idp, provider: p, nameIDFormat: string(crewjam.PersistentNameIDFormat),
		conn: port.IdentityConnection{ID: 7, PartnerID: 42, Protocol: Protocol, Issuer: idpEntity, SubjectClaim: "NameID", EmailClaim: "email"}}
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

// signIn runs Begin, has the test identity provider answer, and returns the
// pending value and the callback parameters, with edit applied to the
// response document before it is encoded.
func (f *fixture) signIn(t *testing.T, edit func(doc *etree.Document)) (string, url.Values) {
	t.Helper()
	r, err := f.provider.Begin(context.Background(), f.conn, port.IdentityBegin{State: "st-1", RedirectURI: callback, LoginHint: "ada@acme.example"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	req, err := crewjam.NewIdpAuthnRequest(f.idp, httptest.NewRequest(http.MethodGet, r.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("the identity provider refused the request: %v", err)
	}
	session := &crewjam.Session{ID: "s", NameID: "user-1", NameIDFormat: f.nameIDFormat, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), Index: "1",
		CustomAttributes: []crewjam.Attribute{
			{Name: "email", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "ada@acme.example"}}},
			{Name: "groups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "admins"}, {Type: "xs:string", Value: "staff"}}},
			{Name: "http://schemas.microsoft.com/claims/authnmethodsreferences", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "http://schemas.microsoft.com/claims/multipleauthn"}}},
		}}
	if err := f.idp.AssertionMaker.MakeAssertion(req, session); err != nil {
		t.Fatal(err)
	}
	if f.editAssertion != nil {
		f.editAssertion(req.Assertion)
	}
	if err := req.MakeAssertionEl(); err != nil {
		t.Fatal(err)
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	if edit != nil {
		edit(doc)
	}
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return r.Pending, url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(raw)}, "RelayState": {"st-1"}}
}

func (f *fixture) complete(pending string, params url.Values) (*port.IdentityAssertion, error) {
	return f.provider.Complete(context.Background(), f.conn, port.IdentityCallback{RedirectURI: callback, Params: params, Pending: pending})
}

func TestSignedResponseSignsIn(t *testing.T) {
	f := newFixture(t)
	pending, params := f.signIn(t, nil)
	a, err := f.complete(pending, params)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if a.Issuer != idpEntity || a.Subject != "user-1" || a.Email != "ada@acme.example" || a.EmailVerified ||
		len(a.Claims["groups"]) != 2 || len(a.AuthMethods) != 1 || a.AuthMethods[0] != "mfa" {
		t.Fatalf("assertion = %+v", a)
	}
}

func TestResponseRefusals(t *testing.T) {
	removeSignatures := func(doc *etree.Document) {
		for _, sig := range doc.FindElements("//Signature") {
			sig.Parent().RemoveChild(sig)
		}
	}
	tamper := func(doc *etree.Document) {
		doc.FindElement("//NameID").SetText("admin")
	}
	// A forged unsigned assertion placed before the signed one.
	wrap := func(doc *etree.Document) {
		signed := doc.FindElement("//Assertion")
		forged := signed.Copy()
		for _, sig := range forged.FindElements("./Signature") {
			forged.RemoveChild(sig)
		}
		forged.FindElement(".//NameID").SetText("admin")
		forged.CreateAttr("ID", "forged")
		doc.Root().InsertChildAt(signed.Index(), forged)
	}
	cases := map[string]func(t *testing.T, f *fixture) (string, url.Values){
		"unsigned":          func(t *testing.T, f *fixture) (string, url.Values) { return f.signIn(t, removeSignatures) },
		"tampered":          func(t *testing.T, f *fixture) (string, url.Values) { return f.signIn(t, tamper) },
		"signature wrapped": func(t *testing.T, f *fixture) (string, url.Values) { return f.signIn(t, wrap) },
		"relay state": func(t *testing.T, f *fixture) (string, url.Values) {
			p, v := f.signIn(t, nil)
			v.Set("RelayState", "other")
			return p, v
		},
		"another request": func(t *testing.T, f *fixture) (string, url.Values) {
			first, _ := f.signIn(t, nil)
			_, second := f.signIn(t, nil)
			return first, second
		},
		"wrong audience": func(t *testing.T, f *fixture) (string, url.Values) {
			p, v := f.signIn(t, nil)
			f.provider.EntityID = "https://other.example/sp"
			return p, v
		},
		"not base64": func(t *testing.T, f *fixture) (string, url.Values) {
			p, v := f.signIn(t, nil)
			v.Set("SAMLResponse", "%%%")
			return p, v
		},
		"idp initiated": func(t *testing.T, f *fixture) (string, url.Values) {
			return f.signIn(t, func(doc *etree.Document) {
				doc.Root().RemoveAttr("InResponseTo")
				for _, el := range doc.FindElements("//SubjectConfirmationData") {
					el.RemoveAttr("InResponseTo")
				}
			})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			pending, params := setup(t, f)
			if a, err := f.complete(pending, params); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Complete = %+v, %v", a, err)
			}
		})
	}
}

func TestExpiredAssertionIsRefused(t *testing.T) {
	f := newFixture(t)
	pending, params := f.signIn(t, nil)
	saved := crewjam.TimeNow
	crewjam.TimeNow = func() time.Time { return time.Now().Add(time.Hour) }
	defer func() { crewjam.TimeNow = saved }()
	if _, err := f.complete(pending, params); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("an hour later = %v", err)
	}
}

func TestWrongRecipientIsRefused(t *testing.T) {
	f := newFixture(t)
	pending, params := f.signIn(t, nil)
	_, err := f.provider.Complete(context.Background(), f.conn, port.IdentityCallback{RedirectURI: "https://api.example/other", Params: params, Pending: pending})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("other recipient = %v", err)
	}
}

func TestConfigurationRefusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	begin := func(conn port.IdentityConnection, redirect string) error {
		_, err := f.provider.Begin(ctx, conn, port.IdentityBegin{State: "s", RedirectURI: redirect})
		return err
	}
	other := f.conn
	other.Issuer = "https://evil.example/metadata"
	oidc := f.conn
	oidc.Protocol = "O"
	for name, err := range map[string]error{
		"issuer is not the entityID": begin(other, callback),
		"not a SAML connection":      begin(oidc, callback),
		"plain-http callback":        begin(f.conn, "http://api.example/cb"),
	} {
		if !errors.Is(err, ErrBadConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.provider.DB.(*metadataDB).qs.metadata = ""
	f.provider.cache = nil
	if err := begin(f.conn, callback); !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("no metadata: %v", err)
	}
	if _, err := ParseMetadata(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="`+idpEntity+`"><IDPSSODescriptor/></EntityDescriptor>`, idpEntity); !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("metadata without a certificate: %v", err)
	}
}

func TestServiceProviderMetadata(t *testing.T) {
	f := newFixture(t)
	md, err := f.provider.Metadata(callback)
	if err != nil || !strings.Contains(string(md), spEntityID) || !strings.Contains(string(md), callback) {
		t.Fatalf("metadata = %s, %v", md, err)
	}
	if _, err := f.provider.Metadata("http://api.example/cb"); !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("plain-http callback: %v", err)
	}
}

func TestOverageAndAttributeFallbacks(t *testing.T) {
	as := &crewjam.Assertion{
		Subject: &crewjam.Subject{NameID: &crewjam.NameID{Value: "ada@acme.example"}},
		AttributeStatements: []crewjam.AttributeStatement{{Attributes: []crewjam.Attribute{
			{Name: "http://schemas.microsoft.com/claims/groups.link", Values: []crewjam.AttributeValue{{Value: "https://graph"}}},
			{Name: "urn:oid:2.5.4.42", FriendlyName: "givenName", Values: []crewjam.AttributeValue{{Value: "Ada"}}},
		}}},
	}
	a, err := assertionFor(port.IdentityConnection{Issuer: idpEntity}, as)
	if err != nil || a.Subject != "ada@acme.example" || a.Email != "ada@acme.example" || a.GivenName != "Ada" ||
		len(a.Overage) != 1 || a.Overage[0] != "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" {
		t.Fatalf("assertion = %+v, %v", a, err)
	}
	if _, err := assertionFor(port.IdentityConnection{Issuer: idpEntity, SubjectClaim: "objectid"}, as); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("missing subject attribute = %v", err)
	}
}

func TestAuthnRequestAsksForUnspecifiedNameID(t *testing.T) {
	f := newFixture(t)
	r, err := f.provider.Begin(context.Background(), f.conn, port.IdentityBegin{State: "st-1", RedirectURI: callback})
	if err != nil {
		t.Fatal(err)
	}
	req, err := crewjam.NewIdpAuthnRequest(f.idp, httptest.NewRequest(http.MethodGet, r.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	if policy := req.Request.NameIDPolicy; policy == nil || (policy.Format != nil && *policy.Format != "") {
		t.Fatalf("NameIDPolicy = %+v, want no Format (unspecified)", policy)
	}
	md, err := f.provider.Metadata(callback)
	if err != nil || strings.Contains(string(md), string(crewjam.TransientNameIDFormat)) {
		t.Fatalf("metadata must not advertise transient: %s, %v", md, err)
	}
}

func TestTransientNameIDIsNotASubject(t *testing.T) {
	f := newFixture(t)
	f.nameIDFormat = string(crewjam.TransientNameIDFormat)
	for _, subjectClaim := range []string{"", "NameID"} {
		f.conn.SubjectClaim = subjectClaim
		pending, params := f.signIn(t, nil)
		if _, err := f.complete(pending, params); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("subject claim %q from a transient NameID = %v", subjectClaim, err)
		}
	}
	f.conn.SubjectClaim = "email"
	pending, params := f.signIn(t, nil)
	if a, err := f.complete(pending, params); err != nil || a.Subject != "ada@acme.example" {
		t.Fatalf("subject attribute beside a transient NameID = %+v, %v", a, err)
	}
}

func TestSignedAssertionShapeRefusals(t *testing.T) {
	cases := map[string]func(*crewjam.Assertion){
		"no subject":              func(a *crewjam.Assertion) { a.Subject = nil },
		"no conditions":           func(a *crewjam.Assertion) { a.Conditions = nil },
		"no confirmation data":    func(a *crewjam.Assertion) { a.Subject.SubjectConfirmations[0].SubjectConfirmationData = nil },
		"no subject confirmation": func(a *crewjam.Assertion) { a.Subject.SubjectConfirmations = nil },
		"holder-of-key only": func(a *crewjam.Assertion) {
			a.Subject.SubjectConfirmations[0].Method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
		},
		"no audience restriction": func(a *crewjam.Assertion) { a.Conditions.AudienceRestrictions = nil },
		"restriction excluding keel": func(a *crewjam.Assertion) {
			a.Conditions.AudienceRestrictions = append(a.Conditions.AudienceRestrictions, crewjam.AudienceRestriction{Audience: crewjam.Audience{Value: "https://other.example"}})
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.editAssertion = edit
			pending, params := f.signIn(t, nil)
			if a, err := f.complete(pending, params); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Complete = %+v, %v", a, err)
			}
		})
	}
}

func TestSHA1SignatureIsRefused(t *testing.T) {
	f := newFixture(t)
	f.idp.SignatureMethod = dsig.RSASHA1SignatureMethod
	pending, params := f.signIn(t, nil)
	if a, err := f.complete(pending, params); !errors.Is(err, ErrInvalidResponse) || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("SHA-1 signed response = %+v, %v", a, err)
	}
}

func TestCheckAssertionExpiredConfirmation(t *testing.T) {
	now := time.Now()
	as := &crewjam.Assertion{
		Subject: &crewjam.Subject{SubjectConfirmations: []crewjam.SubjectConfirmation{{Method: bearerMethod,
			SubjectConfirmationData: &crewjam.SubjectConfirmationData{Recipient: callback, NotOnOrAfter: now.Add(-time.Hour)}}}},
		Conditions: &crewjam.Conditions{AudienceRestrictions: []crewjam.AudienceRestriction{{Audience: crewjam.Audience{Value: spEntityID}}}},
	}
	if err := checkAssertion(as, spEntityID, callback, now); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expired confirmation = %v", err)
	}
	as.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(time.Minute)
	if err := checkAssertion(as, spEntityID, callback, now); err != nil {
		t.Fatalf("valid confirmation = %v", err)
	}
	as.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = now.Add(time.Hour)
	if err := checkAssertion(as, spEntityID, callback, now); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("future confirmation = %v", err)
	}
	as.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = time.Time{}
	if err := checkAssertion(as, spEntityID, "https://api.example/other", now); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("other recipient = %v", err)
	}
}
