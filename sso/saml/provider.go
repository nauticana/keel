// Package saml is the SAML 2.0 service provider behind port.IdentityProvider.
// It lives apart from package sso so an application that never wires SAML
// never links XML signature code.
package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
	dsig "github.com/russellhaering/goxmldsig"
)

// Protocol is the identity_protocol code of SAML connections.
const Protocol = "S"

const (
	nameIDClaim  = "NameID"
	bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// Signature and digest algorithms accepted on responses and assertions.
// goxmldsig also accepts SHA-1, which keel refuses.
var (
	signatureMethods = map[string]bool{
		dsig.RSASHA256SignatureMethod: true, dsig.RSASHA384SignatureMethod: true, dsig.RSASHA512SignatureMethod: true,
		dsig.ECDSASHA256SignatureMethod: true, dsig.ECDSASHA384SignatureMethod: true, dsig.ECDSASHA512SignatureMethod: true,
	}
	digestMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256": true, "http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512": true,
	}
)

var (
	// ErrBadConfiguration: the connection's metadata is unusable.
	ErrBadConfiguration = errors.New("saml: identity provider configuration is invalid")
	// ErrInvalidResponse: the response, its signature, conditions or relay
	// state failed a check.
	ErrInvalidResponse = errors.New("saml: identity provider response is invalid")
)

// Attributes several identity providers use for the same fact, tried after
// the connection's own claim name.
var (
	emailAttributes = []string{"email", "mail", "emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}
	givenNameAttributes  = []string{"givenName", "firstName", "given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"}
	familyNameAttributes = []string{"sn", "surname", "lastName", "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"}
	// Entra ID replaces a long group list with a link to Graph.
	groupOverage = map[string]string{"http://schemas.microsoft.com/claims/groups.link": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"}
)

const qConnectionMetadata = "saml_connection_metadata"

var providerQueries = map[string]string{
	qConnectionMetadata: `SELECT idp_metadata FROM partner_idp_saml WHERE partner_id = ? AND provider_id = ?`,
}

// Provider signs users in with a connection's SAML identity provider by the
// HTTP-Redirect request and HTTP-POST response bindings. Responses must be
// signed by a certificate in the identity provider's metadata, answer the
// request this browser started, be addressed to the callback, and name
// EntityID as their audience. Identity-provider-initiated sign-in is refused.
type Provider struct {
	DB port.DatabaseRepository
	// EntityID is keel's service provider entity id, registered at each
	// identity provider together with the callback URL.
	EntityID string
	// Key and Certificate, when set, sign authentication requests and decrypt
	// encrypted assertions.
	Key         crypto.Signer
	Certificate *x509.Certificate

	once  sync.Once
	qs    port.QueryService
	mu    sync.Mutex
	cache map[int64]cachedMetadata
}

type cachedMetadata struct {
	fingerprint [32]byte
	metadata    *crewjam.EntityDescriptor
}

var _ port.IdentityProvider = (*Provider)(nil)

type pending struct {
	State     string `json:"s"`
	RequestID string `json:"r"`
}

func (p *Provider) Protocol() string { return Protocol }

// Begin builds the authentication request for the HTTP-Redirect binding.
// Extra scopes have no SAML meaning and are ignored.
func (p *Provider) Begin(ctx context.Context, conn port.IdentityConnection, req port.IdentityBegin) (*port.IdentityRedirect, error) {
	if req.State == "" || req.RedirectURI == "" {
		return nil, fmt.Errorf("%w: state and redirect URI are required", ErrBadConfiguration)
	}
	sp, err := p.serviceProvider(ctx, conn, req.RedirectURI)
	if err != nil {
		return nil, err
	}
	location := sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding)
	if location == "" {
		return nil, fmt.Errorf("%w: no HTTP-Redirect sign-on service", ErrBadConfiguration)
	}
	authn, err := sp.MakeAuthenticationRequest(location, crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding)
	if err != nil {
		return nil, fmt.Errorf("saml: authentication request: %w", err)
	}
	if req.LoginHint != "" {
		authn.Subject = &crewjam.Subject{NameID: &crewjam.NameID{Value: req.LoginHint}}
	}
	target, err := authn.Redirect(url.QueryEscape(req.State), sp)
	if err != nil {
		return nil, fmt.Errorf("saml: redirect: %w", err)
	}
	pend, err := json.Marshal(pending{State: req.State, RequestID: authn.ID})
	if err != nil {
		return nil, err
	}
	return &port.IdentityRedirect{URL: target.String(), Pending: string(pend)}, nil
}

// Complete verifies the posted SAMLResponse against the pending request.
func (p *Provider) Complete(ctx context.Context, conn port.IdentityConnection, cb port.IdentityCallback) (*port.IdentityAssertion, error) {
	var pend pending
	if err := json.Unmarshal([]byte(cb.Pending), &pend); err != nil || pend.State == "" || pend.RequestID == "" {
		return nil, fmt.Errorf("%w: pending sign-in", ErrInvalidResponse)
	}
	if subtle.ConstantTimeCompare([]byte(cb.Params.Get("RelayState")), []byte(pend.State)) != 1 {
		return nil, fmt.Errorf("%w: relay state", ErrInvalidResponse)
	}
	encoded := cb.Params.Get("SAMLResponse")
	if encoded == "" || int64(len(encoded)) > config.Config().SSOMaxDocumentSize {
		return nil, fmt.Errorf("%w: no SAMLResponse", ErrInvalidResponse)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: SAMLResponse encoding", ErrInvalidResponse)
	}
	sp, err := p.serviceProvider(ctx, conn, cb.RedirectURI)
	if err != nil {
		return nil, err
	}
	assertion, err := parseResponse(sp, raw, pend.RequestID)
	if err != nil {
		return nil, err
	}
	if assertion.Issuer.Value != conn.Issuer {
		return nil, fmt.Errorf("%w: issuer %q", ErrInvalidResponse, assertion.Issuer.Value)
	}
	if err := checkAssertion(assertion, p.EntityID, sp.AcsURL.String(), crewjam.TimeNow()); err != nil {
		return nil, err
	}
	return assertionFor(conn, assertion)
}

// parseResponse verifies the response with crewjam, which dereferences a
// signed assertion's Subject, Conditions and SubjectConfirmationData
// without checking that they exist; such a panic is a refused response.
func parseResponse(sp *crewjam.ServiceProvider, raw []byte, requestID string) (as *crewjam.Assertion, err error) {
	defer func() {
		if r := recover(); r != nil {
			as, err = nil, fmt.Errorf("%w: malformed assertion", ErrInvalidResponse)
		}
	}()
	as, err = sp.ParseXMLResponse(raw, []string{requestID}, sp.AcsURL)
	if err != nil {
		var invalid *crewjam.InvalidResponseError
		if errors.As(err, &invalid) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, invalid.PrivateErr)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return as, nil
}

// checkAssertion adds what crewjam leaves open: at least one
// AudienceRestriction, each naming keel (SAML Core §2.5.1.4), and a bearer
// confirmation addressed to the callback that is still valid (SAML Profiles
// §4.1.4.2).
func checkAssertion(as *crewjam.Assertion, entityID, acs string, now time.Time) error {
	if as.Subject == nil || as.Conditions == nil {
		return fmt.Errorf("%w: assertion without subject or conditions", ErrInvalidResponse)
	}
	if len(as.Conditions.AudienceRestrictions) == 0 {
		return fmt.Errorf("%w: assertion without audience restriction", ErrInvalidResponse)
	}
	for _, r := range as.Conditions.AudienceRestrictions {
		if r.Audience.Value != entityID {
			return fmt.Errorf("%w: audience restriction %q excludes the service provider", ErrInvalidResponse, r.Audience.Value)
		}
	}
	for _, sc := range as.Subject.SubjectConfirmations {
		d := sc.SubjectConfirmationData
		if sc.Method == bearerMethod && d != nil && d.Recipient == acs &&
			!d.NotBefore.Add(-crewjam.MaxClockSkew).After(now) && now.Before(d.NotOnOrAfter.Add(crewjam.MaxClockSkew)) {
			return nil
		}
	}
	return fmt.Errorf("%w: no valid bearer subject confirmation", ErrInvalidResponse)
}

// strongSignatures verifies XML signatures as crewjam does, refusing SHA-1.
type strongSignatures struct{}

var _ crewjam.SignatureVerifier = strongSignatures{}

func (strongSignatures) VerifySignature(vc *dsig.ValidationContext, el *etree.Element) error {
	for _, m := range el.FindElements(".//Signature/SignedInfo/SignatureMethod") {
		if alg := m.SelectAttrValue("Algorithm", ""); !signatureMethods[alg] {
			return fmt.Errorf("signature method %q is not accepted", alg)
		}
	}
	for _, m := range el.FindElements(".//Signature/SignedInfo/Reference/DigestMethod") {
		if alg := m.SelectAttrValue("Algorithm", ""); !digestMethods[alg] {
			return fmt.Errorf("digest method %q is not accepted", alg)
		}
	}
	if _, err := vc.Validate(el); err != nil {
		return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}
	return nil
}

// Metadata is keel's service provider metadata for identity provider
// administrators: the entity id, the callback as assertion consumer service,
// and the certificate when one is configured.
func (p *Provider) Metadata(callback string) ([]byte, error) {
	acs, err := url.Parse(callback)
	if err != nil || acs.Scheme != "https" || p.EntityID == "" {
		return nil, fmt.Errorf("%w: entity id and https callback are required", ErrBadConfiguration)
	}
	sp := &crewjam.ServiceProvider{EntityID: p.EntityID, AcsURL: *acs, MetadataURL: *acs, Key: p.Key, Certificate: p.Certificate,
		AuthnNameIDFormat: crewjam.UnspecifiedNameIDFormat}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

// assertionFor maps a verified assertion to the neutral identity.
func assertionFor(conn port.IdentityConnection, as *crewjam.Assertion) (*port.IdentityAssertion, error) {
	a := &port.IdentityAssertion{Issuer: conn.Issuer, Claims: map[string][]string{}}
	for _, st := range as.AttributeStatements {
		for _, attr := range st.Attributes {
			for _, v := range attr.Values {
				if v.Value == "" {
					continue
				}
				a.Claims[attr.Name] = append(a.Claims[attr.Name], v.Value)
				if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
					a.Claims[attr.FriendlyName] = append(a.Claims[attr.FriendlyName], v.Value)
				}
			}
			if target, ok := groupOverage[attr.Name]; ok {
				a.Overage = append(a.Overage, target)
			}
		}
	}
	nameID, nameIDFormat := "", ""
	if as.Subject != nil && as.Subject.NameID != nil {
		nameID, nameIDFormat = strings.TrimSpace(as.Subject.NameID.Value), as.Subject.NameID.Format
	}
	subjectClaim := conn.SubjectClaim
	if subjectClaim == "" {
		subjectClaim = nameIDClaim
	}
	if subjectClaim == nameIDClaim {
		if nameIDFormat == string(crewjam.TransientNameIDFormat) {
			return nil, fmt.Errorf("%w: a transient NameID is not a stable subject; configure a persistent NameID or a subject attribute", ErrInvalidResponse)
		}
		a.Subject = nameID
	} else {
		a.Subject = first(a.Claims, subjectClaim)
	}
	if a.Subject == "" {
		return nil, fmt.Errorf("%w: missing subject %q", ErrInvalidResponse, subjectClaim)
	}
	a.Email = first(a.Claims, append([]string{conn.EmailClaim}, emailAttributes...)...)
	if a.Email == "" && strings.Contains(nameID, "@") {
		a.Email = nameID
	}
	a.GivenName = first(a.Claims, givenNameAttributes...)
	a.FamilyName = first(a.Claims, familyNameAttributes...)
	if multiFactor(as, a.Claims) {
		a.AuthMethods = []string{"mfa"}
	}
	return a, nil
}

// multiFactor reads the authentication context and Microsoft's method claim.
func multiFactor(as *crewjam.Assertion, claims map[string][]string) bool {
	for _, st := range as.AuthnStatements {
		if ref := st.AuthnContext.AuthnContextClassRef; ref != nil {
			v := strings.ToLower(ref.Value)
			if strings.Contains(v, "multifactor") || strings.Contains(v, "multipleauthn") || strings.HasSuffix(v, "/mfa") {
				return true
			}
		}
	}
	for _, v := range claims["http://schemas.microsoft.com/claims/authnmethodsreferences"] {
		if strings.Contains(strings.ToLower(v), "multipleauthn") {
			return true
		}
	}
	return false
}

func first(claims map[string][]string, names ...string) string {
	for _, n := range names {
		if n == "" {
			continue
		}
		if v := claims[n]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

// serviceProvider builds the crewjam service provider for a connection and
// callback. The parsed metadata is cached until the stored document changes.
func (p *Provider) serviceProvider(ctx context.Context, conn port.IdentityConnection, callback string) (*crewjam.ServiceProvider, error) {
	if conn.ID <= 0 || conn.PartnerID <= 0 || conn.Protocol != Protocol {
		return nil, fmt.Errorf("%w: connection %d is not a SAML connection", ErrBadConfiguration, conn.ID)
	}
	if p.EntityID == "" {
		return nil, fmt.Errorf("%w: no service provider entity id", ErrBadConfiguration)
	}
	acs, err := url.Parse(callback)
	if err != nil || acs.Scheme != "https" {
		return nil, fmt.Errorf("%w: callback must be https", ErrBadConfiguration)
	}
	md, err := p.metadata(ctx, conn)
	if err != nil {
		return nil, err
	}
	sp := &crewjam.ServiceProvider{
		EntityID: p.EntityID, AcsURL: *acs, MetadataURL: *acs, IDPMetadata: md,
		Key: p.Key, Certificate: p.Certificate, AllowIDPInitiated: false,
		HTTPClient: common.PublicHTTPClient(), SignatureVerifier: strongSignatures{},
		AuthnNameIDFormat: crewjam.UnspecifiedNameIDFormat,
	}
	if p.Key != nil && p.Certificate != nil {
		sp.SignatureMethod = signatureMethod(p.Key)
	}
	return sp, nil
}

func (p *Provider) metadata(ctx context.Context, conn port.IdentityConnection) (*crewjam.EntityDescriptor, error) {
	if p.DB == nil {
		return nil, errors.New("saml: provider has no database")
	}
	p.once.Do(func() { p.qs = p.DB.GetQueryService(ctx, providerQueries) })
	res, err := p.qs.Query(ctx, qConnectionMetadata, conn.PartnerID, conn.ID)
	if err != nil {
		return nil, fmt.Errorf("saml: metadata of connection %d: %w", conn.ID, err)
	}
	if len(res.Rows) != 1 {
		return nil, fmt.Errorf("%w: connection %d has no SAML metadata", ErrBadConfiguration, conn.ID)
	}
	raw := common.AsString(res.Rows[0][0])
	fp := sha256.Sum256([]byte(conn.Issuer + "\x00" + raw))
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.cache[conn.ID]; ok && c.fingerprint == fp {
		return c.metadata, nil
	}
	md, err := ParseMetadata(raw, conn.Issuer)
	if err != nil {
		return nil, err
	}
	if p.cache == nil || len(p.cache) >= config.Config().SSOConnectionCacheSize {
		p.cache = map[int64]cachedMetadata{}
	}
	p.cache[conn.ID] = cachedMetadata{fingerprint: fp, metadata: md}
	return md, nil
}

// ParseMetadata reads an identity provider's metadata and requires its
// entityID to be issuer and at least one signing certificate.
func ParseMetadata(raw, issuer string) (*crewjam.EntityDescriptor, error) {
	var md crewjam.EntityDescriptor
	if err := xml.Unmarshal([]byte(raw), &md); err != nil {
		return nil, fmt.Errorf("%w: metadata: %v", ErrBadConfiguration, err)
	}
	if md.EntityID != issuer || len(md.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("%w: metadata entityID %q is not the issuer", ErrBadConfiguration, md.EntityID)
	}
	for _, idp := range md.IDPSSODescriptors {
		for _, kd := range idp.KeyDescriptors {
			if kd.Use != "encryption" && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
				return &md, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: metadata has no signing certificate", ErrBadConfiguration)
}

func signatureMethod(key crypto.Signer) string {
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
	return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
}
