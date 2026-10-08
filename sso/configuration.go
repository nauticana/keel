package sso

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/oauth/oidc"
)

const (
	googleIssuer   = oidc.GoogleIssuer
	entraHost      = "login.microsoftonline.com"
	entraConsumers = "9188040d-6c67-4c5b-b112-36a304b66dad"
	discoveryPath  = "/.well-known/openid-configuration"
	defaultScopes  = "openid email profile"
)

// Protocol codes (identity_protocol).
const (
	ProtocolOIDC = oidc.ProtocolOIDC
	ProtocolSAML = "S"
)

// Client authentication codes (oidc_client_auth).
const (
	ClientSecretPost  = "P"
	ClientSecretBasic = "B"
	ClientPrivateKey  = "J"
)

var claimName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,99}$`)

// OperatorClient is an app registration the operator owns, such as one
// multi-tenant Entra registration each customer administrator consents to.
// Its credential is used only with issuers under IssuerPrefix, so a partner
// can never send it to an issuer of its choosing.
type OperatorClient struct {
	ClientID     string
	ClientAuth   string
	SecretName   string
	IssuerPrefix string
}

// Configuration is a connection as a partner administrator enters it.
// Protocol is OpenID Connect unless set to ProtocolSAML. For OpenID Connect,
// Credential is a client secret or a PEM private key with its certificate,
// sealed before it is stored, and OperatorClient names an OperatorClients
// preset instead of ClientID and Credential. For SAML, IdPMetadata is the
// identity provider's metadata document, whose entityID is the issuer.
type Configuration struct {
	ID             int64
	Protocol       string
	Caption        string
	Issuer         string
	IdPMetadata    string
	ClientID       string
	ClientAuth     string
	Credential     string
	OperatorClient string
	SubjectClaim   string
	EmailClaim     string
	Scopes         string
	RequireMFA     bool
}

// settings is a validated configuration ready to store.
type settings struct {
	protocol, metadata                                              string
	caption, issuer, discoveryURL, subjectClaim, emailClaim, scopes string
	clientID, clientAuth, secretName, sealed                        string
	requireMFA                                                      bool
}

func (s *Service) validate(c Configuration) (*settings, error) {
	out := &settings{caption: strings.TrimSpace(c.Caption), issuer: strings.TrimRight(strings.TrimSpace(c.Issuer), "/"),
		subjectClaim: strings.TrimSpace(c.SubjectClaim), emailClaim: strings.TrimSpace(c.EmailClaim),
		scopes: strings.Join(strings.Fields(c.Scopes), " "), requireMFA: c.RequireMFA}
	if out.caption == "" || len(out.caption) > 80 {
		return nil, fmt.Errorf("%w: caption is required and at most 80 characters", ErrInvalidConfiguration)
	}
	switch c.Protocol {
	case "", ProtocolOIDC:
		out.protocol = ProtocolOIDC
	case ProtocolSAML:
		return validateSAML(c, out)
	default:
		return nil, fmt.Errorf("%w: protocol %q", ErrInvalidConfiguration, c.Protocol)
	}
	if err := checkIssuer(out.issuer); err != nil {
		return nil, err
	}
	out.discoveryURL = out.issuer + discoveryPath
	if out.subjectClaim == "" {
		out.subjectClaim = "sub"
		if isEntra(out.issuer) {
			out.subjectClaim = "oid"
		}
	}
	if out.emailClaim == "" {
		out.emailClaim = "email"
	}
	if !claimName.MatchString(out.subjectClaim) || !claimName.MatchString(out.emailClaim) {
		return nil, fmt.Errorf("%w: claim names", ErrInvalidConfiguration)
	}
	if out.scopes == "" {
		out.scopes = defaultScopes
	}
	if len(out.scopes) > 255 {
		return nil, fmt.Errorf("%w: scopes are at most 255 characters", ErrInvalidConfiguration)
	}
	if c.OperatorClient != "" {
		op, ok := s.OperatorClients[c.OperatorClient]
		if !ok || op.IssuerPrefix == "" || !strings.HasPrefix(out.issuer+"/", op.IssuerPrefix) {
			return nil, fmt.Errorf("%w: the operator client does not serve this issuer", ErrInvalidConfiguration)
		}
		if c.Credential != "" || c.ClientID != "" {
			return nil, fmt.Errorf("%w: an operator client takes no client id or credential", ErrInvalidConfiguration)
		}
		out.clientID, out.clientAuth, out.secretName = op.ClientID, op.ClientAuth, op.SecretName
		return out, nil
	}
	out.clientID, out.clientAuth = strings.TrimSpace(c.ClientID), c.ClientAuth
	if out.clientID == "" || len(out.clientID) > 255 {
		return nil, fmt.Errorf("%w: client id is required and at most 255 characters", ErrInvalidConfiguration)
	}
	switch out.clientAuth {
	case ClientSecretPost, ClientSecretBasic:
		if strings.TrimSpace(c.Credential) == "" {
			return nil, fmt.Errorf("%w: client secret is required", ErrInvalidConfiguration)
		}
	case ClientPrivateKey:
		if _, _, err := oidc.ParseClientKey(c.Credential); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
		}
	default:
		return nil, fmt.Errorf("%w: client authentication %q", ErrInvalidConfiguration, c.ClientAuth)
	}
	if s.Sealer == nil {
		return nil, fmt.Errorf("sso: no sealer for partner credentials")
	}
	sealed, err := s.Sealer.Seal(c.Credential)
	if err != nil {
		return nil, fmt.Errorf("sso: seal credential: %w", err)
	}
	out.sealed = sealed
	return out, nil
}

// checkIssuer refuses anything but one organization's own HTTPS issuer:
// Entra's shared authorities and its consumer directory answer for many.
func checkIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		len(issuer) > 255 || strings.ContainsAny(issuer, "{}") {
		return fmt.Errorf("%w: issuer must be an absolute https URL", ErrInvalidConfiguration)
	}
	if strings.EqualFold(u.Hostname(), entraHost) {
		tenant := strings.ToLower(strings.Split(strings.TrimPrefix(u.Path, "/"), "/")[0])
		switch tenant {
		case "", "common", "organizations", "consumers", entraConsumers:
			return fmt.Errorf("%w: use the organization's own Entra tenant issuer", ErrInvalidConfiguration)
		}
	}
	return nil
}

func isEntra(issuer string) bool {
	u, err := url.Parse(issuer)
	return err == nil && strings.EqualFold(u.Hostname(), entraHost)
}

// validateSAML reads the identity provider's entityID and single sign-on
// service from its metadata. The full document is parsed again, with its
// certificates, by the SAML provider at each sign-in.
func validateSAML(c Configuration, out *settings) (*settings, error) {
	out.protocol, out.metadata = ProtocolSAML, strings.TrimSpace(c.IdPMetadata)
	if c.ClientID != "" || c.Credential != "" || c.OperatorClient != "" || c.Scopes != "" {
		return nil, fmt.Errorf("%w: a SAML connection takes no client or scopes", ErrInvalidConfiguration)
	}
	if limit := config.Config().SSOMaxDocumentSize; out.metadata == "" || int64(len(out.metadata)) > limit {
		return nil, fmt.Errorf("%w: SAML metadata is required and at most %d bytes", ErrInvalidConfiguration, limit)
	}
	var md struct {
		XMLName  xml.Name `xml:"EntityDescriptor"`
		EntityID string   `xml:"entityID,attr"`
		IDP      []struct {
			SSO []struct {
				Location string `xml:"Location,attr"`
			} `xml:"SingleSignOnService"`
		} `xml:"IDPSSODescriptor"`
	}
	if err := xml.Unmarshal([]byte(out.metadata), &md); err != nil {
		return nil, fmt.Errorf("%w: SAML metadata: %v", ErrInvalidConfiguration, err)
	}
	if md.EntityID == "" || len(md.EntityID) > 255 || strings.ContainsAny(md.EntityID, "{}") || len(md.IDP) == 0 || len(md.IDP[0].SSO) == 0 {
		return nil, fmt.Errorf("%w: SAML metadata needs an entityID and an identity provider sign-on service", ErrInvalidConfiguration)
	}
	if out.issuer != "" && out.issuer != strings.TrimRight(md.EntityID, "/") {
		return nil, fmt.Errorf("%w: the issuer is not the metadata's entityID", ErrInvalidConfiguration)
	}
	out.issuer = md.EntityID
	if out.subjectClaim == "" {
		out.subjectClaim = "NameID"
	}
	if out.emailClaim == "" {
		out.emailClaim = "email"
	}
	if !claimName.MatchString(out.subjectClaim) || (len(out.emailClaim) > 100 || out.emailClaim == "") {
		return nil, fmt.Errorf("%w: claim names", ErrInvalidConfiguration)
	}
	return out, nil
}
