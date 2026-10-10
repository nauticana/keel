package authserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/port"
)

const (
	HandoffCodeTTL    = 60 * time.Second
	HandoffSessionTTL = 10 * time.Minute

	maxHandoffReturnLen = 2000 // oauth_session_handoff.return_url
)

var (
	ErrHandoffReturn = errors.New("hand-off return must be this server's authorize URL")
	ErrHandoffCode   = errors.New("hand-off code is invalid, expired, or already used")
	ErrHandoffUser   = errors.New("hand-off requires an authenticated user")

	errHandoffUnconfigured = errors.New("oauth: session hand-off not built with NewSessionHandoff")
)

// SessionHandoff turns a bearer-authenticated app session into a short-lived
// cookie session on the authorization server host, for SPAs whose session
// never reaches /oauth/authorize as a cookie. The return URL is confined to
// this AS's authorize endpoint at mint and at redeem, so it is never an open
// redirect.
type SessionHandoff struct {
	store     port.SessionHandoffStore
	authorize *url.URL
}

// HandoffGrant is a minted code plus the AS URL the browser navigates to.
type HandoffGrant struct {
	Code      string
	ReturnURL string
	RedeemURL string
}

// HandoffSession is a redeemed code: Token is the cookie credential.
type HandoffSession struct {
	Token     string
	ReturnURL string
	TTL       time.Duration
	User      *port.UserRef
}

// NewSessionHandoff confines returns to authorizeEndpoint, the absolute
// AuthorizationEndpoint from this AS's metadata.
func NewSessionHandoff(store port.SessionHandoffStore, authorizeEndpoint string) (*SessionHandoff, error) {
	if store == nil {
		return nil, errors.New("oauth: session hand-off requires a store")
	}
	u, err := url.Parse(authorizeEndpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, OAuthAuthorizePath) {
		return nil, fmt.Errorf("oauth: session hand-off needs an absolute authorize endpoint, got %q", authorizeEndpoint)
	}
	return &SessionHandoff{store: store, authorize: u}, nil
}

func (s *SessionHandoff) ready() error {
	if s == nil || s.store == nil || s.authorize == nil {
		return errHandoffUnconfigured
	}
	return nil
}

func (s *SessionHandoff) Mint(ctx context.Context, user port.UserRef, rawReturn string) (*HandoffGrant, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if user.UserID <= 0 {
		return nil, ErrHandoffUser
	}
	ret, err := s.canonicalReturn(rawReturn)
	if err != nil {
		return nil, err
	}
	code, err := randToken()
	if err != nil {
		return nil, err
	}
	if err := s.store.SaveHandoff(ctx, &port.SessionHandoffCode{
		CodeHash: hashToken(code), UserID: user.UserID, PartnerID: user.PartnerID, ReturnURL: ret,
	}, HandoffCodeTTL); err != nil {
		return nil, err
	}
	redeem := *s.authorize
	redeem.Path = strings.TrimSuffix(redeem.Path, OAuthAuthorizePath) + OAuthSessionPath
	redeem.RawPath = ""
	redeem.RawQuery = url.Values{"code": {code}, "return": {ret}}.Encode()
	return &HandoffGrant{Code: code, ReturnURL: ret, RedeemURL: redeem.String()}, nil
}

func (s *SessionHandoff) Redeem(ctx context.Context, code, rawReturn string) (*HandoffSession, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	ret, err := s.canonicalReturn(rawReturn)
	if err != nil {
		return nil, err
	}
	if !isToken(code) {
		return nil, ErrHandoffCode
	}
	token, err := randToken()
	if err != nil {
		return nil, err
	}
	user, err := s.store.RedeemHandoff(ctx, hashToken(code), ret, hashToken(token), HandoffSessionTTL)
	if err != nil {
		return nil, err
	}
	if user == nil || user.UserID <= 0 {
		return nil, ErrHandoffCode
	}
	user.Subject = subjectForUser(user.UserID)
	return &HandoffSession{Token: token, ReturnURL: ret, TTL: HandoffSessionTTL, User: user}, nil
}

// Resolve returns the user of a live hand-off session token, nil when the
// token is malformed, unknown, or expired.
func (s *SessionHandoff) Resolve(ctx context.Context, token string) (*port.UserRef, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if !isToken(token) {
		return nil, nil
	}
	user, err := s.store.ResolveHandoffSession(ctx, hashToken(token))
	if err != nil || user == nil || user.UserID <= 0 {
		return nil, err
	}
	user.Subject = subjectForUser(user.UserID)
	return user, nil
}

// End expires the hand-off session of token, so the account behind it is no
// longer used at the authorization endpoint.
func (s *SessionHandoff) End(ctx context.Context, token string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if !isToken(token) {
		return nil
	}
	return s.store.EndHandoffSession(ctx, hashToken(token))
}

// canonicalReturn accepts the authorize URL in absolute or path-absolute form
// and returns it absolute; anything else is ErrHandoffReturn.
func (s *SessionHandoff) canonicalReturn(raw string) (string, error) {
	if raw == "" || len(raw) > maxHandoffReturnLen || strings.ContainsAny(raw, "\\#") {
		return "", ErrHandoffReturn
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" {
		return "", ErrHandoffReturn
	}
	if u.Scheme == "" && u.Host == "" {
		if !strings.HasPrefix(raw, "/") {
			return "", ErrHandoffReturn
		}
	} else if !strings.EqualFold(u.Scheme, s.authorize.Scheme) || !strings.EqualFold(u.Host, s.authorize.Host) {
		return "", ErrHandoffReturn
	}
	if u.EscapedPath() != s.authorize.EscapedPath() {
		return "", ErrHandoffReturn
	}
	u.Scheme, u.Host = s.authorize.Scheme, s.authorize.Host
	out := u.String()
	if len(out) > maxHandoffReturnLen {
		return "", ErrHandoffReturn
	}
	return out, nil
}

// isToken matches randToken's output: 64 lowercase hex characters.
func isToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
