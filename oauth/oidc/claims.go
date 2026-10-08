package oidc

import (
	"crypto/subtle"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/port"
)

// standardClaims are protocol claims, never offered to role mapping.
var standardClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "auth_time": true,
	"nonce": true, "azp": true, "at_hash": true, "c_hash": true, "jti": true, "sid": true,
}

// checkAudience applies the OIDC rule for several audiences: azp must then
// name this client. A single audience was already matched by the parser.
func checkAudience(claims jwt.MapClaims, clientID string) error {
	aud, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("%w: aud: %v", ErrInvalidResponse, err)
	}
	if len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != clientID {
			return fmt.Errorf("%w: azp does not name the client", ErrInvalidResponse)
		}
	}
	return nil
}

func nonceMatches(claims jwt.MapClaims, want string) bool {
	got, _ := claims["nonce"].(string)
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// assertionFromClaims maps verified ID-token claims. subjectClaim and
// emailClaim default to sub and email. Entra signals a group list too long
// for the token with _claim_names or hasgroups; such claims become Overage.
func assertionFromClaims(issuer string, claims jwt.MapClaims, subjectClaim, emailClaim string) (*port.IdentityAssertion, error) {
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	if emailClaim == "" {
		emailClaim = "email"
	}
	a := &port.IdentityAssertion{Issuer: issuer, Claims: map[string][]string{}}
	a.Subject, _ = claims[subjectClaim].(string)
	if a.Subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim %q", ErrInvalidResponse, subjectClaim)
	}
	a.Email, _ = claims[emailClaim].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		a.EmailVerified = v
	case string:
		a.EmailVerified = v == "true"
	}
	a.GivenName, _ = claims["given_name"].(string)
	a.FamilyName, _ = claims["family_name"].(string)
	a.HostedDomain, _ = claims["hd"].(string)
	a.AuthMethods = stringValues(claims["amr"])
	for name, value := range claims {
		if standardClaims[name] || name == "amr" {
			continue
		}
		if values := stringValues(value); len(values) > 0 {
			a.Claims[name] = values
		}
	}
	if names, ok := claims["_claim_names"].(map[string]any); ok {
		for name := range names {
			a.Overage = append(a.Overage, name)
		}
	}
	if has, _ := claims["hasgroups"].(bool); has {
		a.Overage = append(a.Overage, "groups")
	}
	return a, nil
}

func stringValues(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
