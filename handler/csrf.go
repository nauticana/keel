package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"
)

const csrfTokenLen = 32

// CSRF implements the double-submit-cookie pattern: Issue sets a random
// token in an HttpOnly/Secure/Strict cookie, Validate checks that the
// matching form field equals the cookie value in constant time.
//
// Stateless and per-request: use this for server-rendered admin pages
// in downstream services that aren't covered by keel's JWT API auth.
type CSRF struct {
	CookieName string
	Path       string
	TTL        time.Duration
	// Insecure drops the cookie's Secure flag (default keeps it). Only for local
	// HTTP dev — a Secure cookie is not sent over plain HTTP, which would break a
	// localhost consent POST. Never set this in production.
	Insecure bool
}

// Issue mints a fresh token, sets the cookie, and returns the token to
// embed in the form (typically as a hidden <input>).
func (c *CSRF) Issue(w http.ResponseWriter) (string, error) {
	b := make([]byte, csrfTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    tok,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(c.TTL),
	})
	return tok, nil
}

// Validate returns true iff the named form field equals the cookie value.
func (c *CSRF) Validate(r *http.Request, formField string) bool {
	cookie, err := r.Cookie(c.CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	got := r.FormValue(formField)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(cookie.Value)) == 1
}
