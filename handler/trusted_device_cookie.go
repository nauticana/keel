package handler

import (
	"net/http"
	"time"
)

// DefaultTrustedDeviceCookie is the cookie used by keel's built-in 2FA
// flow. Downstream apps that mount their own login handlers may keep the
// default or instantiate a TrustedDeviceCookie with a different name/path.
var DefaultTrustedDeviceCookie = &TrustedDeviceCookie{
	Name: "keel_td",
	Path: "/",
	TTL:  30 * 24 * time.Hour,
}

// TrustedDeviceCookie wraps the HttpOnly+Secure+Strict cookie that carries
// the raw device secret returned by UserService.RegisterTrustedDevice.
// Set immediately after a successful 2FA verify; Get on the next login.
type TrustedDeviceCookie struct {
	Name string
	Path string
	TTL  time.Duration
}

// Set issues the trusted-device cookie with the secret returned by
// RegisterTrustedDevice. The caller MUST NOT log or persist secret
// outside this cookie.
func (c *TrustedDeviceCookie) Set(w http.ResponseWriter, secret string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    secret,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(c.TTL),
	})
}

// Get returns the cookie value or "" if absent. Pass directly to
// UserService.IsTrustedDevice.
func (c *TrustedDeviceCookie) Get(r *http.Request) string {
	if r == nil {
		return ""
	}
	ck, err := r.Cookie(c.Name)
	if err != nil {
		return ""
	}
	return ck.Value
}

// Clear deletes the cookie (typically on RevokeTrustedDevice for the
// current device, or on LogoutEverywhere).
func (c *TrustedDeviceCookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     c.Path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
