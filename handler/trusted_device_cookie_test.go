package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTD() *TrustedDeviceCookie {
	return &TrustedDeviceCookie{Name: "td_test", Path: "/", TTL: time.Hour}
}

func TestTrustedDeviceCookieSetGetRoundtrip(t *testing.T) {
	c := newTD()
	w := httptest.NewRecorder()
	c.Set(w, "raw-secret-value")

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range w.Result().Cookies() {
		r.AddCookie(ck)
	}
	if got := c.Get(r); got != "raw-secret-value" {
		t.Fatalf("Get = %q, want raw-secret-value", got)
	}
}

func TestTrustedDeviceCookieSecureAttrs(t *testing.T) {
	w := httptest.NewRecorder()
	newTD().Set(w, "x")
	cks := w.Result().Cookies()
	if len(cks) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cks))
	}
	c := cks[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected HttpOnly+Secure+Strict; got HttpOnly=%v Secure=%v SameSite=%v", c.HttpOnly, c.Secure, c.SameSite)
	}
}

func TestTrustedDeviceCookieGetAbsent(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := newTD().Get(r); got != "" {
		t.Fatalf("Get on cookie-less request = %q, want \"\"", got)
	}
	if got := newTD().Get(nil); got != "" {
		t.Fatalf("Get(nil) = %q, want \"\"", got)
	}
}

func TestTrustedDeviceCookieClear(t *testing.T) {
	w := httptest.NewRecorder()
	newTD().Clear(w)
	cks := w.Result().Cookies()
	if len(cks) != 1 || cks[0].MaxAge != -1 || cks[0].Value != "" {
		t.Fatalf("Clear should emit a delete cookie (MaxAge=-1, empty value); got %+v", cks)
	}
}
