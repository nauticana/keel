package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newCSRF() *CSRF {
	return &CSRF{CookieName: "kx", Path: "/", TTL: time.Minute}
}

func TestCSRFIssueValidateRoundtrip(t *testing.T) {
	c := newCSRF()
	w := httptest.NewRecorder()
	tok, err := c.Issue(w)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token="+url.QueryEscape(tok)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "kx", Value: tok})
	if !c.Validate(r, "csrf_token") {
		t.Fatal("Validate should accept matching token")
	}
}

func TestCSRFMissingCookie(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if newCSRF().Validate(r, "csrf_token") {
		t.Fatal("Validate should reject missing cookie")
	}
}

func TestCSRFMissingForm(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: "kx", Value: "abc"})
	if newCSRF().Validate(r, "csrf_token") {
		t.Fatal("Validate should reject missing form value")
	}
}

func TestCSRFMismatch(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token=zzz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "kx", Value: "abc"})
	if newCSRF().Validate(r, "csrf_token") {
		t.Fatal("Validate should reject mismatched token")
	}
}

func TestCSRFEmptyCookieValue(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("csrf_token=abc"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "kx", Value: ""})
	if newCSRF().Validate(r, "csrf_token") {
		t.Fatal("Validate should reject empty cookie value")
	}
}
