package human

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

func verifier(t *testing.T, handler http.HandlerFunc) (*SiteVerify, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &SiteVerify{Endpoint: srv.URL, Secret: "s3cret", Client: &http.Client{Timeout: 200 * time.Millisecond}}, srv
}

func TestSiteVerifyPassesTokenSecretAndAddress(t *testing.T) {
	var form map[string]string
	v, _ := verifier(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = map[string]string{"secret": r.Form.Get("secret"), "response": r.Form.Get("response"), "remoteip": r.Form.Get("remoteip")}
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	if err := v.Verify(context.Background(), "tok", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if form["secret"] != "s3cret" || form["response"] != "tok" || form["remoteip"] != "203.0.113.9" {
		t.Fatalf("form = %v", form)
	}
}

func TestSiteVerifyBlankTokenNeverCallsProvider(t *testing.T) {
	calls := 0
	v, _ := verifier(t, func(http.ResponseWriter, *http.Request) { calls++ })
	if err := v.Verify(context.Background(), "  ", ""); !errors.Is(err, port.ErrChallengeRequired) || calls != 0 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

func TestSiteVerifyRejectionIsFailed(t *testing.T) {
	v, _ := verifier(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	})
	err := v.Verify(context.Background(), "tok", "")
	if !errors.Is(err, port.ErrChallengeFailed) || err.Error() != "human: challenge failed: invalid-input-response" {
		t.Fatalf("err = %v", err)
	}
}

func TestSiteVerifyProviderFaultsFailClosed(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"status 500": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"not json":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"timeout":    func(http.ResponseWriter, *http.Request) { time.Sleep(400 * time.Millisecond) },
	}
	for name, h := range cases {
		v, _ := verifier(t, h)
		if err := v.Verify(context.Background(), "tok", ""); !errors.Is(err, port.ErrChallengeUnavailable) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestNewSelectsEndpointAndRefusesBadInput(t *testing.T) {
	if v, err := New("noop", "", time.Second); v != nil || err != nil {
		t.Fatalf("noop = %v, %v", v, err)
	}
	for mode, endpoint := range map[string]string{"turnstile": TurnstileEndpoint, "hcaptcha": HCaptchaEndpoint, "recaptcha": ReCAPTCHAEndpoint} {
		v, err := New(mode, "k", 5*time.Second)
		if err != nil || v.(*SiteVerify).Endpoint != endpoint {
			t.Errorf("%s: %v %v", mode, v, err)
		}
	}
	if _, err := New("other", "k", time.Second); err == nil {
		t.Error("unknown mode accepted")
	}
	if _, err := New("turnstile", " ", time.Second); err == nil {
		t.Error("blank secret accepted")
	}
	if _, err := New("turnstile", "k", 0); err == nil {
		t.Error("zero timeout accepted")
	}
}
