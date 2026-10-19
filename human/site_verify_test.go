package human

import (
	"context"
	"errors"
	"math"
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

func TestSiteVerifyChecksScoreActionAndHostname(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"accepted":      {`{"success":true,"score":0.9,"action":"signup","hostname":"app.example"}`, true},
		"hostname case": {`{"success":true,"score":0.9,"action":"signup","hostname":"APP.EXAMPLE"}`, true},
		"low score":     {`{"success":true,"score":0.3,"action":"signup","hostname":"app.example"}`, false},
		"other action":  {`{"success":true,"score":0.9,"action":"login","hostname":"app.example"}`, false},
		"other host":    {`{"success":true,"score":0.9,"action":"signup","hostname":"evil.example"}`, false},
		"no score (v2)": {`{"success":true,"action":"signup","hostname":"app.example"}`, false},
	} {
		v, _ := verifier(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) })
		v.MinScore, v.Action, v.Hostnames = 0.5, "signup", []string{"app.example"}
		err := v.Verify(context.Background(), "tok", "")
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, port.ErrChallengeFailed)) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestNewSelectsEndpointAndRefusesBadInput(t *testing.T) {
	ok := Settings{Timeout: time.Second, MinScore: 0.5, Action: "signup"}
	if v, err := New("noop", "", ok); v != nil || err != nil {
		t.Fatalf("noop = %v, %v", v, err)
	}
	for mode, endpoint := range map[string]string{"turnstile": TurnstileEndpoint, "hcaptcha": HCaptchaEndpoint, "recaptcha": ReCAPTCHAEndpoint, "recaptcha_v3": ReCAPTCHAEndpoint} {
		v, err := New(mode, "k", ok)
		if err != nil || v.(*SiteVerify).Endpoint != endpoint {
			t.Errorf("%s: %v %v", mode, v, err)
		}
		if sv := v.(*SiteVerify); (mode == "recaptcha_v3") != (sv.MinScore == 0.5 && sv.Action == "signup") {
			t.Errorf("%s: score/action = %v %q", mode, sv.MinScore, sv.Action)
		}
	}
	for name, bad := range map[string]struct {
		mode, secret string
		s            Settings
	}{
		"unknown mode":        {"other", "k", ok},
		"blank secret":        {"turnstile", " ", ok},
		"zero timeout":        {"turnstile", "k", Settings{}},
		"v3 without score":    {"recaptcha_v3", "k", Settings{Timeout: time.Second, Action: "signup"}},
		"v3 score over 1":     {"recaptcha_v3", "k", Settings{Timeout: time.Second, MinScore: 2, Action: "signup"}},
		"v3 non-finite score": {"recaptcha_v3", "k", Settings{Timeout: time.Second, MinScore: math.NaN(), Action: "signup"}},
		"v3 no action":        {"recaptcha_v3", "k", Settings{Timeout: time.Second, MinScore: 0.5}},
	} {
		if _, err := New(bad.mode, bad.secret, bad.s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
