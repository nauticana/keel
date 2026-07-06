package payout

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hmacHex is the same wire format every provider's webhook signature
// uses (lower-case hex HMAC-SHA256). Helper for the verify tests so the
// expected-signature math stays out of each test body.
func hmacHex(secret string, parts ...[]byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, p := range parts {
		mac.Write(p)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// captureRequest reads + parses the inbound request into a small struct
// the assertion helpers can inspect. Used by the httptest handlers below.
type captureRequest struct {
	method        string
	path          string
	contentType   string
	authorization string
	idempotency   string
	body          string
}

func capture(r *http.Request) captureRequest {
	b, _ := io.ReadAll(r.Body)
	return captureRequest{
		method:        r.Method,
		path:          r.URL.Path,
		contentType:   r.Header.Get("Content-Type"),
		authorization: r.Header.Get("Authorization"),
		idempotency:   r.Header.Get("Idempotency-Key"),
		body:          string(b),
	}
}

// -----------------------------------------------------------------------------
// AbstractProvider.hmacSHA256Hex
// -----------------------------------------------------------------------------

func TestAbstractProvider_HMACSHA256Hex(t *testing.T) {
	p := &AbstractProvider{webhookSecret: "shh"}
	got := p.hmacSHA256Hex([]byte("ts"), []byte("."), []byte(`{"a":1}`))
	want := hmacHex("shh", []byte("ts"), []byte("."), []byte(`{"a":1}`))
	if got != want {
		t.Fatalf("hmac mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestAbstractProvider_HMACSHA256Hex_EmptySecret(t *testing.T) {
	p := &AbstractProvider{webhookSecret: ""}
	if got := p.hmacSHA256Hex([]byte("anything")); got != "" {
		t.Fatalf("expected empty string for unset secret, got %q", got)
	}
}

// -----------------------------------------------------------------------------
// Airwallex
// -----------------------------------------------------------------------------

func TestAirwallex_StartOnboarding_RequestShape(t *testing.T) {
	var createReq, linkReq captureRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/accounts":
			createReq = capture(r)
			_, _ = w.Write([]byte(`{"id":"acct_aw_123","status":"PENDING"}`))
		default: // /api/v1/accounts/acct_aw_123/onboarding_link
			linkReq = capture(r)
			_, _ = w.Write([]byte(`{"url":"https://hosted/kyc","expires_at":"2026-05-12T01:00:00Z"}`))
		}
	}))
	defer ts.Close()

	p, err := NewAirwallexProvider("key", "secret", nil)
	if err != nil {
		t.Fatalf("NewAirwallexProvider: %v", err)
	}
	p.apiBase = ts.URL

	sess, err := p.StartOnboarding(context.Background(), StartOnboardingInput{
		UserID:        77,
		PartnerID:     42,
		CountryCode:   "CA",
		Currency:      "CAD",
		AccountHolder: "Test User",
		ReturnURL:     "https://app.example.com/return",
	})
	if err != nil {
		t.Fatalf("StartOnboarding: %v", err)
	}
	if sess.ExternalAccountID != "acct_aw_123" {
		t.Errorf("ExternalAccountID=%q, want acct_aw_123", sess.ExternalAccountID)
	}
	if sess.URL != "https://hosted/kyc" {
		t.Errorf("URL=%q, want https://hosted/kyc", sess.URL)
	}
	if createReq.authorization != "Bearer key" {
		t.Errorf("create authorization=%q, want Bearer key", createReq.authorization)
	}
	if createReq.contentType != "application/json" {
		t.Errorf("create content-type=%q", createReq.contentType)
	}
	if !strings.Contains(createReq.body, `"country_code":"CA"`) {
		t.Errorf("create body missing country_code, got %s", createReq.body)
	}
	if !strings.Contains(linkReq.path, "/api/v1/accounts/acct_aw_123/onboarding_link") {
		t.Errorf("link path=%q", linkReq.path)
	}
}

func TestAirwallex_RequestInstantPayout_InsufficientBalanceTyped(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"insufficient_balance","message":"funds short"}`))
	}))
	defer ts.Close()

	p, _ := NewAirwallexProvider("key", "secret", nil)
	p.apiBase = ts.URL

	_, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		UserID: 1, PartnerID: 1,
		ProviderAccountID: "acct_xxx", Amount: 100, Currency: "USD",
		IdempotencyKey: "k-1",
	})
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("err=%v, want ErrInsufficientBalance", err)
	}
}

func TestAirwallex_VerifyWebhook_Signature(t *testing.T) {
	p, _ := NewAirwallexProvider("key", "shh", nil)
	body := []byte(`{"id":"ev_1","name":"account.activated","account_id":"acct_aw_123"}`)
	const ts = "1234567890"
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature": {sig}, "X-Timestamp": {ts},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventAccountActivated || !ev.Activated {
		t.Errorf("event=%+v, want activated", ev)
	}
	if ev.ExternalAccountID != "acct_aw_123" {
		t.Errorf("ExternalAccountID=%q", ev.ExternalAccountID)
	}
}

func TestAirwallex_VerifyWebhook_BadSignature(t *testing.T) {
	p, _ := NewAirwallexProvider("key", "shh", nil)
	body := []byte(`{"id":"ev_1","name":"account.activated","account_id":"a"}`)
	_, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature": {"deadbeef"}, "X-Timestamp": {"1"},
	}, body)
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("err=%v, want invalid signature", err)
	}
}

// -----------------------------------------------------------------------------
// Stripe Connect
// -----------------------------------------------------------------------------

func TestStripeConnect_StartOnboarding_RequestShape(t *testing.T) {
	var acctReq, linkReq captureRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/accounts":
			acctReq = capture(r)
			_, _ = w.Write([]byte(`{"id":"acct_sc_123"}`))
		default: // /v1/account_links
			linkReq = capture(r)
			_, _ = w.Write([]byte(`{"url":"https://stripe/onb","expires_at":1700000000}`))
		}
	}))
	defer ts.Close()

	p, err := NewStripeConnectProvider("sk_test", "whsec", nil)
	if err != nil {
		t.Fatalf("NewStripeConnectProvider: %v", err)
	}
	p.apiBase = ts.URL

	sess, err := p.StartOnboarding(context.Background(), StartOnboardingInput{
		UserID: 1, PartnerID: 1,
		Email: "u@example.com", CountryCode: "US", Currency: "USD",
		ReturnURL: "https://app/return",
	})
	if err != nil {
		t.Fatalf("StartOnboarding: %v", err)
	}
	if sess.ExternalAccountID != "acct_sc_123" || sess.URL != "https://stripe/onb" {
		t.Errorf("session=%+v", sess)
	}
	// Stripe uses HTTP Basic auth with secret key, not Bearer.
	if !strings.HasPrefix(acctReq.authorization, "Basic ") {
		t.Errorf("acct authorization=%q, want Basic", acctReq.authorization)
	}
	if acctReq.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("acct content-type=%q", acctReq.contentType)
	}
	if !strings.Contains(acctReq.body, "type=express") {
		t.Errorf("acct body missing type=express: %s", acctReq.body)
	}
	if !strings.Contains(acctReq.body, "email=u%40example.com") {
		t.Errorf("acct body missing email: %s", acctReq.body)
	}
	if !strings.Contains(linkReq.body, "account=acct_sc_123") {
		t.Errorf("link body missing account: %s", linkReq.body)
	}
	if !strings.Contains(linkReq.body, "type=account_onboarding") {
		t.Errorf("link body missing type: %s", linkReq.body)
	}
}

func TestStripeConnect_StartOnboarding_RequiresEmail(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "whsec", nil)
	_, err := p.StartOnboarding(context.Background(), StartOnboardingInput{
		CountryCode: "US", ReturnURL: "https://app/return",
	})
	if err == nil || !strings.Contains(err.Error(), "Email required") {
		t.Fatalf("err=%v, want Email required", err)
	}
}

func TestStripeConnect_RequestInstantPayout_FormShape(t *testing.T) {
	var req captureRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req = capture(r)
		_, _ = w.Write([]byte(`{"id":"tr_1","status":"pending"}`))
	}))
	defer ts.Close()

	p, _ := NewStripeConnectProvider("sk", "whsec", nil)
	p.apiBase = ts.URL

	res, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		UserID: 1, PartnerID: 1,
		ProviderAccountID: "acct_x", Amount: 2500, Currency: "USD",
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("RequestInstantPayout: %v", err)
	}
	if res.ProviderPayoutID != "tr_1" || res.Status != "pending" {
		t.Errorf("result=%+v", res)
	}
	if req.idempotency != "idem-1" {
		t.Errorf("Idempotency-Key=%q", req.idempotency)
	}
	if !strings.Contains(req.body, "method=instant") {
		t.Errorf("body missing method=instant: %s", req.body)
	}
	if !strings.Contains(req.body, "destination=acct_x") {
		t.Errorf("body missing destination: %s", req.body)
	}
	if !strings.Contains(req.body, "amount=2500") {
		t.Errorf("body missing amount: %s", req.body)
	}
}

func TestStripeConnect_VerifyWebhook_FullyActivated(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_1","type":"account.updated","data":{"object":{"id":"acct_x","details_submitted":true,"payouts_enabled":true}}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"Stripe-Signature": {"t=" + ts + ",v1=" + sig},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventAccountActivated || !ev.Activated {
		t.Errorf("event=%+v, want activated", ev)
	}
}

func TestStripeConnect_VerifyWebhook_RejectsStaleTimestamp(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_1","type":"account.updated","data":{"object":{"id":"acct_x","details_submitted":true,"payouts_enabled":true}}}`)
	ts := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10) // replayed old delivery
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	if _, err := p.VerifyAndParseWebhook(map[string][]string{
		"Stripe-Signature": {"t=" + ts + ",v1=" + sig},
	}, body); err == nil {
		t.Fatal("expected stale timestamp to be rejected")
	}
}

// -----------------------------------------------------------------------------
// Wise
// -----------------------------------------------------------------------------

func TestWise_StartOnboarding_RequiresProfileID(t *testing.T) {
	p, _ := NewWiseProvider("k", "s", nil)
	p.profileID = "" // explicit unset
	_, err := p.StartOnboarding(context.Background(), StartOnboardingInput{
		Email: "u@x", AccountHolder: "U", Currency: "USD",
	})
	if err == nil || !strings.Contains(err.Error(), "wise_profile_id") {
		t.Fatalf("err=%v, want wise_profile_id", err)
	}
}

func TestWise_StartOnboarding_EmailRecipient(t *testing.T) {
	var req captureRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req = capture(r)
		_, _ = w.Write([]byte(`{"id":555}`))
	}))
	defer ts.Close()

	p, _ := NewWiseProvider("k", "s", nil)
	p.apiBase = ts.URL
	p.profileID = "1234"

	sess, err := p.StartOnboarding(context.Background(), StartOnboardingInput{
		Email: "rcpt@example.com", AccountHolder: "Recipient", Currency: "EUR",
	})
	if err != nil {
		t.Fatalf("StartOnboarding: %v", err)
	}
	if sess.ExternalAccountID != "555" {
		t.Errorf("ExternalAccountID=%q, want 555", sess.ExternalAccountID)
	}
	if sess.URL != "" {
		t.Errorf("URL=%q, want empty (no hosted flow)", sess.URL)
	}
	// Decode body to assert structured fields rather than string-grep.
	var payload struct {
		Currency          string         `json:"currency"`
		Type              string         `json:"type"`
		Profile           string         `json:"profile"`
		AccountHolderName string         `json:"accountHolderName"`
		Details           map[string]any `json:"details"`
	}
	if err := json.Unmarshal([]byte(req.body), &payload); err != nil {
		t.Fatalf("body decode: %v\n%s", err, req.body)
	}
	if payload.Type != "email" || payload.Profile != "1234" || payload.Currency != "EUR" {
		t.Errorf("payload=%+v", payload)
	}
	if payload.Details["email"] != "rcpt@example.com" {
		t.Errorf("details.email=%v", payload.Details["email"])
	}
}

func TestWise_VerifyWebhook_PlainSHA256(t *testing.T) {
	p, _ := NewWiseProvider("k", "shh", nil)
	body := []byte(`{"event_id":"e1","event_type":"recipients#updated","data":{"resource":{"id":"r1","status":"ACTIVE"}}}`)
	// Wise's signature is plain SHA-256 of (secret || body), NOT HMAC.
	h := sha256.Sum256(append([]byte("shh"), body...))
	sig := hex.EncodeToString(h[:])
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature-SHA256": {sig},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventAccountActivated || ev.RawEventID != "e1" {
		t.Errorf("event=%+v", ev)
	}
}

// -----------------------------------------------------------------------------
// factory.NewProvider
// -----------------------------------------------------------------------------

func TestFactory_NewProvider_DispatchesByCode(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{ProviderCodeAirwallex, ProviderCodeAirwallex},
		{"", ProviderCodeAirwallex}, // empty defaults to Airwallex
		{ProviderCodeStripeConnect, ProviderCodeStripeConnect},
		{ProviderCodeWise, ProviderCodeWise},
	}
	for _, c := range cases {
		p, err := NewProvider(c.code, "key", "secret", nil)
		if err != nil {
			t.Errorf("NewProvider(%q): %v", c.code, err)
			continue
		}
		if p.Code() != c.want {
			t.Errorf("NewProvider(%q).Code()=%q, want %q", c.code, p.Code(), c.want)
		}
	}
}

func TestFactory_NewProvider_UnknownCode(t *testing.T) {
	_, err := NewProvider("XX", "key", "secret", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("err=%v, want unknown provider", err)
	}
}
