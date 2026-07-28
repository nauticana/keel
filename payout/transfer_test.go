package payout

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// genWiseTestKey mints an RSA keypair and returns the private key plus
// the PKIX-PEM public key keel consumes as the Wise "webhook secret".
func genWiseTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return key, pubPEM
}

// wiseTestSign produces the Base64 RSA-SHA256 body signature Wise sends
// in X-Signature-SHA256.
func wiseTestSign(t *testing.T, key *rsa.PrivateKey, body []byte) string {
	t.Helper()
	digest := sha256.Sum256(body)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// -----------------------------------------------------------------------------
// minorToDecimal — the provider amount contract (USD 2dp, JPY 0dp, BHD 3dp)
// -----------------------------------------------------------------------------

func TestMinorToDecimal(t *testing.T) {
	cases := []struct {
		amount   int64
		currency string
		want     string
	}{
		{599, "USD", "5.99"},
		{2499, "usd", "24.99"},
		{100, "EUR", "1.00"},
		{5, "USD", "0.05"},
		{0, "USD", "0.00"},
		{-599, "USD", "-5.99"},
		{599, "JPY", "599"},
		{-1500, "JPY", "-1500"},
		{599, "BHD", "0.599"},
		{12345, "BHD", "12.345"},
		{1, "KWD", "0.001"},
	}
	for _, c := range cases {
		if got := minorToDecimal(c.amount, c.currency); got != c.want {
			t.Errorf("minorToDecimal(%d, %s)=%q, want %q", c.amount, c.currency, got, c.want)
		}
	}
}

func TestAirwallex_Payout_ContractAndDecimalAmount(t *testing.T) {
	var path, body string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := capture(r)
		path, body = c.path, c.body
		_, _ = w.Write([]byte(`{"id":"tfr_1","status":"PROCESSING"}`))
	}))
	defer ts.Close()

	p, _ := NewAirwallexProvider("key", "secret", nil)
	p.apiBase = ts.URL
	_, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "ben_x", Amount: 599, Currency: "USD", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("RequestInstantPayout: %v", err)
	}
	// Exact documented contract: /api/v1/transfers/create with
	// transfer_currency, a documented rail (not INSTANT), a required
	// reason, and beneficiary_id.
	if path != "/api/v1/transfers/create" {
		t.Errorf("path=%q, want /api/v1/transfers/create", path)
	}
	for _, frag := range []string{
		`"transfer_amount":5.99`,
		`"transfer_currency":"USD"`,
		`"transfer_method":"LOCAL"`,
		`"reason":`,
		`"beneficiary_id":"ben_x"`,
		`"request_id":"k1"`,
	} {
		if !strings.Contains(body, frag) {
			t.Errorf("body missing %s: %s", frag, body)
		}
	}
	if strings.Contains(body, "INSTANT") {
		t.Errorf("INSTANT is not a documented Airwallex transfer_method: %s", body)
	}

	_, _ = p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "ben_x", Amount: 1500, Currency: "JPY", IdempotencyKey: "k2",
	})
	if !strings.Contains(body, `"transfer_amount":1500`) || strings.Contains(body, "15.00") {
		t.Errorf("JPY 1500 must wire as 1500, body=%s", body)
	}

	_, _ = p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "ben_x", Amount: 599, Currency: "BHD", IdempotencyKey: "k3",
	})
	if !strings.Contains(body, `"transfer_amount":0.599`) {
		t.Errorf("BHD 599 must wire as 0.599, body=%s", body)
	}
}

// -----------------------------------------------------------------------------
// Wise — decimal quote + balance funding
// -----------------------------------------------------------------------------

func TestWise_Payout_QuotesDecimalAndFundsTransfer(t *testing.T) {
	var quoteBody, fundBody, fundPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/quotes"):
			quoteBody = capture(r).body
			_, _ = w.Write([]byte(`{"id":"q-uuid"}`))
		case r.URL.Path == "/v1/transfers":
			_, _ = w.Write([]byte(`{"id":9001,"status":"incoming_payment_waiting"}`))
		case strings.Contains(r.URL.Path, "/payments"):
			c := capture(r)
			fundPath, fundBody = c.path, c.body
			_, _ = w.Write([]byte(`{"status":"COMPLETED"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	p, _ := NewWiseProvider("k", "s", nil)
	p.apiBase = ts.URL
	p.profileID = "77"

	res, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "555", Amount: 599, Currency: "USD", IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("RequestInstantPayout: %v", err)
	}
	if !strings.Contains(quoteBody, `"sourceAmount":5.99`) {
		t.Errorf("USD 599 minor must quote as 5.99, body=%s", quoteBody)
	}
	if fundPath != "/v3/profiles/77/transfers/9001/payments" {
		t.Errorf("funding path=%q", fundPath)
	}
	if !strings.Contains(fundBody, `"type":"BALANCE"`) {
		t.Errorf("funding body=%s", fundBody)
	}
	if res.ProviderPayoutID != "9001" || res.Status != "pending" {
		t.Errorf("result=%+v", res)
	}
}

func TestWise_Payout_FundingRejectedKeepsTransferIdentity(t *testing.T) {
	fundResp := `{"status":"REJECTED","errorCode":"transfer.approval_required"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/quotes"):
			_, _ = w.Write([]byte(`{"id":"q-uuid"}`))
		case r.URL.Path == "/v1/transfers":
			_, _ = w.Write([]byte(`{"id":9002,"status":"incoming_payment_waiting"}`))
		default:
			_, _ = w.Write([]byte(fundResp))
		}
	}))
	defer ts.Close()

	p, _ := NewWiseProvider("k", "s", nil)
	p.apiBase = ts.URL
	p.profileID = "77"
	res, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "555", Amount: 100, Currency: "USD", IdempotencyKey: "idem-2",
	})
	if err == nil || !strings.Contains(err.Error(), "funding rejected") {
		t.Fatalf("err=%v, want funding rejected", err)
	}
	// The transfer exists — its identity must survive the failure so the
	// caller can persist and reconcile it.
	if res == nil || res.ProviderPayoutID != "9002" {
		t.Fatalf("partial result=%+v, want transfer 9002 preserved", res)
	}

	// Wise reports insufficient balance as HTTP 200 REJECTED with a
	// typed errorCode — must map to ErrInsufficientBalance.
	fundResp = `{"status":"REJECTED","errorCode":"transfer.insufficient_funds"}`
	res, err = p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "555", Amount: 100, Currency: "USD", IdempotencyKey: "idem-3",
	})
	if err != ErrInsufficientBalance {
		t.Fatalf("err=%v, want ErrInsufficientBalance", err)
	}
	if res == nil || res.ProviderPayoutID != "9002" {
		t.Fatalf("partial result=%+v, want transfer identity preserved", res)
	}
}

func TestOnboardingService_HandleWebhook_NilSinkIsRetryableError(t *testing.T) {
	log := newFakeWebhookLog()
	svc := &OnboardingService{
		Provider: &fakeProvider{event: &PayoutWebhookEvent{
			Type: PayoutEventTransferPaid, ProviderTransferID: "po_x", RawEventID: "ev_x",
		}},
		WebhookLog: log,
	}
	// No sink wired: a terminal event must fail (claim stays retryable),
	// never be silently marked processed.
	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err == nil {
		t.Fatal("expected configuration error for terminal event with no TransferSink")
	}
	if log.status["AW/ev_x"] != WebhookStatusFailed {
		t.Errorf("claim status=%q, want F (retryable)", log.status["AW/ev_x"])
	}
}

// -----------------------------------------------------------------------------
// Transfer lifecycle webhooks
// -----------------------------------------------------------------------------

func TestWise_TransferStateChangeWebhook(t *testing.T) {
	key, pubPEM := genWiseTestKey(t)
	p, _ := NewWiseProvider("k", pubPEM, nil)
	cases := []struct {
		state string
		want  PayoutWebhookEventType
	}{
		{"outgoing_payment_sent", PayoutEventTransferPaid},
		{"cancelled", PayoutEventTransferFailed},
		{"funds_refunded", PayoutEventTransferReturned},
		{"charged_back", PayoutEventTransferReversed},
		// bounced_back is documented non-final — must NOT dispatch a terminal event.
		{"bounced_back", PayoutEventIgnored},
		{"processing", PayoutEventIgnored},
	}
	for _, c := range cases {
		// The current transfers#state-change schema has no event_id —
		// keel synthesizes a deterministic one from id+state+occurred_at.
		body := []byte(fmt.Sprintf(
			`{"event_type":"transfers#state-change","sent_at":"2026-07-27T10:00:00Z","data":{"resource":{"id":9001,"type":"transfer"},"current_state":"%s","occurred_at":"2026-07-27T09:59:58Z"}}`,
			c.state))
		ev, err := p.VerifyAndParseWebhook(map[string][]string{
			"X-Signature-SHA256": {wiseTestSign(t, key, body)},
		}, body)
		if err != nil {
			t.Fatalf("%s: %v", c.state, err)
		}
		if ev.Type != c.want {
			t.Errorf("%s: type=%s, want %s", c.state, ev.Type, c.want)
		}
		if c.want != PayoutEventIgnored {
			if ev.ProviderTransferID != "9001" {
				t.Errorf("%s: transfer id=%q, want 9001", c.state, ev.ProviderTransferID)
			}
			wantID := "transfer:9001:" + c.state + ":2026-07-27T09:59:58Z"
			if ev.RawEventID != wantID {
				t.Errorf("%s: RawEventID=%q, want %q", c.state, ev.RawEventID, wantID)
			}
			if ev.OccurredAt != "2026-07-27T09:59:58Z" {
				t.Errorf("%s: OccurredAt=%q", c.state, ev.OccurredAt)
			}
		}
	}
}

func TestAirwallex_TransferWebhook(t *testing.T) {
	p, _ := NewAirwallexProvider("key", "shh", nil)
	body := []byte(`{"id":"ev_t1","name":"transfer.update","data":{"id":"po_9","status":"RETURNED"}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature": {hmacHex("shh", []byte(ts), body)},
		"X-Timestamp": {ts},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventTransferReturned || ev.ProviderTransferID != "po_9" {
		t.Errorf("event=%+v", ev)
	}
}

func TestAirwallex_Webhook_RejectsStaleTimestamp(t *testing.T) {
	p, _ := NewAirwallexProvider("key", "shh", nil)
	body := []byte(`{"id":"ev_t2","name":"transfer.update","data":{"id":"po_9","status":"RETURNED"}}`)
	ts := strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)
	if _, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature": {hmacHex("shh", []byte(ts), body)},
		"X-Timestamp": {ts},
	}, body); err == nil || !strings.Contains(err.Error(), "tolerance") {
		t.Fatalf("err=%v, want timestamp outside tolerance", err)
	}
}

func TestStripeConnect_PartialReversalCarriesAmounts(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_pr","type":"transfer.reversed","created":1753600000,"data":{"object":{"id":"tr_1","amount":2500,"amount_reversed":1000}}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"Stripe-Signature": {"t=" + ts + ",v1=" + sig},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.AmountMinor != 2500 || ev.AmountReversedMinor != 1000 {
		t.Errorf("amounts=%d/%d, want 2500/1000 (partial reversal must be distinguishable)", ev.AmountMinor, ev.AmountReversedMinor)
	}
}

func TestStripeConnect_ConnectPayoutPaidWebhook(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_pp","type":"payout.paid","account":"acct_x","data":{"object":{"id":"po_1","amount":2500}}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"Stripe-Signature": {"t=" + ts + ",v1=" + sig},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventTransferPaid || ev.ProviderTransferID != "acct_x:po_1" {
		t.Errorf("event=%+v, want transfer.paid acct_x:po_1", ev)
	}
}

func TestStripeConnect_TransferReversedWebhook(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_9","type":"transfer.reversed","data":{"object":{"id":"tr_1"}}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := hmacHex("shh", []byte(ts), []byte("."), body)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"Stripe-Signature": {"t=" + ts + ",v1=" + sig},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventTransferReversed || ev.ProviderTransferID != "tr_1" {
		t.Errorf("event=%+v", ev)
	}
}

// -----------------------------------------------------------------------------
// GetPayoutStatus
// -----------------------------------------------------------------------------

func TestGetPayoutStatus_AllProviders(t *testing.T) {
	var stripeAccountHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s %s", r.Method, r.URL.Path)
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/transfers/"):
			_, _ = w.Write([]byte(`{"id":"po_1","status":"PAID"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/payouts/"):
			stripeAccountHeader = r.Header.Get("Stripe-Account")
			_, _ = w.Write([]byte(`{"id":"po_9","status":"paid"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/transfers/tr_"):
			_, _ = w.Write([]byte(`{"id":"tr_1","reversed":true}`))
		default: // wise /v1/transfers/{numeric}
			_, _ = w.Write([]byte(`{"id":9001,"status":"outgoing_payment_sent"}`))
		}
	}))
	defer ts.Close()

	aw, _ := NewAirwallexProvider("k", "s", nil)
	aw.apiBase = ts.URL
	if res, err := aw.GetPayoutStatus(context.Background(), "po_1"); err != nil || res.Status != "paid" {
		t.Errorf("airwallex: res=%+v err=%v, want paid", res, err)
	}

	sc, _ := NewStripeConnectProvider("k", "s", nil)
	sc.apiBase = ts.URL
	if res, err := sc.GetPayoutStatus(context.Background(), "acct_x:po_9"); err != nil || res.Status != "paid" {
		t.Errorf("stripe payout: res=%+v err=%v, want paid", res, err)
	}
	if stripeAccountHeader != "acct_x" {
		t.Errorf("stripe payout lookup Stripe-Account=%q, want acct_x", stripeAccountHeader)
	}
	// Legacy bare transfer id: a transfer object can never prove bank
	// delivery — only reversal is a definite outcome.
	if res, err := sc.GetPayoutStatus(context.Background(), "tr_1"); err != nil || res.Status != "reversed" {
		t.Errorf("stripe transfer: res=%+v err=%v, want reversed", res, err)
	}

	wi, _ := NewWiseProvider("k", "s", nil)
	wi.apiBase = ts.URL
	wi.profileID = "77"
	if res, err := wi.GetPayoutStatus(context.Background(), "9001"); err != nil || res.Status != "paid" {
		t.Errorf("wise: res=%+v err=%v, want paid", res, err)
	}
}

// -----------------------------------------------------------------------------
// OnboardingService.HandleWebhook — durable dedup + transfer dispatch
// -----------------------------------------------------------------------------

type fakeProvider struct {
	AbstractProvider
	event *PayoutWebhookEvent
}

func (f *fakeProvider) Code() string { return "AW" }
func (f *fakeProvider) StartOnboarding(context.Context, StartOnboardingInput) (*PayoutOnboardingSession, error) {
	return nil, ErrNotImplemented
}
func (f *fakeProvider) VerifyAndParseWebhook(map[string][]string, []byte) (*PayoutWebhookEvent, error) {
	return f.event, nil
}
func (f *fakeProvider) RequestInstantPayout(context.Context, InstantPayoutInput) (*InstantPayoutResult, error) {
	return nil, ErrNotImplemented
}
func (f *fakeProvider) GetPayoutStatus(context.Context, string) (*InstantPayoutResult, error) {
	return nil, ErrNotImplemented
}

// fakeWebhookLog mirrors SQLWebhookLog's Claim semantics: P/R rows are
// duplicates, F rows are re-claimed.
type fakeWebhookLog struct {
	status map[string]string // key → last processing status
	ids    map[string]int64
	next   int64
}

func newFakeWebhookLog() *fakeWebhookLog {
	return &fakeWebhookLog{status: map[string]string{}, ids: map[string]int64{}}
}

func (f *fakeWebhookLog) Claim(_ context.Context, provider string, ev *PayoutWebhookEvent, _ []byte) (int64, bool, error) {
	k := provider + "/" + ev.RawEventID
	switch f.status[k] {
	case WebhookStatusProcessed, WebhookStatusReceived:
		return 0, true, nil
	case WebhookStatusFailed:
		f.status[k] = WebhookStatusReceived
		return f.ids[k], false, nil
	}
	f.next++
	f.ids[k] = f.next
	f.status[k] = WebhookStatusReceived
	return f.next, false, nil
}

func (f *fakeWebhookLog) UpdateStatus(_ context.Context, logID int64, status, _ string) error {
	for k, id := range f.ids {
		if id == logID {
			f.status[k] = status
		}
	}
	return nil
}

type fakeSink struct {
	events   []*PayoutWebhookEvent
	failNext bool
}

func (f *fakeSink) ApplyTransferEvent(_ context.Context, ev *PayoutWebhookEvent) error {
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("ledger temporarily unavailable")
	}
	f.events = append(f.events, ev)
	return nil
}

func TestOnboardingService_HandleWebhook_DedupAndSink(t *testing.T) {
	ev := &PayoutWebhookEvent{
		Type:               PayoutEventTransferPaid,
		ProviderTransferID: "po_1",
		RawEventID:         "ev_1",
	}
	log := newFakeWebhookLog()
	sink := &fakeSink{}
	svc := &OnboardingService{
		Provider:     &fakeProvider{event: ev},
		WebhookLog:   log,
		TransferSink: sink,
	}

	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if len(sink.events) != 1 || sink.events[0].ProviderTransferID != "po_1" {
		t.Fatalf("sink events=%+v, want one po_1", sink.events)
	}

	// Replay of a processed event: must ACK without re-dispatching.
	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("replay reached the sink: events=%d", len(sink.events))
	}
}

func TestOnboardingService_HandleWebhook_TransientFailureIsRetryable(t *testing.T) {
	ev := &PayoutWebhookEvent{
		Type:               PayoutEventTransferPaid,
		ProviderTransferID: "po_2",
		RawEventID:         "ev_2",
	}
	log := newFakeWebhookLog()
	sink := &fakeSink{failNext: true}
	svc := &OnboardingService{
		Provider:     &fakeProvider{event: ev},
		WebhookLog:   log,
		TransferSink: sink,
	}

	// First delivery fails in the sink — must surface the error (provider retries).
	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err == nil {
		t.Fatal("expected sink failure to surface")
	}
	// The provider's retry must NOT be swallowed as a duplicate.
	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err != nil {
		t.Fatalf("retry after transient failure: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("retry did not reach the sink: events=%d", len(sink.events))
	}
}

func TestOnboardingService_HandleWebhook_IgnoredEventIsAcked(t *testing.T) {
	log := newFakeWebhookLog()
	svc := &OnboardingService{
		Provider:   &fakeProvider{event: &PayoutWebhookEvent{Type: PayoutEventIgnored, RawEventID: "ev_i"}},
		WebhookLog: log,
	}
	if err := svc.HandleWebhook(context.Background(), "AW", nil, []byte(`{}`)); err != nil {
		t.Fatalf("ignored event: %v", err)
	}
	if log.next != 0 {
		t.Errorf("ignored event must not be logged, claims=%d", log.next)
	}
}

var _ PayoutProvider = (*fakeProvider)(nil)

func TestAirwallex_RejectsConnectedAccountAsDestination(t *testing.T) {
	p, _ := NewAirwallexProvider("key", "secret", nil)
	if _, err := p.RequestInstantPayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "acct_aw_123", Amount: 100, Currency: "USD", IdempotencyKey: "k9",
	}); err == nil || !strings.Contains(err.Error(), "Beneficiary") {
		t.Fatalf("err=%v, want beneficiary-required rejection", err)
	}
}

func TestStripeConnect_ResumePayout_ValidatesAndReconciles(t *testing.T) {
	var createReq captureRequest
	creates := 0
	existingPayouts := `{"data":[]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transfers/tr_9":
			_, _ = w.Write([]byte(`{"id":"tr_9","amount":500,"currency":"usd","destination":"acct_x"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/payouts":
			_, _ = w.Write([]byte(existingPayouts))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/payouts":
			creates++
			createReq = capture(r)
			_, _ = w.Write([]byte(`{"id":"po_7","status":"paid"}`))
		case r.URL.Path == "/v1/transfers":
			t.Error("resume must never create a transfer")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	p, _ := NewStripeConnectProvider("sk", "s", nil)
	p.apiBase = ts.URL
	in := InstantPayoutInput{ProviderAccountID: "acct_x", Amount: 500, Currency: "USD", IdempotencyKey: "k1"}

	res, err := p.ResumePayout(context.Background(), in, "tr_9")
	if err != nil {
		t.Fatalf("ResumePayout: %v", err)
	}
	if creates != 1 || createReq.idempotency != "k1-po" || createReq.stripeAccount != "acct_x" {
		t.Errorf("creates=%d req=%+v", creates, createReq)
	}
	if res.ProviderPayoutID != "acct_x:po_7" || res.ProviderFundingID != "tr_9" || res.Status != "paid" {
		t.Errorf("res=%+v", res)
	}

	// An existing payout for the funding transfer is returned, never recreated.
	existingPayouts = `{"data":[{"id":"po_old","status":"in_transit","metadata":{"transfer_id":"tr_9"}}]}`
	res, err = p.ResumePayout(context.Background(), in, "tr_9")
	if err != nil || res.ProviderPayoutID != "acct_x:po_old" || creates != 1 {
		t.Fatalf("res=%+v err=%v creates=%d, want reconciled po_old without a new create", res, err, creates)
	}

	// A mismatched funding transfer is refused.
	if _, err := p.ResumePayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "acct_other", Amount: 500, Currency: "USD", IdempotencyKey: "k1",
	}, "tr_9"); err == nil {
		t.Fatal("mismatched destination must be refused")
	}
}

func TestWise_IdempotencyUUIDDerivation(t *testing.T) {
	u := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	if got := wiseIdempotencyUUID(u); got != u {
		t.Errorf("uuid passthrough=%q", got)
	}
	a, b := wiseIdempotencyUUID("payout-42"), wiseIdempotencyUUID("payout-42")
	if a != b || !wiseUUIDRe.MatchString(a) || a == wiseIdempotencyUUID("payout-43") {
		t.Errorf("derived=%q/%q", a, b)
	}
}

func TestStripeConnect_AcceptsAnyRotationSignature(t *testing.T) {
	p, _ := NewStripeConnectProvider("sk", "shh", nil)
	body := []byte(`{"id":"evt_r","type":"transfer.reversed","data":{"object":{"id":"tr_1","amount":100,"amount_reversed":100}}}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	good := hmacHex("shh", []byte(ts), []byte("."), body)
	header := "t=" + ts + ",v1=deadbeef,v1=" + good
	if _, err := p.VerifyAndParseWebhook(map[string][]string{"Stripe-Signature": {header}}, body); err != nil {
		t.Fatalf("rotation delivery rejected: %v", err)
	}
}

func TestWise_RecipientStateChangeWebhook(t *testing.T) {
	key, pubPEM := genWiseTestKey(t)
	p, _ := NewWiseProvider("k", pubPEM, nil)
	// Documented schema 4.0 envelope: action at data.resource.data.state,
	// timestamp at data.resource.occurred_at.
	body := []byte(`{"data":{"resource":{"id":"700525176","occurred_at":"2026-06-15T13:18:20.265Z","data":{"recipientId":700525176,"profileId":14966143,"currency":"EUR","state":"CREATE"}}},"event_type":"recipients#state-change","schema_version":"4.0.0","sent_at":"2026-06-15T13:18:20.265Z"}`)
	ev, err := p.VerifyAndParseWebhook(map[string][]string{
		"X-Signature-SHA256": {wiseTestSign(t, key, body)},
	}, body)
	if err != nil {
		t.Fatalf("VerifyAndParseWebhook: %v", err)
	}
	if ev.Type != PayoutEventAccountCreated || ev.ExternalAccountID != "700525176" || ev.Activated {
		t.Errorf("event=%+v, want unactivated account.created for 700525176", ev)
	}
	if ev.OccurredAt != "2026-06-15T13:18:20.265Z" || ev.RawEventID == "" {
		t.Errorf("occurred=%q raw=%q", ev.OccurredAt, ev.RawEventID)
	}
}

func TestWise_IsAccountActive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accounts/700525176" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":700525176,"active":true}`))
	}))
	defer ts.Close()
	p, _ := NewWiseProvider("k", "s", nil)
	p.apiBase = ts.URL
	active, err := p.IsAccountActive(context.Background(), "700525176")
	if err != nil || !active {
		t.Fatalf("active=%v err=%v", active, err)
	}
}

func TestStripeConnect_ResumePayout_ReversedFunding(t *testing.T) {
	existingPayouts := `{"data":[]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/transfers/"):
			_, _ = w.Write([]byte(`{"id":"tr_9","amount":500,"amount_reversed":200,"currency":"usd","destination":"acct_x"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/payouts":
			_, _ = w.Write([]byte(existingPayouts))
		default:
			t.Errorf("unexpected %s %s after reversed funding", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	p, _ := NewStripeConnectProvider("sk", "s", nil)
	p.apiBase = ts.URL
	in := InstantPayoutInput{ProviderAccountID: "acct_x", Amount: 500, Currency: "USD", IdempotencyKey: "k1"}

	// No existing payout: reversed funding refuses creation.
	if _, err := p.ResumePayout(context.Background(), in, "tr_9"); err == nil || !strings.Contains(err.Error(), "reversed") {
		t.Fatalf("err=%v, want reversed-funding refusal", err)
	}

	// An already-created payout is still reconciled and returned — the
	// reversal does not un-create it, and the ledger must learn its id.
	existingPayouts = `{"data":[{"id":"po_prior","status":"paid","metadata":{"transfer_id":"tr_9"}}]}`
	res, err := p.ResumePayout(context.Background(), in, "tr_9")
	if err != nil || res.ProviderPayoutID != "acct_x:po_prior" {
		t.Fatalf("res=%+v err=%v, want reconciled po_prior without a POST", res, err)
	}
}

func TestStripeConnect_ResumePayout_FindsPayoutOnLaterPage(t *testing.T) {
	creates := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/transfers/"):
			_, _ = w.Write([]byte(`{"id":"tr_9","amount":500,"currency":"usd","destination":"acct_x"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/payouts":
			if r.URL.Query().Get("starting_after") == "po_a" {
				_, _ = w.Write([]byte(`{"has_more":false,"data":[{"id":"po_b","status":"paid","metadata":{"transfer_id":"tr_9"}}]}`))
			} else {
				_, _ = w.Write([]byte(`{"has_more":true,"data":[{"id":"po_a","status":"paid","metadata":{"transfer_id":"tr_other"}}]}`))
			}
		case r.Method == http.MethodPost:
			creates++
			_, _ = w.Write([]byte(`{"id":"po_new","status":"paid"}`))
		}
	}))
	defer ts.Close()

	p, _ := NewStripeConnectProvider("sk", "s", nil)
	p.apiBase = ts.URL
	res, err := p.ResumePayout(context.Background(), InstantPayoutInput{
		ProviderAccountID: "acct_x", Amount: 500, Currency: "USD", IdempotencyKey: "k1",
	}, "tr_9")
	if err != nil || res.ProviderPayoutID != "acct_x:po_b" || creates != 0 {
		t.Fatalf("res=%+v err=%v creates=%d, want po_b from page 2 without a create", res, err, creates)
	}
}

func TestOnboardingService_RegisterBeneficiary_Guards(t *testing.T) {
	svc := &OnboardingService{}
	if _, err := svc.RegisterBeneficiary(context.Background(), 1, 2, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("err=%v, want provider-not-configured (not a panic)", err)
	}
	svc.Provider = &fakeProvider{}
	if _, err := svc.RegisterBeneficiary(context.Background(), 1, 2, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("err=%v, want capability error", err)
	}
}
