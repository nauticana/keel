package outbox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

const (
	testSecretRef = "partner/42/webhook"
	testSecret    = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
)

type fakeResolver struct {
	dest WebhookDestination
	err  error
}

func (r *fakeResolver) ResolveWebhookDestination(context.Context, Event) (WebhookDestination, error) {
	return r.dest, r.err
}

type fakeSecrets struct {
	values map[string]string
	asked  []string
}

func (s *fakeSecrets) GetSecret(_ context.Context, path string) (string, error) {
	s.asked = append(s.asked, path)
	v, ok := s.values[path]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

type delivery struct {
	header http.Header
	body   []byte
}

type receiver struct {
	*httptest.Server
	mu     sync.Mutex
	got    []delivery
	status int
}

func newReceiver(t *testing.T, status int) *receiver {
	t.Helper()
	r := &receiver{status: status}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, delivery{req.Header.Clone(), body})
		r.mu.Unlock()
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) deliveries() []delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]delivery(nil), r.got...)
}

func serverTLS(s *httptest.Server) *tls.Config {
	return s.Client().Transport.(*http.Transport).TLSClientConfig
}

func serverHost(t *testing.T, s *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

type dispatcherFixture struct {
	*HTTPDispatcher
	resolver *fakeResolver
	secrets  *fakeSecrets
	clock    *clock.Fake
}

func newFixture(t *testing.T, s *httptest.Server, mutate func(*HTTPDispatcherConfig)) *dispatcherFixture {
	t.Helper()
	f := &dispatcherFixture{
		resolver: &fakeResolver{dest: WebhookDestination{PartnerID: 42, URL: s.URL + "/hooks?token=receiver-token", SecretRef: testSecretRef}},
		secrets:  &fakeSecrets{values: map[string]string{testSecretRef: testSecret}},
		clock:    clock.NewFake(time.Unix(1_800_000_000, 0)),
	}
	cfg := HTTPDispatcherConfig{
		Resolver: f.resolver,
		Secrets:  f.secrets,
		Egress:   EgressPolicy{AllowedHosts: []string{serverHost(t, s)}, AllowPrivateNetworks: true},
		TLS:      serverTLS(s),
		Clock:    f.clock,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	d, err := NewHTTPDispatcher(cfg)
	if err != nil {
		t.Fatalf("NewHTTPDispatcher: %v", err)
	}
	f.HTTPDispatcher = d
	return f
}

func testEvent() Event {
	return Event{Id: 7, PartnerID: 42, AggregateType: "finding", AggregateID: "99", EventType: "finding.created", Payload: `{"x":1}`}
}

func mustBePermanent(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want a permanent error, got nil")
	}
	if !isPermanent(err) {
		t.Fatalf("want a permanent error, got retryable: %v", err)
	}
}

func mustBeRetryable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want a retryable error, got nil")
	}
	if isPermanent(err) {
		t.Fatalf("want a retryable error, got permanent: %v", err)
	}
}

func TestHTTPDispatcher_DeliversVerifiableSignedEnvelope(t *testing.T) {
	r := newReceiver(t, http.StatusNoContent)
	f := newFixture(t, r.Server, nil)
	if err := f.Dispatch(context.Background(), testEvent()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	got := r.deliveries()
	if len(got) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(got))
	}
	h := got[0].header
	if h.Get(HeaderWebhookID) != "7" || h.Get("Idempotency-Key") != "7" {
		t.Fatalf("id headers = %q / %q, want the event id", h.Get(HeaderWebhookID), h.Get("Idempotency-Key"))
	}
	if !strings.HasPrefix(h.Get(HeaderWebhookSignature), "v1,") {
		t.Fatalf("signature %q carries no scheme version", h.Get(HeaderWebhookSignature))
	}
	verify := func(secret string, body []byte, now time.Time) error {
		return VerifyWebhookSignature(secret, h.Get(HeaderWebhookID), h.Get(HeaderWebhookTimestamp), body, h.Get(HeaderWebhookSignature), 5*time.Minute, now)
	}
	if err := verify(testSecret, got[0].body, f.clock.Now()); err != nil {
		t.Fatalf("receiver could not verify: %v", err)
	}
	if err := verify(testSecret, append([]byte(" "), got[0].body...), f.clock.Now()); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("tampered body: %v, want ErrWebhookSignature", err)
	}
	if err := verify("another-partner-secret", got[0].body, f.clock.Now()); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("wrong secret: %v, want ErrWebhookSignature", err)
	}
	if err := verify(testSecret, got[0].body, f.clock.Now().Add(time.Hour)); !errors.Is(err, ErrWebhookTimestamp) {
		t.Fatalf("stale delivery: %v, want ErrWebhookTimestamp", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(got[0].body, &envelope); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	want := map[string]any{
		"id": "7", "type": "finding.created", "aggregateType": "finding",
		"aggregateId": "99", "partnerId": "42", "payload": map[string]any{"x": float64(1)},
	}
	for k, v := range want {
		if gotV, _ := json.Marshal(envelope[k]); string(gotV) != mustJSON(t, v) {
			t.Errorf("envelope[%q] = %s, want %s", k, gotV, mustJSON(t, v))
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A retry keeps the receiver's dedupe key and re-signs the new timestamp.
func TestHTTPDispatcher_RetryKeepsIdentityAndResigns(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	f := newFixture(t, r.Server, nil)
	_ = f.Dispatch(context.Background(), testEvent())
	f.clock.Advance(time.Minute)
	_ = f.Dispatch(context.Background(), testEvent())

	got := r.deliveries()
	if len(got) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(got))
	}
	first, second := got[0].header, got[1].header
	if first.Get(HeaderWebhookID) != second.Get(HeaderWebhookID) {
		t.Fatal("event id changed across attempts")
	}
	if string(got[0].body) != string(got[1].body) {
		t.Fatal("body changed across attempts")
	}
	if first.Get(HeaderWebhookTimestamp) == second.Get(HeaderWebhookTimestamp) ||
		first.Get(HeaderWebhookSignature) == second.Get(HeaderWebhookSignature) {
		t.Fatal("retry reused the first attempt's timestamp or signature")
	}
	err := VerifyWebhookSignature(testSecret, second.Get(HeaderWebhookID), first.Get(HeaderWebhookTimestamp),
		got[1].body, second.Get(HeaderWebhookSignature), time.Hour, f.clock.Now())
	if !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("signature must bind its own timestamp, got %v", err)
	}
}

func TestHTTPDispatcher_RefusesAnotherPartnersDestination(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	f := newFixture(t, r.Server, nil)
	f.resolver.dest.PartnerID = 43
	mustBePermanent(t, f.Dispatch(context.Background(), testEvent()))

	unscoped := testEvent()
	unscoped.PartnerID = 0
	mustBePermanent(t, f.Dispatch(context.Background(), unscoped))

	if len(r.deliveries()) != 0 || len(f.secrets.asked) != 0 {
		t.Fatal("a cross-partner event reached the network or the secret store")
	}
}

func TestHTTPDispatcher_EgressRejections(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	host := serverHost(t, r.Server)
	port := r.Listener.Addr().String()[strings.LastIndex(r.Listener.Addr().String(), ":"):]
	cases := map[string]struct {
		url    string
		egress EgressPolicy
	}{
		"plain http":          {"http://" + host + port, EgressPolicy{AllowedHosts: []string{host}, AllowPrivateNetworks: true}},
		"credentials in url":  {"https://user:pw@" + host + port, EgressPolicy{AllowedHosts: []string{host}, AllowPrivateNetworks: true}},
		"host not listed":     {r.URL, EgressPolicy{AllowedHosts: []string{"hooks.example.com"}, AllowPrivateNetworks: true}},
		"apex under wildcard": {"https://example.com", EgressPolicy{AllowedHosts: []string{"*.example.com"}}},
		"private address":     {r.URL, EgressPolicy{AllowedHosts: []string{"*"}}},
		"metadata address":    {"https://169.254.169.254/latest", EgressPolicy{AllowedHosts: []string{"*"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, r.Server, func(cfg *HTTPDispatcherConfig) { cfg.Egress = tc.egress })
			f.resolver.dest.URL = tc.url
			err := f.Dispatch(context.Background(), testEvent())
			mustBePermanent(t, err)
			if !errors.Is(err, ErrEgressDenied) {
				t.Fatalf("err = %v, want ErrEgressDenied", err)
			}
		})
	}
	if n := len(r.deliveries()); n != 0 {
		t.Fatalf("%d rejected destinations were still contacted", n)
	}
}

func TestEgressPolicy_HostPatterns(t *testing.T) {
	p := EgressPolicy{AllowedHosts: []string{"Hooks.Example.com", "*.partner.io"}}
	for host, want := range map[string]bool{
		"hooks.example.com": true, "a.partner.io": true, "a.b.partner.io": true,
		"partner.io": false, "evilpartner.io": false, "example.com": false,
	} {
		if got := p.hostAllowed(host); got != want {
			t.Errorf("hostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
	if (EgressPolicy{}).hostAllowed("anything.com") {
		t.Error("the zero policy must reject everything")
	}
}

func TestNewHTTPDispatcher_FailsClosedOnMissingWiring(t *testing.T) {
	full := HTTPDispatcherConfig{
		Resolver: &fakeResolver{}, Secrets: &fakeSecrets{},
		Egress: EgressPolicy{AllowedHosts: []string{"hooks.example.com"}},
	}
	for name, strip := range map[string]func(*HTTPDispatcherConfig){
		"resolver":   func(c *HTTPDispatcherConfig) { c.Resolver = nil },
		"secrets":    func(c *HTTPDispatcherConfig) { c.Secrets = nil },
		"allow-list": func(c *HTTPDispatcherConfig) { c.Egress.AllowedHosts = nil },
	} {
		cfg := full
		strip(&cfg)
		if _, err := NewHTTPDispatcher(cfg); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}

func TestHTTPDispatcher_StatusClassification(t *testing.T) {
	for status, permanent := range map[int]bool{
		http.StatusRequestTimeout: false, http.StatusTooEarly: false, http.StatusTooManyRequests: false,
		http.StatusInternalServerError: false, http.StatusBadGateway: false, http.StatusServiceUnavailable: false,
		http.StatusBadRequest: true, http.StatusUnauthorized: true, http.StatusNotFound: true, http.StatusGone: true,
	} {
		r := newReceiver(t, status)
		err := newFixture(t, r.Server, nil).Dispatch(context.Background(), testEvent())
		if permanent {
			mustBePermanent(t, err)
		} else {
			mustBeRetryable(t, err)
		}
	}
}

func TestHTTPDispatcher_RedirectIsNotFollowed(t *testing.T) {
	elsewhere := newReceiver(t, http.StatusOK)
	redirecting := httptest.NewTLSServer(http.RedirectHandler(elsewhere.URL, http.StatusTemporaryRedirect))
	t.Cleanup(redirecting.Close)

	err := newFixture(t, redirecting, nil).Dispatch(context.Background(), testEvent())
	mustBePermanent(t, err)
	if len(elsewhere.deliveries()) != 0 {
		t.Fatal("signed request followed a redirect to another host")
	}
}

func TestHTTPDispatcher_TimeoutIsRetryable(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	f := newFixture(t, slow, func(cfg *HTTPDispatcherConfig) { cfg.Timeout = 50 * time.Millisecond })
	err := f.Dispatch(context.Background(), testEvent())
	mustBeRetryable(t, err)
	if strings.Contains(err.Error(), "receiver-token") {
		t.Fatalf("error leaks the destination URL into last_error: %v", err)
	}
}

func TestHTTPDispatcher_SecretFailureSendsNothing(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	for name, values := range map[string]map[string]string{
		"lookup failed": {},
		"empty secret":  {testSecretRef: ""},
		"bad whsec":     {testSecretRef: "whsec_!!!"},
	} {
		f := newFixture(t, r.Server, nil)
		f.secrets.values = values
		mustBeRetryable(t, f.Dispatch(context.Background(), testEvent()))
		if len(f.secrets.asked) != 1 || f.secrets.asked[0] != testSecretRef {
			t.Errorf("%s: secret lookups = %v, want the destination's ref", name, f.secrets.asked)
		}
	}
	if n := len(r.deliveries()); n != 0 {
		t.Fatalf("%d unsigned deliveries were sent", n)
	}
}

func TestHTTPDispatcher_ResolverErrorKeepsItsClassification(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	f := newFixture(t, r.Server, nil)
	f.resolver.err = errors.New("db unavailable")
	mustBeRetryable(t, f.Dispatch(context.Background(), testEvent()))
	f.resolver.err = Permanent(errors.New("subscription removed"))
	mustBePermanent(t, f.Dispatch(context.Background(), testEvent()))
}

func TestHTTPDispatcher_InvalidPayloadIsPermanent(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	e := testEvent()
	e.Payload = "{not json"
	mustBePermanent(t, newFixture(t, r.Server, nil).Dispatch(context.Background(), e))
}

func TestHandleJob_PermanentErrorDeadLettersImmediately(t *testing.T) {
	qs := applied(newFakeQS(), qFail)
	w := &Worker{Dispatcher: &fakeDispatcher{err: Permanent(errors.New("HTTP 410"))}, MaxAttempts: 5}
	_ = handle(w, qs, &fakeLogger{}, claimRow(int64(42), 0, 555))
	if qs.ran(qFail) == nil {
		t.Fatal("permanent failure was not dead-lettered on the first attempt")
	}
	if qs.ran(qRetry) != nil {
		t.Fatal("permanent failure was scheduled for retry")
	}
}
