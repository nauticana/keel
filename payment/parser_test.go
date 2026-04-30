package payment

import "testing"

func TestStripeParser_CheckoutCompleted(t *testing.T) {
	body := []byte(`{
		"id":"evt_1",
		"type":"checkout.session.completed",
		"created": 1700000000,
		"data":{"object":{
			"amount_total": 1999,
			"currency":"usd",
			"metadata":{"partner_id":"42","plan":"pro"}
		}}
	}`)
	e, err := NewStripeEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.ProviderEventID != "evt_1" {
		t.Errorf("event id: %q", e.ProviderEventID)
	}
	if e.EventType != "checkout.session.completed" {
		t.Errorf("event type: %q", e.EventType)
	}
	if e.Amount != 19.99 {
		t.Errorf("amount: %v", e.Amount)
	}
	if e.Currency != "USD" {
		t.Errorf("currency: %q", e.Currency)
	}
	if e.Metadata["partner_id"] != "42" || e.Metadata["plan"] != "pro" {
		t.Errorf("metadata: %+v", e.Metadata)
	}
	if e.PaidAt.IsZero() {
		t.Error("expected PaidAt set")
	}
}

func TestStripeParser_InvoicePaid(t *testing.T) {
	body := []byte(`{
		"id":"evt_2","type":"invoice.paid",
		"data":{"object":{"amount_paid": 5000, "currency":"eur"}}
	}`)
	e, err := NewStripeEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Amount != 50.00 {
		t.Errorf("amount: %v", e.Amount)
	}
	if e.Currency != "EUR" {
		t.Errorf("currency: %q", e.Currency)
	}
}

// v0.5.1-D: setup-mode checkout.session.completed pre-extracts Mode,
// SetupIntentID, and CustomerID so domain handlers branch on typed
// fields instead of re-parsing RawPayload.
func TestStripeParser_SetupModeCheckoutFields(t *testing.T) {
	body := []byte(`{
		"id":"evt_3",
		"type":"checkout.session.completed",
		"created": 1700000000,
		"data":{"object":{
			"mode":"setup",
			"setup_intent":"seti_xyz",
			"customer":"cus_abc",
			"metadata":{"user_id":"42"}
		}}
	}`)
	e, err := NewStripeEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Mode != "setup" {
		t.Errorf("mode: %q", e.Mode)
	}
	if e.SetupIntentID != "seti_xyz" {
		t.Errorf("setup_intent: %q", e.SetupIntentID)
	}
	if e.CustomerID != "cus_abc" {
		t.Errorf("customer: %q", e.CustomerID)
	}
}

// v0.5.1-D: setup_intent.* events report the SetupIntent's own id
// since data.object IS the SetupIntent (not a Checkout Session that
// references one).
func TestStripeParser_SetupIntentSucceededFields(t *testing.T) {
	body := []byte(`{
		"id":"evt_4",
		"type":"setup_intent.succeeded",
		"data":{"object":{
			"id":"seti_zzz",
			"customer":"cus_abc",
			"metadata":{"user_id":"42"}
		}}
	}`)
	e, err := NewStripeEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.SetupIntentID != "seti_zzz" {
		t.Errorf("setup_intent id: %q (expected seti_zzz)", e.SetupIntentID)
	}
	if e.CustomerID != "cus_abc" {
		t.Errorf("customer: %q", e.CustomerID)
	}
	if e.Mode != "" {
		t.Errorf("setup_intent events should leave Mode empty, got %q", e.Mode)
	}
}

// v0.5.1-D: events that don't carry mode / setup_intent / customer
// leave the new fields zero-valued.
func TestStripeParser_NoSetupFields_LeavesEmpty(t *testing.T) {
	body := []byte(`{
		"id":"evt_5","type":"invoice.paid",
		"data":{"object":{"amount_paid": 1000, "currency":"usd"}}
	}`)
	e, err := NewStripeEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Mode != "" || e.SetupIntentID != "" || e.CustomerID != "" {
		t.Errorf("expected setup fields empty for invoice.paid; got %+v", e)
	}
}

func TestStripeParser_MalformedJSON(t *testing.T) {
	_, err := NewStripeEventParser().Parse([]byte("not-json"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// P0-24: parser must reject events that lack an id. Synthesizing one
// would defeat idempotency in payment_webhook_log, so the parser
// refuses rather than papering over the gap.
func TestStripeParser_RejectsMissingID(t *testing.T) {
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{}}}`)
	if _, err := NewStripeEventParser().Parse(body); err == nil {
		t.Fatal("expected error for missing event id")
	}
}

func TestLemonSqueezyParser_RejectsMissingID(t *testing.T) {
	body := []byte(`{"meta":{"event_name":"order_created"},"data":{"attributes":{}}}`)
	if _, err := NewLemonSqueezyEventParser().Parse(body); err == nil {
		t.Fatal("expected error for missing data.id")
	}
}

// FuzzStripeParser feeds attacker-controlled bodies into the parser.
// The contract is "never panic": the parser must either return a valid
// canonical event or an error. A panic on a hostile webhook body lets
// a single malformed delivery crash the worker, which becomes a free
// DoS — Stripe will retry the bad payload on a fixed schedule and
// keep the loop alive.
//
// Run as a normal test (seed-corpus only) via `go test`, or as a
// targeted fuzzer via `go test -fuzz=FuzzStripeParser -fuzztime=30s`.
// The seed corpus exercises shape variation (missing fields, wrong
// types, extreme amounts, NaN/Inf-shaped numbers, deeply-nested
// objects) so the mutator has useful starting points.
func FuzzStripeParser(f *testing.F) {
	f.Add([]byte(`{"id":"evt_1","type":"checkout.session.completed","created":1700000000,"data":{"object":{"amount_total":1999,"currency":"usd","metadata":{"k":"v"}}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"id":"x"}`))
	f.Add([]byte(`{"id":"x","data":{"object":null}}`))
	f.Add([]byte(`{"id":"x","data":{"object":{"amount":-9223372036854775808}}}`))
	f.Add([]byte(`{"id":"x","data":{"object":{"amount":"not-a-number"}}}`))
	f.Add([]byte(`{"id":"x","data":{"object":{"metadata":{"k":["nested"]}}}}`))
	f.Add([]byte(`{"id":"x","created":-1,"data":{"object":{"amount_paid":1.5e308}}}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewStripeEventParser().Parse(body)
	})
}

// FuzzLemonSqueezyParser is the LemonSqueezy companion to
// FuzzStripeParser. Same contract: never panic on attacker-controlled
// bodies. LemonSqueezy's payload shape is different (data.id,
// meta.event_name, attributes.total_usd) so it gets its own seed
// corpus.
func FuzzLemonSqueezyParser(f *testing.F) {
	f.Add([]byte(`{"meta":{"event_name":"order_created","custom_data":{"k":"v"}},"data":{"id":"99","attributes":{"total":2500,"currency":"usd","created_at":"2024-01-02T03:04:05Z"}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"meta":null,"data":null}`))
	f.Add([]byte(`{"data":{"id":""}}`))
	f.Add([]byte(`{"data":{"id":"99","attributes":{"created_at":"not-a-time"}}}`))
	f.Add([]byte(`{"data":{"id":"99","attributes":{"total":"-1"}}}`))
	f.Add([]byte(`{"data":{"id":"99","attributes":{"total_usd":1.7e308,"currency":"\x00"}}}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewLemonSqueezyEventParser().Parse(body)
	})
}

func TestLemonSqueezyParser(t *testing.T) {
	body := []byte(`{
		"meta":{"event_name":"order_created","custom_data":{"partner_id":"7"}},
		"data":{"id":"99","attributes":{"total":2500,"currency":"usd","created_at":"2024-01-02T03:04:05Z"}}
	}`)
	e, err := NewLemonSqueezyEventParser().Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.EventType != "order_created" {
		t.Errorf("event type: %q", e.EventType)
	}
	if e.ProviderEventID != "99" {
		t.Errorf("id: %q", e.ProviderEventID)
	}
	if e.Amount != 25.00 {
		t.Errorf("amount: %v", e.Amount)
	}
	if e.Currency != "USD" {
		t.Errorf("currency: %q", e.Currency)
	}
	if e.Metadata["partner_id"] != "7" {
		t.Errorf("metadata: %+v", e.Metadata)
	}
	if e.PaidAt.IsZero() {
		t.Error("expected PaidAt")
	}
}
