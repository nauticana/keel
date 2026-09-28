package payment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type refundFixture struct {
	svc      *BaseRefundService
	store    *memRefundStore
	client   *fakeRefundClient
	captures *fakeCaptureReader
}

func newRefundFixture() refundFixture {
	store := newMemRefundStore()
	client := &fakeRefundClient{store: store}
	captures := &fakeCaptureReader{captured: map[string]CapturedPayment{"pi_1": {AmountMinor: 1000, Currency: "USD"}}}
	return refundFixture{
		svc:      NewBaseRefundService(memRefundRepo{store: store}, ProviderStripe, client, captures),
		store:    store,
		client:   client,
		captures: captures,
	}
}

func (f refundFixture) request(t *testing.T, key string, amount int64) RefundRecord {
	t.Helper()
	rec, err := f.svc.Request(context.Background(), RefundInstruction{
		PaymentID: "pi_1", RequesterID: 7, AmountMinor: amount, Currency: "usd", Reason: "late", IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("Request(%s): %v", key, err)
	}
	return rec
}

func (f refundFixture) approved(t *testing.T, key string, amount int64) RefundRecord {
	t.Helper()
	rec, err := f.svc.Approve(context.Background(), f.request(t, key, amount).ID, 8)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return rec
}

func TestRefundRequestBoundsByCapturedIncludingPending(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	first := f.request(t, "k1", 600)
	if first.Status != RefundRequestPending || first.Currency != "USD" || first.Provider != ProviderStripe {
		t.Fatalf("first = %+v", first)
	}
	if _, err := f.svc.Request(ctx, RefundInstruction{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 401, Currency: "USD", IdempotencyKey: "k2"}); !errors.Is(err, ErrRefundExceedsBalance) {
		t.Fatalf("over-refund err = %v", err)
	}
	f.request(t, "k3", 400)
	if f.captures.calls != 1 {
		t.Fatalf("captured amount read %d times, want once per payment", f.captures.calls)
	}
	for _, inTx := range f.store.lockedIn {
		if !inTx {
			t.Fatal("balance locked outside a transaction")
		}
	}
	if _, err := f.svc.Reject(ctx, first.ID, 8, "duplicate"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	f.request(t, "k4", 600)
}

func TestRefundRequestValidationAndCurrency(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	for _, in := range []RefundInstruction{
		{RequesterID: 7, AmountMinor: 1, Currency: "USD", IdempotencyKey: "k"},
		{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 0, Currency: "USD", IdempotencyKey: "k"},
		{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 1, Currency: "US", IdempotencyKey: "k"},
		{PaymentID: "pi_1", AmountMinor: 1, Currency: "USD", IdempotencyKey: "k"},
	} {
		if _, err := f.svc.Request(ctx, in); !errors.Is(err, ErrRefundInvalidInstruction) {
			t.Fatalf("Request(%+v) err = %v", in, err)
		}
	}
	if _, err := f.svc.Request(ctx, RefundInstruction{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 1, Currency: "EUR", IdempotencyKey: "k"}); !errors.Is(err, ErrRefundCurrencyMismatch) {
		t.Fatalf("currency err = %v", err)
	}
	if _, err := f.svc.Request(ctx, RefundInstruction{PaymentID: "pi_unknown", RequesterID: 7, AmountMinor: 1, Currency: "USD", IdempotencyKey: "k"}); !errors.Is(err, ErrRefundCapturedAmountAbsent) {
		t.Fatalf("unknown payment err = %v", err)
	}
}

func TestRefundRequestIdempotency(t *testing.T) {
	f := newRefundFixture()
	first := f.request(t, "k1", 300)
	again := f.request(t, "k1", 300)
	if again.ID != first.ID || len(f.store.requests) != 1 {
		t.Fatalf("replayed request created %d rows", len(f.store.requests))
	}
	if _, err := f.svc.Request(context.Background(), RefundInstruction{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 301, Currency: "USD", IdempotencyKey: "k1"}); !errors.Is(err, ErrRefundIdempotencyConflict) {
		t.Fatalf("conflicting reuse err = %v", err)
	}
}

func TestRefundApprovalRules(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	rec := f.request(t, "k1", 300)
	if _, err := f.svc.Execute(ctx, rec.ID); !errors.Is(err, ErrRefundNotApproved) {
		t.Fatalf("execute pending err = %v", err)
	}
	if _, err := f.svc.Approve(ctx, rec.ID, 7); !errors.Is(err, ErrRefundSelfApproval) {
		t.Fatalf("self approval err = %v", err)
	}
	approved, err := f.svc.Approve(ctx, rec.ID, 8)
	if err != nil || approved.Status != RefundRequestApproved || approved.ApproverID != 8 {
		t.Fatalf("approve = %+v, %v", approved, err)
	}
	if again, err := f.svc.Approve(ctx, rec.ID, 8); err != nil || again.Status != RefundRequestApproved {
		t.Fatalf("repeated approve = %+v, %v", again, err)
	}
	if _, err := f.svc.Approve(ctx, rec.ID, 9); !errors.Is(err, ErrRefundInvalidState) {
		t.Fatalf("second approver err = %v", err)
	}
	if _, err := f.svc.Approve(ctx, 999, 8); !errors.Is(err, ErrRefundRequestNotFound) {
		t.Fatalf("missing request err = %v", err)
	}
}

func TestRefundExecuteIsRetrySafe(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	rec := f.approved(t, "k1", 300)
	transient := errors.New("connection reset")
	f.client.respond = func(req RefundRequest) (RefundResult, error) { return RefundResult{}, transient }
	failed, err := f.svc.Execute(ctx, rec.ID)
	if !errors.Is(err, transient) || failed.Status != RefundRequestApproved || failed.LastError == "" {
		t.Fatalf("transient execute = %+v, %v", failed, err)
	}
	f.client.respond = nil
	done, err := f.svc.Execute(ctx, rec.ID)
	if err != nil || done.Status != RefundRequestSucceeded || done.ProviderRefundID == "" || done.ProviderAmountMinor != 300 || done.AttemptCount != 2 {
		t.Fatalf("retried execute = %+v, %v", done, err)
	}
	if again, err := f.svc.Execute(ctx, rec.ID); err != nil || again.ProviderRefundID != done.ProviderRefundID {
		t.Fatalf("replayed execute = %+v, %v", again, err)
	}
	if len(f.client.calls) != 2 || f.client.calls[0].IdempotencyKey != "k1" || f.client.calls[1].IdempotencyKey != "k1" {
		t.Fatalf("provider calls = %+v", f.client.calls)
	}
	if f.client.calls[0].PaymentID != "pi_1" || f.client.calls[0].Currency != "USD" || f.client.txOpen {
		t.Fatalf("provider call %+v, called inside tx = %v", f.client.calls[0], f.client.txOpen)
	}
}

func TestRefundExecuteAmountMismatchIsNotResubmitted(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	rec := f.approved(t, "k1", 300)
	f.client.respond = func(req RefundRequest) (RefundResult, error) {
		return RefundResult{RefundID: "re_x", Status: RefundSucceeded, AmountMinor: 250, Currency: "USD"}, ErrRefundAmountMismatch
	}
	got, err := f.svc.Execute(ctx, rec.ID)
	if !errors.Is(err, ErrRefundAmountMismatch) || got.Status != RefundRequestSucceeded || got.ProviderAmountMinor != 250 {
		t.Fatalf("mismatch execute = %+v, %v", got, err)
	}
	if _, err := f.svc.Execute(ctx, rec.ID); err != nil || len(f.client.calls) != 1 {
		t.Fatalf("mismatch resubmitted: calls=%d err=%v", len(f.client.calls), err)
	}
	f.request(t, "k2", 750)
}

func TestRefundExecuteProviderDeclineReleasesBalance(t *testing.T) {
	f := newRefundFixture()
	rec := f.approved(t, "k1", 1000)
	f.client.respond = func(req RefundRequest) (RefundResult, error) {
		return RefundResult{RefundID: "re_f", Status: RefundFailed, AmountMinor: req.AmountMinor}, nil
	}
	got, err := f.svc.Execute(context.Background(), rec.ID)
	if !errors.Is(err, ErrRefundProviderDeclined) || got.Status != RefundRequestFailed {
		t.Fatalf("declined execute = %+v, %v", got, err)
	}
	f.request(t, "k2", 1000)
}

func TestRefundExecuteRejectsMissingProviderResult(t *testing.T) {
	f := newRefundFixture()
	rec := f.approved(t, "k1", 300)
	f.client.respond = func(RefundRequest) (RefundResult, error) {
		return RefundResult{}, nil
	}
	got, err := f.svc.Execute(context.Background(), rec.ID)
	if err == nil || got.Status != RefundRequestApproved || got.LastError == "" {
		t.Fatalf("missing provider result = %+v, %v", got, err)
	}
}

func TestApplyRefundEventConvertsCumulativeToDelta(t *testing.T) {
	f := newRefundFixture()
	ctx := context.Background()
	event := func(cumulative int64) *PaymentEvent {
		return &PaymentEvent{Provider: ProviderStripe, ProviderEventID: "evt", PaymentID: "pi_1", Currency: "USD", MinorUnits: -cumulative, RefundCumulative: true}
	}
	for _, step := range []struct{ cumulative, delta, total int64 }{
		{500, 500, 500},
		{500, 0, 500},
		{800, 300, 800},
		{700, 0, 800},
	} {
		got, err := f.svc.ApplyRefundEvent(ctx, event(step.cumulative))
		if err != nil || got.DeltaMinor != step.delta || got.CumulativeMinor != step.total || got.Currency != "USD" {
			t.Fatalf("apply %d = %+v, %v", step.cumulative, got, err)
		}
	}
	if _, err := f.svc.Request(ctx, RefundInstruction{PaymentID: "pi_1", RequesterID: 7, AmountMinor: 201, Currency: "USD", IdempotencyKey: "k"}); !errors.Is(err, ErrRefundExceedsBalance) {
		t.Fatalf("provider-side refunds not bounding requests: %v", err)
	}
	f.request(t, "k", 200)
	if _, err := f.svc.ApplyRefundEvent(ctx, &PaymentEvent{Provider: ProviderStripe, PaymentID: "pi_1", MinorUnits: -100, RefundID: "re_1"}); !errors.Is(err, ErrRefundEventNotCumulative) {
		t.Fatalf("per-refund event err = %v", err)
	}
	bad := event(900)
	bad.Currency = "EUR"
	if _, err := f.svc.ApplyRefundEvent(ctx, bad); !errors.Is(err, ErrRefundCurrencyMismatch) {
		t.Fatalf("currency err = %v", err)
	}
}

func TestStripeCapturedAmount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/payment_intents/pi_1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"amount":1200,"amount_received":1000,"currency":"jpy"}`))
	}))
	defer srv.Close()
	got, err := newTestChargeClient(srv).CapturedAmount(context.Background(), "pi_1")
	if err != nil || got.AmountMinor != 1000 || got.Currency != "JPY" {
		t.Fatalf("CapturedAmount = %+v, %v", got, err)
	}
}

func TestRefundExecuteStopsAfterIdempotencyWindow(t *testing.T) {
	f := newRefundFixture()
	f.svc.IdempotencyWindow = time.Hour
	ctx := context.Background()
	rec := f.approved(t, "k1", 300)
	f.client.respond = func(RefundRequest) (RefundResult, error) { return RefundResult{}, errors.New("timeout") }
	if _, err := f.svc.Execute(ctx, rec.ID); err == nil {
		t.Fatal("ambiguous attempt reported success")
	}
	f.store.now = f.store.now.Add(59 * time.Minute)
	if _, err := f.svc.Execute(ctx, rec.ID); err == nil || errors.Is(err, ErrRefundNeedsReconciliation) {
		t.Fatalf("retry inside window err = %v", err)
	}
	f.client.respond = nil
	f.store.now = f.store.now.Add(time.Minute)
	got, err := f.svc.Execute(ctx, rec.ID)
	if !errors.Is(err, ErrRefundNeedsReconciliation) || got.Status != RefundRequestApproved || got.FirstAttemptAt.IsZero() {
		t.Fatalf("retry past window = %+v, %v", got, err)
	}
	if len(f.client.calls) != 2 || got.AttemptCount != 2 {
		t.Fatalf("provider calls = %d, attempts = %d, want 2 each", len(f.client.calls), got.AttemptCount)
	}
}
