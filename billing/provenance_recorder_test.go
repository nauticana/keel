package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

type provenanceRecorderCall struct {
	name string
	args []any
}

type provenanceRecorderTx struct {
	calls     []provenanceRecorderCall
	nextID    int64
	committed bool
}

func (f *provenanceRecorderTx) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, provenanceRecorderCall{name: name, args: args})
	switch name {
	case qProvenanceInvoice:
		return &model.QueryResult{Rows: [][]any{{int64(41), "USD"}}}, nil
	case qProvenanceInsertPayment:
		return &model.QueryResult{Rows: [][]any{{args[0]}}}, nil
	case qProvenanceInsertLine:
		return &model.QueryResult{Rows: [][]any{{args[0]}}}, nil
	case qProvenanceInsertAllocation:
		return &model.QueryResult{Rows: [][]any{{args[0]}}}, nil
	default:
		return &model.QueryResult{}, nil
	}
}

func (f *provenanceRecorderTx) GenID() int64 {
	f.nextID++
	return f.nextID
}

func (f *provenanceRecorderTx) Commit(context.Context) error {
	f.committed = true
	return nil
}

func (f *provenanceRecorderTx) Rollback(context.Context) error { return nil }

type provenanceRecorderRepo struct {
	port.DatabaseRepository
	tx *provenanceRecorderTx
}

func (f provenanceRecorderRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return f.tx, nil
}

func callsNamed(calls []provenanceRecorderCall, name string) []provenanceRecorderCall {
	var matches []provenanceRecorderCall
	for _, call := range calls {
		if call.name == name {
			matches = append(matches, call)
		}
	}
	return matches
}

func TestProvenanceRecorderPreservesCreditsAndAllocatesCapturedMoney(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tx := &provenanceRecorderTx{}
	var recognized []ProvenanceAllocation
	recorder := NewBaseProvenanceRecorder(provenanceRecorderRepo{tx: tx}, BaseProvenanceRecorderOptions{
		Recognition: RecognitionHookFunc(func(_ context.Context, _ port.TxQueryService, allocation ProvenanceAllocation) error {
			recognized = append(recognized, allocation)
			return nil
		}),
	})
	event := &payment.PaymentEvent{
		Provider:             payment.ProviderStripe,
		ProviderEventID:      "evt_1",
		PaymentID:            "pi_1",
		InvoiceID:            "in_1",
		EventType:            "invoice.paid",
		MinorUnits:           2500,
		Currency:             "USD",
		InvoiceLinesComplete: true,
		InvoiceLines: []payment.InvoiceLine{
			{ProviderLineID: "il_service", Description: "service", AmountMinor: 3000, Currency: "USD", ServiceFrom: start, ServiceTo: start.AddDate(0, 1, 0)},
			{ProviderLineID: "il_credit", Description: "proration credit", AmountMinor: -500, Currency: "USD", ServiceFrom: start, ServiceTo: start.AddDate(0, 1, 0)},
		},
	}

	if err := recorder.RecordPayment(context.Background(), 7, event); err != nil {
		t.Fatalf("RecordPayment: %v", err)
	}
	if !tx.committed {
		t.Fatal("provenance transaction was not committed")
	}
	payments := callsNamed(tx.calls, qProvenanceInsertPayment)
	if len(payments) != 1 || payments[0].args[3] != "pi_1" {
		t.Fatalf("provider payment identity = %#v, want pi_1", payments)
	}
	lines := callsNamed(tx.calls, qProvenanceInsertLine)
	if len(lines) != 2 || lines[0].args[5] != int64(3000) || lines[1].args[5] != int64(-500) {
		t.Fatalf("persisted canonical line amounts = %#v", lines)
	}
	allocations := callsNamed(tx.calls, qProvenanceInsertAllocation)
	if len(allocations) != 1 || allocations[0].args[4] != int64(2500) {
		t.Fatalf("captured allocations = %#v, want one 2500 allocation", allocations)
	}
	if len(recognized) != 1 || recognized[0].AmountMinor != 2500 {
		t.Fatalf("recognized allocations = %#v, want one 2500 allocation", recognized)
	}
}

func TestApportionLineAmountsAllowsZeroShareAndSignedLines(t *testing.T) {
	amounts, err := apportionLineAmounts(1, []payment.InvoiceLine{
		{AmountMinor: 1000},
		{AmountMinor: -500},
		{AmountMinor: 1000},
	})
	if err != nil {
		t.Fatalf("apportionLineAmounts: %v", err)
	}
	if amounts[0] != 0 || amounts[1] != 0 || amounts[2] != 1 {
		t.Fatalf("amounts = %v, want [0 0 1]", amounts)
	}
}

func TestPaymentIdentityPreferenceAndDescriptionLimit(t *testing.T) {
	event := &payment.PaymentEvent{PaymentID: " pi_1 ", ChargeID: "ch_1", ProviderEventID: "evt_1"}
	if got := paymentIdentity(event); got != "pi_1" {
		t.Fatalf("paymentIdentity = %q, want pi_1", got)
	}
	long := ""
	for range 201 {
		long += "界"
	}
	if got := truncateRunes(long, 200); len([]rune(got)) != 200 {
		t.Fatalf("truncated description has %d runes, want 200", len([]rune(got)))
	}
}

func TestProvenanceRecorderRejectsPaidEventWithoutInvoice(t *testing.T) {
	recorder := NewBaseProvenanceRecorder(provenanceRecorderRepo{}, BaseProvenanceRecorderOptions{})
	err := recorder.RecordPayment(context.Background(), 7, &payment.PaymentEvent{
		MinorUnits: 100,
		Currency:   "USD",
		PaymentID:  "pi_1",
	})
	if !errors.Is(err, ErrMissingInvoiceIdentity) {
		t.Fatalf("RecordPayment error = %v, want ErrMissingInvoiceIdentity", err)
	}
}

var _ port.TxQueryService = (*provenanceRecorderTx)(nil)
