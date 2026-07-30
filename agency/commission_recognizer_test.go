package agency

import (
	"context"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type recognizerTx struct {
	start   time.Time
	inserts [][]any
}

func (f *recognizerTx) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	switch name {
	case qCommissionDelegations:
		return &model.QueryResult{Rows: [][]any{{int64(7), int64(9), f.start, nil}}}, nil
	case qCommissionModels:
		mid := f.start.Add(10 * time.Hour)
		return &model.QueryResult{Rows: [][]any{
			{int64(11), "R", f.start, mid},
			{int64(12), "W", mid, nil},
		}}, nil
	case qRateGet:
		return &model.QueryResult{Rows: [][]any{{int64(1000)}}}, nil
	case qCommissionInsert:
		f.inserts = append(f.inserts, args)
		return &model.QueryResult{}, nil
	default:
		return &model.QueryResult{}, nil
	}
}

func (f *recognizerTx) QueryService(string, map[string]string) port.QueryService { return f }
func (f *recognizerTx) GenID() int64                                             { return 101 }
func (f *recognizerTx) Commit(context.Context) error                             { return nil }
func (f *recognizerTx) Rollback(context.Context) error                           { return nil }

func TestRecognizeApportionsBeforeReferralFilter(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tx := &recognizerTx{start: start}
	recognizer := NewBaseCommissionRecognizer(nil)
	err := recognizer.Recognize(context.Background(), tx, port.AgencyCommissionSource{
		InvoiceLinePaymentID: 5,
		ClientPartnerID:      6,
		PeriodStart:          start,
		PeriodEnd:            start.Add(20 * time.Hour),
		GrossAmountMinor:     1001,
		Currency:             "usd",
		EarnedAt:             start,
	})
	if err != nil {
		t.Fatalf("Recognize: %v", err)
	}
	if len(tx.inserts) != 1 {
		t.Fatalf("earning inserts = %d, want 1 referral span", len(tx.inserts))
	}
	args := tx.inserts[0]
	if got := args[5]; got != int64(500) {
		t.Errorf("eligible gross = %v, want 500 (wholesale half is not redirected)", got)
	}
	if got := args[6]; got != int64(50) {
		t.Errorf("commission = %v, want 50", got)
	}
	if got := args[8]; got != "USD" {
		t.Errorf("currency = %v, want USD", got)
	}
}

func TestCutCommissionSpansDropsDuplicateBoundaries(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	mid := start.Add(time.Hour)
	end := start.Add(2 * time.Hour)
	spans := cutCommissionSpans([]time.Time{mid, mid, start, end}, start, end)
	if len(spans) != 2 || !spans[0].to.Equal(mid) || !spans[1].from.Equal(mid) {
		t.Fatalf("spans = %#v", spans)
	}
}

var _ port.TxQueryService = (*recognizerTx)(nil)
var _ port.TxQueryCatalog = (*recognizerTx)(nil)
