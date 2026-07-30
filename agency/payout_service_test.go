package agency

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payout"
	"github.com/nauticana/keel/service"
)

func TestMonthStartUsesUTC(t *testing.T) {
	at := time.Date(2026, 8, 1, 0, 30, 0, 0, time.FixedZone("east", 2*60*60))
	got := monthStart(at)
	want := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("monthStart = %v, want %v", got, want)
	}
}

type payoutServiceQueryStub struct {
	calls []string
	now   time.Time
}

func (f *payoutServiceQueryStub) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, name)
	switch name {
	case qPayoutClaim:
		return &model.QueryResult{Rows: [][]any{{
			int64(9), int64(10), int64(500), "USD", "acct_1", "agency-1", "",
			int64(4), f.now.Add(-24 * time.Hour),
		}}}, nil
	case qPayoutMarkManual:
		return &model.QueryResult{Rows: [][]any{{int64(1)}}}, nil
	default:
		return &model.QueryResult{}, nil
	}
}

func (f *payoutServiceQueryStub) GenID() int64 { return 1 }

type payoutProviderStub struct {
	payout.PayoutProvider
	requests int
}

func (f *payoutProviderStub) RequestInstantPayout(context.Context, payout.InstantPayoutInput) (*payout.InstantPayoutResult, error) {
	f.requests++
	return nil, nil
}

func TestDispatchOutsideIdempotencyWindowParksManual(t *testing.T) {
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	qs := &payoutServiceQueryStub{now: now}
	provider := &payoutProviderStub{}
	svc := &BaseAgencyPayoutService{
		AbstractService:      service.AbstractService{QS: qs},
		Provider:             provider,
		now:                  func() time.Time { return now },
		maxDispatchAttempts:  3,
		idempotencyRetention: 20 * time.Hour,
	}
	if err := svc.dispatchOne(context.Background(), 1); err != nil {
		t.Fatalf("dispatchOne: %v", err)
	}
	if provider.requests != 0 {
		t.Fatalf("provider requests = %d, want 0 for an unresolved old payout", provider.requests)
	}
	if len(qs.calls) != 2 || qs.calls[1] != qPayoutMarkManual {
		t.Fatalf("query calls = %v, want claim then manual review", qs.calls)
	}
}

func TestPayoutSelectionIncludesPayableReversalsImmediately(t *testing.T) {
	const predicate = "c.entry_type = 'R' OR c.earned_at < ?"
	for name, query := range map[string]string{
		qPayoutGroups:  agencyPayoutQueries[qPayoutGroups],
		qPayoutEntries: agencyPayoutQueries[qPayoutEntries],
	} {
		if !strings.Contains(query, predicate) {
			t.Errorf("%s does not bypass the earning cutoff for payable reversals", name)
		}
	}
}
