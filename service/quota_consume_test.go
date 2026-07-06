package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

type quotaCall struct {
	name string
	args []any
}

type quotaFakeQS struct {
	rows  map[string][][]any
	errs  map[string]error
	calls []quotaCall
}

func newQuotaFakeQS() *quotaFakeQS {
	return &quotaFakeQS{rows: map[string][][]any{}, errs: map[string]error{}}
}

func (f *quotaFakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, quotaCall{name, args})
	if err := f.errs[name]; err != nil {
		return nil, err
	}
	return &model.QueryResult{Rows: f.rows[name]}, nil
}
func (f *quotaFakeQS) GenID() int64 { return 1 }

func (f *quotaFakeQS) callIndex(name string) int {
	for i := range f.calls {
		if f.calls[i].name == name {
			return i
		}
	}
	return -1
}

type quotaFakeTx struct {
	*quotaFakeQS
	commits   int
	rollbacks int
}

func (f *quotaFakeTx) Commit(context.Context) error   { f.commits++; return nil }
func (f *quotaFakeTx) Rollback(context.Context) error { f.rollbacks++; return nil }

type quotaFakeRepo struct {
	data.DatabaseRepository
	qs       *quotaFakeQS
	tx       *quotaFakeTx
	beginErr error
	begins   int
}

func (r *quotaFakeRepo) GetQueryService(context.Context, map[string]string) data.QueryService {
	return r.qs
}
func (r *quotaFakeRepo) BeginTx(context.Context, map[string]string) (data.TxQueryService, error) {
	r.begins++
	if r.beginErr != nil {
		return nil, r.beginErr
	}
	return r.tx, nil
}

var (
	_ data.QueryService   = (*quotaFakeQS)(nil)
	_ data.TxQueryService = (*quotaFakeTx)(nil)
)

// newQuotaSvc wires a QuotaServiceDb over fakes: qs serves the cache load,
// tx serves the in-transaction reads/writes.
func newQuotaSvc(subs [][]any) (*QuotaServiceDb, *quotaFakeQS, *quotaFakeTx) {
	qs := newQuotaFakeQS()
	qs.rows[qGetPartnerSubscription] = subs
	tx := &quotaFakeTx{quotaFakeQS: newQuotaFakeQS()}
	return &QuotaServiceDb{Repo: &quotaFakeRepo{qs: qs, tx: tx}}, qs, tx
}

func TestConsumeQuotaAllows(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(5), "D"}})
	tx.rows[qGetResourceUsage] = [][]any{{int64(4)}}

	allowed, resetAt, err := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "test")
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v, want true nil", allowed, err)
	}
	if resetAt.IsZero() {
		t.Fatal("daily quota must return a reset time")
	}
	lock, usage, ins := tx.callIndex(qLockQuota), tx.callIndex(qGetResourceUsage), tx.callIndex(qAddUsage)
	if lock != 0 || usage < lock || ins < usage {
		t.Fatalf("call order lock=%d usage=%d insert=%d", lock, usage, ins)
	}
	if tx.calls[lock].args[0] != "7:API_CALLS" {
		t.Fatalf("lock key = %v", tx.calls[lock].args[0])
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func TestConsumeQuotaDeniesAtLimit(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(5), "D"}})
	tx.rows[qGetResourceUsage] = [][]any{{int64(5)}}

	allowed, resetAt, err := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "test")
	if err != nil || allowed {
		t.Fatalf("allowed=%v err=%v, want false nil", allowed, err)
	}
	now := time.Now().UTC()
	wantReset := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	if !resetAt.Equal(wantReset) {
		t.Fatalf("resetAt=%v want %v", resetAt, wantReset)
	}
	if tx.callIndex(qAddUsage) != -1 {
		t.Fatal("denied request must not insert usage")
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func TestConsumeQuotaMonthlyReset(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(1), "M"}})
	tx.rows[qGetResourceUsage] = [][]any{{int64(1)}}

	_, resetAt, _ := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "test")
	now := time.Now().UTC()
	want := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	if !resetAt.Equal(want) {
		t.Fatalf("resetAt=%v want %v", resetAt, want)
	}
}

func TestConsumeQuotaUnlimitedInsertsWithoutUsageRead(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(-1), ""}})

	allowed, resetAt, err := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "test")
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if !resetAt.IsZero() {
		t.Fatalf("all-time quota resetAt=%v, want zero", resetAt)
	}
	if tx.callIndex(qGetResourceUsage) != -1 {
		t.Fatal("unlimited must skip the usage read")
	}
	if tx.callIndex(qAddUsage) == -1 || tx.commits != 1 {
		t.Fatal("unlimited must still record usage")
	}
}

func TestConsumeQuotaUnknownResourceFailsClosed(t *testing.T) {
	svc, _, _ := newQuotaSvc(nil)
	repo := svc.Repo.(*quotaFakeRepo)

	allowed, _, err := svc.ConsumeQuota(context.Background(), 7, "NOPE", 1, "test")
	if err != nil || allowed {
		t.Fatalf("allowed=%v err=%v, want false nil", allowed, err)
	}
	if repo.begins != 0 {
		t.Fatal("unknown resource must not open a transaction")
	}
}

func TestConsumeQuotaLiveCountResource(t *testing.T) {
	svc, _, tx := newQuotaSvc([][]any{{"MAX_DOMAINS", int64(3), ""}})
	tx.rows["MAX_DOMAINS"] = [][]any{{int64(3)}}

	allowed, _, err := svc.ConsumeQuota(context.Background(), 7, "MAX_DOMAINS", 1, "test")
	if err != nil || allowed {
		t.Fatalf("allowed=%v err=%v, want false nil", allowed, err)
	}
	if tx.callIndex("MAX_DOMAINS") == -1 || tx.callIndex(qGetResourceUsage) != -1 {
		t.Fatal("live-count resource must use its count query, not the ledger sum")
	}
}

func TestConsumeQuotaFailsClosedOnErrors(t *testing.T) {
	boom := errors.New("boom")

	svc, _, _ := newQuotaSvc([][]any{{"API_CALLS", int64(5), "D"}})
	svc.Repo.(*quotaFakeRepo).beginErr = boom
	if allowed, _, err := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "t"); err == nil || allowed {
		t.Fatalf("begin error: allowed=%v err=%v", allowed, err)
	}

	svc, _, tx := newQuotaSvc([][]any{{"API_CALLS", int64(5), "D"}})
	tx.rows[qGetResourceUsage] = [][]any{{int64(0)}}
	tx.errs[qAddUsage] = boom
	if allowed, _, err := svc.ConsumeQuota(context.Background(), 7, "API_CALLS", 1, "t"); err == nil || allowed {
		t.Fatalf("insert error: allowed=%v err=%v", allowed, err)
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("insert error: commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}
