package service

import (
	"context"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// planQS answers the partner's quota and add-on reads from mutable plan state.
type planQS struct {
	*quotaFakeQS
	onLoad   func()
	captions map[string]string
}

func (q *planQS) Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error) {
	if name == qGetResourceCaption {
		q.calls = append(q.calls, quotaCall{name, args})
		if caption, ok := q.captions[args[0].(string)]; ok {
			return &model.QueryResult{Rows: [][]any{{caption}}}, nil
		}
		return &model.QueryResult{}, nil
	}
	if name == qGetPartnerSubscription && q.onLoad != nil {
		load := q.onLoad
		q.onLoad = nil
		load()
	}
	return q.quotaFakeQS.Query(ctx, name, args...)
}

func newPlanQuota(limit int64) (*QuotaServiceDb, *planQS) {
	qs := &planQS{quotaFakeQS: newQuotaFakeQS()}
	qs.rows[qGetPartnerSubscription] = [][]any{{"MAX_DOMAINS", limit, "N"}}
	qs.rows["MAX_DOMAINS"] = [][]any{{int64(1)}}
	return &QuotaServiceDb{Repo: &planRepo{qs: qs}}, qs
}

type planRepo struct {
	port.DatabaseRepository
	qs *planQS
}

func (r *planRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r.qs }

func allowsSecondDomain(t *testing.T, s *QuotaServiceDb) bool {
	t.Helper()
	ok, err := s.CheckQuota(context.Background(), 7, "MAX_DOMAINS", 1)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// A downgrade (10 domains → 1) takes effect on the next check once the
// partner is invalidated, not after quota_cache_ttl.
func TestQuotaInvalidatePartnerAppliesDowngrade(t *testing.T) {
	s, qs := newPlanQuota(10)
	if !allowsSecondDomain(t, s) {
		t.Fatal("10-domain plan refused a second domain")
	}
	qs.rows[qGetPartnerSubscription] = [][]any{{"MAX_DOMAINS", int64(1), "N"}}
	if !allowsSecondDomain(t, s) {
		t.Fatal("cache should still hold the old plan before invalidation")
	}
	s.InvalidatePartner(context.Background(), 7)
	if allowsSecondDomain(t, s) {
		t.Fatal("downgraded partner kept the old limit after invalidation")
	}
}

// A refresh replaces the partner's set: a resource the new plan drops is
// refused instead of keeping its old limit.
func TestQuotaRefreshDropsRemovedResource(t *testing.T) {
	withQuotaTTL(t, 0)
	s, qs := newPlanQuota(10)
	if !allowsSecondDomain(t, s) {
		t.Fatal("10-domain plan refused a second domain")
	}
	qs.rows[qGetPartnerSubscription] = nil
	time.Sleep(time.Millisecond)
	if allowsSecondDomain(t, s) {
		t.Fatal("a resource the plan dropped kept its old limit")
	}
}

// Add-on presence expires with quota_cache_ttl like limits do.
func TestQuotaAddonCacheExpires(t *testing.T) {
	withQuotaTTL(t, 0)
	s, qs := newPlanQuota(10)
	qs.rows[qGetPartnerAddon] = [][]any{{"EXTRA", int32(1)}}
	if ok, err := s.CheckAddon(context.Background(), 7, "EXTRA"); err != nil || !ok {
		t.Fatalf("active add-on: ok=%v err=%v", ok, err)
	}
	qs.rows[qGetPartnerAddon] = nil
	time.Sleep(time.Millisecond)
	if ok, err := s.CheckAddon(context.Background(), 7, "EXTRA"); err != nil || ok {
		t.Fatalf("cancelled add-on: ok=%v err=%v", ok, err)
	}
}

// A load that began before an invalidation answers its caller but is not
// cached, so the next check reads the new plan.
func TestQuotaInvalidationDuringLoad(t *testing.T) {
	s, qs := newPlanQuota(10)
	qs.onLoad = func() { s.InvalidatePartner(context.Background(), 7) }
	if !allowsSecondDomain(t, s) {
		t.Fatal("in-flight load did not answer its caller")
	}
	qs.rows[qGetPartnerSubscription] = [][]any{{"MAX_DOMAINS", int64(1), "N"}}
	if allowsSecondDomain(t, s) {
		t.Fatal("a load that raced an invalidation was cached")
	}
}

// An invalidation published by one process drops the partner in another.
func TestQuotaInvalidationCrossesProcesses(t *testing.T) {
	bus := cache.NewMemoryCacheService()
	defer bus.Close()
	publisher, _ := newPlanQuota(10)
	publisher.Bus = bus
	listener, qs := newPlanQuota(10)
	listener.Bus = bus

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- listener.Listen(ctx) }()

	if !allowsSecondDomain(t, listener) {
		t.Fatal("10-domain plan refused a second domain")
	}
	qs.rows[qGetPartnerSubscription] = [][]any{{"MAX_DOMAINS", int64(1), "N"}}
	deadline := time.Now().Add(2 * time.Second)
	for allowsSecondDomain(t, listener) {
		if time.Now().After(deadline) {
			t.Fatal("listener never dropped the invalidated partner")
		}
		publisher.InvalidatePartner(ctx, 7)
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not return after cancellation")
	}

	if err := (&QuotaServiceDb{}).Listen(context.Background()); err != nil {
		t.Fatalf("Listen without a bus: %v", err)
	}
}

func withQuotaTTL(t *testing.T, ttl time.Duration) {
	t.Helper()
	previous := config.Config()
	next := *previous
	next.QuotaCacheTTL = ttl
	config.SetConfig(&next)
	t.Cleanup(func() { config.SetConfig(previous) })
}

func TestQuotaPlanOverages(t *testing.T) {
	s, qs := newPlanQuota(10)
	s.Queries = map[string]string{"MAX_LOCATIONS": "SELECT 1", "KEYWORDS": "SELECT 1"}
	qs.rows[qGetPartnerSubscription] = [][]any{{"MAX_DOMAINS", int64(10), "N"}, {"MAX_LOCATIONS", int64(10), "N"}}
	qs.rows["MAX_DOMAINS"] = [][]any{{int64(4)}}
	qs.rows["KEYWORDS"] = [][]any{{int64(50)}}
	qs.rows["MAX_LOCATIONS"] = [][]any{{int64(3)}}
	qs.captions = map[string]string{"MAX_DOMAINS": "Domains", "MAX_LOCATIONS": "Locations"}
	ctx := context.Background()

	// Target lists MAX_LOCATIONS at 1 and drops MAX_DOMAINS: both are over.
	qs.rows[qGetPlanLimits] = [][]any{{"MAX_LOCATIONS", int64(1)}, {"API_CALLS", int64(100)}}
	got, err := s.PlanOverages(ctx, 7, "STANDARD")
	if err != nil {
		t.Fatal(err)
	}
	want := []port.QuotaOverage{
		{Resource: "MAX_DOMAINS", Caption: "Domains", Count: 4, Limit: 0},
		{Resource: "MAX_LOCATIONS", Caption: "Locations", Count: 3, Limit: 1},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("overages = %+v, want %+v", got, want)
	}

	// KEYWORDS is counted but neither plan lists it, so it limits nothing.
	// Unlimited and sufficient limits allow the change.
	qs.rows[qGetPlanLimits] = [][]any{{"MAX_LOCATIONS", int64(-1)}, {"MAX_DOMAINS", int64(4)}}
	if got, err := s.PlanOverages(ctx, 7, "PRO"); err != nil || len(got) != 0 {
		t.Fatalf("allowed change: %+v %v", got, err)
	}

	// A counted resource missing from the catalog fails instead of showing a code.
	delete(qs.captions, "MAX_LOCATIONS")
	qs.rows[qGetPlanLimits] = [][]any{{"MAX_LOCATIONS", int64(1)}, {"MAX_DOMAINS", int64(4)}}
	if _, err := s.PlanOverages(ctx, 7, "STANDARD"); err == nil {
		t.Fatal("overage without a catalog caption succeeded")
	}
}
