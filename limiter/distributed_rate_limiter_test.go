package limiter

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/port"
)

// stubStore is an in-memory MultiScopeAdmitter whose calls can be failed or blocked.
type stubStore struct {
	mu      sync.Mutex
	counts  map[string]int64
	fail    error
	block   chan struct{}
	calls   []int64
	started int
}

func (s *stubStore) setFail(err error) { s.mu.Lock(); s.fail = err; s.mu.Unlock() }

func (s *stubStore) setBlock(gate chan struct{}) { s.mu.Lock(); s.block = gate; s.mu.Unlock() }

func (s *stubStore) count(key string) int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.counts[key] }

func (s *stubStore) callCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.calls) }

func (s *stubStore) startedCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.started }

func (s *stubStore) Admit(ctx context.Context, scopes ...cache.AdmissionScope) (cache.AdmissionResult, error) {
	s.mu.Lock()
	s.started++
	gate, fail := s.block, s.fail
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return cache.AdmissionResult{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, max(scopes[0].Cost, 1))
	if fail != nil {
		return cache.AdmissionResult{}, fail
	}
	if s.counts == nil {
		s.counts = map[string]int64{}
	}
	for _, scope := range scopes {
		if s.counts[scope.Key]+max(scope.Cost, 1) > scope.Limit {
			return cache.AdmissionResult{RejectedKey: scope.Key, RetryAfter: scope.Window}, nil
		}
	}
	counts := make([]int64, len(scopes))
	for i, scope := range scopes {
		s.counts[scope.Key] += max(scope.Cost, 1)
		counts[i] = s.counts[scope.Key]
	}
	return cache.AdmissionResult{Admitted: true, Counts: counts}, nil
}

type metrics struct {
	mu    sync.Mutex
	names []string
}

func (m *metrics) RecordMetric(_ context.Context, mm port.MetricMeasurement) error {
	m.mu.Lock()
	m.names = append(m.names, mm.Name)
	m.mu.Unlock()
	return nil
}

func config() DistributedRateLimiterConfig {
	return DistributedRateLimiterConfig{
		Lanes:               map[string]WindowLane{"turn": {Partner: WindowLimit{Limit: 4, Window: time.Second}, Fleet: WindowLimit{Limit: 6, Window: time.Second}}},
		KeyPrefix:           "rl",
		StoreTimeout:        50 * time.Millisecond,
		FallbackFraction:    0.5,
		FallbackMaxPartners: 64,
		RecoveryProbe:       time.Second,
	}
}

func replicas(t *testing.T, store *stubStore, m *metrics, count int, fake *clock.Fake) []*DistributedRateLimiter {
	t.Helper()
	out := make([]*DistributedRateLimiter, count)
	for i := range out {
		var err error
		if out[i], err = NewDistributedRateLimiter(store, config()); err != nil {
			t.Fatal(err)
		}
		if fake != nil {
			out[i].Clock = fake
		}
		if m != nil {
			out[i].Metrics = m
		}
	}
	return out
}

func TestDistributedRejectsInvalidConfig(t *testing.T) {
	store := &stubStore{}
	bad := []func(*DistributedRateLimiterConfig){
		func(c *DistributedRateLimiterConfig) { c.Lanes = nil },
		func(c *DistributedRateLimiterConfig) { c.Lanes["turn"] = WindowLane{Partner: WindowLimit{Limit: 1}} },
		func(c *DistributedRateLimiterConfig) { c.KeyPrefix = "" },
		func(c *DistributedRateLimiterConfig) { c.StoreTimeout = 0 },
		func(c *DistributedRateLimiterConfig) { c.FallbackFraction = 1.5 },
		func(c *DistributedRateLimiterConfig) { c.FallbackMaxPartners = 0 },
	}
	for i, mutate := range bad {
		c := config()
		mutate(&c)
		if _, err := NewDistributedRateLimiter(store, c); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	if _, err := NewDistributedRateLimiter(nil, config()); err == nil {
		t.Error("nil store must be rejected")
	}
}

func TestDistributedFallbackReductionDoesNotOverflow(t *testing.T) {
	const maxInt64 = int64(1<<63 - 1)
	got := reducedWindowLimit(WindowLimit{Limit: maxInt64, Window: time.Second}, 1)
	if got.Limit != maxInt64 {
		t.Fatalf("limit = %d, want %d", got.Limit, maxInt64)
	}
	if ttl := admissionTTL(time.Duration(1<<63 - 1)); ttl <= 0 {
		t.Fatalf("overflowed admission TTL: %s", ttl)
	}
}

func TestDistributedReplicasShareQuotaAndFleetRejectionChargesNothing(t *testing.T) {
	store := &stubStore{}
	fake := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	reps := replicas(t, store, nil, 2, fake)
	ctx := context.Background()

	// Partner limit 4, fleet 6: two partners alternating trip the fleet first.
	admitted, last := 0, error(nil)
	for i := range 8 {
		if err := reps[i%2].Allow(ctx, "turn", subject(int64(1+i%2))); err == nil {
			admitted++
		} else {
			last = err
		}
	}
	if admitted != 6 || !errors.Is(last, ErrRateLimited) {
		t.Fatalf("admitted %d last %v", admitted, last)
	}
	var limit *LimitError
	if !errors.As(last, &limit) || limit.Scope != "turn.fleet" {
		t.Fatalf("rejection = %v", last)
	}
	partnerKey, _, _ := windowKey("rl", "turn", "p", 1, time.Second, fake.Now())
	fleetKey, _, _ := windowKey("rl", "turn", "f", 0, time.Second, fake.Now())
	if store.count(partnerKey) != 3 || store.count(fleetKey) != 6 {
		t.Fatalf("partner=%d fleet=%d, want exactly the admissions", store.count(partnerKey), store.count(fleetKey))
	}
	if !strings.HasPrefix(partnerKey, "{rl:turn}") || !strings.HasPrefix(fleetKey, "{rl:turn}") {
		t.Fatalf("keys must share a hash tag: %s %s", partnerKey, fleetKey)
	}
}

func TestDistributedExhaustedWindowCostsNoRoundTrips(t *testing.T) {
	store := &stubStore{}
	fake := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	rep := replicas(t, store, nil, 1, fake)[0]
	ctx := context.Background()
	for range 4 {
		if err := rep.Allow(ctx, "turn", subject(1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := rep.Allow(ctx, "turn", subject(1)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fifth = %v", err)
	}
	before := store.callCount()
	for range 10 {
		if err := rep.Allow(ctx, "turn", subject(1)); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("exhausted = %v", err)
		}
	}
	if store.callCount() != before {
		t.Fatalf("exhausted window reached the store %d times", store.callCount()-before)
	}
	fake.Advance(time.Second)
	if err := rep.Allow(ctx, "turn", subject(1)); err != nil {
		t.Fatalf("new window = %v", err)
	}
}

func TestDistributedFallsBackWithReducedQuotaAndRecovers(t *testing.T) {
	store := &stubStore{}
	m := &metrics{}
	fake := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	reps := replicas(t, store, m, 2, fake)
	ctx := context.Background()

	store.setFail(errors.New("store down"))
	// Fraction 0.5 of limit 4: two local admissions per replica, then rejection.
	for i, rep := range reps {
		for range 2 {
			if err := rep.Allow(ctx, "turn", subject(3)); err != nil {
				t.Fatalf("replica %d fallback admit = %v", i, err)
			}
		}
		if err := rep.Allow(ctx, "turn", subject(3)); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("replica %d fallback reject = %v", i, err)
		}
		if !rep.Degraded() {
			t.Fatalf("replica %d should be degraded", i)
		}
	}
	store.setFail(nil)
	if err := reps[0].Allow(ctx, "turn", subject(3)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("before probe = %v", err)
	}
	fake.Advance(time.Second)
	if err := reps[0].Allow(ctx, "turn", subject(3)); err != nil {
		t.Fatalf("probe = %v", err)
	}
	if reps[0].Degraded() {
		t.Fatal("probe success must clear degraded mode")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.names) != 3 || m.names[0] != MetricStoreOutages || m.names[2] != MetricStoreRecoveries {
		t.Fatalf("metrics = %v", m.names)
	}
}

func TestDistributedFallbackDoesNotRefillInsideSharedWindow(t *testing.T) {
	store := &stubStore{}
	store.setFail(errors.New("store down"))
	fake := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	rep := replicas(t, store, nil, 1, fake)[0]
	ctx := context.Background()

	for range 2 {
		if err := rep.Allow(ctx, "turn", subject(1)); err != nil {
			t.Fatal(err)
		}
	}
	fake.Advance(900 * time.Millisecond)
	if err := rep.Allow(ctx, "turn", subject(1)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fallback refilled inside the fixed window: %v", err)
	}
	fake.Advance(100 * time.Millisecond)
	if err := rep.Allow(ctx, "turn", subject(1)); err != nil {
		t.Fatalf("new fallback window = %v", err)
	}
}

func TestDistributedCanceledProbeStaysDegraded(t *testing.T) {
	store := &stubStore{}
	fake := clock.NewFake(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	rep := replicas(t, store, nil, 1, fake)[0]
	store.setFail(errors.New("store down"))
	if err := rep.Allow(context.Background(), "turn", subject(1)); err != nil {
		t.Fatal(err)
	}
	store.setFail(nil)
	fake.Advance(time.Second)
	gate := make(chan struct{})
	store.setBlock(gate)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- rep.Allow(ctx, "turn", subject(1)) }()
	deadline := time.Now().Add(time.Second)
	for store.startedCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("recovery probe did not reach the store")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe = %v", err)
	}
	if !rep.Degraded() {
		t.Fatal("caller cancellation must not mark the store recovered")
	}
	close(gate)
}

func TestDistributedTimeoutDegradesButCancellationDoesNot(t *testing.T) {
	store := &stubStore{}
	gate := make(chan struct{})
	store.setBlock(gate)
	defer close(gate)
	rep := replicas(t, store, nil, 1, nil)[0]
	if err := rep.Allow(context.Background(), "turn", subject(1)); err != nil {
		t.Fatalf("timeout must fall back locally: %v", err)
	}
	if !rep.Degraded() {
		t.Fatal("store timeout must degrade")
	}
	rep2 := replicas(t, store, nil, 1, nil)[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rep2.Allow(ctx, "turn", subject(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}
	if rep2.Degraded() {
		t.Fatal("caller cancellation must not degrade")
	}
}

func hot(limit int64) admission {
	return admission{
		scopes:  []cache.AdmissionScope{{Key: "hot", Limit: limit, Window: time.Second}},
		retries: []retryAdvice{{scope: "hot", after: time.Second, until: time.Now().Add(time.Second)}},
	}
}

func runConcurrent(t *testing.T, a *sharedAdmitter, request admission, callers int, release func()) (admitted, rejected int) {
	t.Helper()
	results := make(chan bool, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			advice, err := a.admit(context.Background(), request)
			if err != nil {
				t.Error(err)
			}
			results <- advice == nil
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for a.pending(request.key()) < int64(callers-1) {
		if time.Now().After(deadline) {
			t.Fatal("followers did not join the pending batch")
		}
		time.Sleep(time.Millisecond)
	}
	release()
	wg.Wait()
	close(results)
	for ok := range results {
		if ok {
			admitted++
		} else {
			rejected++
		}
	}
	return admitted, rejected
}

func TestDistributedCoalescesHotKeyToTheExactBoundary(t *testing.T) {
	store := &stubStore{}
	gate := make(chan struct{})
	store.setBlock(gate)
	a := &sharedAdmitter{store: store, timeout: time.Second, maxExhausted: 64, now: time.Now}

	admitted, rejected := runConcurrent(t, a, hot(100), 6, func() { close(gate) })
	if admitted != 6 || rejected != 0 || store.callCount() != 2 {
		t.Fatalf("admitted %d rejected %d calls %d, want one leader and one batch", admitted, rejected, store.callCount())
	}

	store2 := &stubStore{}
	gate2 := make(chan struct{})
	store2.setBlock(gate2)
	a2 := &sharedAdmitter{store: store2, timeout: time.Second, maxExhausted: 64, now: time.Now}
	admitted, rejected = runConcurrent(t, a2, hot(4), 6, func() { close(gate2) })
	if admitted != 4 || rejected != 2 || store2.count("hot") != 4 {
		t.Fatalf("admitted %d rejected %d counter %d, want exactly the limit", admitted, rejected, store2.count("hot"))
	}
	calls := store2.callCount()
	if advice, err := a2.admit(context.Background(), hot(4)); err != nil || advice == nil || store2.callCount() != calls {
		t.Fatalf("exhausted window: advice %v err %v calls %d→%d", advice, err, calls, store2.callCount())
	}
}

func TestDistributedCloseIsIdempotent(t *testing.T) {
	rep := replicas(t, &stubStore{}, nil, 1, nil)[0]
	rep.Close()
	rep.Close()
	if err := rep.Allow(context.Background(), "turn", subject(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed = %v", err)
	}
	if err := rep.Allow(context.Background(), "nope", subject(1)); err == nil {
		t.Fatal("unknown lane must fail closed")
	}
}

func TestDistributedCloseStopsUnlimitedLane(t *testing.T) {
	c := config()
	c.Lanes["unlimited"] = WindowLane{}
	rep, err := NewDistributedRateLimiter(&stubStore{}, c)
	if err != nil {
		t.Fatal(err)
	}
	rep.Close()
	if err := rep.Allow(context.Background(), "unlimited", subject(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed unlimited lane = %v", err)
	}
}
