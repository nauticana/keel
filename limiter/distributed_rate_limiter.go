package limiter

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// WindowLimit is one shared fixed-window admission scope; both zero disables it.
type WindowLimit struct {
	Limit  int64
	Window time.Duration
}

func (l WindowLimit) enabled() bool { return l.Limit > 0 && l.Window > 0 }

func (l WindowLimit) valid() bool { return l.Limit == 0 && l.Window == 0 || l.enabled() }

// WindowLane is one admission concern shared across replicas: a per-partner window and a fleet window.
type WindowLane struct {
	Partner WindowLimit
	Fleet   WindowLimit
}

// DistributedRateLimiterConfig configures shared partner and fleet admission over a cache.
type DistributedRateLimiterConfig struct {
	Lanes map[string]WindowLane
	// KeyPrefix namespaces the counters in the shared store.
	KeyPrefix string
	// StoreTimeout bounds one store round trip; a slower store counts as unreachable.
	StoreTimeout time.Duration
	// FallbackFraction is the share of each limit one replica admits locally while the store is unreachable;
	// each reduced fixed-window limit is rounded up to at least one.
	FallbackFraction float64
	// FallbackMaxPartners bounds the local fallback counters and the exhausted-window marks.
	FallbackMaxPartners int
	// RecoveryProbe is how long the limiter stays degraded before a single caller probes the store again.
	RecoveryProbe time.Duration
}

const (
	MetricStoreOutages    = "limiter_store_outages_total"
	MetricStoreRecoveries = "limiter_store_recoveries_total"
)

// DistributedRateLimiter enforces partner and fleet admission across replicas with fixed-window counters
// charged atomically in a shared store; while the store is unreachable it degrades to reduced local windows.
type DistributedRateLimiter struct {
	Clock   clock.Clock
	Metrics port.MetricsRecorder

	config   DistributedRateLimiterConfig
	fallback *fallbackWindowLimiter
	admitter *sharedAdmitter

	mu            sync.Mutex
	degraded      bool
	degradedUntil time.Time
	probing       bool
	generation    uint64
	closed        bool
}

var _ port.RateLimiter = (*DistributedRateLimiter)(nil)

// NewDistributedRateLimiter validates config and binds the limiter to a store that charges every scope of one
// decision atomically; two separate increments would over-admit the fleet by the callers in flight.
func NewDistributedRateLimiter(store cache.MultiScopeAdmitter, config DistributedRateLimiterConfig) (*DistributedRateLimiter, error) {
	if store == nil {
		return nil, fmt.Errorf("distributed rate limiter: store is required")
	}
	if len(config.Lanes) == 0 {
		return nil, fmt.Errorf("distributed rate limiter: at least one lane is required")
	}
	for name, lane := range config.Lanes {
		if !lane.Partner.valid() || !lane.Fleet.valid() {
			return nil, fmt.Errorf("distributed rate limiter: lane %q needs positive limit and window or neither", name)
		}
	}
	if config.KeyPrefix == "" {
		return nil, fmt.Errorf("distributed rate limiter: key prefix is required")
	}
	if config.StoreTimeout <= 0 || config.RecoveryProbe <= 0 {
		return nil, fmt.Errorf("distributed rate limiter: store timeout and recovery probe must be positive")
	}
	if config.FallbackFraction <= 0 || config.FallbackFraction > 1 || math.IsNaN(config.FallbackFraction) {
		return nil, fmt.Errorf("distributed rate limiter: fallback fraction must be in (0, 1]")
	}
	if config.FallbackMaxPartners <= 0 {
		return nil, fmt.Errorf("distributed rate limiter: fallback max partners must be positive")
	}
	l := &DistributedRateLimiter{config: config}
	lanes := make(map[string]*fallbackWindowLane, len(config.Lanes))
	for name, lane := range config.Lanes {
		lanes[name] = &fallbackWindowLane{
			partner: reducedWindowLimit(lane.Partner, config.FallbackFraction),
			fleet:   reducedWindowLimit(lane.Fleet, config.FallbackFraction),
		}
	}
	l.fallback = &fallbackWindowLimiter{lanes: lanes, maxPartners: config.FallbackMaxPartners}
	l.admitter = &sharedAdmitter{store: store, timeout: config.StoreTimeout, maxExhausted: config.FallbackMaxPartners, now: l.now}
	return l, nil
}

func (l *DistributedRateLimiter) now() time.Time {
	if l.Clock == nil {
		return time.Now()
	}
	return l.Clock.Now()
}

// Allow admits one call on a lane; an unconfigured lane fails closed.
func (l *DistributedRateLimiter) Allow(ctx context.Context, lane string, subject model.AdmissionSubject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if subject.PartnerID <= 0 {
		return ErrInvalidSubject
	}
	limits, ok := l.config.Lanes[lane]
	if !ok {
		return fmt.Errorf("distributed rate limiter: unknown lane %q", lane)
	}
	now := l.now()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return ErrClosed
	}
	if !limits.Partner.enabled() && !limits.Fleet.enabled() {
		l.mu.Unlock()
		return nil
	}
	useFallback, probe, generation := l.routeLocked(now)
	l.mu.Unlock()
	if useFallback {
		return l.fallback.allow(lane, subject.PartnerID, now)
	}
	err := l.allowShared(ctx, lane, subject.PartnerID, limits, now)
	var outage *storeOutage
	if errors.As(err, &outage) {
		l.markOutage(ctx, lane, now)
		return l.fallback.allow(lane, subject.PartnerID, now)
	}
	if probe {
		if err == nil || errors.Is(err, ErrRateLimited) {
			l.markRecovered(ctx, lane, generation)
		} else {
			l.markProbeAborted(now, generation)
		}
	}
	return err
}

// Degraded reports whether admission currently runs on the local fallback.
func (l *DistributedRateLimiter) Degraded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.degraded
}

// Close stops admission; it is idempotent and owns no goroutines.
func (l *DistributedRateLimiter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// routeLocked decides shared vs. local admission; one caller per RecoveryProbe becomes the probe.
func (l *DistributedRateLimiter) routeLocked(now time.Time) (useFallback, probe bool, generation uint64) {
	if !l.degraded {
		return false, false, l.generation
	}
	if now.Before(l.degradedUntil) || l.probing {
		return true, false, l.generation
	}
	l.probing = true
	return false, true, l.generation
}

func (l *DistributedRateLimiter) markOutage(ctx context.Context, lane string, now time.Time) {
	l.mu.Lock()
	entered := !l.degraded
	l.degraded = true
	l.probing = false
	l.degradedUntil = now.Add(l.config.RecoveryProbe)
	l.generation++
	l.mu.Unlock()
	if entered {
		l.count(ctx, MetricStoreOutages, lane)
	}
}

// markRecovered clears degraded mode only when no newer outage arrived while the probe was in flight.
func (l *DistributedRateLimiter) markRecovered(ctx context.Context, lane string, generation uint64) {
	l.mu.Lock()
	recovered := l.degraded && l.probing && l.generation == generation
	if recovered {
		l.degraded = false
	}
	l.probing = false
	l.mu.Unlock()
	if recovered {
		l.count(ctx, MetricStoreRecoveries, lane)
	}
}

// markProbeAborted keeps degraded mode after a caller cancellation and delays
// the next probe, because cancellation says nothing about store health.
func (l *DistributedRateLimiter) markProbeAborted(now time.Time, generation uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.degraded && l.probing && l.generation == generation {
		l.degradedUntil = now.Add(l.config.RecoveryProbe)
	}
	l.probing = false
}

func (l *DistributedRateLimiter) count(ctx context.Context, name, lane string) {
	if l.Metrics == nil {
		return
	}
	if err := l.Metrics.RecordMetric(ctx, port.MetricMeasurement{Name: name, Kind: port.MetricCounter, Value: 1, Labels: map[string]string{"lane": lane}}); err != nil {
		log.Printf("limiter: record metric %s: %v", name, err)
	}
}

// storeOutage marks a store failure so Allow can distinguish it from a limit rejection.
type storeOutage struct{ err error }

func (e *storeOutage) Error() string { return "rate limit store unavailable: " + e.err.Error() }

func (e *storeOutage) Unwrap() error { return e.err }

// allowShared charges the partner and fleet windows as one all-or-nothing decision.
func (l *DistributedRateLimiter) allowShared(ctx context.Context, lane string, partnerID int64, limits WindowLane, now time.Time) error {
	var request admission
	if limits.Partner.enabled() {
		key, ttl, retry := windowKey(l.config.KeyPrefix, lane, "p", partnerID, limits.Partner.Window, now)
		request.scopes = append(request.scopes, cache.AdmissionScope{Key: key, Limit: limits.Partner.Limit, Window: ttl})
		request.retries = append(request.retries, retryAdvice{scope: lane + ".partner", after: retry, until: now.Add(retry)})
	}
	if limits.Fleet.enabled() {
		key, ttl, retry := windowKey(l.config.KeyPrefix, lane, "f", 0, limits.Fleet.Window, now)
		request.scopes = append(request.scopes, cache.AdmissionScope{Key: key, Limit: limits.Fleet.Limit, Window: ttl})
		request.retries = append(request.retries, retryAdvice{scope: lane + ".fleet", after: retry, until: now.Add(retry)})
	}
	rejected, err := l.admitter.admit(ctx, request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return &storeOutage{err: err}
	}
	if rejected != nil {
		return &LimitError{Err: ErrRateLimited, Scope: rejected.scope, After: rejected.after}
	}
	return nil
}

func epochOf(now time.Time, window time.Duration) int64 { return now.UnixNano() / int64(window) }

// windowKey names one epoch-aligned counter and returns its cleanup TTL and the delay to the next window.
// The "{prefix:lane}" hash tag keeps a lane's counters on one Redis Cluster slot, which the atomic charge
// requires; the fleet counter is shared by all partners, so the tag cannot be narrower.
func windowKey(prefix, lane, kind string, id int64, window time.Duration, now time.Time) (string, time.Duration, time.Duration) {
	epoch := epochOf(now, window)
	key := "{" + prefix + ":" + lane + "}:" + kind + ":" + strconv.FormatInt(id, 10) + ":" + strconv.FormatInt(epoch, 10)
	retry := time.Duration((epoch+1)*int64(window) - now.UnixNano())
	return key, admissionTTL(window), retry
}

func admissionTTL(window time.Duration) time.Duration {
	if window > time.Duration(1<<63-1)/2 {
		return window
	}
	return 2 * window
}

// admission is one partner+fleet charge; scopes and retries are index-aligned.
type admission struct {
	scopes  []cache.AdmissionScope
	retries []retryAdvice
}

func (a admission) key() string {
	parts := make([]string, len(a.scopes))
	for i, scope := range a.scopes {
		parts[i] = scope.Key
	}
	return strings.Join(parts, "|")
}

// retryAdvice is what a rejection tells the caller; until is when the window rolls over.
type retryAdvice struct {
	scope string
	after time.Duration
	until time.Time
}

// sharedAdmitter serializes charges per admission: while one store call is in flight, arriving callers with the
// same keys join the next batch, which its leader sends as one Admit costing the batch size. A rejected batch is
// then charged one member at a time to the exact boundary; the first single rejection marks that window exhausted
// locally, so the rest of the window costs no round trips — a fixed-window counter only grows inside its epoch,
// so the mark cannot go stale.
type sharedAdmitter struct {
	store        cache.MultiScopeAdmitter
	timeout      time.Duration
	maxExhausted int
	now          func() time.Time

	mu        sync.Mutex
	states    map[string]*admitKeyState
	exhausted map[string]retryAdvice
}

type admitKeyState struct {
	next *admitBatch
}

type admitBatch struct {
	n        int64
	current  bool
	claimed  bool
	ready    chan struct{}
	done     chan struct{}
	admitted int64        // members positioned at or below this succeed
	rejected *retryAdvice // what the others are told
	err      error
	taken    int64
}

// admit returns nil when the caller is admitted, the rejecting scope's advice when it is not, and an error only
// when the store failed.
func (c *sharedAdmitter) admit(ctx context.Context, request admission) (*retryAdvice, error) {
	if len(request.scopes) == 0 {
		return nil, nil
	}
	if advice := c.exhaustedAdvice(request); advice != nil {
		return advice, nil
	}
	key := request.key()
	c.mu.Lock()
	if c.states == nil {
		c.states = make(map[string]*admitKeyState)
	}
	state := c.states[key]
	if state == nil {
		c.states[key] = &admitKeyState{}
		c.mu.Unlock()
		admitted, rejected, err := c.charge(ctx, request, 1)
		c.handoff(key)
		if err != nil || admitted == 1 {
			return nil, err
		}
		return rejected, nil
	}
	batch := state.next
	if batch == nil {
		batch = &admitBatch{ready: make(chan struct{}), done: make(chan struct{})}
		state.next = batch
	}
	batch.n++
	c.mu.Unlock()

	select {
	case <-batch.ready:
	case <-ctx.Done():
		return nil, c.leave(key, batch, ctx.Err())
	}
	c.mu.Lock()
	lead := !batch.claimed
	if lead {
		batch.claimed = true
	}
	n := batch.n
	c.mu.Unlock()
	if lead {
		go c.finishBatch(context.WithoutCancel(ctx), key, batch, request, n)
	}
	select {
	case <-batch.done:
		if batch.err != nil {
			return nil, batch.err
		}
		c.mu.Lock()
		batch.taken++
		position := batch.taken
		c.mu.Unlock()
		if position <= batch.admitted {
			return nil, nil
		}
		return batch.rejected, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *sharedAdmitter) finishBatch(ctx context.Context, key string, batch *admitBatch, request admission, n int64) {
	batch.admitted, batch.rejected, batch.err = c.charge(ctx, request, n)
	close(batch.done)
	c.handoff(key)
}

// charge admits n callers at once when the windows have room, otherwise one at a time up to the exact boundary.
func (c *sharedAdmitter) charge(ctx context.Context, request admission, n int64) (int64, *retryAdvice, error) {
	result, err := c.call(ctx, request, n)
	if err != nil {
		return 0, nil, err
	}
	if result.Admitted {
		return n, nil, nil
	}
	if n == 1 {
		return 0, c.markExhausted(request, result.RejectedKey), nil
	}
	for admitted := int64(0); admitted < n; admitted++ {
		result, err := c.call(ctx, request, 1)
		if err != nil {
			return admitted, nil, err
		}
		if !result.Admitted {
			return admitted, c.markExhausted(request, result.RejectedKey), nil
		}
	}
	return n, nil, nil
}

func (c *sharedAdmitter) call(ctx context.Context, request admission, cost int64) (cache.AdmissionResult, error) {
	scopes := make([]cache.AdmissionScope, len(request.scopes))
	for i, scope := range request.scopes {
		scope.Cost = cost
		scopes[i] = scope
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.store.Admit(callCtx, scopes...)
}

// markExhausted records that rejectedKey has no room left this window and returns its advice.
func (c *sharedAdmitter) markExhausted(request admission, rejectedKey string) *retryAdvice {
	for i, scope := range request.scopes {
		if scope.Key != rejectedKey {
			continue
		}
		advice := request.retries[i]
		c.mu.Lock()
		if c.exhausted == nil {
			c.exhausted = make(map[string]retryAdvice)
		}
		if len(c.exhausted) >= c.maxExhausted {
			c.dropExpiredLocked()
		}
		if len(c.exhausted) < c.maxExhausted {
			c.exhausted[rejectedKey] = advice
		}
		c.mu.Unlock()
		return &advice
	}
	return &retryAdvice{scope: "unknown"}
}

// exhaustedAdvice answers from the local mark when one of the request's windows is known to be full.
func (c *sharedAdmitter) exhaustedAdvice(request admission) *retryAdvice {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, scope := range request.scopes {
		advice, ok := c.exhausted[scope.Key]
		if !ok {
			continue
		}
		if !now.Before(advice.until) {
			delete(c.exhausted, scope.Key)
			continue
		}
		advice.after = advice.until.Sub(now)
		return &advice
	}
	return nil
}

func (c *sharedAdmitter) dropExpiredLocked() {
	now := c.now()
	for key, advice := range c.exhausted {
		if !now.Before(advice.until) {
			delete(c.exhausted, key)
		}
	}
}

func (c *sharedAdmitter) handoff(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handoffLocked(key)
}

// handoffLocked releases the key or promotes the waiting batch to current.
func (c *sharedAdmitter) handoffLocked(key string) {
	state := c.states[key]
	if state == nil || state.next == nil || state.next.n == 0 {
		delete(c.states, key)
		return
	}
	batch := state.next
	state.next = nil
	batch.current = true
	close(batch.ready)
}

// leave withdraws a canceled member from an unsent batch; a member already charged keeps its slot unused.
func (c *sharedAdmitter) leave(key string, batch *admitBatch, cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if batch.claimed {
		return cause
	}
	batch.n--
	if batch.n > 0 {
		return cause
	}
	if batch.current {
		c.handoffLocked(key)
	} else if state := c.states[key]; state != nil && state.next == batch {
		state.next = nil
	}
	return cause
}

func (c *sharedAdmitter) pending(key string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state := c.states[key]; state != nil && state.next != nil {
		return state.next.n
	}
	return 0
}
