package cache

import (
	"container/list"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/config"
)

// MemoryCacheService is a process-local CacheService implementation
// for deployments that don't run a separate Valkey/Redis. It backs the
// keel rate-limit and OTP-token paths well enough that downstream
// projects without an external cache still get bounded abuse — keel
// previously fell back to a NoOp here, which silently disabled the
// caps and let attackers pump unbounded OTP SMS/email.
//
// Backend selection: when neither valkey_url nor redis_url is set,
// NewCacheService returns this implementation by default.
//
// Constraints to know before deploying multi-instance:
//
//  1. State is per process. Two backend processes have two independent
//     caches.
//  2. Rate-limit caps multiply by N processes. cap=3/contact × 4
//     instances = effective max 12/contact in the window. Still
//     bounded; the user accepted this trade-off when wiring memory.
//  3. OTPHandler.mintOTPToken / resolveOTPToken require the same
//     process across /send and /verify. Behind a non-sticky LB the
//     verify will phantom-miss. Multi-instance deploys MUST either use
//     sticky sessions (e.g. Caddy `lb_policy ip_hash`) or provision
//     Valkey/Redis.
//  4. Publish is fan-out to in-process subscribers ONLY. Cross-process
//     messaging silently does not work. None of the keel-shipped
//     handlers use pub/sub today, so this is forward-looking guidance.
//  5. The KV half is capped at memory_cache_max_entries and evicts the
//     least-recently-used key once full. Eviction can drop a live
//     rate-limit counter and reset that window — one more reason a
//     multi-instance deploy belongs on Valkey. Lists are uncapped:
//     they are caller-drained queues.
type MemoryCacheService struct {
	// clock is set at construction: the sweeper goroutine reads it unlocked, so
	// a later assignment would race. Inject with NewMemoryCacheServiceWithClock.
	clock clock.Clock
	mu    sync.Mutex
	kv    map[string]*list.Element
	// lru orders kv by recency, most recent at the front.
	lru      *list.List
	capacity int
	lists    map[string][]string
	pubsub   map[string][]chan string
	stop     chan struct{}
	closed   bool
}

type kvEntry struct {
	key     string
	value   string
	expires time.Time // zero = no expiry
}

// NewMemoryCacheService allocates a memory cache and starts the
// background TTL sweeper. The sweeper drops keys whose expiry has
// passed every memory_cache_sweep_interval; expired keys are also dropped
// lazily on Get/Increment so memory only grows between sweeps and the
// caller never sees a stale value.
func NewMemoryCacheService() *MemoryCacheService {
	return NewMemoryCacheServiceWithClock(clock.System{})
}

// NewMemoryCacheServiceWithClock creates a cache with the given time source.
func NewMemoryCacheServiceWithClock(timeSource clock.Clock) *MemoryCacheService {
	if timeSource == nil {
		timeSource = clock.System{}
	}
	c := &MemoryCacheService{
		clock:    timeSource,
		kv:       make(map[string]*list.Element),
		lru:      list.New(),
		capacity: config.Config().MemoryCacheMaxEntries,
		lists:    make(map[string][]string),
		pubsub:   make(map[string][]chan string),
		stop:     make(chan struct{}),
	}
	go c.sweepLoop()
	return c
}

func (c *MemoryCacheService) now() time.Time {
	if c.clock == nil {
		return time.Now()
	}
	return c.clock.Now()
}

// entry returns the live entry for key, dropping it if expired. Callers hold c.mu.
func (c *MemoryCacheService) entry(key string, touch bool) (*kvEntry, bool) {
	el, ok := c.kv[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*kvEntry)
	if !e.expires.IsZero() && !c.now().Before(e.expires) {
		c.remove(el)
		return nil, false
	}
	if touch {
		c.lru.MoveToFront(el)
	}
	return e, true
}

// store inserts or replaces key, evicting LRU entries over capacity. Callers hold c.mu.
func (c *MemoryCacheService) store(e *kvEntry) {
	if el, ok := c.kv[e.key]; ok {
		el.Value = e
		c.lru.MoveToFront(el)
		return
	}
	c.kv[e.key] = c.lru.PushFront(e)
	for c.capacity > 0 && c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		if oldest == nil {
			return
		}
		c.remove(oldest)
	}
}

// remove drops an element from the map and the recency list. Callers hold c.mu.
func (c *MemoryCacheService) remove(el *list.Element) {
	delete(c.kv, el.Value.(*kvEntry).key)
	c.lru.Remove(el)
}

func (c *MemoryCacheService) sweepLoop() {
	t := time.NewTicker(config.Config().MemoryCacheSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.sweep()
		}
	}
}

func (c *MemoryCacheService) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for el := c.lru.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*kvEntry); !e.expires.IsZero() && !now.Before(e.expires) {
			c.remove(el)
		}
		el = next
	}
}

func (c *MemoryCacheService) Get(ctx context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entry(key, true)
	if !ok {
		return "", ErrCacheMiss
	}
	return e.value, nil
}

func (c *MemoryCacheService) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	var expires time.Time
	if ttl > 0 {
		expires = c.now().Add(ttl)
	}
	c.store(&kvEntry{key: key, value: value, expires: expires})
	c.mu.Unlock()
	return nil
}

func (c *MemoryCacheService) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	if el, ok := c.kv[key]; ok {
		c.remove(el)
	}
	c.mu.Unlock()
	return nil
}

// Increment matches Valkey/Redis INCR semantics: missing-or-expired
// keys start at 1, existing values are parsed as int64 and bumped.
// The expires field is preserved across increments, so the caller's
// usual pattern — Increment then Set(.., ttl) only when count==1 —
// keeps working without resetting the window on subsequent hits.
func (c *MemoryCacheService) Increment(ctx context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entry(key, true)
	if !ok {
		c.store(&kvEntry{key: key, value: "1"})
		return 1, nil
	}
	n, _ := strconv.ParseInt(e.value, 10, 64)
	n++
	e.value = strconv.FormatInt(n, 10)
	return n, nil
}

func (c *MemoryCacheService) IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return c.IncrementByWithTTL(ctx, key, 1, ttl)
}

func (c *MemoryCacheService) IncrementByWithTTL(_ context.Context, key string, n int64, ttl time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entry(key, true)
	if !ok {
		c.store(&kvEntry{key: key, value: strconv.FormatInt(n, 10), expires: c.now().Add(ttl)})
		return n, nil
	}
	count, _ := strconv.ParseInt(e.value, 10, 64)
	count += n
	e.value = strconv.FormatInt(count, 10) // keep the existing window expiry
	return count, nil
}

var _ MultiScopeAdmitter = (*MemoryCacheService)(nil)

// Admit charges every scope under one lock. Process-local like the rest of
// MemoryCacheService: N instances admit N times the configured limit.
func (c *MemoryCacheService) Admit(_ context.Context, scopes ...AdmissionScope) (AdmissionResult, error) {
	if len(scopes) == 0 {
		return AdmissionResult{Admitted: true}, nil
	}
	normalized, err := normalizeAdmissionScopes(scopes)
	if err != nil {
		return AdmissionResult{}, err
	}
	if c.capacity > 0 && len(normalized) > c.capacity {
		return AdmissionResult{}, fmt.Errorf("cache: %d admission scopes exceed memory capacity %d", len(normalized), c.capacity)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, scope := range normalized {
		used := int64(0)
		if e, ok := c.entry(scope.Key, false); ok {
			used, _ = strconv.ParseInt(e.value, 10, 64)
		}
		if used+scope.Cost > scope.Limit {
			retry := time.Duration(0)
			if e, ok := c.entry(scope.Key, false); ok && !e.expires.IsZero() {
				retry = e.expires.Sub(now)
			}
			return AdmissionResult{RejectedKey: scope.Key, RetryAfter: max(retry, 0)}, nil
		}
	}
	counts := make([]int64, len(normalized))
	for i, scope := range normalized {
		e, ok := c.entry(scope.Key, true)
		if !ok {
			counts[i] = scope.Cost
			c.store(&kvEntry{key: scope.Key, value: strconv.FormatInt(scope.Cost, 10), expires: now.Add(scope.Window)})
			continue
		}
		n, _ := strconv.ParseInt(e.value, 10, 64)
		n += scope.Cost
		e.value = strconv.FormatInt(n, 10) // keep the existing window expiry
		counts[i] = n
	}
	return AdmissionResult{Admitted: true, Counts: counts}, nil
}

func (c *MemoryCacheService) RPush(ctx context.Context, key, value string) error {
	c.mu.Lock()
	c.lists[key] = append(c.lists[key], value)
	c.mu.Unlock()
	return nil
}

func (c *MemoryCacheService) LPopAll(ctx context.Context, key string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	items := c.lists[key]
	if len(items) == 0 {
		return nil, nil
	}
	delete(c.lists, key)
	return items, nil
}

// Publish fans out to subscribers in this process only. Sends are
// non-blocking — a slow subscriber drops the message rather than
// stalling Publish — to match the "lossy real-time" semantics of the
// Redis pub/sub channel and avoid one stuck consumer wedging others.
func (c *MemoryCacheService) Publish(ctx context.Context, channel, message string) error {
	c.mu.Lock()
	subs := append([]chan string(nil), c.pubsub[channel]...)
	c.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- message:
		default:
		}
	}
	return nil
}

// Subscribe returns a buffered channel that receives messages
// Publish'd on the same channel name in this process. The returned
// channel closes when ctx is cancelled or Close is called on the
// service.
func (c *MemoryCacheService) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	out := make(chan string, 100)
	c.mu.Lock()
	c.pubsub[channel] = append(c.pubsub[channel], out)
	c.mu.Unlock()

	go func() {
		<-ctx.Done()
		c.mu.Lock()
		// Close() may have already drained pubsub and closed `out`; only
		// close here if the channel is still in the map. Without this guard
		// a Close()-then-cancel sequence panics with "close of closed channel".
		found := false
		subs := c.pubsub[channel]
		for i, ch := range subs {
			if ch == out {
				c.pubsub[channel] = append(subs[:i], subs[i+1:]...)
				found = true
				break
			}
		}
		c.mu.Unlock()
		if found {
			close(out)
		}
	}()
	return out, nil
}

// Close stops the sweeper and closes every active subscriber channel.
// Idempotent — second call is a no-op.
func (c *MemoryCacheService) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.stop)
	for ch, subs := range c.pubsub {
		for _, s := range subs {
			close(s)
		}
		delete(c.pubsub, ch)
	}
	c.mu.Unlock()
	return nil
}

var _ CacheService = (*MemoryCacheService)(nil)
