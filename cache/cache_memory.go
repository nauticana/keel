package cache

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// MemoryCacheService is a process-local CacheService implementation
// for deployments that don't run a separate Valkey/Redis. It backs the
// keel rate-limit and OTP-token paths well enough that downstream
// projects without an external cache still get bounded abuse — keel
// previously fell back to a NoOp here, which silently disabled the
// caps and let attackers pump unbounded OTP SMS/email.
//
// Backend selection: when neither --valkey_url nor --redis_url is set,
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
type MemoryCacheService struct {
	mu     sync.Mutex
	kv     map[string]*kvEntry
	lists  map[string][]string
	pubsub map[string][]chan string
	stop   chan struct{}
	closed bool
}

type kvEntry struct {
	value   string
	expires time.Time // zero = no expiry
}

// NewMemoryCacheService allocates a memory cache and starts the
// background TTL sweeper. The sweeper drops keys whose expiry has
// passed every memorySweepInterval; expired keys are also dropped
// lazily on Get/Increment so memory only grows between sweeps and the
// caller never sees a stale value.
func NewMemoryCacheService() *MemoryCacheService {
	c := &MemoryCacheService{
		kv:     make(map[string]*kvEntry),
		lists:  make(map[string][]string),
		pubsub: make(map[string][]chan string),
		stop:   make(chan struct{}),
	}
	go c.sweepLoop()
	return c
}

const memorySweepInterval = time.Minute

func (c *MemoryCacheService) sweepLoop() {
	t := time.NewTicker(memorySweepInterval)
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
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.kv {
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(c.kv, k)
		}
	}
}

func (c *MemoryCacheService) Get(ctx context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.kv[key]
	if !ok {
		return "", ErrCacheMiss
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		delete(c.kv, key)
		return "", ErrCacheMiss
	}
	return e.value, nil
}

func (c *MemoryCacheService) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	var expires time.Time
	if ttl > 0 {
		expires = time.Now().Add(ttl)
	}
	c.mu.Lock()
	c.kv[key] = &kvEntry{value: value, expires: expires}
	c.mu.Unlock()
	return nil
}

func (c *MemoryCacheService) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	delete(c.kv, key)
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
	e, ok := c.kv[key]
	if ok && !e.expires.IsZero() && time.Now().After(e.expires) {
		ok = false
	}
	if !ok {
		c.kv[key] = &kvEntry{value: "1"}
		return 1, nil
	}
	n, _ := strconv.ParseInt(e.value, 10, 64)
	n++
	e.value = strconv.FormatInt(n, 10)
	return n, nil
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
