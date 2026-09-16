package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
)

type lruEntry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time // zero = no expiry
}

func (e *lruEntry[K, V]) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && !now.Before(e.expiresAt)
}

// LRU is a fixed-capacity typed cache with per-entry TTL under one lock: the
// in-process hot cache a service puts in front of a store. For a shared,
// string-valued cache use CacheService instead.
type LRU[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	entries  map[K]*list.Element
	order    *list.List
	sweep    *list.Element
	clock    clock.Clock
}

// NewLRU returns a cache of at most capacity entries; a nil clock uses system time.
func NewLRU[K comparable, V any](capacity int, timeSource clock.Clock) *LRU[K, V] {
	if capacity <= 0 {
		panic("cache: LRU capacity must be positive")
	}
	if timeSource == nil {
		timeSource = clock.System{}
	}
	return &LRU[K, V]{
		capacity: capacity,
		entries:  make(map[K]*list.Element, capacity),
		order:    list.New(),
		clock:    timeSource,
	}
}

// Get returns a live value and refreshes its recency; an expired entry is dropped.
func (c *LRU[K, V]) Get(key K) (V, bool) {
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.entries[key]
	if element == nil {
		var zero V
		return zero, false
	}
	item := element.Value.(*lruEntry[K, V])
	if item.expired(now) {
		c.remove(element)
		var zero V
		return zero, false
	}
	c.order.MoveToFront(element)
	return item.value, true
}

// Set inserts or replaces a value; a non-positive ttl means no expiry.
func (c *LRU[K, V]) Set(key K, value V, ttl time.Duration) {
	now := c.clock.Now()
	expiresAt := time.Time{}
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		item := element.Value.(*lruEntry[K, V])
		item.value = value
		item.expiresAt = expiresAt
		c.order.MoveToFront(element)
		return
	}
	if len(c.entries) >= c.capacity {
		c.remove(c.order.Back())
	}
	c.entries[key] = c.order.PushFront(&lruEntry[K, V]{key: key, value: value, expiresAt: expiresAt})
}

// Delete removes a key without disturbing other entries.
func (c *LRU[K, V]) Delete(key K) {
	c.mu.Lock()
	if element := c.entries[key]; element != nil {
		c.remove(element)
	}
	c.mu.Unlock()
}

// Len counts resident entries, including expired ones not yet swept.
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Sweep scans up to limit entries from the least-recent end, dropping expired
// ones, and reports how many it scanned.
func (c *LRU[K, V]) Sweep(limit int) int {
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	scanned := 0
	element := c.sweep
	if element == nil {
		element = c.order.Back()
	}
	for element != nil && scanned < limit {
		previous := element.Prev()
		if element.Value.(*lruEntry[K, V]).expired(now) {
			c.remove(element)
		}
		element = previous
		scanned++
	}
	c.sweep = element
	return scanned
}

func (c *LRU[K, V]) remove(element *list.Element) {
	if element == nil {
		return
	}
	if c.sweep == element {
		c.sweep = element.Prev()
	}
	delete(c.entries, element.Value.(*lruEntry[K, V]).key)
	c.order.Remove(element)
}
