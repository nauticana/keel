package cache

import (
	"context"
	"errors"
	"time"
)

// ErrCacheMiss is the standard sentinel returned by CacheService.Get
// when the key is absent. Adapters MUST translate their backend's
// native miss signal (redis.Nil, etc.) to this so consumers can write
//
//	if errors.Is(err, port.ErrCacheMiss) { /* not in cache */ }
//
// without importing the underlying client.
var ErrCacheMiss = errors.New("cache: miss")

// CacheService is the unified key-value + list + pub/sub port. The KV half
// (Get/Set/Delete/Increment) covers session/rate-limit caching; the list
// half (RPush/LPopAll) backs lightweight queues — e.g. batched location
// fan-in for tracker workers; the pub/sub half (Publish/Subscribe) backs
// real-time broadcast — e.g. WebSocket fan-out. All methods are satisfied
// by a Redis/Valkey backend or by the in-process MemoryCacheService
// fallback; tests can use either or wire their own stub.
type CacheService interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Increment(ctx context.Context, key string) (int64, error)
	// IncrementWithTTL atomically increments key and, on first creation, sets a
	// fixed-window TTL — without the Increment-then-Set race that can reset the
	// counter. Use it for rate limiting (fixed window per key).
	IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)

	RPush(ctx context.Context, key string, value string) error
	LPopAll(ctx context.Context, key string) ([]string, error)
	Publish(ctx context.Context, channel string, message string) error
	Subscribe(ctx context.Context, channel string) (<-chan string, error)

	// Close releases backend resources (connection pools, sweeper
	// goroutines, subscriber channels). Idempotent. Owners that want
	// clean shutdown should call this after the HTTP server stops;
	// processes that exit immediately can skip it.
	Close() error
}
