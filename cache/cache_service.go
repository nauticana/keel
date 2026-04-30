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
// by a Redis/Valkey backend; consumers that don't need streaming can wire
// the NoOp implementation in tests.
type CacheService interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Increment(ctx context.Context, key string) (int64, error)

	RPush(ctx context.Context, key string, value string) error
	LPopAll(ctx context.Context, key string) ([]string, error)
	Publish(ctx context.Context, channel string, message string) error
	Subscribe(ctx context.Context, channel string) (<-chan string, error)

	// Close releases the connection pool. Idempotent and safe to call
	// even when no backing connection was opened (NoOp adapter).
	// Owners that want clean shutdown should call this after the HTTP
	// server stops; processes that exit immediately can skip it.
	Close() error
}
