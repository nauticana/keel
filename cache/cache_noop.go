package cache

import (
	"context"
	"time"
)

// NoOpCacheService is the fallback implementation used when neither
// --redis_url nor --valkey_url is configured. Get returns the
// port-level miss sentinel; mutators silently succeed; Subscribe
// keeps the channel open until ctx cancels so consumers don't see a
// distinguishable "no traffic vs healthy shutdown" close immediately.
type NoOpCacheService struct{}

func (c *NoOpCacheService) Get(ctx context.Context, key string) (string, error) {
	return "", ErrCacheMiss
}
func (c *NoOpCacheService) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return nil
}
func (c *NoOpCacheService) Delete(ctx context.Context, key string) error             { return nil }
func (c *NoOpCacheService) Increment(ctx context.Context, key string) (int64, error) { return 0, nil }

func (c *NoOpCacheService) RPush(ctx context.Context, key string, value string) error { return nil }
func (c *NoOpCacheService) LPopAll(ctx context.Context, key string) ([]string, error) {
	return nil, nil
}
func (c *NoOpCacheService) Publish(ctx context.Context, channel string, message string) error {
	return nil
}

// Subscribe returns a channel that stays open until ctx is cancelled
// — without this, consumers would see an immediate close and
// confuse it with a healthy disconnect from a real backend.
func (c *NoOpCacheService) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	ch := make(chan string)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (c *NoOpCacheService) Close() error { return nil }
