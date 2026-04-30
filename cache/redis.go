package cache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/secret"
	"github.com/redis/go-redis/v9"
)

// CacheServiceImpl satisfies port.CacheService for both Redis and Valkey
// backends. The two protocols are wire-identical — the same struct handles
// single-node and cluster mode by holding a redis.UniversalClient under the
// hood. NewCacheService below decides which client variant to instantiate
// from the flag values.
type CacheServiceImpl struct {
	client redis.UniversalClient
}

// NewCacheService constructs the cache service from the keel common flags
// and the secret provider. It chooses the implementation by inspecting the
// flag values, in this precedence:
//
//  1. --valkey_url set    → Valkey path. Honors --valkey_cluster. Reads the
//     `valkey_password` secret (empty if missing).
//  2. --redis_url  set    → Redis single-node path. Reads the
//     `redis_password` secret (empty if missing).
//  3. neither set         → NoOp implementation. Lets dev / test boot without
//     a cache and silences cache-dependent paths.
//
// Setting both flags at once is a configuration error and returns nil + err
// so callers fail fast at startup instead of silently picking one.
//
// URL accepted forms:
//   - host:port                       — plain
//   - redis://host:port/db            — RESP URL, plaintext
//   - rediss://host:port/db           — RESP URL, TLS
//
// Passwords MUST NOT be embedded in the URL. They are pulled from the
// secret provider so they can be rotated without redeploying.
func NewCacheService(ctx context.Context, secrets secret.SecretProvider) (CacheService, error) {
	valkeyAddr := strings.TrimSpace(*common.ValkeyURL)
	redisAddr := strings.TrimSpace(*common.RedisURL)

	if valkeyAddr != "" && redisAddr != "" {
		return nil, fmt.Errorf("cache: --valkey_url and --redis_url are mutually exclusive — set exactly one")
	}

	if valkeyAddr != "" {
		password, _ := secrets.GetSecret(ctx, "valkey_password")
		return newValkeyClient(valkeyAddr, strings.TrimSpace(password), *common.ValkeyCluster), nil
	}
	if redisAddr != "" {
		password, _ := secrets.GetSecret(ctx, "redis_password")
		return newValkeyClient(redisAddr, strings.TrimSpace(password), false), nil
	}
	return &NoOpCacheService{}, nil
}

// newValkeyClient builds a redis.UniversalClient from a parsed address +
// password + cluster flag. Shared by both the Valkey and Redis paths since
// the wire protocol is identical; the only branch is single-node vs
// cluster-mode client construction.
func newValkeyClient(addr, password string, cluster bool) *CacheServiceImpl {
	var opts *redis.Options
	if strings.HasPrefix(addr, "redis://") || strings.HasPrefix(addr, "rediss://") {
		parsed, err := redis.ParseURL(addr)
		if err != nil {
			// Fall back to raw addr so the caller sees the connection error
			// at first use rather than silently ignoring a malformed URL.
			opts = &redis.Options{Addr: addr, DB: 0}
		} else {
			opts = parsed
		}
	} else {
		opts = &redis.Options{Addr: addr, DB: 0}
	}
	if password != "" {
		opts.Password = password
	}

	var client redis.UniversalClient
	if cluster {
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:     []string{opts.Addr},
			Username:  opts.Username,
			Password:  opts.Password,
			TLSConfig: opts.TLSConfig,
		})
	} else {
		client = redis.NewClient(opts)
	}
	return &CacheServiceImpl{client: client}
}

// Close releases the connection pool. Idempotent — safe to call
// multiple times or with a nil client.
func (s *CacheServiceImpl) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *CacheServiceImpl) Get(ctx context.Context, key string) (string, error) {
	v, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		// Translate the redis-specific miss sentinel to the port-level sentinel so consumers can branch on errors.Is(err,ErrCacheMiss) without importing go-redis directly.
		return "", ErrCacheMiss
	}
	return v, err
}

func (s *CacheServiceImpl) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *CacheServiceImpl) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func (s *CacheServiceImpl) Increment(ctx context.Context, key string) (int64, error) {
	return s.client.Incr(ctx, key).Result()
}

func (s *CacheServiceImpl) RPush(ctx context.Context, key string, value string) error {
	return s.client.RPush(ctx, key, value).Err()
}

func (s *CacheServiceImpl) LPopAll(ctx context.Context, key string) ([]string, error) {
	n, err := s.client.LLen(ctx, key).Result()
	if err != nil || n == 0 {
		return nil, err
	}
	items, err := s.client.LPopCount(ctx, key, int(n)).Result()
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *CacheServiceImpl) Publish(ctx context.Context, channel string, message string) error {
	return s.client.Publish(ctx, channel, message).Err()
}

// Subscribe opens a Redis pub/sub subscription on channel. The
// returned channel closes when ctx cancels or the subscription
// errors. The underlying *PubSub is also closed in the same path —
// without that, every Subscribe call would leak a server-side
// subscription record (P1-15).
func (s *CacheServiceImpl) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	sub := s.client.Subscribe(ctx, channel)
	ch := make(chan string, 100)
	go func() {
		// Defers run LIFO: close ch first (consumers see the
		// channel close), then close the pub/sub handle so the
		// server-side resource is released.
		defer sub.Close()
		defer close(ch)
		for {
			msg, err := sub.ReceiveMessage(ctx)
			if err != nil {
				return
			}
			ch <- msg.Payload
		}
	}()
	return ch, nil
}
