package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/nauticana/keel/secret"
)

var (
	ErrNoBucket      = errors.New("storage: a bucket name is required")
	ErrNotConfigured = errors.New("storage: storage_mode is not configured")
)

const bucketBuildTimeout = 30 * time.Second

// Buckets holds one storage_mode store per bucket for the process, built on
// first use. A failed build is not cached, so the next Get retries it.
type Buckets struct {
	secrets secret.SecretProvider
	build   func(ctx context.Context, secrets secret.SecretProvider, bucket string) (ObjectStorage, error)

	mu     sync.RWMutex
	stores map[string]ObjectStorage
	group  singleflight.Group
}

func NewBuckets(secrets secret.SecretProvider) *Buckets {
	return &Buckets{secrets: secrets, build: NewFromConfig, stores: map[string]ObjectStorage{}}
}

// Get returns bucket's store, wrapping ErrNoBucket for a blank name and
// ErrNotConfigured when storage_mode is empty.
func (b *Buckets) Get(ctx context.Context, bucket string) (ObjectStorage, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, ErrNoBucket
	}
	if b == nil || b.build == nil {
		return nil, ErrNotConfigured
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	st, ok := b.stores[bucket]
	b.mu.RUnlock()
	if ok {
		return st, nil
	}
	// The shared build outlives an individual caller but remains bounded. Its
	// context is never cancelled after a success: a provider client may keep it
	// to refresh credentials.
	result := b.group.DoChan(bucket, func() (any, error) {
		buildCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		timer := time.AfterFunc(bucketBuildTimeout, cancel)
		st, err := b.build(buildCtx, b.secrets, bucket)
		if !timer.Stop() && err == nil {
			err = context.DeadlineExceeded
		}
		if err != nil {
			cancel()
			return nil, err
		}
		if st == nil {
			cancel()
			return nil, ErrNotConfigured
		}
		b.mu.Lock()
		b.stores[bucket] = st
		b.mu.Unlock()
		return st, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(ObjectStorage), nil
	}
}
