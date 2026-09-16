package cache

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
)

// ShardedLRU partitions keys across independently locked LRUs and sweeps
// expired entries in bounded batches on a background ticker, so a large hot
// cache neither serializes on one lock nor stalls on a full scan.
type ShardedLRU[K comparable, V any] struct {
	shards    []*LRU[K, V]
	seed      maphash.Seed
	next      int
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewShardedLRU splits totalCapacity across shards. sweepInterval <= 0 or
// sweepBatch <= 0 disables the sweeper; expiry is still enforced on read.
func NewShardedLRU[K comparable, V any](shards, totalCapacity int, sweepInterval time.Duration, sweepBatch int, timeSource clock.Clock) *ShardedLRU[K, V] {
	if shards <= 0 || totalCapacity < shards {
		panic("cache: sharded LRU needs at least one slot per shard")
	}
	if timeSource == nil {
		timeSource = clock.System{}
	}
	sharded := &ShardedLRU[K, V]{
		shards: make([]*LRU[K, V], shards),
		seed:   maphash.MakeSeed(),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	base, extra := totalCapacity/shards, totalCapacity%shards
	for i := range sharded.shards {
		capacity := base
		if i < extra {
			capacity++
		}
		sharded.shards[i] = NewLRU[K, V](capacity, timeSource)
	}
	if sweepInterval > 0 && sweepBatch > 0 {
		go sharded.sweeper(timeSource.NewTicker(sweepInterval), sweepBatch)
	} else {
		close(sharded.done)
	}
	return sharded
}

func (s *ShardedLRU[K, V]) shard(key K) *LRU[K, V] {
	return s.shards[maphash.Comparable(s.seed, key)%uint64(len(s.shards))]
}

func (s *ShardedLRU[K, V]) Get(key K) (V, bool)                   { return s.shard(key).Get(key) }
func (s *ShardedLRU[K, V]) Set(key K, value V, ttl time.Duration) { s.shard(key).Set(key, value, ttl) }
func (s *ShardedLRU[K, V]) Delete(key K)                          { s.shard(key).Delete(key) }

// Len sums shard lengths without holding two locks at once.
func (s *ShardedLRU[K, V]) Len() int {
	total := 0
	for _, shard := range s.shards {
		total += shard.Len()
	}
	return total
}

// Close stops the sweeper and waits for it to exit; it is idempotent.
func (s *ShardedLRU[K, V]) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
	})
	return nil
}

func (s *ShardedLRU[K, V]) sweeper(ticker clock.Ticker, batch int) {
	defer close(s.done)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C():
			// Each tick spends at most one batch, rotating the starting shard for fairness.
			remaining := batch
			for range s.shards {
				if remaining <= 0 {
					break
				}
				remaining -= s.shards[s.next].Sweep(remaining)
				s.next = (s.next + 1) % len(s.shards)
			}
		case <-s.stop:
			return
		}
	}
}
