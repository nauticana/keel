package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauticana/keel/secret"
)

func countingBuckets(t *testing.T, fail error) (*Buckets, *atomic.Int32) {
	t.Helper()
	var builds atomic.Int32
	b := NewBuckets(nil)
	b.build = func(context.Context, secret.SecretProvider, string) (ObjectStorage, error) {
		builds.Add(1)
		if fail != nil {
			return nil, fail
		}
		return NewStorageFile(Spec{Mode: "file", Bucket: t.TempDir()})
	}
	return b, &builds
}

func TestBucketsBuildsEachBucketOnce(t *testing.T) {
	b, builds := countingBuckets(t, nil)
	var wg sync.WaitGroup
	stores := make([]ObjectStorage, 16)
	for i := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := b.Get(context.Background(), "public")
			if err != nil {
				t.Error(err)
			}
			stores[i] = st
		}()
	}
	wg.Wait()
	if n := builds.Load(); n != 1 {
		t.Fatalf("built %d stores for one bucket, want 1", n)
	}
	for _, st := range stores[1:] {
		if st != stores[0] {
			t.Fatal("callers got different stores for one bucket")
		}
	}
	other, err := b.Get(context.Background(), "private")
	if err != nil || other == stores[0] || builds.Load() != 2 {
		t.Fatalf("second bucket: %v, builds %d", err, builds.Load())
	}
}

func TestBucketsRefusesBlankBucket(t *testing.T) {
	b, builds := countingBuckets(t, nil)
	for _, name := range []string{"", "  "} {
		if _, err := b.Get(context.Background(), name); !errors.Is(err, ErrNoBucket) {
			t.Fatalf("Get(%q) = %v, want ErrNoBucket", name, err)
		}
	}
	if builds.Load() != 0 {
		t.Fatal("blank bucket reached the factory")
	}
}

func TestBucketsDoesNotCacheFailures(t *testing.T) {
	down := errors.New("credentials unavailable")
	b, builds := countingBuckets(t, down)
	for range 2 {
		if _, err := b.Get(context.Background(), "public"); !errors.Is(err, down) {
			t.Fatalf("err = %v", err)
		}
	}
	if builds.Load() != 2 {
		t.Fatalf("builds = %d, want a retry after failure", builds.Load())
	}

	b.build = func(context.Context, secret.SecretProvider, string) (ObjectStorage, error) { return nil, nil }
	if _, err := b.Get(context.Background(), "public"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("disabled storage: %v", err)
	}
}

func TestBucketsCallerCancellationDoesNotLeakOrCancelSharedBuild(t *testing.T) {
	b := NewBuckets(nil)
	started := make(chan struct{})
	release := make(chan struct{})
	var built context.Context
	b.build = func(ctx context.Context, _ secret.SecretProvider, _ string) (ObjectStorage, error) {
		built = ctx
		close(started)
		select {
		case <-release:
			return NewStorageFile(Spec{Mode: "file", Bucket: t.TempDir()})
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Get(ctx, "public")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled caller: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled caller remained blocked on the shared build")
	}

	close(release)
	if _, err := b.Get(context.Background(), "public"); err != nil {
		t.Fatalf("shared build did not finish for the next caller: %v", err)
	}
	if built.Err() != nil {
		t.Fatalf("a stored client's build context was cancelled: %v", built.Err())
	}
}

func TestBucketsZeroValueFailsClearly(t *testing.T) {
	var b Buckets
	if _, err := b.Get(context.Background(), "public"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("zero value: %v", err)
	}
}
