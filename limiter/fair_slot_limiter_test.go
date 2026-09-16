package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

func subject(id int64) model.AdmissionSubject { return model.AdmissionSubject{PartnerID: id} }

func TestFairSlotLimiterGrantsAndReleases(t *testing.T) {
	l := &FairSlotLimiter{Capacity: 2, MaxWaiters: 4096}
	ctx := context.Background()

	first, err := l.AcquireWeighted(ctx, subject(1), 2)
	if err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() {
		lease, err := l.Acquire(ctx, subject(1))
		if err == nil {
			lease.Release()
		}
		blocked <- err
	}()
	select {
	case err := <-blocked:
		t.Fatalf("second acquire should block, got %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	// Double release must not free extra capacity.
	first.Release()
	lease, err := l.AcquireWeighted(ctx, subject(1), 2)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
}

func TestFairSlotLimiterRoundRobinAcrossPartners(t *testing.T) {
	l := &FairSlotLimiter{Capacity: 1, MaxWaiters: 4096}
	ctx := context.Background()
	hold, err := l.Acquire(ctx, subject(1))
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan int64, 3)
	acquire := func(id int64) {
		lease, err := l.Acquire(ctx, subject(id))
		if err != nil {
			t.Error(err)
			return
		}
		order <- id
		lease.Release()
	}
	go acquire(1)
	time.Sleep(10 * time.Millisecond)
	go acquire(1)
	time.Sleep(10 * time.Millisecond)
	go acquire(2)
	time.Sleep(10 * time.Millisecond)

	hold.Release()
	got := []int64{<-order, <-order, <-order}
	if got[0] != 1 || got[1] != 2 || got[2] != 1 {
		t.Fatalf("grant order = %v, want round-robin", got)
	}
}

func TestFairSlotLimiterCancellationDoesNotLeak(t *testing.T) {
	l := &FairSlotLimiter{Capacity: 1, MaxWaiters: 4096}
	hold, err := l.Acquire(context.Background(), subject(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, subject(2)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled acquire = %v", err)
	}
	hold.Release()
	lease, err := l.Acquire(context.Background(), subject(3))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
}

func TestFairSlotLimiterValidation(t *testing.T) {
	l := &FairSlotLimiter{Capacity: 2, MaxWaiters: 4096}
	ctx := context.Background()
	if _, err := l.Acquire(ctx, model.AdmissionSubject{}); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("subject = %v", err)
	}
	if _, err := l.AcquireWeighted(ctx, subject(1), 0); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("weight = %v", err)
	}
	if _, err := l.AcquireWeighted(ctx, subject(1), 3); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("oversized = %v", err)
	}
	if _, err := (&FairSlotLimiter{}).Acquire(ctx, subject(1)); err == nil {
		t.Fatal("unconfigured limiter must fail")
	}
}
