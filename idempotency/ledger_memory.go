// Package idempotency keeps replay-safe records of mutating operations behind port.IdempotencyLedger.
package idempotency

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// MemoryLedger is a process-local ledger. Lease > 0 lets Begin take over an in-flight key older than the lease
// under a new fence; the previous holder's writes then fail with ErrInvalidTransition.
type MemoryLedger struct {
	AbstractLedger
	Clock clock.Clock

	mu      sync.Mutex
	entries map[string]memoryEntry
}

func (l *MemoryLedger) now() time.Time {
	if l.Clock == nil {
		return time.Now()
	}
	return l.Clock.Now()
}

type memoryEntry struct {
	model.LedgerEntry
	at time.Time
}

var _ port.IdempotencyLedger = (*MemoryLedger)(nil)

func (l *MemoryLedger) Begin(_ context.Context, key string) (model.LedgerEntry, error) {
	if err := l.validateKey(key); err != nil {
		return model.LedgerEntry{}, err
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]memoryEntry{}
	}
	if e, ok := l.entries[key]; ok {
		if e.State != model.LedgerInFlight || l.Lease <= 0 || now.Before(e.at.Add(l.Lease)) {
			return model.LedgerEntry{State: e.State, Result: cloneBytes(e.Result)}, nil
		}
	}
	fence, err := newFence()
	if err != nil {
		return model.LedgerEntry{}, err
	}
	l.entries[key] = memoryEntry{LedgerEntry: model.LedgerEntry{State: model.LedgerInFlight, Fence: fence}, at: now}
	return model.LedgerEntry{State: model.LedgerNew, Fence: fence}, nil
}

func (l *MemoryLedger) Renew(ctx context.Context, key, fence string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.validateKey(key); err != nil {
		return err
	}
	if err := l.validateFence(fence); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || e.Fence != fence || e.State != model.LedgerInFlight {
		return ErrInvalidTransition
	}
	e.at = l.now()
	l.entries[key] = e
	return nil
}

func (l *MemoryLedger) Complete(_ context.Context, key, fence string, result []byte) error {
	if err := l.validateResult(result); err != nil {
		return err
	}
	return l.transition(key, fence, model.LedgerCompleted, result)
}

func (l *MemoryLedger) MarkUnknown(_ context.Context, key, fence string) error {
	return l.transition(key, fence, model.LedgerUnknown, nil)
}

func (l *MemoryLedger) Release(_ context.Context, key, fence string) error {
	if err := l.validateKey(key); err != nil {
		return err
	}
	if err := l.validateFence(fence); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || e.Fence != fence || (e.State != model.LedgerInFlight && e.State != model.LedgerUnknown) {
		return ErrInvalidTransition
	}
	delete(l.entries, key)
	return nil
}

func (l *MemoryLedger) transition(key, fence string, state model.LedgerState, result []byte) error {
	if err := l.validateKey(key); err != nil {
		return err
	}
	if err := l.validateFence(fence); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || e.Fence != fence {
		return ErrInvalidTransition
	}
	if e.State == state && (state != model.LedgerCompleted || bytes.Equal(e.Result, result)) {
		return nil
	}
	if e.State != model.LedgerInFlight && e.State != model.LedgerUnknown {
		return ErrInvalidTransition
	}
	l.entries[key] = memoryEntry{LedgerEntry: model.LedgerEntry{State: state, Result: cloneBytes(result), Fence: fence}, at: l.now()}
	return nil
}
