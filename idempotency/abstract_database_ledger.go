package idempotency

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	qFind     = "keel_idempotency_find"
	qClaim    = "keel_idempotency_claim"
	qReclaim  = "keel_idempotency_reclaim"
	qRenew    = "keel_idempotency_renew"
	qComplete = "keel_idempotency_complete"
	qUnknown  = "keel_idempotency_unknown"
	qRelease  = "keel_idempotency_release"
)

const (
	stateInFlight  = "I"
	stateCompleted = "C"
	stateUnknown   = "U"
)

var states = map[string]model.LedgerState{stateInFlight: model.LedgerInFlight, stateCompleted: model.LedgerCompleted, stateUnknown: model.LedgerUnknown}

// ledgerQueryProvider supplies the database-specific SQL used by AbstractDatabaseLedger.
type ledgerQueryProvider interface {
	GetQueries() map[string]string
}

// AbstractDatabaseLedger adds provider-neutral named-query initialization. It is incomplete and must be embedded
// by a database-specific implementation that supplies its own SQL catalog.
type AbstractDatabaseLedger struct {
	AbstractLedger
	db            port.DatabaseRepository
	queryProvider ledgerQueryProvider

	once sync.Once
	qs   port.QueryService
}

// GetQueries returns the SQL catalog supplied by the concrete database implementation.
func (l *AbstractDatabaseLedger) GetQueries() map[string]string {
	if l.queryProvider == nil {
		return nil
	}
	return l.queryProvider.GetQueries()
}

func (l *AbstractDatabaseLedger) query(ctx context.Context) (port.QueryService, error) {
	if l.db == nil {
		return nil, fmt.Errorf("idempotency: database is required")
	}
	queries := l.GetQueries()
	if len(queries) == 0 {
		return nil, fmt.Errorf("idempotency: query provider returned no queries")
	}
	l.once.Do(func() { l.qs = l.db.GetQueryService(ctx, queries) })
	if l.qs == nil {
		return nil, fmt.Errorf("idempotency: database returned no query service")
	}
	return l.qs, nil
}

func (l *AbstractDatabaseLedger) begin(ctx context.Context, key string) (model.LedgerEntry, error) {
	if err := l.validateKey(key); err != nil {
		return model.LedgerEntry{}, err
	}
	qs, err := l.query(ctx)
	if err != nil {
		return model.LedgerEntry{}, err
	}
	fence, err := newFence()
	if err != nil {
		return model.LedgerEntry{}, err
	}
	claimed, err := l.changed(ctx, qs, qClaim, key, fence)
	if err != nil {
		return model.LedgerEntry{}, err
	}
	if claimed {
		return model.LedgerEntry{State: model.LedgerNew, Fence: fence}, nil
	}
	res, err := qs.Query(ctx, qFind, key)
	if err != nil {
		return model.LedgerEntry{}, err
	}
	if len(res.Rows) == 0 {
		return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q vanished between claim and read", key)
	}
	if len(res.Rows[0]) < 2 {
		return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q returned a malformed row", key)
	}
	stateCode := common.AsString(res.Rows[0][0])
	state, ok := states[stateCode]
	if !ok {
		return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q has unknown state %q", key, stateCode)
	}
	entry := model.LedgerEntry{State: state}
	if raw := res.Rows[0][1]; raw != nil {
		switch value := raw.(type) {
		case []byte:
			entry.Result = cloneBytes(value)
		case string:
			entry.Result = []byte(value)
		default:
			return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q has unsupported result type %T", key, raw)
		}
	}
	if entry.State == model.LedgerCompleted && entry.Result == nil {
		return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q is completed without a result", key)
	}
	if entry.State != model.LedgerCompleted && entry.Result != nil {
		return model.LedgerEntry{}, fmt.Errorf("idempotency: key %q has a result in state %q", key, stateCode)
	}
	if entry.State == model.LedgerInFlight && l.Lease > 0 {
		taken, err := l.changed(ctx, qs, qReclaim, fence, key, l.leaseSeconds())
		if err != nil {
			return model.LedgerEntry{}, err
		}
		if taken {
			return model.LedgerEntry{State: model.LedgerNew, Fence: fence}, nil
		}
	}
	return entry, nil
}

// leaseSeconds is the lease as the whole seconds the SQL interval takes; sub-second leases round up to one.
func (l *AbstractDatabaseLedger) leaseSeconds() int64 {
	seconds := int64(l.Lease / time.Second)
	if l.Lease%time.Second != 0 {
		seconds++
	}
	return max(1, seconds)
}

func (l *AbstractDatabaseLedger) renew(ctx context.Context, key, fence string) error {
	return l.write(ctx, key, fence, qRenew, key, fence)
}

func (l *AbstractDatabaseLedger) complete(ctx context.Context, key, fence string, result []byte) error {
	if err := l.validateResult(result); err != nil {
		return err
	}
	return l.update(ctx, key, fence, qComplete, result, key, fence, result)
}

func (l *AbstractDatabaseLedger) markUnknown(ctx context.Context, key, fence string) error {
	return l.update(ctx, key, fence, qUnknown, key, fence)
}

func (l *AbstractDatabaseLedger) release(ctx context.Context, key, fence string) error {
	return l.update(ctx, key, fence, qRelease, key, fence)
}

func (l *AbstractDatabaseLedger) update(ctx context.Context, key, fence, name string, args ...any) error {
	// Terminal writes must land even when the caller is already gone.
	return l.write(context.WithoutCancel(ctx), key, fence, name, args...)
}

func (l *AbstractDatabaseLedger) write(ctx context.Context, key, fence, name string, args ...any) error {
	if err := l.validateKey(key); err != nil {
		return err
	}
	if err := l.validateFence(fence); err != nil {
		return err
	}
	qs, err := l.query(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, name, args...)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrInvalidTransition
	}
	return nil
}

func (l *AbstractDatabaseLedger) changed(ctx context.Context, qs port.QueryService, name string, args ...any) (bool, error) {
	res, err := qs.Query(ctx, name, args...)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0, nil
}
