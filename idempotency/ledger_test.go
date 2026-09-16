package idempotency

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func TestMemoryLedgerStatesAndFencedReclaim(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	l := &MemoryLedger{AbstractLedger: AbstractLedger{Lease: time.Minute}, Clock: fake}
	ctx := context.Background()

	first, err := l.Begin(ctx, "k")
	if err != nil || first.State != model.LedgerNew || first.Fence == "" {
		t.Fatalf("first begin = %+v, %v", first, err)
	}
	if e, _ := l.Begin(ctx, "k"); e.State != model.LedgerInFlight || e.Fence != "" {
		t.Fatalf("concurrent begin must not hand out the fence: %+v", e)
	}
	fake.Advance(2 * time.Minute)
	second, _ := l.Begin(ctx, "k")
	if second.State != model.LedgerNew || second.Fence == "" || second.Fence == first.Fence {
		t.Fatalf("lapsed lease must be taken over under a new fence: %+v", second)
	}
	// A renewed claim is never taken over; the stale holder's writes fail; the new holder's land.
	if err := l.Renew(ctx, "k", first.Fence); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("renew with a superseded fence = %v", err)
	}
	if err := l.Renew(ctx, "k", second.Fence); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := l.Renew(canceled, "k", second.Fence); !errors.Is(err, context.Canceled) {
		t.Fatalf("renew on canceled context = %v", err)
	}
	fake.Advance(50 * time.Second)
	if e, _ := l.Begin(ctx, "k"); e.State != model.LedgerInFlight {
		t.Fatalf("renewed claim was taken over: %+v", e)
	}
	if err := l.Complete(ctx, "k", first.Fence, []byte("stale")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("stale fence complete = %v", err)
	}
	if err := l.Complete(ctx, "k", second.Fence, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if e, _ := l.Begin(ctx, "k"); e.State != model.LedgerCompleted || string(e.Result) != `{"ok":true}` {
		t.Fatalf("replay = %+v", e)
	}
	if err := l.Complete(ctx, "k", second.Fence, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("same-result complete must be idempotent: %v", err)
	}
	if err := l.Complete(ctx, "k", second.Fence, []byte("other")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("different result = %v", err)
	}

	u, _ := l.Begin(ctx, "u")
	if err := l.MarkUnknown(ctx, "u", u.Fence); err != nil {
		t.Fatal(err)
	}
	fake.Advance(time.Hour)
	if e, _ := l.Begin(ctx, "u"); e.State != model.LedgerUnknown || e.Fence != "" {
		t.Fatalf("unknown is never taken over: %+v", e)
	}
	if err := l.Complete(ctx, "u", u.Fence, []byte("verified")); err != nil {
		t.Fatalf("holder reconciles unknown as executed: %v", err)
	}
	r, _ := l.Begin(ctx, "r")
	if err := l.Release(ctx, "r", r.Fence); err != nil {
		t.Fatal(err)
	}
	if e, _ := l.Begin(ctx, "r"); e.State != model.LedgerNew {
		t.Fatalf("released key must be new, got %+v", e)
	}
	if err := l.Complete(ctx, "k", "", []byte("x")); !errors.Is(err, ErrEmptyFence) {
		t.Fatalf("empty fence = %v", err)
	}
	if err := l.Complete(ctx, "k", second.Fence, nil); !errors.Is(err, ErrNilResult) {
		t.Fatalf("nil result = %v", err)
	}
	if _, err := l.Begin(ctx, string(make([]rune, MaxKeyLength+1))); !errors.Is(err, ErrKeyTooLong) {
		t.Fatalf("long key = %v", err)
	}
}

func TestMemoryLedgerResultsDoNotAlias(t *testing.T) {
	l := &MemoryLedger{}
	ctx := context.Background()
	c, _ := l.Begin(ctx, "k")
	result := []byte("abc")
	if err := l.Complete(ctx, "k", c.Fence, result); err != nil {
		t.Fatal(err)
	}
	result[0] = 'x'
	e, _ := l.Begin(ctx, "k")
	e.Result[0] = 'y'
	if again, _ := l.Begin(ctx, "k"); string(again.Result) != "abc" {
		t.Fatalf("ledger storage aliased: %q", again.Result)
	}
	e2, _ := l.Begin(ctx, "empty")
	if err := l.Complete(ctx, "empty", e2.Fence, []byte{}); err != nil {
		t.Fatal(err)
	}
	if e, _ := l.Begin(ctx, "empty"); e.Result == nil || len(e.Result) != 0 {
		t.Fatalf("empty result must remain distinct from nil: %#v", e.Result)
	}
}

// scriptedDB answers named queries from a script and records the order and arguments they ran with.
type scriptedDB struct {
	port.DatabaseRepository
	rows  map[string][][]any
	names []string
	args  map[string][]any
}

func (db *scriptedDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return db
}
func (db *scriptedDB) GenID() int64 { return 1 }
func (db *scriptedDB) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	return db.query(name, args...)
}

func (db *scriptedDB) query(name string, args ...any) (*model.QueryResult, error) {
	db.names = append(db.names, name)
	if db.args == nil {
		db.args = map[string][]any{}
	}
	db.args[name] = args
	return &model.QueryResult{Rows: db.rows[name]}, nil
}

func TestPgsqlLedgerBeginPaths(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		rows  map[string][][]any
		want  model.LedgerState
		fence bool
		asked []string
	}{
		{"fresh key claims", map[string][][]any{qClaim: {{"k"}}}, model.LedgerNew, true, []string{qClaim}},
		{"completed replays", map[string][][]any{qFind: {{"C", []byte(`{"r":1}`)}}}, model.LedgerCompleted, false, []string{qClaim, qFind}},
		{"live claim stays in flight", map[string][][]any{qFind: {{"I", nil}}}, model.LedgerInFlight, false, []string{qClaim, qFind, qReclaim}},
		{"lapsed claim is taken over", map[string][][]any{qFind: {{"I", nil}}, qReclaim: {{"k"}}}, model.LedgerNew, true, []string{qClaim, qFind, qReclaim}},
		{"unknown blocks", map[string][][]any{qFind: {{"U", nil}}}, model.LedgerUnknown, false, []string{qClaim, qFind}},
	}
	for _, tc := range cases {
		db := &scriptedDB{rows: tc.rows}
		e, err := NewPgsqlLedger(db, time.Minute).Begin(ctx, "k")
		if err != nil || e.State != tc.want || (e.Fence != "") != tc.fence {
			t.Fatalf("%s: %+v, %v", tc.name, e, err)
		}
		if len(db.names) != len(tc.asked) {
			t.Fatalf("%s: queries %v, want %v", tc.name, db.names, tc.asked)
		}
		for i := range tc.asked {
			if db.names[i] != tc.asked[i] {
				t.Fatalf("%s: queries %v, want %v", tc.name, db.names, tc.asked)
			}
		}
	}
	// Without a lease a live claim is never probed for takeover.
	db := &scriptedDB{rows: map[string][][]any{qFind: {{"I", nil}}}}
	if _, err := NewPgsqlLedger(db, 0).Begin(ctx, "k"); err != nil || len(db.names) != 2 {
		t.Fatalf("no-lease begin asked %v, %v", db.names, err)
	}
	for _, corrupt := range [][][]any{{{"X", nil}}, {{"C", nil}}, {{"I", []byte("x")}}} {
		db := &scriptedDB{rows: map[string][][]any{qFind: corrupt}}
		if _, err := NewPgsqlLedger(db, 0).Begin(ctx, "k"); err == nil {
			t.Fatalf("corrupt row %v must fail closed", corrupt)
		}
	}
}

func TestPgsqlLedgerWritesAreFencedAndSurviveCancellation(t *testing.T) {
	db := &failingDB{scriptedDB: scriptedDB{rows: map[string][][]any{
		qComplete: {{"k"}}, qUnknown: {{"k"}}, qRelease: {{"k"}}, qRenew: {{"k"}},
	}}}
	l := NewPgsqlLedger(db, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, err := range map[string]error{
		"complete": l.Complete(ctx, "k", "f1", []byte("x")),
		"unknown":  l.MarkUnknown(ctx, "k", "f1"),
		"release":  l.Release(ctx, "k", "f1"),
	} {
		if err != nil {
			t.Fatalf("%s on a canceled context: %v", name, err)
		}
	}
	for _, name := range []string{qComplete, qUnknown, qRelease} {
		found := false
		for _, a := range db.args[name] {
			if a == "f1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s did not bind the fence: %v", name, db.args[name])
		}
	}
	if err := l.Renew(context.Background(), "k", "f1"); err != nil {
		t.Fatalf("renew active claim: %v", err)
	}
	if args := db.args[qRenew]; len(args) != 2 || args[1] != "f1" {
		t.Fatalf("renew did not bind the fence: %v", args)
	}
	rejected := NewPgsqlLedger(&scriptedDB{rows: map[string][][]any{}}, 0)
	if err := rejected.Complete(context.Background(), "k", "stale", []byte("x")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unmatched fence = %v", err)
	}
	if err := rejected.Complete(context.Background(), "k", "", []byte("x")); !errors.Is(err, ErrEmptyFence) {
		t.Fatalf("empty fence = %v", err)
	}
	if _, err := NewPgsqlLedger(nil, 0).Begin(context.Background(), "k"); err == nil {
		t.Fatal("missing database must fail")
	}
}

type failingDB struct {
	scriptedDB
	failOn string
}

func (db *failingDB) GetQueryService(context.Context, map[string]string) port.QueryService { return db }

func (db *failingDB) Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == db.failOn {
		return nil, errors.New("store down")
	}
	return db.scriptedDB.query(name, args...)
}

func TestPgsqlLedgerErrorsNeverGrantAClaim(t *testing.T) {
	for _, failOn := range []string{qClaim, qFind, qReclaim} {
		db := &failingDB{scriptedDB: scriptedDB{rows: map[string][][]any{qFind: {{"I", nil}}}}, failOn: failOn}
		e, err := NewPgsqlLedger(db, time.Minute).Begin(context.Background(), "k")
		if err == nil || e.State != "" || e.Result != nil || e.Fence != "" {
			t.Fatalf("failure at %s returned %+v, %v; want an empty entry and an error", failOn, e, err)
		}
	}
	// The takeover bound is the lease in whole seconds, decided by the database clock.
	db := &scriptedDB{rows: map[string][][]any{qFind: {{"I", nil}}}}
	NewPgsqlLedger(db, 90*time.Second+time.Millisecond).Begin(context.Background(), "k")
	if args := db.args[qReclaim]; len(args) != 3 || args[2] != int64(91) {
		t.Fatalf("reclaim args = %v, want the lease rounded up to whole seconds last", args)
	}
	maxLease := time.Duration(1<<63 - 1)
	if got, want := NewPgsqlLedger(db, maxLease).leaseSeconds(), int64(maxLease/time.Second)+1; got != want {
		t.Fatalf("maximum lease seconds = %d, want %d", got, want)
	}
}

func TestPgsqlLedgerRenewHonorsCancellation(t *testing.T) {
	db := &failingDB{scriptedDB: scriptedDB{rows: map[string][][]any{qRenew: {{"k"}}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewPgsqlLedger(db, time.Minute).Renew(ctx, "k", "f1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("renew on canceled context = %v", err)
	}
}

func TestAbstractDatabaseLedgerIsNotConcrete(t *testing.T) {
	if _, ok := any((*AbstractDatabaseLedger)(nil)).(port.IdempotencyLedger); ok {
		t.Fatal("AbstractDatabaseLedger must be embedded, not used directly")
	}
}
