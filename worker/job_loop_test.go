package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
)

// --- test doubles -----------------------------------------------------------

type qcall struct {
	name string
	args []any
}

// fakeQS returns a fixed QueryResult (or error) per query name and records the
// calls it received.
type fakeQS struct {
	fixed map[string]*model.QueryResult
	errs  map[string]error
	calls []qcall
	genID int64
}

func (f *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, qcall{name, args})
	if err := f.errs[name]; err != nil {
		return nil, err
	}
	if r := f.fixed[name]; r != nil {
		return r, nil
	}
	return &model.QueryResult{}, nil
}

func (f *fakeQS) GenID() int64 { return f.genID }

func (f *fakeQS) argsFor(name string) []any {
	for _, c := range f.calls {
		if c.name == name {
			return c.args
		}
	}
	return nil
}

func (f *fakeQS) countCalls(name string) int {
	n := 0
	for _, c := range f.calls {
		if c.name == name {
			n++
		}
	}
	return n
}

type fakeLogger struct {
	infos, errs []string
}

func (l *fakeLogger) Initialize(_, _ string) error { return nil }
func (l *fakeLogger) Close()                       {}
func (l *fakeLogger) Access(string)                {}
func (l *fakeLogger) Info(s string)                { l.infos = append(l.infos, s) }
func (l *fakeLogger) Warning(string)               {}
func (l *fakeLogger) Error(s string)               { l.errs = append(l.errs, s) }
func (l *fakeLogger) Fatal(string)                 {}

var (
	_ data.QueryService        = (*fakeQS)(nil)
	_ logger.ApplicationLogger = (*fakeLogger)(nil)
)

func qr(rows ...[]any) *model.QueryResult { return &model.QueryResult{Rows: rows} }

func newLoop(qs *fakeQS, lg *fakeLogger) *JobLoop {
	return &JobLoop{
		QS:              qs,
		Journal:         lg,
		GetPendingQuery: "pending",
		ClaimQuery:      "claim",
		ReclaimQuery:    "reclaim",
		WorkerName:      "test",
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// --- Run --------------------------------------------------------------------

func TestJobLoop_Run_claimsAndHandles(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		"pending": qr([]any{int64(1), "a"}, []any{int64(2), "b"}),
		"claim":   qr([]any{int64(1)}), // non-empty → claim won
	}}
	lg := &fakeLogger{}

	var got []int64
	newLoop(qs, lg).Run(context.Background(), func(_ context.Context, id int64, row []any) error {
		got = append(got, id)
		if len(row) != 2 {
			t.Fatalf("handler got row len %d, want 2", len(row))
		}
		return nil
	})

	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("handled ids = %v, want [1 2]", got)
	}
	if qs.countCalls("claim") != 2 {
		t.Fatalf("claim calls = %d, want 2", qs.countCalls("claim"))
	}
}

func TestJobLoop_Run_leasedThreadsTokenAndPassesClaimRow(t *testing.T) {
	qs := &fakeQS{
		genID: 555,
		fixed: map[string]*model.QueryResult{
			"pending": qr([]any{int64(7)}),                     // id only
			"claim":   qr([]any{int64(7), "data", int64(555)}), // full row incl token
		},
	}
	loop := newLoop(qs, &fakeLogger{})
	loop.Leased = true

	var gotRow []any
	loop.Run(context.Background(), func(_ context.Context, _ int64, row []any) error {
		gotRow = row
		return nil
	})

	if len(gotRow) != 3 || gotRow[2] != int64(555) {
		t.Fatalf("handler got %v, want the claim row carrying token 555", gotRow)
	}
	if a := qs.argsFor("claim"); len(a) != 2 || a[0] != int64(555) || a[1] != int64(7) {
		t.Fatalf("claim args = %v, want [token=555, id=7]", a)
	}
}

func TestJobLoop_Run_lostClaimSkipped(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		"pending": qr([]any{int64(7)}),
		"claim":   qr(), // empty → another worker won the race
	}}
	lg := &fakeLogger{}

	handled := 0
	newLoop(qs, lg).Run(context.Background(), func(context.Context, int64, []any) error {
		handled++
		return nil
	})

	if handled != 0 {
		t.Fatalf("handled = %d, want 0 (claim lost)", handled)
	}
}

func TestJobLoop_Run_handlerErrorLoggedAndContinues(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		"pending": qr([]any{int64(1)}, []any{int64(2)}),
		"claim":   qr([]any{int64(1)}),
	}}
	lg := &fakeLogger{}

	handled := 0
	newLoop(qs, lg).Run(context.Background(), func(_ context.Context, id int64, _ []any) error {
		handled++
		return errors.New("boom")
	})

	if handled != 2 {
		t.Fatalf("handled = %d, want 2 (loop continues past error)", handled)
	}
	if !anyContains(lg.errs, "job 1 failed") || !anyContains(lg.errs, "job 2 failed") {
		t.Fatalf("expected per-job failure logs, got %v", lg.errs)
	}
}

func TestJobLoop_Run_fetchErrorLogged(t *testing.T) {
	qs := &fakeQS{errs: map[string]error{"pending": errors.New("db down")}}
	lg := &fakeLogger{}

	handled := 0
	newLoop(qs, lg).Run(context.Background(), func(context.Context, int64, []any) error {
		handled++
		return nil
	})

	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if !anyContains(lg.errs, "failed to fetch pending") {
		t.Fatalf("expected fetch error log, got %v", lg.errs)
	}
}

func TestJobLoop_Run_claimErrorSkipsJob(t *testing.T) {
	qs := &fakeQS{
		fixed: map[string]*model.QueryResult{"pending": qr([]any{int64(5)})},
		errs:  map[string]error{"claim": errors.New("claim failed")},
	}
	lg := &fakeLogger{}

	handled := 0
	newLoop(qs, lg).Run(context.Background(), func(context.Context, int64, []any) error {
		handled++
		return nil
	})

	if handled != 0 {
		t.Fatalf("handled = %d, want 0", handled)
	}
	if !anyContains(lg.errs, "failed to claim job 5") {
		t.Fatalf("expected claim error log, got %v", lg.errs)
	}
}

func TestJobLoop_Run_ctxCancelStops(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		"pending": qr([]any{int64(1)}, []any{int64(2)}),
		"claim":   qr([]any{int64(1)}),
	}}
	lg := &fakeLogger{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handled := 0
	newLoop(qs, lg).Run(ctx, func(context.Context, int64, []any) error {
		handled++
		return nil
	})

	if handled != 0 {
		t.Fatalf("handled = %d, want 0 (ctx cancelled)", handled)
	}
}

// --- Reclaim ----------------------------------------------------------------

func TestJobLoop_Reclaim_emptyQueryIsNoop(t *testing.T) {
	qs := &fakeQS{}
	lg := &fakeLogger{}
	loop := newLoop(qs, lg)
	loop.ReclaimQuery = ""

	loop.Reclaim(context.Background())

	if len(qs.calls) != 0 {
		t.Fatalf("expected no QS calls, got %v", qs.calls)
	}
	if len(lg.infos) != 0 {
		t.Fatalf("expected no logs, got %v", lg.infos)
	}
}

func TestJobLoop_Reclaim_logsOnlyWhenRowsDemoted(t *testing.T) {
	// rows demoted → Info logged
	qsRows := &fakeQS{fixed: map[string]*model.QueryResult{"reclaim": qr([]any{int64(1)}, []any{int64(2)})}}
	lgRows := &fakeLogger{}
	newLoop(qsRows, lgRows).Reclaim(context.Background())
	if !anyContains(lgRows.infos, "reclaimed 2") {
		t.Fatalf("expected reclaim count log, got %v", lgRows.infos)
	}

	// zero rows → quiet (no log) so steady-state ticks stay silent
	qsNone := &fakeQS{fixed: map[string]*model.QueryResult{"reclaim": qr()}}
	lgNone := &fakeLogger{}
	newLoop(qsNone, lgNone).Reclaim(context.Background())
	if len(lgNone.infos) != 0 {
		t.Fatalf("expected no log for zero rows, got %v", lgNone.infos)
	}
}

func TestJobLoop_Reclaim_errorLogged(t *testing.T) {
	qs := &fakeQS{errs: map[string]error{"reclaim": errors.New("nope")}}
	lg := &fakeLogger{}
	newLoop(qs, lg).Reclaim(context.Background())
	if !anyContains(lg.errs, "failed to reclaim") {
		t.Fatalf("expected reclaim error log, got %v", lg.errs)
	}
}
