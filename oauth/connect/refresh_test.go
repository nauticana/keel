package connect

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
)

func oneStale(qs *fakeQS) {
	qs.next[qListActive] = &model.QueryResult{Rows: [][]any{{int64(7), int64(0), "google", "O", int64(5)}}}
}

// A claimed credential is refreshed and counted once.
func TestRefreshStaleClaimsAndRefreshes(t *testing.T) {
	s, qs := newTestStore(t)
	oneStale(qs)
	sealed, _ := s.seal("the-refresh-token")
	qs.next[qClaim] = &model.QueryResult{Rows: [][]any{{sealed}}}

	var got string
	s.Refresh = func(_ context.Context, _, token string) (RefreshResult, error) {
		got = token
		return RefreshResult{AccessToken: "new-access"}, nil
	}
	refreshed, skipped, failed, err := RefreshStale(context.Background(), s, nil)
	if err != nil || refreshed != 1 || skipped != 0 || failed != 0 {
		t.Fatalf("got refreshed=%d skipped=%d failed=%d err=%v, want 1/0/0/nil", refreshed, skipped, failed, err)
	}
	if got != "the-refresh-token" {
		t.Fatalf("refresher received %q, want the decrypted claimed cred", got)
	}
}

// A credential another replica claimed is counted as skipped, not refreshed.
func TestRefreshStaleSkipsUnclaimed(t *testing.T) {
	s, qs := newTestStore(t)
	oneStale(qs) // qClaim unseeded → 0 rows → claim lost
	refreshed, skipped, failed, err := RefreshStale(context.Background(), s, nil)
	if err != nil || refreshed != 0 || skipped != 1 || failed != 0 {
		t.Fatalf("got refreshed=%d skipped=%d failed=%d err=%v, want 0/1/0/nil", refreshed, skipped, failed, err)
	}
}

func TestRefreshStaleCountsFailures(t *testing.T) {
	s, qs := newTestStore(t)
	oneStale(qs)
	sealed, _ := s.seal("rt")
	qs.next[qClaim] = &model.QueryResult{Rows: [][]any{{sealed}}}
	s.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) {
		return RefreshResult{}, errors.New("invalid_grant")
	}
	refreshed, skipped, failed, err := RefreshStale(context.Background(), s, nil)
	if err != nil || refreshed != 0 || skipped != 0 || failed != 1 {
		t.Fatalf("got refreshed=%d skipped=%d failed=%d err=%v, want 0/0/1/nil", refreshed, skipped, failed, err)
	}
}

// A worklist-read failure is returned (not silently swallowed).
func TestRefreshStaleWorklistError(t *testing.T) {
	s, qs := newTestStore(t)
	qs.err = errors.New("db down")
	if _, _, _, err := RefreshStale(context.Background(), s, nil); err == nil {
		t.Fatal("worklist read failure should return an error")
	}
}

// A corrupt/unreadable claimed credential is CAS-marked errored (a failure).
func TestRefreshStaleMarksUnreadableErrored(t *testing.T) {
	s, qs := newTestStore(t)
	oneStale(qs)
	other, _ := newTestStore(t) // sealed under a different key → won't open
	corrupt, _ := other.seal("x")
	qs.next[qClaim] = &model.QueryResult{Rows: [][]any{{corrupt}}}

	refreshed, skipped, failed, err := RefreshStale(context.Background(), s, nil)
	if err != nil || refreshed != 0 || skipped != 0 || failed != 1 {
		t.Fatalf("got refreshed=%d skipped=%d failed=%d err=%v, want 0/0/1/nil", refreshed, skipped, failed, err)
	}
	if _, found := qs.last(qMarkErroredCAS); !found {
		t.Fatal("unreadable credential should be CAS-marked errored")
	}
}
