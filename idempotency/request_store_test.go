package idempotency

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/keeltest"
)

func TestRequestStoreBegin(t *testing.T) {
	key, digest, boom := strings.Repeat("k", 64), strings.Repeat("d", 64), errors.New("boom")
	for name, tc := range map[string]struct {
		row      []any
		response string
		err      error
	}{
		"in flight":    {row: []any{digest, "I", nil}, err: ErrInFlight},
		"unknown":      {row: []any{digest, "U", nil}, err: ErrOutcomeUnknown},
		"other body":   {row: []any{strings.Repeat("e", 64), "I", nil}, err: ErrKeyReused},
		"completed":    {row: []any{digest, "C", []byte("r")}, response: "r"},
		"just removed": {err: ErrInFlight},
	} {
		q := keeltest.NewQueries()
		if tc.row != nil {
			q.Rows(qRequestFind, tc.row)
		}
		fence, response, err := (&RequestStore{DB: &keeltest.Database{Queries: q}}).Begin(context.Background(), key, digest, time.Hour)
		if fence != "" || string(response) != tc.response || !errors.Is(err, tc.err) {
			t.Errorf("%s: %q %q %v", name, fence, response, err)
		}
	}

	q := keeltest.NewQueries().Rows(qRequestClaim, []any{key})
	s := &RequestStore{DB: &keeltest.Database{Queries: q}}
	fence, _, err := s.Begin(context.Background(), key, digest, time.Hour)
	if err != nil || len(fence) != 32 || q.Calls[qRequestClaim][0][3] != int64(3600) || len(q.Calls[qRequestPrune]) != 1 {
		t.Fatalf("claim: %q %v %v", fence, err, q.Calls)
	}
	if err := s.Complete(context.Background(), key, fence, []byte("r")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("superseded fence: %v", err)
	}
	if err := s.Complete(context.Background(), key, fence, nil); !errors.Is(err, ErrNilResult) {
		t.Fatalf("nil response: %v", err)
	}
	q.Fail(qRequestClaim, boom)
	if _, _, err := s.Begin(context.Background(), key, digest, time.Hour); !errors.Is(err, boom) {
		t.Fatalf("claim failure: %v", err)
	}
	if _, _, err := s.Begin(context.Background(), "short", digest, time.Hour); err == nil {
		t.Fatal("accepted a malformed key")
	}
	if _, _, err := (&RequestStore{}).Begin(context.Background(), key, digest, time.Hour); err == nil {
		t.Fatal("zero store accepted a claim")
	}
}
