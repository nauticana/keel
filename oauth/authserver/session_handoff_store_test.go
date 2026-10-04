package authserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type recordedQuery struct {
	name string
	args []any
}

type fakeHandoffQS struct {
	calls []recordedQuery
	rows  [][]any
	err   error
}

func (f *fakeHandoffQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, recordedQuery{name, args})
	if f.err != nil {
		return nil, f.err
	}
	return &model.QueryResult{Rows: f.rows}, nil
}

func (f *fakeHandoffQS) GenID() int64 { return 0 }

var _ port.QueryService = (*fakeHandoffQS)(nil)

func TestHandoffSQLIsAtomicAndUsesDBClock(t *testing.T) {
	redeem := oauthHandoffQueries[oauthRedeemHandoff]
	for _, want := range []string{"consumed_at IS NULL", "expires_at > CURRENT_TIMESTAMP", "return_url = ?", "RETURNING"} {
		if !strings.Contains(redeem, want) {
			t.Errorf("redeem SQL lacks %q", want)
		}
	}
	for _, name := range []string{oauthRedeemHandoff, oauthResolveHandoff} {
		if !strings.Contains(oauthHandoffQueries[name], "h.created_at > u.tokens_valid_after") {
			t.Errorf("%s outlives access-token revocation", name)
		}
	}
	for name, sql := range oauthHandoffQueries {
		if strings.Contains(sql, "BIGSERIAL") {
			t.Errorf("%s uses BIGSERIAL", name)
		}
	}
	if !strings.Contains(oauthHandoffQueries[oauthInsertHandoff], "nextval('oauth_session_handoff_seq')") {
		t.Error("insert does not draw from oauth_session_handoff_seq")
	}
}

func TestHandoffStoreDBArguments(t *testing.T) {
	qs := &fakeHandoffQS{}
	s := &SessionHandoffStoreDB{qs: qs}
	ctx := context.Background()
	if err := s.SaveHandoff(ctx, &port.SessionHandoffCode{CodeHash: "h", UserID: 7, ReturnURL: "r"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	want := []recordedQuery{
		{oauthPruneHandoffs, []any{int64(7)}},
		{oauthInsertHandoff, []any{"h", int64(7), nil, "r", int64(60)}},
	}
	if !reflect.DeepEqual(qs.calls, want) {
		t.Fatalf("calls = %#v", qs.calls)
	}

	qs.calls, qs.rows = nil, [][]any{{int64(7), int64(3)}}
	u, err := s.RedeemHandoff(ctx, "c", "r", "s", 10*time.Minute)
	if err != nil || u == nil || u.UserID != 7 || u.PartnerID != 3 {
		t.Fatalf("redeem = %+v, %v", u, err)
	}
	if got := qs.calls[0].args; !reflect.DeepEqual(got, []any{"s", int64(600), "c", "r"}) {
		t.Fatalf("redeem args = %#v", got)
	}

	qs.rows = nil
	if u, err := s.ResolveHandoffSession(ctx, "s"); u != nil || err != nil {
		t.Fatalf("no row: %+v, %v", u, err)
	}
}

func TestHandoffStoreDBSurfacesErrors(t *testing.T) {
	boom := errors.New("db down")
	s := &SessionHandoffStoreDB{qs: &fakeHandoffQS{err: boom}}
	ctx := context.Background()
	if err := s.SaveHandoff(ctx, &port.SessionHandoffCode{UserID: 1}, time.Minute); !errors.Is(err, boom) {
		t.Errorf("save err = %v", err)
	}
	if _, err := s.RedeemHandoff(ctx, "c", "r", "s", time.Minute); !errors.Is(err, boom) {
		t.Errorf("redeem err = %v", err)
	}
	if _, err := s.ResolveHandoffSession(ctx, "s"); !errors.Is(err, boom) {
		t.Errorf("resolve err = %v", err)
	}
}
