package connect

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
)

func TestUpsertConnectionRecordsGrantedScopes(t *testing.T) {
	s, qs := newTestStore(t)
	if err := s.UpsertConnection(context.Background(), 7, client.Connection{
		Provider: "gsc", ConnType: "O", CredRef: "tok", APIEndpoint: "https://api",
		GrantedScopes: []string{"webmasters.readonly", "openid"},
	}); err != nil {
		t.Fatal(err)
	}
	c, _ := qs.last(qUpsertConnection)
	if got := c.args[6]; got != "webmasters.readonly openid" {
		t.Fatalf("granted_scopes = %v, want the space-separated set", got)
	}
	// No scopes reported: the column is NULL, not an empty string.
	if err := s.UpsertConnection(context.Background(), 7, client.Connection{Provider: "square", ConnType: "A", CredRef: "k"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := qs.last(qUpsertConnection); c.args[6] != nil {
		t.Fatalf("granted_scopes = %v, want nil", c.args[6])
	}
}

func TestGrantedAndMissingScopes(t *testing.T) {
	s, qs := newTestStore(t)
	qs.next[qGrantedScopes] = &model.QueryResult{Rows: [][]any{{"webmasters.readonly openid"}}}

	granted, err := s.GrantedScopes(context.Background(), 7, "gsc")
	if err != nil || !reflect.DeepEqual(granted, []string{"webmasters.readonly", "openid"}) {
		t.Fatalf("granted = %v, %v", granted, err)
	}
	missing, err := s.MissingScopes(context.Background(), 7, "gsc", []string{"webmasters", "openid"})
	if err != nil || !reflect.DeepEqual(missing, []string{"webmasters"}) {
		t.Fatalf("missing = %v, %v", missing, err)
	}
}

// No row is not "no scopes": a caller must not read an absent connection as a
// narrow grant and ask the partner to re-consent to a connection they never made.
func TestGrantedScopesWithoutConnection(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.GrantedScopes(context.Background(), 7, "gsc"); !errors.Is(err, ErrNoActiveConnection) {
		t.Fatalf("err = %v, want ErrNoActiveConnection", err)
	}
}

// A refresh that reports a scope set updates the record; one that reports none
// leaves the recorded set standing.
func TestRefreshPersistsReportedScopes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		want  any
	}{
		{"reported", "webmasters,openid", "webmasters openid"},
		{"not reported", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, qs := newTestStore(t)
			seedCred(s, qs, "refresh-tok", 3)
			s.Refresh = func(context.Context, string, string) (RefreshResult, error) {
				return RefreshResult{AccessToken: "at", Scope: tc.scope}, nil
			}
			if _, err := s.RefreshAccessToken(context.Background(), 7, "gsc"); err != nil {
				t.Fatal(err)
			}
			done, ok := qs.last(qCompleteCAS)
			if !ok {
				t.Fatal("no completion")
			}
			if done.args[0] != tc.want {
				t.Fatalf("scope arg = %v, want %v", done.args[0], tc.want)
			}
		})
	}
}
