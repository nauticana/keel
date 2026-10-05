package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/port"
)

type revokedOAuth struct {
	port.OAuthTokenStore
	users []int64
}

func (r *revokedOAuth) RevokeForUser(_ context.Context, userID int64) error {
	r.users = append(r.users, userID)
	return nil
}

func memberStore() *memStore {
	store := newMemStore(7)
	store.members[[2]int64{7, 11}] = true
	return store
}

func TestEndMembershipEndsRolesAndRevokesSessions(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	oauth := &revokedOAuth{}
	svc.OAuthTokens = oauth
	token, _ := svc.CreateRefreshToken(7)
	if session, err := svc.ValidateRefreshToken(token); err != nil || session.PartnerId != 11 {
		t.Fatalf("refresh before = %+v, %v", session, err)
	} else {
		token = session.NewRefreshToken
	}

	if err := svc.EndMembership(11, 7, "left"); err != nil {
		t.Fatal(err)
	}
	if len(store.endedRoles) != 1 || store.endedRoles[0] != 7 {
		t.Fatalf("role assignments ended for %v", store.endedRoles)
	}
	if _, err := svc.ValidateRefreshToken(token); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after the membership ended: %v", err)
	}
	if _, ok := store.cutoffs[7]; !ok {
		t.Fatal("access tokens issued so far must be rejected")
	}
	if len(oauth.users) != 1 || oauth.users[0] != 7 {
		t.Fatalf("authorization-server tokens = %v", oauth.users)
	}
	for _, c := range [][2]int64{{11, 7}, {12, 7}, {0, 7}, {11, 0}} {
		if err := svc.EndMembership(c[0], int(c[1]), "again"); !errors.Is(err, ErrNoMembership) {
			t.Errorf("EndMembership(%d, %d) = %v", c[0], c[1], err)
		}
	}
}

func TestEndMembershipRollsBackOnFailure(t *testing.T) {
	store := memberStore()
	store.failQuery[qEndPermissions] = errDatabaseDown
	svc := newLocalUserService(t, store)
	if err := svc.EndMembership(11, 7, "left"); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("err = %v", err)
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits %d rollbacks %d", store.commits, store.rollbacks)
	}
}

// An ended row is read-only: the end statements may only touch open rows,
// and rows are never deleted.
func TestEndStatementsTouchOnlyOpenRows(t *testing.T) {
	for _, name := range []string{qEndMembership, qEndPermissions} {
		sql := LocalUserQueries[name]
		if !strings.Contains(sql, "endda IS NULL") || !strings.Contains(sql, "SET endda = CURRENT_TIMESTAMP") || strings.Contains(strings.ToUpper(sql), "DELETE") {
			t.Errorf("%s = %s", name, sql)
		}
	}
}
