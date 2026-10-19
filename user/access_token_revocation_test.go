package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

func token(t *testing.T, s *LocalUserService, userID int, issuedAt time.Time) string {
	t.Helper()
	session := s.newSession(userID, "Ada", "L", "ada@example.com", UserStatusActive, "")
	session.IssuedAt = issuedAt.Unix()
	tok, err := s.CreateJWT(session)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRevokeAccessTokens(t *testing.T) {
	store := newMemStore(7)
	s := newLocalUserService(t, store)
	old := token(t, s, 7, time.Now().Add(-time.Minute))
	if _, err := s.ParseJWT(old); err != nil {
		t.Fatalf("no cutoff yet: %v", err)
	}
	if _, err := s.ParseJWT(old); err != nil || store.count(qTokensValidAfter) != 1 {
		t.Fatalf("the cutoff is cached between requests: %v, %d reads", err, store.count(qTokensValidAfter))
	}
	if err := s.RevokeAccessTokens(7); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ParseJWT(old); !errors.Is(err, ErrAccessTokenRevoked) {
		t.Fatalf("a token issued before the cutoff is rejected on the revoking node: %v", err)
	}
	if _, err := s.ParseJWT(token(t, s, 7, time.Now().Add(2*time.Second))); err != nil {
		t.Errorf("a token issued after the cutoff is accepted: %v", err)
	}
}

func TestRevokeAccessTokensRejectsUnknownUser(t *testing.T) {
	s := newLocalUserService(t, newMemStore())
	if err := s.RevokeAccessTokens(404); err == nil {
		t.Fatal("revoking an unknown user must fail")
	}
}

func TestAccessTokenCutoffFailsClosed(t *testing.T) {
	store := newMemStore(8)
	s := newLocalUserService(t, store)
	store.failQuery[qTokensValidAfter] = errDatabaseDown
	if _, err := s.ParseJWT(token(t, s, 8, time.Now())); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("an unreadable cutoff must reject the token: %v", err)
	}
}

func TestDeleteAccountRevokesAccessTokens(t *testing.T) {
	store := newMemStore(9)
	s := newLocalUserService(t, store)
	tok := token(t, s, 9, time.Now().Add(-time.Minute))
	if _, err := s.ParseJWT(tok); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccount(9, "requested"); err != nil {
		t.Fatal(err)
	}
	if !store.deleted[9] || store.commits != 1 || store.count(qRevokeAllRefreshTokensForID) != 1 || store.count(qAddUserActivity) != 1 {
		t.Fatalf("anonymized, refresh tokens revoked and history written in one commit: %+v", store)
	}
	if _, err := s.ParseJWT(tok); !errors.Is(err, ErrAccessTokenRevoked) {
		t.Errorf("a deleted account's access token must stop working: %v", err)
	}
}

func TestDeleteAccountRefusesLegalHold(t *testing.T) {
	store := newMemStore(10)
	store.holds[10] = true
	s := newLocalUserService(t, store)
	if err := s.DeleteAccount(10, "requested"); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("want ErrLegalHold, got %v", err)
	}
	if store.deleted[10] || store.commits != 0 || store.rollbacks != 1 || store.count(qAddUserActivity) != 0 {
		t.Errorf("a held account is left untouched: %+v", store)
	}
	if err := s.DeleteAccount(11, "requested"); err == nil {
		t.Error("an unknown user is an error")
	}
}

func TestDeleteAccountRejectsLongReasonBeforeDeleting(t *testing.T) {
	store := newMemStore(12)
	s := newLocalUserService(t, store)
	if err := s.DeleteAccount(12, strings.Repeat("é", MaxHistoryReason+1)); !errors.Is(err, ErrReasonTooLong) {
		t.Fatalf("want ErrReasonTooLong, got %v", err)
	}
	if store.deleted[12] || store.commits != 0 {
		t.Errorf("nothing is deleted: %+v", store)
	}
	if err := s.DeleteAccount(12, strings.Repeat("é", MaxHistoryReason)); err != nil {
		t.Fatalf("a reason at the column width is accepted: %v", err)
	}
}

func TestDeleteAccountJournalsFailedHistory(t *testing.T) {
	store := newMemStore(13)
	store.failQuery[qAddUserActivity] = errDatabaseDown
	s := newLocalUserService(t, store)
	journal := &errorJournal{}
	s.Journal = journal
	if err := s.DeleteAccount(13, "requested"); err != nil {
		t.Fatalf("a committed deletion is not reported as failed: %v", err)
	}
	if !store.deleted[13] || len(journal.errors) != 1 || !strings.Contains(journal.errors[0], "write history") {
		t.Fatalf("deleted and journaled: deleted=%v journal=%v", store.deleted[13], journal.errors)
	}
}

func TestDeleteAccountRunsOnDeletedInTheTransaction(t *testing.T) {
	store := newMemStore(14, 15)
	s := newLocalUserService(t, store)
	var got int64
	s.OnDeleted = func(_ context.Context, tx port.TxQueryService, userID int64) error {
		if tx == nil {
			t.Error("OnDeleted runs without the deletion transaction")
		}
		got = userID
		if userID == 15 {
			return errDatabaseDown
		}
		return nil
	}
	if err := s.DeleteAccount(14, "requested"); err != nil || got != 14 || store.commits != 1 {
		t.Fatalf("err=%v user=%d commits=%d", err, got, store.commits)
	}
	if err := s.DeleteAccount(15, "requested"); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("want the hook's error, got %v", err)
	}
	if store.commits != 1 || store.rollbacks != 1 {
		t.Errorf("a failed hook rolls the deletion back: %+v", store)
	}
}
