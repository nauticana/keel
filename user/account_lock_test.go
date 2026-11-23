package user

import (
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
)

func TestLockAccountRevokesSessionsAndRecordsTheActor(t *testing.T) {
	store := memberStore()
	store.addAccount(7, "a@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)
	oauth := &revokedOAuth{}
	svc.OAuthTokens = oauth
	token, _ := svc.CreateRefreshToken(&model.UserSession{Id: 7, SignInMethod: SignInPassword}, SessionDevice{})
	commits := store.commits

	if err := svc.LockAccount(3, 7, "fraud"); err != nil {
		t.Fatal(err)
	}
	if store.accounts[7].status != UserStatusAdminLock || store.commits != commits+1 {
		t.Fatalf("status %s, commits %d", store.accounts[7].status, store.commits-commits)
	}
	if _, err := svc.ValidateRefreshToken(token, SessionDevice{}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after lock: %v", err)
	}
	if _, ok := store.cutoffs[7]; !ok || len(oauth.users) != 1 {
		t.Fatalf("access cutoff %v, authorization-server revocations %v", store.cutoffs, oauth.users)
	}
	if h := store.history[len(store.history)-1]; h[0] != 7 || h[2] != UserActivityLock || h[4] != "fraud" || h[6] != 3 {
		t.Fatalf("history = %v", h)
	}

	if err := svc.UnlockAccount(3, 7, "cleared"); err != nil {
		t.Fatal(err)
	}
	if store.accounts[7].status != UserStatusActive {
		t.Fatalf("status after unlock %s", store.accounts[7].status)
	}
	if h := store.history[len(store.history)-1]; h[2] != UserActivityUnlock || h[4] != "cleared" || h[6] != 3 {
		t.Fatalf("history = %v", h)
	}
	if err := svc.UnlockAccount(3, 7, ""); !errors.Is(err, ErrAccountState) {
		t.Fatalf("unlock of an active account: %v", err)
	}
}

func TestLockAccountRefusesBadInput(t *testing.T) {
	store := memberStore()
	store.addAccount(7, "a@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)
	for _, c := range [][2]int{{0, 7}, {3, 0}} {
		if err := svc.LockAccount(c[0], c[1], ""); !isBadRequest(err) {
			t.Errorf("LockAccount(%d, %d) = %v", c[0], c[1], err)
		}
	}
	if err := svc.LockAccount(7, 7, ""); !errors.Is(err, ErrSelfAction) {
		t.Errorf("self lock = %v", err)
	}
	if err := svc.LockAccount(3, 7, strings.Repeat("x", MaxHistoryReason+1)); !errors.Is(err, ErrReasonTooLong) {
		t.Errorf("long reason = %v", err)
	}
	if err := svc.LockAccount(3, 9, ""); !errors.Is(err, ErrAccountState) {
		t.Errorf("unknown account = %v", err)
	}
	if store.accounts[7].status != UserStatusActive || store.commits != 0 {
		t.Fatalf("status %s, commits %d", store.accounts[7].status, store.commits)
	}
}

// Locking then unlocking must not activate an account that could not sign in.
func TestLockAccountLeavesUnusableAccountsAlone(t *testing.T) {
	for _, status := range []string{UserStatusExpired, UserStatusInitial, UserStatusDeleted, UserStatusAdminLock} {
		store := memberStore()
		store.addAccount(7, "a@acme.com", status)
		svc := newLocalUserService(t, store)
		if err := svc.LockAccount(3, 7, ""); !errors.Is(err, ErrAccountState) || store.accounts[7].status != status {
			t.Errorf("status %s: err %v, now %s", status, err, store.accounts[7].status)
		}
	}
	store := memberStore()
	store.addAccount(7, "a@acme.com", UserStatusSelfLocked)
	if err := newLocalUserService(t, store).LockAccount(3, 7, ""); err != nil || store.accounts[7].status != UserStatusAdminLock {
		t.Fatalf("self-locked account: %v, %s", err, store.accounts[7].status)
	}
}

func TestLockAccountRollsBackOnFailure(t *testing.T) {
	store := memberStore()
	store.addAccount(7, "a@acme.com", UserStatusActive)
	store.failQuery[qRevokeAccessTokens] = errDatabaseDown
	svc := newLocalUserService(t, store)
	if err := svc.LockAccount(3, 7, ""); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("err = %v", err)
	}
	if store.commits != 0 || store.rollbacks != 1 {
		t.Fatalf("commits %d rollbacks %d", store.commits, store.rollbacks)
	}
}

func TestExpireAndActivateAccount(t *testing.T) {
	store := memberStore()
	store.addAccount(7, "a@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)
	token, _ := svc.CreateRefreshToken(&model.UserSession{Id: 7, SignInMethod: SignInPassword}, SessionDevice{})

	if err := svc.ExpireAccount(3, 7, "contract ended"); err != nil || store.accounts[7].status != UserStatusExpired {
		t.Fatalf("expire: %v, status %s", err, store.accounts[7].status)
	}
	if _, err := svc.ValidateRefreshToken(token, SessionDevice{}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after expire: %v", err)
	}
	if h := store.history[len(store.history)-1]; h[2] != UserActivityExpire || h[3] != UserStatusExpired || h[6] != 3 {
		t.Fatalf("history = %v", h)
	}
	for name, refused := range map[string]error{
		"expire again": svc.ExpireAccount(3, 7, ""),
		"lock":         svc.LockAccount(3, 7, ""),
		"unlock":       svc.UnlockAccount(3, 7, ""),
	} {
		if !errors.Is(refused, ErrAccountState) {
			t.Errorf("%s of an expired account: %v", name, refused)
		}
	}
	if err := svc.ActivateAccount(3, 7, "renewed"); err != nil || store.accounts[7].status != UserStatusActive {
		t.Fatalf("activate: %v, status %s", err, store.accounts[7].status)
	}
	if h := store.history[len(store.history)-1]; h[2] != UserActivityActivate || h[4] != "renewed" {
		t.Fatalf("history = %v", h)
	}

	store.accounts[7].status = UserStatusInitial
	if err := svc.ActivateAccount(3, 7, ""); err != nil || store.accounts[7].status != UserStatusActive {
		t.Fatalf("activate a new account: %v", err)
	}
	for _, status := range []string{UserStatusAdminLock, UserStatusDeleted, UserStatusActive} {
		store.accounts[7].status = status
		if err := svc.ActivateAccount(3, 7, ""); !errors.Is(err, ErrAccountState) || store.accounts[7].status != status {
			t.Errorf("activate from %s: %v", status, err)
		}
	}
}
