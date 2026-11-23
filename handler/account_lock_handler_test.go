package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// actionGrantDB allows exactly the listed object/action pairs on scope.
type actionGrantDB struct {
	port.DatabaseRepository
	scope   string
	actions map[string]bool
}

func (d actionGrantDB) CheckActionPermission(_ context.Context, p model.Principal, object, action, scope string) (bool, bool) {
	return p.Valid() && scope == d.scope && d.actions[object+"/"+action], false
}

type lockUsers struct {
	user.UserService
	calls []string
	err   error
}

func (u *lockUsers) LockAccount(actorID, userID int, reason string) error {
	u.calls = append(u.calls, fmt.Sprint("lock ", actorID, " ", userID, " ", reason))
	return u.err
}

func (u *lockUsers) ExpireAccount(actorID, userID int, reason string) error {
	u.calls = append(u.calls, fmt.Sprint("expire ", actorID, " ", userID, " ", reason))
	return u.err
}

func (u *lockUsers) ActivateAccount(actorID, userID int, note string) error {
	u.calls = append(u.calls, fmt.Sprint("activate ", actorID, " ", userID, " ", note))
	return u.err
}

func (u *lockUsers) UnlockAccount(actorID, userID int, note string) error {
	u.calls = append(u.calls, fmt.Sprint("unlock ", actorID, " ", userID, " ", note))
	return u.err
}

func TestAccountLockActionsUseTheSessionActorAndGrant(t *testing.T) {
	users := &lockUsers{}
	h := &AccountLockHandler{UserService: users, DB: actionGrantDB{scope: "user_account", actions: map[string]bool{"USER_ACCOUNT/LOCK": true}}}
	routes := h.Routes("/api/v1")
	call := func(path, body string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		stashSession(r, &model.UserSession{Id: 3})
		w := httptest.NewRecorder()
		routes[path](w, r)
		return w.Code
	}
	if code := call("/api/v1/user_account/lock", `{"id":7,"reason":"fraud"}`); code != http.StatusNoContent ||
		fmt.Sprint(users.calls) != "[lock 3 7 fraud]" {
		t.Fatalf("lock = %d, calls %v", code, users.calls)
	}
	if code := call("/api/v1/user_account/unlock", `{"id":7,"note":"ok"}`); code != http.StatusForbidden || len(users.calls) != 1 {
		t.Fatalf("unlock without the grant = %d, calls %v", code, users.calls)
	}
	h.DB = actionGrantDB{scope: "user_account", actions: map[string]bool{"USER_ACCOUNT/EXPIRE": true, "USER_ACCOUNT/ACTIVATE": true}}
	routes = h.Routes("/api/v1")
	call("/api/v1/user_account/expire", `{"id":"7","reason":"ended"}`)
	call("/api/v1/user_account/activate", `{"id":7,"note":"renewed"}`)
	if got := fmt.Sprint(users.calls[1:]); got != "[expire 3 7 ended activate 3 7 renewed]" || call("/api/v1/user_account/lock", `{"id":7}`) != http.StatusForbidden {
		t.Fatalf("calls %v", got)
	}
	h.DB = actionGrantDB{scope: "user_account", actions: map[string]bool{"USER_ACCOUNT/LOCK": true}}
	routes = h.Routes("/api/v1")
	for err, want := range map[error]int{user.ErrAccountState: http.StatusConflict, user.ErrSelfAction: http.StatusConflict, model.NewBadRequest("id is required"): http.StatusBadRequest, user.ErrReasonTooLong: http.StatusBadRequest} {
		users.err = err
		if code := call("/api/v1/user_account/lock", `{"id":7}`); code != want {
			t.Errorf("%v = %d, want %d", err, code, want)
		}
	}
}
