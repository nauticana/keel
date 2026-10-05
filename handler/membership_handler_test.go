package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type membershipUsers struct {
	user.UserService
	partner int64
	userID  int
	err     error
}

func (u *membershipUsers) EndMembership(partnerID int64, userID int, _ string) error {
	u.partner, u.userID = partnerID, userID
	return u.err
}

func TestMembershipEndUsesTheSessionPartner(t *testing.T) {
	users := &membershipUsers{}
	h := &MembershipHandler{AbstractHandler: AbstractHandler{UserService: users}}
	call := func(body string, session *model.UserSession) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/partner_user/end", strings.NewReader(body))
		if session != nil {
			stashSession(r, session)
		}
		w := httptest.NewRecorder()
		h.End(w, r)
		return w.Code
	}
	admin := &model.UserSession{Id: 3, PartnerId: 7}
	if code := call(`{"userId":9,"partnerId":99,"reason":"left"}`, admin); code != http.StatusOK || users.partner != 7 || users.userID != 9 {
		t.Fatalf("status %d, service saw partner %d user %d", code, users.partner, users.userID)
	}
	for body, want := range map[string]int{`{}`: http.StatusBadRequest, `{"userId":9,"reason":"` + strings.Repeat("x", 201) + `"}`: http.StatusBadRequest} {
		if code := call(body, admin); code != want {
			t.Errorf("%s = %d, want %d", body[:8], code, want)
		}
	}
	if code := call(`{"userId":9}`, &model.UserSession{Id: 3}); code != http.StatusUnauthorized {
		t.Fatalf("no partner = %d", code)
	}
	users.err = user.ErrNoMembership
	if code := call(`{"userId":9}`, admin); code != http.StatusNotFound {
		t.Fatalf("no membership = %d", code)
	}
	route := h.Routes("/api/v1")["/api/v1/partner_user/end"]
	w := httptest.NewRecorder()
	route(w, httptest.NewRequest(http.MethodPost, "/api/v1/partner_user/end", strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("route without a session = %d", w.Code)
	}
}
