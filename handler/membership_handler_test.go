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
	h := &MembershipHandler{UserService: users}
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

type directoryUsers struct {
	user.UserService
	partner int64
	search  string
}

func (u *directoryUsers) Members(partnerID int64, search string) ([]user.Member, error) {
	u.partner, u.search = partnerID, search
	return []user.Member{{UserID: 4, Name: "Ada Lovelace"}}, nil
}

func TestMembershipDirectoryUsesTheSessionPartner(t *testing.T) {
	users := &directoryUsers{}
	h := &MembershipHandler{UserService: users}
	call := func(session *model.UserSession) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/partner_user/directory?q=ada&partnerId=99", nil)
		if session != nil {
			stashSession(r, session)
		}
		w := httptest.NewRecorder()
		h.Directory(w, r)
		return w
	}
	w := call(&model.UserSession{Id: 3, PartnerId: 7})
	if w.Code != http.StatusOK || users.partner != 7 || users.search != "ada" || !strings.Contains(w.Body.String(), `"userId":"4"`) {
		t.Fatalf("status %d partner %d search %q body %s", w.Code, users.partner, users.search, w.Body)
	}
	if w := call(&model.UserSession{Id: 3}); w.Code != http.StatusUnauthorized {
		t.Fatalf("no partner = %d", w.Code)
	}
	if _, ok := h.Routes("/api/v1")["/api/v1/partner_user/directory"]; !ok {
		t.Fatal("directory route not mounted")
	}
}
