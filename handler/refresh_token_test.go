package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type refreshUsers struct {
	user.UserService
	minted  int
	revoked []string
}

func (u *refreshUsers) CreateJWT(s *model.UserSession) (string, error) { return "jwt-" + s.Email, nil }
func (u *refreshUsers) CreateRefreshToken(int) (string, error) {
	u.minted++
	return "refresh-new", nil
}
func (u *refreshUsers) ValidateRefreshToken(token string) (*model.UserSession, error) {
	if token != "refresh-old" {
		if token == "refresh-db-error" {
			return nil, errors.New("database unavailable")
		}
		return nil, user.ErrInvalidRefreshToken
	}
	return &model.UserSession{Id: 7, PartnerId: 3, Email: "a@b", NewRefreshToken: "refresh-rotated"}, nil
}
func (u *refreshUsers) RevokeRefreshToken(token string) error {
	u.revoked = append(u.revoked, token)
	return nil
}

var _ user.UserService = (*refreshUsers)(nil)

func TestSessionTokens_MintsPair(t *testing.T) {
	users := &refreshUsers{}
	h := &AbstractHandler{UserService: users}
	resp, err := h.SessionTokens(&model.UserSession{Id: 7, PartnerId: 3, Email: "a@b"})
	if err != nil || resp["token"] != "jwt-a@b" || resp["refreshToken"] != "refresh-new" || resp["userId"] != 7 || users.minted != 1 {
		t.Fatalf("resp=%v err=%v minted=%d", resp, err, users.minted)
	}
}

func TestRefreshToken_RotatesAndRejectsReuse(t *testing.T) {
	users := &refreshUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"refreshToken":"refresh-old"}`, 200},
		{`{"refreshToken":"refresh-reused"}`, 401},
		{`{"refreshToken":"refresh-db-error"}`, 500},
		{`{}`, 400},
	} {
		rec := httptest.NewRecorder()
		h.RefreshToken(rec, httptest.NewRequest(http.MethodPost, "/public/token/refresh", strings.NewReader(tc.body)))
		if rec.Code != tc.status {
			t.Fatalf("body=%s status=%d want=%d resp=%s", tc.body, rec.Code, tc.status, rec.Body.String())
		}
		if tc.status != 200 {
			continue
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Data["token"] != "jwt-a@b" || out.Data["refreshToken"] != "refresh-rotated" || out.Data["partnerId"] != float64(3) {
			t.Fatalf("data=%v", out.Data)
		}
	}
	if rec := httptest.NewRecorder(); true {
		h.RefreshToken(rec, httptest.NewRequest(http.MethodGet, "/public/token/refresh", nil))
		if rec.Code != 405 {
			t.Fatalf("GET status=%d", rec.Code)
		}
	}
}

func TestLogout_RevokesPresentedToken(t *testing.T) {
	users := &refreshUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}}
	rec := httptest.NewRecorder()
	h.Logout(rec, httptest.NewRequest(http.MethodPost, "/public/logout", strings.NewReader(`{"refreshToken":"refresh-old"}`)))
	if rec.Code != 200 || len(users.revoked) != 1 || users.revoked[0] != "refresh-old" {
		t.Fatalf("status=%d revoked=%v", rec.Code, users.revoked)
	}
}
