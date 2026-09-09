package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

type wsUsers struct{ user.UserService }

func (wsUsers) ParseJWT(token string) (*model.UserSession, error) {
	if token != "ok" {
		return nil, errors.New("bad token")
	}
	return &model.UserSession{Id: 7}, nil
}

type recordingHub struct{ upgraded []int }

func (r *recordingHub) HandleUpgrade(w http.ResponseWriter, _ *http.Request, userID int) {
	r.upgraded = append(r.upgraded, userID)
	w.WriteHeader(http.StatusSwitchingProtocols)
}
func (*recordingHub) Broadcast(string, []byte)     {}
func (*recordingHub) SendToUser(int, []byte) error { return nil }

var _ port.WebSocketHub = (*recordingHub)(nil)

func TestWebSocketHandler_AuthFromHeaderOrQuery(t *testing.T) {
	hub := &recordingHub{}
	h := &WebSocketHandler{AbstractHandler: AbstractHandler{UserService: wsUsers{}}, Hub: hub}
	for _, tc := range []struct {
		name   string
		header string
		url    string
		status int
	}{
		{"query token", "", "/public/ws?token=ok", http.StatusSwitchingProtocols},
		{"bearer", "Bearer ok", "/public/ws", http.StatusSwitchingProtocols},
		{"bad token", "", "/public/ws?token=nope", http.StatusUnauthorized},
		{"missing", "", "/public/ws", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		h.Connect(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s: status=%d want=%d", tc.name, rec.Code, tc.status)
		}
	}
	if len(hub.upgraded) != 2 || hub.upgraded[0] != 7 {
		t.Fatalf("upgraded=%v", hub.upgraded)
	}
	rec := httptest.NewRecorder()
	(&WebSocketHandler{AbstractHandler: AbstractHandler{UserService: wsUsers{}}}).Connect(rec, httptest.NewRequest(http.MethodGet, "/public/ws?token=ok", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no hub status=%d", rec.Code)
	}
}
