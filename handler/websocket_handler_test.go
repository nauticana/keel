package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/realtime"
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

func TestWebSocketHandler_Auth(t *testing.T) {
	hub := &recordingHub{}
	mem := cache.NewMemoryCacheService()
	t.Cleanup(func() { _ = mem.Close() })
	h := &WebSocketHandler{UserService: wsUsers{}, Hub: hub, Tickets: &realtime.TicketService{Cache: mem}}

	mint := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, common.WebSocketTicketRoute, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.Ticket(rec, req)
		return rec
	}
	if rec := mint("nope"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("mint without a session: %d", rec.Code)
	}
	var minted struct {
		Data struct {
			Ticket    string `json:"ticket"`
			ExpiresIn int    `json:"expiresIn"`
		} `json:"data"`
	}
	rec := mint("ok")
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil || minted.Data.ExpiresIn != 30 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mint: %v %s", err, rec.Body)
	}

	for _, tc := range []struct {
		name, header, url string
		status            int
	}{
		{"ticket", "", "/public/ws?ticket=" + minted.Data.Ticket, http.StatusSwitchingProtocols},
		{"used ticket", "", "/public/ws?ticket=" + minted.Data.Ticket, http.StatusUnauthorized},
		{"unknown ticket", "", "/public/ws?ticket=" + strings.Repeat("a", 64), http.StatusUnauthorized},
		{"bearer", "Bearer ok", "/public/ws", http.StatusSwitchingProtocols},
		{"access token in the URL", "", "/public/ws?token=ok", http.StatusUnauthorized},
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
	h.Hub, h.Tickets = nil, nil
	rec = httptest.NewRecorder()
	h.Connect(rec, httptest.NewRequest(http.MethodGet, "/public/ws", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no hub status=%d", rec.Code)
	}
	if rec := mint("ok"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no tickets status=%d", rec.Code)
	}
	if !common.IsPartnerOptional(common.WebSocketTicketRoute) {
		t.Fatal("a user without a partner must be able to mint a ticket")
	}
}
