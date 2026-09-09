package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/config"
)

func serve(t *testing.T, h *Hub) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.Header.Get("X-User"))
		h.HandleUpgrade(w, r, id)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server, userID int, origin string) *websocket.Conn {
	t.Helper()
	hdr := http.Header{"X-User": {strconv.Itoa(userID)}}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), hdr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

func read(t *testing.T, ws *websocket.Conn) map[string]any {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(msg, &out)
	return out
}

func send(t *testing.T, ws *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := ws.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 100 && !cond(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met")
	}
}

func TestHub_SubscribeBroadcastUnsubscribeAndSendToUser(t *testing.T) {
	h := &Hub{CanSubscribe: func(context.Context, int, string) (bool, error) { return true, nil }}
	srv := serve(t, h)
	ws := dial(t, srv, 7, "")

	send(t, ws, frame{Op: "subscribe", Channel: "room:1"})
	if ack := read(t, ws); ack["op"] != "subscribed" || ack["channel"] != "room:1" {
		t.Fatalf("ack=%v", ack)
	}
	h.Broadcast("room:1", []byte(`{"status":"done"}`))
	if got := read(t, ws); got["channel"] != "room:1" || got["data"].(map[string]any)["status"] != "done" {
		t.Fatalf("broadcast=%v", got)
	}
	if err := h.SendToUser(7, []byte(`{"direct":true}`)); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ws); got["direct"] != true {
		t.Fatalf("direct=%v", got)
	}
	send(t, ws, frame{Op: "unsubscribe", Channel: "room:1"})
	if ack := read(t, ws); ack["op"] != "unsubscribed" {
		t.Fatalf("ack=%v", ack)
	}
	h.Broadcast("room:1", []byte(`{}`))
	_ = ws.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("received after unsubscribe")
	}
	if err := h.SendToUser(99, nil); err == nil {
		t.Fatal("unknown user must error locally")
	}
}

func TestHub_CanSubscribeAndOnMessage(t *testing.T) {
	var mu sync.Mutex
	var inbound []string
	h := &Hub{
		CanSubscribe: func(_ context.Context, userID int, channel string) (bool, error) {
			return channel == "mine:"+strconv.Itoa(userID), nil
		},
		OnMessage: func(_ context.Context, userID int, msg []byte) error {
			mu.Lock()
			inbound = append(inbound, strconv.Itoa(userID)+":"+string(msg))
			mu.Unlock()
			return nil
		},
	}
	ws := dial(t, serve(t, h), 7, "")
	send(t, ws, frame{Op: "subscribe", Channel: "mine:8"})
	if got := read(t, ws); got["op"] != "error" || got["reason"] != "forbidden" {
		t.Fatalf("got=%v", got)
	}
	send(t, ws, frame{Op: "subscribe", Channel: "mine:7"})
	if got := read(t, ws); got["op"] != "subscribed" {
		t.Fatalf("got=%v", got)
	}
	send(t, ws, map[string]any{"type": "location", "lat": 1})
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(inbound) == 1 })
	if !strings.HasPrefix(inbound[0], "7:{") {
		t.Fatalf("inbound=%v", inbound)
	}
}

func TestHub_RelayAcrossHubs(t *testing.T) {
	c := cache.NewMemoryCacheService()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allow := func(context.Context, int, string) (bool, error) { return true, nil }
	a, b := &Hub{Cache: c, CanSubscribe: allow}, &Hub{Cache: c, CanSubscribe: allow}
	for _, h := range []*Hub{a, b} {
		if err := h.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ws := dial(t, serve(t, b), 7, "")
	send(t, ws, frame{Op: "subscribe", Channel: "room:1"})
	read(t, ws)

	a.Broadcast("room:1", []byte(`{"from":"a"}`))
	if got := read(t, ws); got["data"].(map[string]any)["from"] != "a" {
		t.Fatalf("got=%v", got)
	}
	if err := PublishUser(ctx, c, 7, []byte(`{"from":"worker"}`)); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ws); got["from"] != "worker" {
		t.Fatalf("got=%v", got)
	}
	if err := (&Hub{}).Run(ctx); err == nil {
		t.Fatal("Run without Cache must error")
	}
}

func TestHub_OriginCheck(t *testing.T) {
	saved := config.Config().CORSOrigin
	config.Config().CORSOrigin = "https://app.example"
	t.Cleanup(func() { config.Config().CORSOrigin = saved })
	srv := serve(t, &Hub{CanSubscribe: func(context.Context, int, string) (bool, error) { return true, nil }})
	dial(t, srv, 1, "https://app.example")
	dial(t, srv, 1, "")
	_, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), http.Header{"Origin": {"https://evil.example"}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("err=%v resp=%v", err, resp)
	}
}
