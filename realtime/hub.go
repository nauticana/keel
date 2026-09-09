// Package realtime is a WebSocket hub with channel subscriptions and a
// cache-backed relay so any process or pod can deliver to a connected user.
package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 30 * time.Second
	maxFrame   = 64 << 10
)

// Control frame. {"op":"subscribe"|"unsubscribe","channel":"…"} from the
// client; the hub answers subscribed / unsubscribed / error. Any other
// frame reaches OnMessage unchanged.
type frame struct {
	Op      string `json:"op"`
	Channel string `json:"channel,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type conn struct {
	ws     *websocket.Conn
	userID int
	wmu    sync.Mutex
}

func (c *conn) write(msg []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return err
	}
	return c.ws.WriteMessage(websocket.TextMessage, msg)
}

func (c *conn) writeFrame(f frame) {
	b, err := json.Marshal(f)
	if err != nil || c.write(b) != nil {
		_ = c.ws.Close()
	}
}

// Hub holds this process's live sockets. With Cache set, SendToUser and
// Broadcast publish through the relay (see Run) so every pod delivers to
// its own sockets; without it they deliver locally only.
type Hub struct {
	Cache   cache.CacheService
	Journal logger.ApplicationLogger
	// CanSubscribe gates channel subscriptions; nil denies them.
	CanSubscribe func(ctx context.Context, userID int, channel string) (bool, error)
	// OnMessage receives every non-control frame a client sends.
	OnMessage func(ctx context.Context, userID int, message []byte) error
	// CheckOrigin defaults to the cors_origin allowlist; a missing Origin
	// (native apps) is always accepted.
	CheckOrigin func(r *http.Request) bool

	mu       sync.RWMutex
	users    map[int]map[*conn]struct{}
	channels map[string]map[*conn]struct{}
}

func (h *Hub) HandleUpgrade(w http.ResponseWriter, r *http.Request, userID int) {
	check := h.CheckOrigin
	if check == nil {
		check = originAllowed
	}
	ws, err := (&websocket.Upgrader{CheckOrigin: check}).Upgrade(w, r, nil)
	if err != nil {
		h.logError("upgrade: %v", err)
		return
	}
	c := &conn{ws: ws, userID: userID}
	h.add(c)
	go h.serve(c)
}

func (h *Hub) serve(c *conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		h.remove(c)
		_ = c.ws.Close()
	}()
	go h.ping(ctx, c)
	c.ws.SetReadLimit(maxFrame)
	if err := c.ws.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return
	}
	c.ws.SetPongHandler(func(string) error { return c.ws.SetReadDeadline(time.Now().Add(pongWait)) })
	for {
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		h.handle(ctx, c, msg)
	}
}

func (h *Hub) ping(ctx context.Context, c *conn) {
	t := time.NewTicker(pingPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.wmu.Lock()
			err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
			c.wmu.Unlock()
			if err != nil {
				_ = c.ws.Close()
				return
			}
		}
	}
}

func (h *Hub) handle(ctx context.Context, c *conn, msg []byte) {
	var f frame
	if json.Unmarshal(msg, &f) == nil && (f.Op == "subscribe" || f.Op == "unsubscribe") {
		if f.Channel == "" {
			c.writeFrame(frame{Op: "error", Reason: "channel required"})
			return
		}
		if f.Op == "unsubscribe" {
			h.unsubscribe(c, f.Channel)
			c.writeFrame(frame{Op: "unsubscribed", Channel: f.Channel})
			return
		}
		if h.CanSubscribe == nil {
			c.writeFrame(frame{Op: "error", Channel: f.Channel, Reason: "forbidden"})
			return
		}
		allowed, err := h.CanSubscribe(ctx, c.userID, f.Channel)
		if err != nil {
			h.logError("authorize channel %s: %v", f.Channel, err)
			c.writeFrame(frame{Op: "error", Channel: f.Channel, Reason: "unavailable"})
			return
		}
		if !allowed {
			c.writeFrame(frame{Op: "error", Channel: f.Channel, Reason: "forbidden"})
			return
		}
		h.subscribe(c, f.Channel)
		c.writeFrame(frame{Op: "subscribed", Channel: f.Channel})
		return
	}
	if h.OnMessage != nil {
		if err := h.OnMessage(ctx, c.userID, msg); err != nil {
			h.logError("inbound user %d: %v", c.userID, err)
			c.writeFrame(frame{Op: "error", Reason: "message rejected"})
		}
	}
}

// SendToUser delivers a raw payload to every socket of userID. Through the
// relay the result is fire-and-forget; locally it errors when nobody is connected.
func (h *Hub) SendToUser(userID int, message []byte) error {
	if h.Cache != nil {
		return PublishUser(context.Background(), h.Cache, userID, message)
	}
	return h.deliverUser(userID, message)
}

// Broadcast delivers {"channel":…,"data":…} to every subscriber of channel.
func (h *Hub) Broadcast(channel string, message []byte) {
	if h.Cache != nil {
		if err := PublishChannel(context.Background(), h.Cache, channel, message); err != nil {
			h.logError("publish channel %s: %v", channel, err)
		}
		return
	}
	if err := h.deliverChannel(channel, message); err != nil {
		h.logError("deliver channel %s: %v", channel, err)
	}
}

func (h *Hub) deliverUser(userID int, message []byte) error {
	h.mu.RLock()
	conns := snapshot(h.users[userID])
	h.mu.RUnlock()
	if len(conns) == 0 {
		return fmt.Errorf("user %d not connected", userID)
	}
	for _, c := range conns {
		if err := c.write(message); err != nil {
			_ = c.ws.Close()
		}
	}
	return nil
}

func (h *Hub) deliverChannel(channel string, message []byte) error {
	envelope, err := json.Marshal(map[string]any{"channel": channel, "data": json.RawMessage(message)})
	if err != nil {
		return fmt.Errorf("encode channel payload: %w", err)
	}
	h.mu.RLock()
	conns := snapshot(h.channels[channel])
	h.mu.RUnlock()
	for _, c := range conns {
		if err := c.write(envelope); err != nil {
			_ = c.ws.Close()
		}
	}
	return nil
}

func snapshot(set map[*conn]struct{}) []*conn {
	items := make([]*conn, 0, len(set))
	for c := range set {
		items = append(items, c)
	}
	return items
}

func (h *Hub) add(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.users == nil {
		h.users = map[int]map[*conn]struct{}{}
		h.channels = map[string]map[*conn]struct{}{}
	}
	if h.users[c.userID] == nil {
		h.users[c.userID] = map[*conn]struct{}{}
	}
	h.users[c.userID][c] = struct{}{}
}

func (h *Hub) remove(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.users[c.userID], c)
	if len(h.users[c.userID]) == 0 {
		delete(h.users, c.userID)
	}
	for name, subs := range h.channels {
		delete(subs, c)
		if len(subs) == 0 {
			delete(h.channels, name)
		}
	}
}

func (h *Hub) subscribe(c *conn, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.channels[channel] == nil {
		h.channels[channel] = map[*conn]struct{}{}
	}
	h.channels[channel][c] = struct{}{}
}

func (h *Hub) unsubscribe(c *conn, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.channels[channel], c)
	if len(h.channels[channel]) == 0 {
		delete(h.channels, channel)
	}
}

func (h *Hub) logError(format string, args ...any) {
	if h.Journal != nil {
		h.Journal.Error("realtime: " + fmt.Sprintf(format, args...))
	}
}

func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	allowed := strings.TrimSpace(config.Config().CORSOrigin)
	if allowed == "*" {
		return true
	}
	if allowed == "" {
		parsed, err := url.Parse(origin)
		return err == nil && strings.EqualFold(parsed.Host, r.Host)
	}
	for _, a := range strings.Split(allowed, ",") {
		if strings.TrimSpace(a) == origin {
			return true
		}
	}
	return false
}

var _ port.WebSocketHub = (*Hub)(nil)
