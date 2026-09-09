package realtime

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nauticana/keel/cache"
)

const (
	relayUser    = "ws:user"
	relayChannel = "ws:channel"
)

type envelope struct {
	UserID  int    `json:"userId,omitempty"`
	Channel string `json:"channel,omitempty"`
	Payload string `json:"payload"`
}

// PublishUser delivers payload to userID's sockets on whichever pod holds
// them. Usable from workers that hold no sockets.
func PublishUser(ctx context.Context, c cache.CacheService, userID int, payload []byte) error {
	return publish(ctx, c, relayUser, envelope{UserID: userID, Payload: string(payload)})
}

// PublishChannel delivers payload to every subscriber of channel, fleet-wide.
func PublishChannel(ctx context.Context, c cache.CacheService, channel string, payload []byte) error {
	return publish(ctx, c, relayChannel, envelope{Channel: channel, Payload: string(payload)})
}

func publish(ctx context.Context, c cache.CacheService, topic string, env envelope) error {
	if c == nil {
		return fmt.Errorf("realtime: no cache service for relay")
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.Publish(ctx, topic, string(b))
}

// Run relays published user and channel messages to this process's sockets
// until ctx ends. Call it once per hub when Cache is set.
func (h *Hub) Run(ctx context.Context) error {
	if h.Cache == nil {
		return fmt.Errorf("realtime: Run needs Cache")
	}
	users, err := h.Cache.Subscribe(ctx, relayUser)
	if err != nil {
		return err
	}
	channels, err := h.Cache.Subscribe(ctx, relayChannel)
	if err != nil {
		return err
	}
	go h.relay(users, func(e envelope) { _ = h.deliverUser(e.UserID, []byte(e.Payload)) })
	go h.relay(channels, func(e envelope) {
		if err := h.deliverChannel(e.Channel, []byte(e.Payload)); err != nil {
			h.logError("relay channel %s: %v", e.Channel, err)
		}
	})
	return nil
}

func (h *Hub) relay(in <-chan string, deliver func(envelope)) {
	for msg := range in {
		var e envelope
		if err := json.Unmarshal([]byte(msg), &e); err != nil {
			h.logError("relay decode: %v", err)
			continue
		}
		deliver(e)
	}
}
