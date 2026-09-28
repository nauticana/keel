package realtime

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/port"
)

// NotificationChannel is the conventional LocalNotificationService channel for UserDispatcher.
const NotificationChannel = "realtime"

// UserDispatcher delivers a notification as a live frame
// {"op":"notification","type","title","body","data"} to the recipient's
// sockets on any pod. A user with no live socket is not an error.
type UserDispatcher struct {
	Cache cache.CacheService
}

var _ port.TypedMessageDispatcher = (*UserDispatcher)(nil)

type notificationFrame struct {
	Op    string            `json:"op"`
	Type  string            `json:"type,omitempty"`
	Title string            `json:"title"`
	Body  string            `json:"body,omitempty"`
	Data  map[string]string `json:"data,omitempty"`
}

func (d *UserDispatcher) DispatchTyped(ctx context.Context, userID int, notificationType, title, body string, data map[string]string) error {
	if userID <= 0 {
		return fmt.Errorf("realtime: userID required")
	}
	payload, err := json.Marshal(notificationFrame{Op: "notification", Type: notificationType, Title: title, Body: body, Data: data})
	if err != nil {
		return fmt.Errorf("realtime: encode notification: %w", err)
	}
	return PublishUser(ctx, d.Cache, userID, payload)
}

func (d *UserDispatcher) Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error {
	return d.DispatchTyped(ctx, userID, "", title, body, data)
}

// Send fails: a socket is addressed by user id only.
func (d *UserDispatcher) Send(context.Context, string, string, string, map[string]string) error {
	return fmt.Errorf("realtime: no address delivery; set NotificationRequest.UserID")
}
