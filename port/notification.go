package port

import (
	"context"
	"time"
)

type NotificationSender interface {
	SendEmail(ctx context.Context, to, subject, body string) error
	SendSMS(ctx context.Context, to, body string) error
}

type NotificationRequest struct {
	UserID int
	// To, when set, is an explicit channel address (email / phone / device token)
	// delivered via MessageDispatcher.Send, bypassing userID resolution. Leave it
	// empty to resolve the address from UserID via Dispatch. For SMS to a national
	// number, pass the ISO region in Data["country"] so it normalizes to E.164.
	To      string
	Type    string
	Channel string
	Title   string
	Body    string
	Data    map[string]string
}

type NotificationService interface {
	Send(ctx context.Context, req NotificationRequest) error
}

type InboxMessage struct {
	ID        int64             `json:"id,string"`
	Type      string            `json:"type"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Data      map[string]string `json:"data"`
	ReadAt    *time.Time        `json:"readAt"`
	CreatedAt time.Time         `json:"createdAt"`
}

type InboxPage struct {
	Messages    []InboxMessage `json:"messages"`
	UnreadCount int64          `json:"unreadCount"`
}

// NotificationInbox is the persisted, user-scoped in-app inbox.
type NotificationInbox interface {
	Add(ctx context.Context, userID int, notificationType, title, body string, data map[string]string) (int64, error)
	// List returns messages older than beforeID (0 = newest), newest first.
	List(ctx context.Context, userID int, beforeID int64, limit int) (*InboxPage, error)
	MarkRead(ctx context.Context, userID int, id int64) error
	MarkAllRead(ctx context.Context, userID int) error
}
