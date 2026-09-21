package port

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type NotificationSender interface {
	SendEmail(ctx context.Context, to, subject, body string) error
	SendSMS(ctx context.Context, to, body string) error
}

type NotificationRequest struct {
	UserID int
	// PartnerID scopes the suppression check to one tenant; 0 consults only the
	// fleet-wide entries.
	PartnerID int64
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
	// DedupeKey collapses repeats: the first Send under a key is delivered and
	// every later one is ErrNotificationDuplicate until the ledger forgets it.
	// Ignored unless the service has a ledger.
	DedupeKey string
}

// NotificationService delivers a notification, or refuses it. Refusals are
// typed: ErrNotificationSuppressed (the recipient must not be contacted on this
// channel) and ErrNotificationDuplicate (a repeat under the same DedupeKey) are
// outcomes the caller can tell apart from a delivery, never a silent success.
type NotificationService interface {
	Send(ctx context.Context, req NotificationRequest) error
}

// NotificationSuppressor answers whether a contact may be delivered to on a
// channel. Honoring unsubscribes, bounces and complaints is a compliance
// obligation (CAN-SPAM, CASL, carrier rules for SMS), so the check belongs
// behind the service rather than at each call site. partnerID scopes the
// lookup; an entry recorded fleet-wide applies to every tenant.
type NotificationSuppressor interface {
	Suppressed(ctx context.Context, channel, contact string, partnerID int64) (suppressed bool, reason string, err error)
}

var (
	// ErrNotificationSuppressed: the recipient is on the suppression list.
	ErrNotificationSuppressed = errors.New("notification: recipient is suppressed")
	// ErrNotificationDuplicate: another Send already carried this DedupeKey.
	ErrNotificationDuplicate = errors.New("notification: duplicate of an already-sent notification")
)

// SuppressedError names the channel and why, never the contact.
type SuppressedError struct {
	Channel string
	Reason  string
}

func (e *SuppressedError) Error() string {
	return fmt.Sprintf("notification: %s recipient is suppressed (%s)", e.Channel, e.Reason)
}

func (e *SuppressedError) Unwrap() error { return ErrNotificationSuppressed }

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
