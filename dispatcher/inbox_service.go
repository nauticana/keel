package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	InboxChannel      = "inbox"
	InboxMaxPageLimit = 100

	qInboxInsert      = "inbox_insert"
	qInboxList        = "inbox_list"
	qInboxUnreadCount = "inbox_unread_count"
	qInboxMarkRead    = "inbox_mark_read"
	qInboxMarkAllRead = "inbox_mark_all_read"
)

var ErrInboxMessageNotFound = errors.New("inbox: message not found")

var inboxQueries = map[string]string{
	qInboxInsert: `
INSERT INTO user_notification (id, user_id, notification_type, title, body, data)
VALUES (nextval('user_notification_seq'), ?, ?, ?, ?, ?)
RETURNING id`,

	qInboxList: `
SELECT id, notification_type, title, body, data, read_at, created_at
  FROM user_notification
 WHERE user_id = ? AND (? = 0 OR id < ?)
 ORDER BY id DESC
 LIMIT ?`,

	qInboxUnreadCount: `
SELECT COUNT(*) FROM user_notification WHERE user_id = ? AND read_at IS NULL`,

	qInboxMarkRead: `
UPDATE user_notification
   SET read_at = COALESCE(read_at, CURRENT_TIMESTAMP)
 WHERE id = ? AND user_id = ?
RETURNING id`,

	qInboxMarkAllRead: `
UPDATE user_notification
   SET read_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND read_at IS NULL`,
}

// InboxService persists the in-app inbox. Registered under InboxChannel it is
// also a notification channel; LocalNotificationService stores req.Type with it.
type InboxService struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

var (
	_ port.NotificationInbox = (*InboxService)(nil)
	_ port.MessageDispatcher = (*InboxService)(nil)
)

func (s *InboxService) queries(ctx context.Context) (port.QueryService, error) {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, inboxQueries) })
	if s.qs == nil {
		return nil, fmt.Errorf("inbox: query service not available")
	}
	return s.qs, nil
}

func (s *InboxService) Add(ctx context.Context, userID int, notificationType, title, body string, data map[string]string) (int64, error) {
	if userID <= 0 || title == "" {
		return 0, fmt.Errorf("inbox: userID and title required")
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return 0, err
	}
	var dataJSON any
	if len(data) > 0 {
		b, err := json.Marshal(data)
		if err != nil {
			return 0, fmt.Errorf("inbox: marshal data: %w", err)
		}
		dataJSON = string(b)
	}
	res, err := qs.Query(ctx, qInboxInsert, userID, common.NullIfEmpty(notificationType), title, body, dataJSON)
	if err != nil {
		return 0, fmt.Errorf("inbox: insert: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, fmt.Errorf("inbox: insert returned no id")
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

func (s *InboxService) List(ctx context.Context, userID int, beforeID int64, limit int) (*port.InboxPage, error) {
	qs, err := s.queries(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > InboxMaxPageLimit {
		limit = InboxMaxPageLimit
	}
	res, err := qs.Query(ctx, qInboxList, userID, beforeID, beforeID, limit)
	if err != nil {
		return nil, fmt.Errorf("inbox: list: %w", err)
	}
	page := &port.InboxPage{Messages: make([]port.InboxMessage, 0, len(res.Rows))}
	for _, row := range res.Rows {
		msg := port.InboxMessage{
			ID:    common.AsInt64(row[0]),
			Type:  common.AsString(row[1]),
			Title: common.AsString(row[2]),
			Body:  common.AsString(row[3]),
			Data:  map[string]string{},
		}
		if raw := common.AsString(row[4]); raw != "" {
			if err := json.Unmarshal([]byte(raw), &msg.Data); err != nil {
				return nil, fmt.Errorf("inbox: message %d data: %w", msg.ID, err)
			}
		}
		if readAt, ok := row[5].(time.Time); ok {
			msg.ReadAt = &readAt
		}
		msg.CreatedAt, _ = row[6].(time.Time)
		page.Messages = append(page.Messages, msg)
	}
	unread, err := qs.Query(ctx, qInboxUnreadCount, userID)
	if err != nil {
		return nil, fmt.Errorf("inbox: unread count: %w", err)
	}
	if len(unread.Rows) > 0 {
		page.UnreadCount = common.AsInt64(unread.Rows[0][0])
	}
	return page, nil
}

func (s *InboxService) MarkRead(ctx context.Context, userID int, id int64) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	res, err := qs.Query(ctx, qInboxMarkRead, id, userID)
	if err != nil {
		return fmt.Errorf("inbox: mark read: %w", err)
	}
	if len(res.Rows) == 0 {
		return ErrInboxMessageNotFound
	}
	return nil
}

func (s *InboxService) MarkAllRead(ctx context.Context, userID int) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	if _, err := qs.Query(ctx, qInboxMarkAllRead, userID); err != nil {
		return fmt.Errorf("inbox: mark all read: %w", err)
	}
	return nil
}

func (s *InboxService) Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error {
	_, err := s.Add(ctx, userID, "", title, body, data)
	return err
}

// Send fails: an inbox is addressed by user id only.
func (s *InboxService) Send(context.Context, string, string, string, map[string]string) error {
	return fmt.Errorf("inbox: no address delivery; set NotificationRequest.UserID")
}
