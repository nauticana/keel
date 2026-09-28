package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

// Queue enqueues a notification as one pending row per resolved channel. A
// channel is resolved when it is forced for the type, or the user enabled it,
// or it is one of the type's Channels and the user has not disabled it.
type Queue struct {
	DB port.DatabaseRepository
	// Channels lists the channels a type is delivered on unless the user opts out.
	Channels func(notificationType string) []string
	// ForcedChannels lists the channels a type is always delivered on, whatever the preferences.
	ForcedChannels func(notificationType string) []string
	// Addressable drops channels userID cannot be reached on, forced or not; nil keeps every channel.
	Addressable func(ctx context.Context, userID int, channel string) (bool, error)

	once sync.Once
	qs   port.QueryService
}

func (q *Queue) query(ctx context.Context) port.QueryService {
	q.once.Do(func() { q.qs = q.DB.GetQueryService(ctx, queries) })
	return q.qs
}

// Enqueue queues msg for userID in its own transaction and returns the ids of
// the created rows; none when every channel is opted out.
func (q *Queue) Enqueue(ctx context.Context, userID int, notificationType string, msg Message) ([]int64, error) {
	tx, err := q.DB.BeginTx(ctx, WriteQueries())
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	ids, err := q.EnqueueTx(ctx, tx, userID, notificationType, msg)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return ids, nil
}

// EnqueueTx queues msg inside the caller's transaction, which must have merged
// WriteQueries(), so the notification commits atomically with a domain write.
func (q *Queue) EnqueueTx(ctx context.Context, tx port.TxQueryService, userID int, notificationType string, msg Message) ([]int64, error) {
	if userID <= 0 || notificationType == "" || msg.Title == "" {
		return nil, ErrInvalidMessage
	}
	channels, err := q.resolveChannels(ctx, tx, userID, notificationType)
	if err != nil {
		return nil, err
	}
	var dataJSON any
	if len(msg.Data) > 0 {
		b, err := json.Marshal(msg.Data)
		if err != nil {
			return nil, fmt.Errorf("notify: marshal data: %w", err)
		}
		dataJSON = string(b)
	}
	var partnerID any
	if msg.PartnerID > 0 {
		partnerID = msg.PartnerID
	}
	ids := make([]int64, 0, len(channels))
	for _, channel := range channels {
		id := tx.GenID()
		if _, err := tx.Query(ctx, qInsert, id, userID, partnerID, notificationType, channel, msg.Title, common.NullIfEmpty(msg.Body), dataJSON); err != nil {
			return nil, fmt.Errorf("notify: insert %s notification: %w", channel, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (q *Queue) resolveChannels(ctx context.Context, qs port.QueryService, userID int, notificationType string) ([]string, error) {
	res, err := qs.Query(ctx, qTypePreferences, userID, notificationType)
	if err != nil {
		return nil, fmt.Errorf("notify: read preferences: %w", err)
	}
	preferred := make(map[string]bool, len(res.Rows))
	var resolved []string
	add := func(channel string) {
		if channel != "" && !slices.Contains(resolved, channel) {
			resolved = append(resolved, channel)
		}
	}
	for _, row := range res.Rows {
		channel, enabled := common.AsString(row[0]), common.AsBool(row[1])
		preferred[channel] = enabled
		if enabled {
			add(channel)
		}
	}
	if q.Channels != nil {
		for _, channel := range q.Channels(notificationType) {
			if enabled, set := preferred[channel]; !set || enabled {
				add(channel)
			}
		}
	}
	if q.ForcedChannels != nil {
		for _, channel := range q.ForcedChannels(notificationType) {
			add(channel)
		}
	}
	if q.Addressable == nil {
		return resolved, nil
	}
	reachable := resolved[:0]
	for _, channel := range resolved {
		ok, err := q.Addressable(ctx, userID, channel)
		if err != nil {
			return nil, fmt.Errorf("notify: %s address for user %d: %w", channel, userID, err)
		}
		if ok {
			reachable = append(reachable, channel)
		}
	}
	return reachable, nil
}

// SetPreference records whether userID wants notificationType on channel. A
// forced channel is still delivered when disabled.
func (q *Queue) SetPreference(ctx context.Context, userID int, notificationType, channel string, enabled bool) error {
	if userID <= 0 || notificationType == "" || channel == "" {
		return ErrInvalidChannel
	}
	if _, err := q.query(ctx).Query(ctx, qSetPreference, userID, notificationType, channel, enabled); err != nil {
		return fmt.Errorf("notify: set preference: %w", err)
	}
	return nil
}

// Preferences returns every explicit preference userID has recorded.
func (q *Queue) Preferences(ctx context.Context, userID int) ([]Preference, error) {
	res, err := q.query(ctx).Query(ctx, qUserPreferences, userID)
	if err != nil {
		return nil, fmt.Errorf("notify: list preferences: %w", err)
	}
	out := make([]Preference, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, Preference{
			NotificationType: common.AsString(row[0]),
			Channel:          common.AsString(row[1]),
			Enabled:          common.AsBool(row[2]),
		})
	}
	return out, nil
}
