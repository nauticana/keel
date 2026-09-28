package approval

import (
	"time"

	"github.com/nauticana/keel/common"
)

// Event is one approval_event audit row.
type Event struct {
	ID        int64
	RequestID int64
	EventType string
	ActorID   int64
	Note      string
	CreatedAt time.Time
}

func eventFromRow(r []any) *Event {
	return &Event{
		ID: common.AsInt64(r[0]), RequestID: common.AsInt64(r[1]), EventType: common.AsString(r[2]),
		ActorID: common.AsInt64(r[3]), Note: common.AsString(r[4]), CreatedAt: common.AsTime(r[5]),
	}
}
