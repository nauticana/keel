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
	ActorID   int64 // 0 for a system event such as expiry
	Note      string
	CreatedAt time.Time
}

func eventFromRow(r []any) *Event {
	actorID, _ := common.AsInt64OK(r[3])
	return &Event{
		ID: common.AsInt64(r[0]), RequestID: common.AsInt64(r[1]), EventType: common.AsString(r[2]),
		ActorID: actorID, Note: common.AsString(r[4]), CreatedAt: common.AsTime(r[5]),
	}
}
