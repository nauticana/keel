package approval

import (
	"time"

	"github.com/nauticana/keel/common"
)

// Request is one approval_request row; CheckerID is 0 until decided.
type Request struct {
	ID           int64
	PartnerID    int64
	ObjectType   string
	ObjectID     int64
	Status       string
	MakerID      int64
	SubmittedAt  time.Time
	CheckerID    int64
	DecidedAt    time.Time
	DecisionNote string
	ExpiresAt    time.Time // zero when the request does not expire
	Expired      bool      // pending and past ExpiresAt on the store clock
}

func requestFromRow(r []any) *Request {
	checkerID, _ := common.AsInt64OK(r[7])
	return &Request{
		ID: common.AsInt64(r[0]), PartnerID: common.AsInt64(r[1]), ObjectType: common.AsString(r[2]),
		ObjectID: common.AsInt64(r[3]), Status: common.AsString(r[4]), MakerID: common.AsInt64(r[5]),
		SubmittedAt: common.AsTime(r[6]), CheckerID: checkerID, DecidedAt: common.AsTime(r[8]),
		DecisionNote: common.AsString(r[9]), ExpiresAt: common.AsTime(r[10]),
		Expired: common.AsString(r[4]) == StatusPending && common.AsBool(r[11]),
	}
}
