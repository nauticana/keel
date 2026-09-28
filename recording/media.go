package recording

import "github.com/nauticana/keel/common"

const (
	MediaPending = "P"
	MediaReady   = "U"
	MediaFailed  = "X"
	MediaPurged  = "R"
)

type Media struct {
	ID          int64
	SessionID   int64
	Bucket      string
	ObjectKey   string
	ContentType string
	SizeBytes   int64
	Status      string
}

func mediaFromRow(row []any) *Media {
	return &Media{ID: common.AsInt64(row[0]), SessionID: common.AsInt64(row[1]), Bucket: common.AsString(row[2]), ObjectKey: common.AsString(row[3]), ContentType: common.AsString(row[4]), SizeBytes: common.AsInt64(row[5]), Status: common.AsString(row[6])}
}
