package model

import "time"

type TableChangeLog struct {
	ID        int64
	TableName string
	RecordKey string
	Action    string
	DataHash  string
	OldData   map[string]any
	CreatedAt time.Time
	CreatedBy int
}
