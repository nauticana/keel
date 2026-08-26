package port

import (
	"context"
	"errors"
	"time"

	"github.com/nauticana/keel/model"
)

// ErrChangeNotFound is returned for a missing id and for a row outside the
// caller's scope alike, so ids cannot be probed across partners.
var ErrChangeNotFound = errors.New("table change: not found")

// ChangeFilter narrows a FindChanges read. Zero values are unrestricted.
type ChangeFilter struct {
	TableName string
	RecordKey string
	Action    string
	CreatedBy int
	Begda     time.Time
	Endda     time.Time
}

// TableLogger is the audit store for row changes. Reads take the caller's
// scope as resolved by the table service — partnerID / ownerID with 0 meaning
// unrestricted, the same convention as TableService — and never return a row
// outside it. The logger does not resolve roles; the caller collapses
// global-role / bypass_scope into 0 before calling.
type TableLogger interface {
	Init() error
	LogChange(ctx context.Context, change *model.TableChangeLog) error
	GetChange(ctx context.Context, id int64, partnerID int64, ownerID int) (*model.TableChangeLog, error)
	FindChanges(ctx context.Context, filter ChangeFilter, partnerID int64, ownerID int) ([]*model.TableChangeLog, error)
	Close()
}
