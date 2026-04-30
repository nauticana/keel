package port

import (
	"github.com/nauticana/keel/model"
	"time"
)

type TableLogger interface {
	Init() error
	LogChange(change *model.TableChangeLog) error
	GetChange(id int64) (*model.TableChangeLog, error)
	FindChanges(tableName string, userId int, key string, action string, begda time.Time, endda time.Time) ([]*model.TableChangeLog, error)
	Close()
}
