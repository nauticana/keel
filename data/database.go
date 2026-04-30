package data

import (
	"context"

	"github.com/nauticana/keel/model"
)

type DatabaseRepository interface {
	Connect(ctx context.Context) error
	Init(ctx context.Context) error
	GetQueryService(ctx context.Context, queries map[string]string) QueryService
	CreateTableService(ctx context.Context, table *model.TableDefinition) TableService
	GetTableService(tableName string) TableService
	GetTableDefinition(tableName string) *model.TableDefinition
	GetTableDefinitions() map[string]*model.TableDefinition
	GetForeignKey(consName string) *model.ForeignKey
	LoadColumns(ctx context.Context) (map[string][]*model.TableColumn, error)
	LoadPrimaryKeys(ctx context.Context) (map[string][]string, error)
	GetForeignKeys(ctx context.Context) (*model.QueryResult, error)
	TypeScriptTables(baseclass string, indent int) []*[]byte
	BeginTx(ctx context.Context, queries map[string]string) (TxQueryService, error)

	// RunInTx executes fn inside a database transaction. fn receives a
	// TxView that yields TableService instances bound to the in-flight
	// tx — every call through that view ends up in the same DB
	// transaction as the others. Commits when fn returns nil; rolls
	// back on any error or panic. Used by RelationAPI.Post to ship a
	// parent + children write batch atomically (P1-35).
	RunInTx(ctx context.Context, fn func(view TxView) error) error
}

// TxView yields TableService values bound to an in-flight transaction.
// Implementations are produced by DatabaseRepository.RunInTx; consumers
// do not construct them directly.
//
// All TableService objects returned by Table share the same underlying
// transaction, so writes against them commit (or roll back) together.
type TxView interface {
	// Table returns a transaction-bound TableService for the given
	// table name, or nil when no service is registered for it. The
	// returned value is only valid for the duration of the
	// surrounding RunInTx callback.
	Table(name string) TableService
}
