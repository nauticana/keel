package rest

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// 'S' (secret) columns are stripped from read results; non-secret columns stay.
func TestMaskSecretColumns_StripsSecretsKeepsRest(t *testing.T) {
	table := &model.TableDefinition{Columns: []*model.TableColumn{
		{ColumnName: "id", PascalName: "Id"},
		{ColumnName: "passtext", PascalName: "Passtext", DisplayMode: model.DisplaySecret},
		{ColumnName: "user_email", PascalName: "UserEmail"},
	}}
	records := []any{
		map[string]any{"Id": int64(1), "Passtext": "$2a$12$hash", "UserEmail": "a@b.com"},
	}
	maskSecretColumns(records, table)

	m := records[0].(map[string]any)
	if _, present := m["Passtext"]; present {
		t.Fatal("secret column Passtext should be stripped from read results")
	}
	if m["UserEmail"] != "a@b.com" || m["Id"] != int64(1) {
		t.Fatal("non-secret columns must be preserved")
	}
}

func relNode(seq, parentSeq int, pascal string) *childNode {
	return &childNode{seq: seq, parentSeq: parentSeq, pascal: pascal,
		rel: RelationAPI{ChildServices: map[string]RelationAPI{}}}
}

// Existing single-level configs (every parent_seq = 0, the column default) must
// stay direct children of the master — the backward-compatible contract.
func TestLinkChildRelations_FlatSingleLevel(t *testing.T) {
	root := map[string]RelationAPI{}
	linkChildRelations(root, []*childNode{relNode(1, 0, "A"), relNode(2, 0, "B"), relNode(3, 0, "C")})
	if len(root) != 3 {
		t.Fatalf("expected 3 direct children, got %d", len(root))
	}
	for _, k := range []string{"A", "B", "C"} {
		if _, ok := root[k]; !ok {
			t.Fatalf("%s should be a direct child of the master", k)
		}
	}
}

// parent_seq > 0 nests under the referenced relation, recursively.
func TestLinkChildRelations_MultiLevelNesting(t *testing.T) {
	root := map[string]RelationAPI{}
	// Deliberately out of order to prove order-independence.
	linkChildRelations(root, []*childNode{
		relNode(16, 9, "Variants"),
		relNode(9, 8, "Items"),
		relNode(8, 0, "Offerings"),
	})
	if _, ok := root["Offerings"]; !ok {
		t.Fatal("Offerings should be a direct child of the master")
	}
	if _, ok := root["Items"]; ok {
		t.Fatal("Items must NOT be a direct child of the master")
	}
	items := root["Offerings"].ChildServices
	if _, ok := items["Items"]; !ok {
		t.Fatal("Items should nest under Offerings")
	}
	if _, ok := items["Items"].ChildServices["Variants"]; !ok {
		t.Fatal("Variants should nest under Items")
	}
}

// A parent_seq pointing at a missing seq degrades to the master, never errors.
func TestLinkChildRelations_UnresolvedParentFallsBackToRoot(t *testing.T) {
	root := map[string]RelationAPI{}
	linkChildRelations(root, []*childNode{relNode(9, 99, "Orphan")})
	if _, ok := root["Orphan"]; !ok {
		t.Fatal("orphan with unresolved parent_seq should fall back to the master")
	}
}

type hookTableService struct {
	port.TableService
	table    *model.TableDefinition
	inserted bool
}

func (s *hookTableService) GetTable() *model.TableDefinition { return s.table }
func (s *hookTableService) Insert(context.Context, int64, int, any) ([]int64, error) {
	s.inserted = true
	return nil, nil
}

type hookTxView struct {
	port.TxView
	table port.TableService
}

func (v *hookTxView) Table(string) port.TableService { return v.table }

type hookDatabase struct {
	port.DatabaseRepository
	view       port.TxView
	committed  bool
	rolledBack bool
}

func (d *hookDatabase) RunInTx(ctx context.Context, fn func(port.TxView) error) error {
	if err := fn(d.view); err != nil {
		d.rolledBack = true
		return err
	}
	d.committed = true
	return nil
}

func TestTransactionalWriteHookFailureRollsBackAutoCRUD(t *testing.T) {
	table := &hookTableService{table: &model.TableDefinition{TableName: "commission_rule"}}
	db := &hookDatabase{view: &hookTxView{table: table}}
	want := errors.New("schedule gap")
	called := false
	rel := &RelationAPI{
		DataService:   table,
		ChildServices: map[string]RelationAPI{},
		Database:      db,
		TransactionalWriteHook: func(_ context.Context, tx port.TxView, partnerID int64, userID int, tableName string, items []any) error {
			called = true
			if tx != db.view || partnerID != 7 || userID != 9 || tableName != "commission_rule" || len(items) != 1 {
				t.Fatalf("unexpected hook context: partner=%d user=%d table=%q items=%d", partnerID, userID, tableName, len(items))
			}
			return want
		},
	}

	err := rel.Post(context.Background(), 7, 9, map[string]any{"op_code": "I"})
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want schedule gap", err)
	}
	if !called || !table.inserted || !db.rolledBack || db.committed {
		t.Fatalf("called=%v inserted=%v rolledBack=%v committed=%v", called, table.inserted, db.rolledBack, db.committed)
	}
}
