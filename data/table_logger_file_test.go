package data

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func newTestLogger(t *testing.T) *TableLoggerFile {
	t.Helper()
	l := &TableLoggerFile{RootPath: t.TempDir()}
	if err := l.Init(); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestTableLoggerFile_GetChangeScope(t *testing.T) {
	l := newTestLogger(t)
	ctx := context.Background()
	change := &model.TableChangeLog{
		TableName: "invoice", RecordKey: "7", Action: "U",
		OldData: map[string]any{"amount": 100}, PartnerID: 5, OwnerUserID: 42, CreatedBy: 42,
	}
	if err := l.LogChange(ctx, change); err != nil {
		t.Fatal(err)
	}
	if change.ID == 0 || change.DataHash == "" {
		t.Fatalf("LogChange did not stamp id / hash: %+v", change)
	}

	cases := []struct {
		name      string
		partnerID int64
		ownerID   int
		visible   bool
	}{
		{"unrestricted", 0, 0, true},
		{"own partner", 5, 0, true},
		{"own partner and owner", 5, 42, true},
		{"other partner", 6, 0, false},
		{"other owner", 5, 43, false},
		{"owner only, other user", 0, 1, false},
	}
	for _, c := range cases {
		got, err := l.GetChange(ctx, change.ID, c.partnerID, c.ownerID)
		switch {
		case c.visible && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.visible && got.ID != change.ID:
			t.Errorf("%s: got id %d, want %d", c.name, got.ID, change.ID)
		case !c.visible && !errors.Is(err, port.ErrChangeNotFound):
			t.Errorf("%s: want ErrChangeNotFound, got %v (row %v)", c.name, err, got)
		}
	}

	if _, err := l.GetChange(ctx, change.ID+1, 0, 0); !errors.Is(err, port.ErrChangeNotFound) {
		t.Errorf("missing id: want ErrChangeNotFound, got %v", err)
	}
	if _, err := l.FindChanges(ctx, port.ChangeFilter{TableName: "invoice"}, 5, 0); !errors.Is(err, ErrFindChangesUnsupported) {
		t.Errorf("FindChanges: want ErrFindChangesUnsupported, got %v", err)
	}
}
