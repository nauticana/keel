package connect

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/port"
)

type fakeTx struct {
	*fakeQS
	committed, rolledBack bool
}

func (t *fakeTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *fakeTx) Rollback(context.Context) error { t.rolledBack = true; return nil }

type txDB struct {
	port.DatabaseRepository
	tx *fakeTx
}

func (d txDB) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return d.tx, nil
}

func newAnnouncingStore(t *testing.T, rows map[string]*model.QueryResult) (*CredentialStoreDB, *fakeTx) {
	t.Helper()
	s, _ := newTestStore(t)
	tx := &fakeTx{fakeQS: &fakeQS{next: rows}}
	s.DB, s.AnnounceChanges = txDB{tx: tx}, true
	return s, tx
}

func TestDisconnectAnnouncesInSameTransaction(t *testing.T) {
	s, tx := newAnnouncingStore(t, map[string]*model.QueryResult{qDeleteConnection: {Rows: [][]any{{int64(5)}}}})
	if err := s.DisconnectConnection(client.WithEntity(context.Background(), 9), 7, "gads"); err != nil {
		t.Fatal(err)
	}
	ev, ok := tx.last("keel_outbox_insert")
	if !ok || !tx.committed {
		t.Fatalf("event enqueued=%v committed=%v", ok, tx.committed)
	}
	var change ConnectionChange
	if err := json.Unmarshal([]byte(ev.args[5].(string)), &change); err != nil {
		t.Fatal(err)
	}
	if ev.args[1] != int64(7) || ev.args[3] != "5" || ev.args[4] != ConnectionChangedEvent ||
		change != (ConnectionChange{PartnerID: 7, EntityID: 9, Provider: "gads"}) {
		t.Fatalf("event args=%v change=%+v", ev.args, change)
	}
}

func TestUpsertAnnouncesConnected(t *testing.T) {
	s, tx := newAnnouncingStore(t, map[string]*model.QueryResult{qUpsertConnection: {Rows: [][]any{{int64(5)}}}})
	if err := s.UpsertConnection(context.Background(), 7, client.Connection{Provider: "meta", ConnType: "O", CredRef: "tok"}); err != nil {
		t.Fatal(err)
	}
	ev, _ := tx.last("keel_outbox_insert")
	var change ConnectionChange
	if err := json.Unmarshal([]byte(ev.args[5].(string)), &change); err != nil || !change.Connected {
		t.Fatalf("change=%+v err=%v", change, err)
	}
}

func TestNoAnnouncementWhenNothingChanged(t *testing.T) {
	s, tx := newAnnouncingStore(t, map[string]*model.QueryResult{qUpdateStatus: {Rows: [][]any{{int64(5), false}}}})
	if err := s.UpdateConnectionStatus(context.Background(), 7, "meta", "O", "E"); err != nil {
		t.Fatal(err)
	}
	if tx.count("keel_outbox_insert") != 0 || !tx.committed || tx.rolledBack {
		t.Fatalf("calls=%v committed=%v rolledBack=%v", tx.calls, tx.committed, tx.rolledBack)
	}
}

func TestAnnouncementFailureRollsBack(t *testing.T) {
	s, tx := newAnnouncingStore(t, map[string]*model.QueryResult{qDeleteConnection: {Rows: [][]any{{int64(5)}}}})
	boom := errors.New("outbox down")
	tx.hook = func(name string) {
		if name == "keel_outbox_insert" {
			tx.err = boom
		}
	}
	if err := s.DisconnectConnection(context.Background(), 7, "gads"); !errors.Is(err, boom) {
		t.Fatalf("err=%v, want %v", err, boom)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}
}

func TestStatusTransitionAnnounces(t *testing.T) {
	s, tx := newAnnouncingStore(t, map[string]*model.QueryResult{qUpdateStatus: {Rows: [][]any{{int64(5), true}}}})
	if err := s.UpdateConnectionStatus(context.Background(), 7, "meta", "O", "E"); err != nil {
		t.Fatal(err)
	}
	ev, ok := tx.last("keel_outbox_insert")
	if !ok || !tx.committed {
		t.Fatalf("event enqueued=%v committed=%v", ok, tx.committed)
	}
	var change ConnectionChange
	if err := json.Unmarshal([]byte(ev.args[5].(string)), &change); err != nil || change.Connected {
		t.Fatalf("change=%+v err=%v", change, err)
	}
}
