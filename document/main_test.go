package document

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
	"github.com/nauticana/keel/storage"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

type catalog struct{ defs []dms.RepositoryDefinition }

func (c *catalog) Repositories(context.Context) ([]dms.RepositoryDefinition, error) {
	return c.defs, nil
}

// memStore is an in-memory stand-in for the document tables, driven by query name.
type memStore struct {
	types      map[string][]any // contrep_id, max_bytes, media_types, requires_review
	owners     map[string]any   // contrep_id → partner_id or nil
	rows       map[int64][]any  // partner_document in selectFields order
	nextID     int64
	inserted   []int64 // rows written in the open transaction
	groupLocks int
}

func (m *memStore) GenID() int64                 { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error { m.inserted = nil; return nil }
func (m *memStore) Rollback(context.Context) error {
	for _, id := range m.inserted {
		delete(m.rows, id)
	}
	m.inserted = nil
	return nil
}

func same(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a == b
}

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case qGetType:
		if row, ok := m.types[args[0].(string)]; ok {
			out.Rows = [][]any{row}
		}
	case qRepositoryOwner:
		if owner, ok := m.owners[args[0].(string)]; ok {
			out.Rows = [][]any{{owner}}
		}
	case qNextVersion:
		var max int64
		for _, r := range m.rows {
			if r[3] == args[0] && r[4] == args[1] && same(r[5], args[2]) && r[8].(int64) > max {
				max = r[8].(int64)
			}
		}
		out.Rows = [][]any{{max + 1}}
	case qInsert:
		m.rows[args[0].(int64)] = []any{args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], int64(args[8].(int)),
			args[9], args[10], args[11], args[12], time.Now(), args[13], nil, nil, nil, nil, nil, nil}
		m.inserted = append(m.inserted, args[0].(int64))
	case qSupersede:
		for _, r := range m.rows {
			if r[3] == args[0] && r[4] == args[1] && same(r[5], args[2]) && r[14] == StatusApproved && r[0] != args[3] {
				r[14], r[18] = StatusSuperseded, time.Now()
			}
		}
	case qLockGroup:
		m.groupLocks++
	case qGet, qLock:
		if r, ok := m.rows[args[1].(int64)]; ok && r[3] == args[0] {
			out.Rows = [][]any{r}
		}
	case qListByPartner:
		for _, r := range m.rows {
			if r[3] == args[0] && r[14] != StatusRetired {
				out.Rows = append(out.Rows, r)
			}
		}
	case qByVersion:
		for _, r := range m.rows {
			if r[3] == args[0] && same(r[5], args[1]) && r[4] == args[2] && r[8] == int64(args[3].(int)) {
				out.Rows = [][]any{r}
			}
		}
	case qLatest:
		latest := map[any][]any{}
		for _, r := range m.rows {
			if r[3] == args[0] && same(r[5], args[1]) && r[14] != StatusRetired {
				if cur, ok := latest[r[4]]; !ok || r[8].(int64) > cur[8].(int64) {
					latest[r[4]] = r
				}
			}
		}
		for _, r := range latest {
			out.Rows = append(out.Rows, r)
		}
	case qReviewedBy:
		for _, r := range m.rows {
			if r[3] == args[0] && r[15] == args[1] {
				out.Rows = append(out.Rows, r)
			}
		}
	case qPending:
		for _, r := range m.rows {
			if r[3] == args[0] && r[14] == StatusPending {
				out.Rows = append(out.Rows, r)
			}
		}
	case qApproved:
		for _, r := range m.rows {
			if r[3] == args[0] && r[4] == args[1] && same(r[5], args[2]) && r[14] == StatusApproved {
				out.Rows = append(out.Rows, r)
			}
		}
	case qSetReview:
		r := m.rows[args[3].(int64)]
		r[14], r[15], r[16], r[17] = args[0], args[1], time.Now(), args[2]
	case qRetire:
		r := m.rows[args[0].(int64)]
		r[14], r[19] = StatusRetired, time.Now()
	case qRetiredBefore:
		cursorAt, cursorID := args[1].(time.Time), args[2].(int64)
		for _, r := range m.rows {
			at := r[19].(time.Time)
			if r[14] == StatusRetired && r[20] == nil && at.Before(args[0].(time.Time)) &&
				(at.After(cursorAt) || (at.Equal(cursorAt) && r[0].(int64) > cursorID)) {
				out.Rows = append(out.Rows, []any{r[0], r[1], r[2], at})
			}
		}
	case qSetPurged:
		m.rows[args[0].(int64)][20] = time.Now()
	default:
		return nil, errors.New("unexpected query " + name)
	}
	return out, nil
}

type memRepo struct {
	port.DatabaseRepository
	store *memStore
}

func (r memRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.store
}
func (r memRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return r.store, nil
}

func newService(t *testing.T) (*DocumentService, *memStore) {
	t.Helper()
	store := &memStore{
		types: map[string][]any{
			"licence":    {"docs", int64(64), "image/png, application/pdf", true, true},
			"logo":       {"docs", int64(64), "image/png", false, true},
			"attachment": {"docs", int64(64), "image/png", false, false},
			"cold":       {"cold", int64(64), "image/png", false, true},
			"foreign":    {"other", int64(64), "image/png", false, true},
		},
		owners: map[string]any{"docs": nil, "other": int64(99), "cold": nil},
		rows:   map[int64][]any{},
	}
	repos := &dms.ContentRepositoryService{Catalog: &catalog{defs: []dms.RepositoryDefinition{
		{ID: "docs", Storage: storage.Spec{Mode: "file", Bucket: t.TempDir()}},
		{ID: "other", Storage: storage.Spec{Mode: "file", Bucket: t.TempDir()}},
		{ID: "cold", Storage: storage.Spec{Mode: "file", Bucket: t.TempDir()}},
	}}}
	docs := &dms.ContentDocumentService{Repos: repos, MaxBytes: 1 << 20}
	return &DocumentService{DB: memRepo{store: store}, Repos: repos, Docs: docs}, store
}

var png = append([]byte("\x89PNG\r\n\x1a\n"), 1, 2, 3)

func upload(typ string, userID int64, body []byte) Upload {
	return Upload{PartnerID: 7, UserID: userID, DocumentType: typ, Title: "Front", FileName: "../front.png", UploadedBy: 3, OriginIP: "10.0.0.1", Body: bytesReader(body)}
}
