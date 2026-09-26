package dms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/storage"
)

type catalog struct{ defs []RepositoryDefinition }

func (c *catalog) Repositories(context.Context) ([]RepositoryDefinition, error) { return c.defs, nil }

type recorder struct {
	stored, deleted []string
	fail            bool
}

func (r *recorder) Stored(_ context.Context, _, docKey, compID string) error {
	r.stored = append(r.stored, docKey+"/"+compID)
	if r.fail {
		return errors.New("index down")
	}
	return nil
}

func (r *recorder) Deleted(_ context.Context, _, docKey, compID string) error {
	r.deleted = append(r.deleted, docKey+"/"+compID)
	return nil
}

func fileDef(id, root string) RepositoryDefinition {
	return RepositoryDefinition{ID: id, Storage: storage.Spec{Mode: "file", Bucket: root}}
}

func newService(t *testing.T) (*ContentDocumentService, *catalog, *recorder) {
	t.Helper()
	cat := &catalog{defs: []RepositoryDefinition{fileDef("K1", t.TempDir())}}
	obs := &recorder{}
	repos := &ContentRepositoryService{Catalog: cat, Reserved: []string{"ClientKeys"}}
	return &ContentDocumentService{Repos: repos, Observer: obs, MaxBytes: 1 << 20}, cat, obs
}

func comp(id, body string) ComponentInput {
	return ComponentInput{ID: id, ContentType: "text/plain", Charset: "utf-8", AppVersion: "1", Body: strings.NewReader(body)}
}

func mustCreate(t *testing.T, s *ContentDocumentService, docKey string, comps ...ComponentInput) {
	t.Helper()
	if err := s.Create(context.Background(), "K1", docKey, "", comps); err != nil {
		t.Fatal(err)
	}
}

// legacy writes a component object without a header, as archives written
// before header objects existed look.
func legacy(t *testing.T, s *ContentDocumentService, docKey, id, dateC string) {
	t.Helper()
	repo, err := s.Repos.Get(context.Background(), "K1")
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{AttrDocID: docKey, AttrCompID: id, AttrContentType: "application/pdf", AttrContentLength: "1",
		AttrDateC: dateC, AttrTimeC: "10:00:00", AttrDateM: dateC, AttrTimeM: "10:00:00"}
	if err := repo.Storage.PutObject(context.Background(), repo.Key(docKey, id), strings.NewReader("x"), "", attrs); err != nil {
		t.Fatal(err)
	}
}

func fixedClock(s *ContentDocumentService, at string) {
	ts, _ := time.Parse(DateFormat+" "+TimeFormat, at)
	s.Now = func() time.Time { return ts }
}
