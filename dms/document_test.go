package dms

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/nauticana/keel/storage"
)

func TestCreateInfoReadRoundTrip(t *testing.T) {
	s, _, obs := newService(t)
	ctx := context.Background()
	fixedClock(s, "2026-01-02 03:04:05")
	if err := s.Create(ctx, "K1", "D1", "du", []ComponentInput{comp("data", "hello"), comp("descr", "")}); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Info(ctx, "K1", "D1")
	if err != nil {
		t.Fatal(err)
	}
	if doc.DocProt != "du" || doc.DateC != "2026-01-02" || doc.TimeM != "03:04:05" || len(doc.Components) != 2 {
		t.Fatalf("info: %+v", doc)
	}
	data := doc.Components[0]
	if data.ID != "data" || data.Length != 5 || data.ContentType != "text/plain" || data.Charset != "utf-8" || data.AppVersion != "1" ||
		data.Digest != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("component: %+v", data)
	}
	if doc.Components[1].Length != 0 {
		t.Errorf("an empty component must exist with length 0: %+v", doc.Components[1])
	}
	content, c, err := s.Read(ctx, "K1", "D1", "data")
	if err != nil || string(content) != "hello" || c.Digest != data.Digest {
		t.Fatalf("read: %q %+v %v", content, c, err)
	}
	r, err := s.Open(ctx, "K1", "D1", "data")
	if err != nil {
		t.Fatal(err)
	}
	streamed, _ := io.ReadAll(r)
	r.Close()
	if string(streamed) != "hello" {
		t.Errorf("open: %q", streamed)
	}
	if !slices.Equal(obs.stored, []string{"D1/data", "D1/descr"}) {
		t.Errorf("observer: %v", obs.stored)
	}
	if err := s.Create(ctx, "K1", "D1", "", nil); !errors.Is(err, ErrDocumentExists) {
		t.Errorf("second create: %v", err)
	}
}

func TestCreateWithoutComponentsAndServerSetting(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	if err := s.Create(ctx, "K1", "D1", "serversetting", nil); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Info(ctx, "K1", "D1")
	if err != nil || doc.DocProt != DocProtServerSetting || len(doc.Components) != 0 {
		t.Fatalf("empty document: %+v %v", doc, err)
	}
	if err := s.Create(ctx, "K1", "D2", "", nil); err != nil {
		t.Fatal(err)
	}
	if doc, _ := s.Info(ctx, "K1", "D2"); doc.DocProt != "" {
		t.Errorf("an explicit empty docProt is unrestricted, not the server setting: %q", doc.DocProt)
	}
	for attrs, want := range map[*map[string]string]string{
		{}: DocProtServerSetting, {AttrDocProt: docProtNone}: "", {AttrDocProt: "du"}: "du",
	} {
		if got := DocProtOf(*attrs); got != want {
			t.Errorf("DocProtOf(%v) = %q, want %q", *attrs, got, want)
		}
	}
	legacy(t, s, "L1", "data", "2020-01-01")
	if doc, _ := s.Info(ctx, "K1", "L1"); doc.DocProt != DocProtServerSetting {
		t.Errorf("a legacy document without a header uses the server setting: %q", doc.DocProt)
	}
}

func TestCreateRollsBackOnTooLarge(t *testing.T) {
	s, _, _ := newService(t)
	s.MaxBytes = 4
	ctx := context.Background()
	err := s.Create(ctx, "K1", "D1", "", []ComponentInput{comp("data", "ok"), comp("big", "toolong")})
	if !errors.Is(err, ErrComponentTooLarge) {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Info(ctx, "K1", "D1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("a failed create must leave nothing behind: %v", err)
	}
}

func TestPutComponentRequiresDocument(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	if err := s.PutComponent(ctx, "K1", "D1", comp("data", "x")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("put on a missing document: %v", err)
	}
	if _, err := s.Info(ctx, "K1", "D1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("a refused put must not create a document: %v", err)
	}
}

func TestPutComponentKeepsCreationStampAndTouchesHeader(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	fixedClock(s, "2026-01-01 00:00:00")
	mustCreate(t, s, "D1", comp("data", "v1"))
	fixedClock(s, "2026-01-02 00:00:00")
	if err := s.PutComponent(ctx, "K1", "D1", comp("data", "v2")); err != nil {
		t.Fatal(err)
	}
	doc, _ := s.Info(ctx, "K1", "D1")
	c := doc.Components[0]
	if c.DateC != "2026-01-01" || c.DateM != "2026-01-02" || c.Length != 2 {
		t.Errorf("overwritten component: %+v", c)
	}
	if doc.DateC != "2026-01-01" || doc.DateM != "2026-01-02" {
		t.Errorf("header stamps: %+v", doc)
	}
}

func TestLegacyDocumentUpgradesOnTouch(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	legacy(t, s, "L1", "data", "2020-05-05")
	legacy(t, s, "L1", "descr", "2019-01-01")

	doc, err := s.Info(ctx, "K1", "L1")
	if err != nil || doc.DateC != "2019-01-01" || len(doc.Components) != 2 {
		t.Fatalf("legacy info: %+v %v", doc, err)
	}
	if err := s.Create(ctx, "K1", "L1", "", nil); !errors.Is(err, ErrDocumentExists) {
		t.Errorf("create over a legacy document: %v", err)
	}
	if err := s.DeleteComponent(ctx, "K1", "L1", "data"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteComponent(ctx, "K1", "L1", "descr"); err != nil {
		t.Fatal(err)
	}
	doc, err = s.Info(ctx, "K1", "L1")
	if err != nil || len(doc.Components) != 0 || doc.DateC != "2019-01-01" {
		t.Fatalf("the empty document must survive with the oldest creation stamp: %+v %v", doc, err)
	}
}

func TestReplace(t *testing.T) {
	s, _, obs := newService(t)
	ctx := context.Background()
	mustCreate(t, s, "D1", comp("a", "1"), comp("b", "2"))
	obs.stored = nil
	if err := s.Replace(ctx, "K1", "D1", []ComponentInput{comp("b", "22"), comp("c", "3")}); err != nil {
		t.Fatal(err)
	}
	doc, _ := s.Info(ctx, "K1", "D1")
	var ids []string
	for _, c := range doc.Components {
		ids = append(ids, c.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"b", "c"}) {
		t.Errorf("components after replace: %v", ids)
	}
	if !slices.Equal(obs.stored, []string{"D1/b", "D1/c"}) || !slices.Equal(obs.deleted, []string{"D1/a"}) {
		t.Errorf("observer: stored %v deleted %v", obs.stored, obs.deleted)
	}
}

func TestDeleteDocument(t *testing.T) {
	s, _, obs := newService(t)
	ctx := context.Background()
	mustCreate(t, s, "D1", comp("a", "1"))
	if err := s.Delete(ctx, "K1", "D1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Info(ctx, "K1", "D1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("deleted document still readable: %v", err)
	}
	if err := s.Delete(ctx, "K1", "D1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("delete of a missing document: %v", err)
	}
	if !slices.Equal(obs.deleted, []string{"D1/"}) {
		t.Errorf("observer: %v", obs.deleted)
	}
}

func TestInvalidAndReservedKeys(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	for _, key := range []string{"a/b", "..", ".", "", HeaderComponent, "ClientKeys"} {
		if err := s.Create(ctx, "K1", key, "", nil); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("document key %q: %v", key, err)
		}
	}
	for _, id := range []string{"a/b", HeaderComponent, ""} {
		if err := s.Create(ctx, "K1", "D1", "", []ComponentInput{comp(id, "x")}); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("component id %q: %v", id, err)
		}
	}
	if err := s.Create(ctx, "K1", "D1", "", []ComponentInput{comp("a", "x"), comp("a", "y")}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("duplicate component: %v", err)
	}
}

func TestListSkipsReserved(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	mustCreate(t, s, "D1", comp("a", "1"))
	mustCreate(t, s, "D2")
	repo, _ := s.Repos.Get(ctx, "K1")
	if err := repo.Storage.PutObject(ctx, repo.Key("ClientKeys", "S01.cer"), nil, "", nil); err != nil {
		t.Fatal(err)
	}
	keys, err := s.List(ctx, "K1", 0)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"D1", "D2"}) {
		t.Errorf("list: %v", keys)
	}
	if keys, _ := s.List(ctx, "K1", 1); len(keys) != 1 || keys[0] == "ClientKeys" {
		t.Errorf("list limit: %v", keys)
	}
}

func TestReadOnlyRepository(t *testing.T) {
	s, cat, _ := newService(t)
	ctx := context.Background()
	mustCreate(t, s, "D1", comp("a", "1"))
	cat.defs[0].Status = StatusMigrating
	if err := s.Repos.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.PutComponent(ctx, "K1", "D1", comp("a", "2")); !errors.Is(err, ErrRepositoryReadOnly) {
		t.Errorf("write to a migrating repository: %v", err)
	}
	if _, err := s.Info(ctx, "K1", "D1"); err != nil {
		t.Errorf("reads must continue: %v", err)
	}
}

func TestObserverErrorIsSoft(t *testing.T) {
	s, _, obs := newService(t)
	obs.fail = true
	err := s.Create(context.Background(), "K1", "D1", "", []ComponentInput{comp("a", "1")})
	if !errors.Is(err, ErrObserver) || !Succeeded(err) {
		t.Fatalf("observer failure must be soft: %v", err)
	}
	if _, err := s.Info(context.Background(), "K1", "D1"); err != nil {
		t.Errorf("document must exist after a soft failure: %v", err)
	}
}

type contended struct{ storage.ObjectStorage }

func (contended) SetObjectAttributes(context.Context, string, map[string]string) error {
	return storage.ErrPreconditionFailed
}

func TestHeaderStaleIsSoft(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	mustCreate(t, s, "D1", comp("a", "1"))
	repo, _ := s.Repos.Get(ctx, "K1")
	repo.Storage = contended{repo.Storage}
	s.HeaderRetries = 2
	err := s.PutComponent(ctx, "K1", "D1", comp("a", "2"))
	if !errors.Is(err, ErrHeaderStale) || !Succeeded(err) {
		t.Fatalf("exhausted header retries must be soft: %v", err)
	}
	if content, _, _ := s.Read(ctx, "K1", "D1", "a"); string(content) != "2" {
		t.Errorf("component must be written: %q", content)
	}
	if Succeeded(errors.New("hard")) {
		t.Error("a hard error is not success")
	}
}
