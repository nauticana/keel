package dms

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/storage"
)

func TestPrefixDefaultsAndOverlap(t *testing.T) {
	root := t.TempDir()
	a := fileDef("A", root)
	if a.Prefix() != "A/" {
		t.Errorf("prefix: %q", a.Prefix())
	}
	nested := fileDef("B", root)
	nested.PathPrefix = "/A/B/"
	repos := &ContentRepositoryService{Catalog: StaticCatalog{a, nested}}
	if err := repos.Reload(context.Background()); !errors.Is(err, ErrPrefixOverlap) {
		t.Errorf("nested prefix on one bucket: %v", err)
	}
	other := fileDef("B", t.TempDir())
	other.PathPrefix = "A/B"
	repos = &ContentRepositoryService{Catalog: StaticCatalog{a, other}}
	if err := repos.Reload(context.Background()); err != nil {
		t.Errorf("same prefix on another bucket is fine: %v", err)
	}
}

func TestReloadIsAllOrNothing(t *testing.T) {
	cat := &catalog{defs: []RepositoryDefinition{fileDef("K1", t.TempDir())}}
	repos := &ContentRepositoryService{Catalog: cat}
	ctx := context.Background()
	if _, err := repos.Get(ctx, "K1"); err != nil {
		t.Fatal(err)
	}
	cat.defs = []RepositoryDefinition{fileDef("K2", t.TempDir()), {ID: "bad", Status: "sometimes"}}
	if err := repos.Reload(ctx); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("bad definition: %v", err)
	}
	if _, err := repos.Get(ctx, "K1"); err != nil {
		t.Errorf("old map must stay after a failed reload: %v", err)
	}
	if _, err := repos.Get(ctx, "K2"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Errorf("nothing from the failed reload may be visible: %v", err)
	}
}

func TestRemoveAndLocationGuards(t *testing.T) {
	s, cat, _ := newService(t)
	ctx := context.Background()
	repo, _ := s.Repos.Get(ctx, "K1")
	if err := repo.Storage.PutObject(ctx, repo.Key("ClientKeys", "S01.cer"), nil, "", nil); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, s, "D1", comp("a", "1"))

	if err := s.Repos.Remove(ctx, "K1"); !errors.Is(err, ErrRepositoryInUse) {
		t.Errorf("remove with documents: %v", err)
	}
	moved := cat.defs[0]
	moved.PathPrefix = "elsewhere"
	cat.defs = []RepositoryDefinition{moved}
	if err := s.Repos.Reload(ctx); !errors.Is(err, ErrRepositoryInUse) {
		t.Errorf("location change with documents: %v", err)
	}
	renamed := fileDef("K1", repo.Definition.Storage.Bucket)
	renamed.Caption = "Invoices"
	cat.defs = []RepositoryDefinition{renamed}
	if err := s.Repos.Reload(ctx); err != nil {
		t.Errorf("caption change with documents: %v", err)
	}

	if err := s.Delete(ctx, "K1", "D1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Repos.Remove(ctx, "K1"); err != nil {
		t.Errorf("remove with only reserved objects: %v", err)
	}
	if _, err := s.Repos.Get(ctx, "K1"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Errorf("removed repository still served: %v", err)
	}
}

func TestAddVerifiesBucket(t *testing.T) {
	repos := &ContentRepositoryService{Catalog: StaticCatalog{}}
	ctx := context.Background()
	if _, err := repos.Add(ctx, fileDef("K9", t.TempDir()+"/missing")); !errors.Is(err, storage.ErrBucketNotFound) {
		t.Errorf("add with a missing bucket: %v", err)
	}
	if _, err := repos.Add(ctx, fileDef("K9", t.TempDir())); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.Add(ctx, fileDef("K9", t.TempDir())); !errors.Is(err, ErrRepositoryExists) {
		t.Errorf("duplicate add: %v", err)
	}
	for _, def := range []RepositoryDefinition{{ID: "a/b"}, {ID: ""}, {ID: "x", Storage: storage.Spec{Mode: "file"}}} {
		if _, err := repos.Add(ctx, def); !errors.Is(err, ErrInvalidDefinition) {
			t.Errorf("definition %+v: %v", def, err)
		}
	}
}
