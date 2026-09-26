package dms

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/storage"
)

// ContentRepositoryService holds the repositories a process serves, built from
// a catalog and changed at runtime with Add, Remove and Reload. Reserved lists
// document keys the caller uses for its own objects under a repository prefix
// (for example client certificates); document operations refuse them and the
// delete guard ignores them.
type ContentRepositoryService struct {
	Catalog  RepositoryCatalog
	Secrets  secret.SecretProvider
	Reserved []string

	mu     sync.RWMutex
	repos  map[string]*ContentRepository
	loaded bool
}

func (s *ContentRepositoryService) IsReserved(docKey string) bool {
	for _, r := range s.Reserved {
		if r == docKey {
			return true
		}
	}
	return false
}

func (s *ContentRepositoryService) ensureLoaded(ctx context.Context) error {
	s.mu.RLock()
	loaded := s.loaded
	s.mu.RUnlock()
	if loaded {
		return nil
	}
	return s.Reload(ctx)
}

// Get returns the repository, binding its bucket on first use.
func (s *ContentRepositoryService) Get(ctx context.Context, id string) (*ContentRepository, error) {
	if err := s.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	repo, ok := s.repos[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRepositoryNotFound, id)
	}
	return s.bind(ctx, repo)
}

func (s *ContentRepositoryService) bind(ctx context.Context, repo *ContentRepository) (*ContentRepository, error) {
	s.mu.RLock()
	bound := repo.Storage != nil
	s.mu.RUnlock()
	if bound {
		return repo, nil
	}
	store, err := storage.New(ctx, repo.Definition.Storage, s.Secrets)
	if err != nil {
		return nil, fmt.Errorf("dms: repository %s: %w", repo.Definition.ID, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if repo.Storage == nil {
		repo.Storage = store
	}
	return repo, nil
}

// Definitions returns a snapshot of the loaded definitions.
func (s *ContentRepositoryService) Definitions(ctx context.Context) ([]RepositoryDefinition, error) {
	if err := s.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	defs := make([]RepositoryDefinition, 0, len(s.repos))
	for _, r := range s.repos {
		defs = append(defs, r.Definition)
	}
	return defs, nil
}

// HasDocuments reports whether any non-reserved document exists in the repository.
func (s *ContentRepositoryService) HasDocuments(ctx context.Context, repo *ContentRepository) (bool, error) {
	names, err := repo.Storage.ListPrefixes(ctx, repo.Definition.Prefix(), len(s.Reserved)+1)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if !s.IsReserved(n) {
			return true, nil
		}
	}
	return false, nil
}

// checkLocation refuses moving a repository that still holds documents.
func (s *ContentRepositoryService) checkLocation(ctx context.Context, old *ContentRepository, def RepositoryDefinition) error {
	if old.Definition.sameLocation(def) {
		return nil
	}
	old, err := s.bind(ctx, old)
	if err != nil {
		return err
	}
	inUse, err := s.HasDocuments(ctx, old)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("%w: %s cannot change its storage location", ErrRepositoryInUse, def.ID)
	}
	return nil
}

// Reload reads the catalog and swaps the repository map atomically. It is
// all-or-nothing: a definition that breaks a rule leaves the old map in place.
// Repositories whose definition did not change keep their bound bucket.
func (s *ContentRepositoryService) Reload(ctx context.Context) error {
	defs, err := s.Catalog.Repositories(ctx)
	if err != nil {
		return fmt.Errorf("dms: catalog: %w", err)
	}
	if err := validateSet(defs); err != nil {
		return err
	}
	s.mu.RLock()
	old := s.repos
	s.mu.RUnlock()
	next := make(map[string]*ContentRepository, len(defs))
	for _, d := range defs {
		if prev, ok := old[d.ID]; ok {
			if prev.Definition == d {
				next[d.ID] = prev
				continue
			}
			if err := s.checkLocation(ctx, prev, d); err != nil {
				return err
			}
		}
		next[d.ID] = &ContentRepository{Definition: d}
	}
	s.mu.Lock()
	s.repos, s.loaded = next, true
	s.mu.Unlock()
	return nil
}

// Add registers one repository and binds its bucket at once, so a missing
// bucket (storage.ErrBucketNotFound) is reported to the caller. Persisting the
// definition is the caller's job.
func (s *ContentRepositoryService) Add(ctx context.Context, def RepositoryDefinition) (*ContentRepository, error) {
	if err := s.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	existing := make([]RepositoryDefinition, 0, len(s.repos)+1)
	for _, r := range s.repos {
		existing = append(existing, r.Definition)
	}
	s.mu.RUnlock()
	if err := validateSet(append(existing, def)); err != nil {
		return nil, err
	}
	store, err := storage.New(ctx, def.Storage, s.Secrets)
	if err != nil {
		return nil, fmt.Errorf("dms: repository %s: %w", def.ID, err)
	}
	repo := &ContentRepository{Definition: def, Storage: store}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.repos[def.ID]; dup {
		return nil, fmt.Errorf("%w: %s", ErrRepositoryExists, def.ID)
	}
	s.repos[def.ID] = repo
	return repo, nil
}

// Remove unregisters a repository that holds no documents (ErrRepositoryInUse
// otherwise). The caller deletes its reserved objects first, or they are orphaned.
func (s *ContentRepositoryService) Remove(ctx context.Context, id string) error {
	repo, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	inUse, err := s.HasDocuments(ctx, repo)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("%w: %s", ErrRepositoryInUse, id)
	}
	s.mu.Lock()
	delete(s.repos, id)
	s.mu.Unlock()
	return nil
}
