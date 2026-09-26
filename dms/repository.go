// Package dms is the document model over storage.ObjectStorage: content
// repositories in front of buckets, and ArchiveLink-style documents (a header
// plus components) whose metadata lives in object attributes. It imports no
// database package, so a content server without a database can link it.
package dms

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrRepositoryNotFound = errors.New("dms: repository not found")
	ErrRepositoryExists   = errors.New("dms: repository already exists")
	ErrRepositoryInUse    = errors.New("dms: repository holds documents")
	ErrRepositoryReadOnly = errors.New("dms: repository is not writable")
	ErrPrefixOverlap      = errors.New("dms: repository prefix overlaps another on the same bucket")
	ErrInvalidDefinition  = errors.New("dms: invalid repository definition")
)

type RepositoryStatus string

const (
	StatusActive    RepositoryStatus = "active"
	StatusReadOnly  RepositoryStatus = "read-only"
	StatusMigrating RepositoryStatus = "migrating"
)

type RepositoryCatalog interface {
	Repositories(ctx context.Context) ([]RepositoryDefinition, error)
}

// StaticCatalog serves definitions the caller decoded from its own configuration.
type StaticCatalog []RepositoryDefinition

func (c StaticCatalog) Repositories(context.Context) ([]RepositoryDefinition, error) { return c, nil }

func validateSet(defs []RepositoryDefinition) error {
	for i, d := range defs {
		if err := d.validate(); err != nil {
			return err
		}
		for _, o := range defs[:i] {
			if o.ID == d.ID {
				return fmt.Errorf("%w: %s", ErrRepositoryExists, d.ID)
			}
			if d.overlaps(o) {
				return fmt.Errorf("%w: %s and %s", ErrPrefixOverlap, d.ID, o.ID)
			}
		}
	}
	return nil
}
