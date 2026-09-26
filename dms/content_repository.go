package dms

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/storage"
)

// ContentRepository is a definition bound to its bucket.
type ContentRepository struct {
	Definition RepositoryDefinition
	Storage    storage.ObjectStorage
}

// Key joins parts under the repository prefix.
func (r *ContentRepository) Key(parts ...string) string {
	return r.Definition.Prefix() + strings.Join(parts, "/")
}

func (r *ContentRepository) writable() error {
	if s := r.Definition.status(); s != StatusActive {
		return fmt.Errorf("%w: %s is %s", ErrRepositoryReadOnly, r.Definition.ID, s)
	}
	return nil
}
