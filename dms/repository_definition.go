package dms

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/storage"
)

// RepositoryDefinition is one content repository. A content server embeds it
// in its own configuration entries; a client application reads it from a table.
type RepositoryDefinition struct {
	ID             string           `json:"id"`
	Caption        string           `json:"caption"`
	Storage        storage.Spec     `json:"storage"`
	PathPrefix     string           `json:"path_prefix"` // defaults to ID
	DefaultDocProt string           `json:"default_doc_prot"`
	Status         RepositoryStatus `json:"status"` // defaults to active
}

// Prefix is the key prefix of every object in the repository, always ending in "/".
func (d RepositoryDefinition) Prefix() string {
	p := strings.Trim(d.PathPrefix, "/")
	if p == "" {
		p = d.ID
	}
	return p + "/"
}

func (d RepositoryDefinition) status() RepositoryStatus {
	if d.Status == "" {
		return StatusActive
	}
	return d.Status
}

func (d RepositoryDefinition) validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.ContainsAny(d.ID, "/ ") || len(d.ID) > 30 {
		return fmt.Errorf("%w: id %q", ErrInvalidDefinition, d.ID)
	}
	switch d.status() {
	case StatusActive, StatusReadOnly, StatusMigrating:
	default:
		return fmt.Errorf("%w: status %q of %s", ErrInvalidDefinition, d.Status, d.ID)
	}
	if strings.TrimSpace(d.Storage.Bucket) == "" {
		return fmt.Errorf("%w: %s has no bucket", ErrInvalidDefinition, d.ID)
	}
	return nil
}

// sameLocation reports whether two definitions store objects in the same place.
func (d RepositoryDefinition) sameLocation(o RepositoryDefinition) bool {
	return d.Storage.Mode == o.Storage.Mode && d.Storage.Bucket == o.Storage.Bucket && d.Prefix() == o.Prefix()
}

func (d RepositoryDefinition) overlaps(o RepositoryDefinition) bool {
	if d.Storage.Mode != o.Storage.Mode || d.Storage.Bucket != o.Storage.Bucket {
		return false
	}
	a, b := d.Prefix(), o.Prefix()
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}
