package dms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nauticana/keel/storage"
)

// HeaderComponent is the reserved component id of the zero-byte object that
// represents the document header.
const HeaderComponent = "dochdr_"

// Attribute keys, lowercase with underscores so every provider round-trips them.
const (
	AttrDocID         = "doc_id"
	AttrCompID        = "comp_id"
	AttrDocProt       = "doc_prot"
	AttrContentType   = "content_type"
	AttrCharset       = "charset"
	AttrAppVersion    = "app_version"
	AttrContentLength = "content_length"
	AttrContentDigest = "content_digest"
	AttrDateC         = "date_c"
	AttrTimeC         = "time_c"
	AttrDateM         = "date_m"
	AttrTimeM         = "time_m"

	DateFormat = "2006-01-02"
	TimeFormat = "15:04:05"
)

var (
	ErrDocumentExists    = errors.New("dms: document already exists")
	ErrInvalidKey        = errors.New("dms: invalid document or component id")
	ErrComponentTooLarge = errors.New("dms: component exceeds the size limit")
	// ErrObserver and ErrHeaderStale are soft: the operation succeeded and the
	// error is for logging. See Succeeded.
	ErrObserver    = errors.New("dms: observer failed")
	ErrHeaderStale = errors.New("dms: document header stamp could not be refreshed")
)

// Succeeded reports whether an operation's result means the objects were
// written or deleted: nil, or only soft errors.
func Succeeded(err error) bool {
	if err == nil {
		return true
	}
	for _, e := range flatten(err) {
		if !errors.Is(e, ErrObserver) && !errors.Is(e, ErrHeaderStale) {
			return false
		}
	}
	return true
}

func flatten(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, flatten(e)...)
		}
		return out
	}
	return []error{err}
}

type Component struct {
	ID           string
	ContentType  string
	Charset      string
	AppVersion   string
	Length       int64
	Digest       string
	DateC, TimeC string
	DateM, TimeM string
}

type Document struct {
	Repository   string
	Key          string
	DocProt      string // "" means the repository default
	DateC, TimeC string
	DateM, TimeM string
	Components   []Component
}

// ComponentInput is one component to write. Body is buffered up to MaxBytes.
type ComponentInput struct {
	ID          string
	ContentType string
	Charset     string
	AppVersion  string
	Body        io.Reader
}

// Observer is told about every stored and deleted component after the
// operation succeeded; compID is "" when a whole document was deleted.
type Observer interface {
	Stored(ctx context.Context, contRep, docKey, compID string) error
	Deleted(ctx context.Context, contRep, docKey, compID string) error
}

func validID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.Contains(id, "/")
}

func compID(id string) error {
	if !validID(id) || id == HeaderComponent {
		return fmt.Errorf("%w: component %q", ErrInvalidKey, id)
	}
	return nil
}

func notFound(docKey string) error {
	return fmt.Errorf("dms: document %s: %w", docKey, storage.ErrNotFound)
}

func uniqueIDs(comps []ComponentInput) error {
	seen := map[string]bool{}
	for _, c := range comps {
		if err := compID(c.ID); err != nil {
			return err
		}
		if seen[c.ID] {
			return fmt.Errorf("%w: duplicate component %q", ErrInvalidKey, c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

func componentFromAttrs(id string, attrs map[string]string) Component {
	length, _ := strconv.ParseInt(attrs[AttrContentLength], 10, 64)
	return Component{
		ID: id, ContentType: attrs[AttrContentType], Charset: attrs[AttrCharset], AppVersion: attrs[AttrAppVersion],
		Length: length, Digest: attrs[AttrContentDigest],
		DateC: attrs[AttrDateC], TimeC: attrs[AttrTimeC], DateM: attrs[AttrDateM], TimeM: attrs[AttrTimeM],
	}
}
