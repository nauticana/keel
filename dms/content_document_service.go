package dms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/storage"
)

// ContentDocumentService stores documents as a header object plus one object
// per component under <prefix>/<docKey>/. It stores content types as given
// and does no scanning; the caller scans before the write.
type ContentDocumentService struct {
	Repos         *ContentRepositoryService
	Observer      Observer // optional
	MaxBytes      int64    // largest component body; required
	HeaderRetries int      // attempts to refresh the header stamp under contention; 0 means 5
	Now           func() time.Time
}

func (s *ContentDocumentService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *ContentDocumentService) stamps() (string, string) {
	now := s.now()
	return now.Format(DateFormat), now.Format(TimeFormat)
}

func (s *ContentDocumentService) repo(ctx context.Context, id string, write bool) (*ContentRepository, error) {
	repo, err := s.Repos.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if write {
		if s.MaxBytes <= 0 {
			return nil, fmt.Errorf("dms: ContentDocumentService.MaxBytes is required")
		}
		if err := repo.writable(); err != nil {
			return nil, err
		}
	}
	return repo, nil
}

func (s *ContentDocumentService) docKey(docKey string) error {
	if !validID(docKey) || docKey == HeaderComponent || s.Repos.IsReserved(docKey) {
		return fmt.Errorf("%w: document %q", ErrInvalidKey, docKey)
	}
	return nil
}

// components lists the component ids of a document, and whether its header exists.
func (s *ContentDocumentService) components(ctx context.Context, repo *ContentRepository, docKey string) (hasHeader bool, ids []string, err error) {
	keys, err := repo.Storage.ListObjects(ctx, repo.Key(docKey)+"/", 0)
	if err != nil {
		return false, nil, err
	}
	for _, k := range keys {
		if id := path.Base(k); id == HeaderComponent {
			hasHeader = true
		} else {
			ids = append(ids, id)
		}
	}
	return hasHeader, ids, nil
}

func (s *ContentDocumentService) headerAttributes(docKey, docProt, dateC, timeC string) map[string]string {
	dateM, timeM := s.stamps()
	attrs := map[string]string{
		AttrDocID: docKey, AttrCompID: HeaderComponent,
		AttrDateC: dateC, AttrTimeC: timeC, AttrDateM: dateM, AttrTimeM: timeM,
	}
	switch docProt {
	case DocProtServerSetting:
	case "":
		attrs[AttrDocProt] = docProtNone
	default:
		attrs[AttrDocProt] = docProt
	}
	return attrs
}

// putHeader writes the header if absent; ErrExists means another writer did.
func (s *ContentDocumentService) putHeader(ctx context.Context, repo *ContentRepository, docKey, docProt, dateC, timeC string) error {
	return repo.Storage.PutObjectIfAbsent(ctx, repo.Key(docKey, HeaderComponent), strings.NewReader(""), "", s.headerAttributes(docKey, docProt, dateC, timeC))
}

// upgrade writes the header of a legacy document that has components only,
// dating it from its oldest component.
func (s *ContentDocumentService) upgrade(ctx context.Context, repo *ContentRepository, docKey string, ids []string) error {
	dateC, timeC := s.stamps()
	for _, id := range ids {
		attrs, err := repo.Storage.GetObjectAttributes(ctx, repo.Key(docKey, id))
		if err != nil {
			return err
		}
		if d, t := attrs[AttrDateC], attrs[AttrTimeC]; d != "" && d+t < dateC+timeC {
			dateC, timeC = d, t
		}
	}
	if err := s.putHeader(ctx, repo, docKey, DocProtServerSetting, dateC, timeC); err != nil && !errors.Is(err, storage.ErrExists) {
		return err
	}
	return nil
}

// require checks the document exists and gives it a header if it lacks one.
func (s *ContentDocumentService) require(ctx context.Context, repo *ContentRepository, docKey string) ([]string, error) {
	hasHeader, ids, err := s.components(ctx, repo, docKey)
	if err != nil {
		return nil, err
	}
	if !hasHeader && len(ids) == 0 {
		return nil, notFound(docKey)
	}
	if !hasHeader {
		if err := s.upgrade(ctx, repo, docKey, ids); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// touchHeader moves the header's modified stamp forward, retrying when a
// parallel writer changed the header in between. Exhausting the retries is
// the soft ErrHeaderStale: the component is already written.
func (s *ContentDocumentService) touchHeader(ctx context.Context, repo *ContentRepository, docKey string) error {
	key := repo.Key(docKey, HeaderComponent)
	retries := s.HeaderRetries
	if retries <= 0 {
		retries = 5
	}
	var err error
	for attempt := 0; attempt < retries; attempt++ {
		var attrs map[string]string
		attrs, err = repo.Storage.GetObjectAttributes(ctx, key)
		if err != nil {
			break
		}
		dateM, timeM := s.stamps()
		if attrs[AttrDateM]+attrs[AttrTimeM] > dateM+timeM {
			return nil
		}
		attrs[AttrDateM], attrs[AttrTimeM] = dateM, timeM
		if err = repo.Storage.SetObjectAttributes(ctx, key, attrs); err == nil {
			return nil
		}
		if !errors.Is(err, storage.ErrPreconditionFailed) {
			break
		}
	}
	return fmt.Errorf("%w: %s: %v", ErrHeaderStale, docKey, err)
}

func (s *ContentDocumentService) putComponent(ctx context.Context, repo *ContentRepository, docKey string, in ComponentInput, old map[string]string) error {
	body := in.Body
	if body == nil {
		body = strings.NewReader("")
	}
	content, err := io.ReadAll(io.LimitReader(body, s.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("dms: read component %s: %w", in.ID, err)
	}
	if int64(len(content)) > s.MaxBytes {
		return fmt.Errorf("%w: %s", ErrComponentTooLarge, in.ID)
	}
	digest := sha256.Sum256(content)
	date, clock := s.stamps()
	attrs := map[string]string{
		AttrDocID: docKey, AttrCompID: in.ID,
		AttrContentType: in.ContentType, AttrCharset: in.Charset, AttrAppVersion: in.AppVersion,
		AttrContentLength: strconv.Itoa(len(content)), AttrContentDigest: hex.EncodeToString(digest[:]),
		AttrDateC: date, AttrTimeC: clock, AttrDateM: date, AttrTimeM: clock,
	}
	if old[AttrDateC] != "" {
		attrs[AttrDateC], attrs[AttrTimeC] = old[AttrDateC], old[AttrTimeC]
	}
	return repo.Storage.PutObject(ctx, repo.Key(docKey, in.ID), bytes.NewReader(content), in.ContentType, attrs)
}

func (s *ContentDocumentService) notify(ctx context.Context, repoID, docKey string, stored, deleted []string) error {
	if s.Observer == nil {
		return nil
	}
	var errs []error
	for _, id := range stored {
		if err := s.Observer.Stored(ctx, repoID, docKey, id); err != nil {
			errs = append(errs, fmt.Errorf("%w: stored %s/%s: %v", ErrObserver, docKey, id, err))
		}
	}
	for _, id := range deleted {
		if err := s.Observer.Deleted(ctx, repoID, docKey, id); err != nil {
			errs = append(errs, fmt.Errorf("%w: deleted %s/%s: %v", ErrObserver, docKey, id, err))
		}
	}
	return errors.Join(errs...)
}

// Create writes a new document: a header, then its components. An existing
// document is ErrDocumentExists; a failed component put removes what was written.
func (s *ContentDocumentService) Create(ctx context.Context, repoID, docKey, docProt string, comps []ComponentInput) error {
	repo, err := s.repo(ctx, repoID, true)
	if err != nil {
		return err
	}
	if err := s.docKey(docKey); err != nil {
		return err
	}
	if err := uniqueIDs(comps); err != nil {
		return err
	}
	// A legacy document with components but no header is still "exists".
	if keys, err := repo.Storage.ListObjects(ctx, repo.Key(docKey)+"/", 1); err != nil {
		return err
	} else if len(keys) > 0 {
		return fmt.Errorf("%w: %s", ErrDocumentExists, docKey)
	}
	dateC, timeC := s.stamps()
	if err := s.putHeader(ctx, repo, docKey, docProt, dateC, timeC); errors.Is(err, storage.ErrExists) {
		return fmt.Errorf("%w: %s", ErrDocumentExists, docKey)
	} else if err != nil {
		return err
	}
	var written []string
	for _, c := range comps {
		if err := s.putComponent(ctx, repo, docKey, c, nil); err != nil {
			for _, id := range append(written, HeaderComponent) {
				_ = repo.Storage.DeleteObject(ctx, repo.Key(docKey, id))
			}
			return err
		}
		written = append(written, c.ID)
	}
	return s.notify(ctx, repoID, docKey, written, nil)
}

// PutComponent creates or overwrites one component of an existing document.
func (s *ContentDocumentService) PutComponent(ctx context.Context, repoID, docKey string, in ComponentInput) error {
	repo, err := s.repo(ctx, repoID, true)
	if err != nil {
		return err
	}
	if err := s.docKey(docKey); err != nil {
		return err
	}
	if err := compID(in.ID); err != nil {
		return err
	}
	if _, err := s.require(ctx, repo, docKey); err != nil {
		return err
	}
	old, err := repo.Storage.GetObjectAttributes(ctx, repo.Key(docKey, in.ID))
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if err := s.putComponent(ctx, repo, docKey, in, old); err != nil {
		return err
	}
	return errors.Join(s.touchHeader(ctx, repo, docKey), s.notify(ctx, repoID, docKey, []string{in.ID}, nil))
}

// Replace makes comps the document's whole component set.
func (s *ContentDocumentService) Replace(ctx context.Context, repoID, docKey string, comps []ComponentInput) error {
	repo, err := s.repo(ctx, repoID, true)
	if err != nil {
		return err
	}
	if err := s.docKey(docKey); err != nil {
		return err
	}
	if err := uniqueIDs(comps); err != nil {
		return err
	}
	existing, err := s.require(ctx, repo, docKey)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	var written []string
	for _, c := range comps {
		old, err := repo.Storage.GetObjectAttributes(ctx, repo.Key(docKey, c.ID))
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		if err := s.putComponent(ctx, repo, docKey, c, old); err != nil {
			return err
		}
		keep[c.ID] = true
		written = append(written, c.ID)
	}
	var removed []string
	for _, id := range existing {
		if keep[id] {
			continue
		}
		if err := repo.Storage.DeleteObject(ctx, repo.Key(docKey, id)); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		removed = append(removed, id)
	}
	return errors.Join(s.touchHeader(ctx, repo, docKey), s.notify(ctx, repoID, docKey, written, removed))
}

// DeleteComponent removes one component; the document stays, even when empty.
func (s *ContentDocumentService) DeleteComponent(ctx context.Context, repoID, docKey, id string) error {
	repo, err := s.repo(ctx, repoID, true)
	if err != nil {
		return err
	}
	if err := s.docKey(docKey); err != nil {
		return err
	}
	if err := compID(id); err != nil {
		return err
	}
	if _, err := s.require(ctx, repo, docKey); err != nil {
		return err
	}
	if err := repo.Storage.DeleteObject(ctx, repo.Key(docKey, id)); err != nil {
		return err
	}
	return errors.Join(s.touchHeader(ctx, repo, docKey), s.notify(ctx, repoID, docKey, nil, []string{id}))
}

// Delete removes the document with every component.
func (s *ContentDocumentService) Delete(ctx context.Context, repoID, docKey string) error {
	repo, err := s.repo(ctx, repoID, true)
	if err != nil {
		return err
	}
	if err := s.docKey(docKey); err != nil {
		return err
	}
	keys, err := repo.Storage.ListObjects(ctx, repo.Key(docKey)+"/", 0)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return notFound(docKey)
	}
	for _, k := range keys {
		if err := repo.Storage.DeleteObject(ctx, k); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	return s.notify(ctx, repoID, docKey, nil, []string{""})
}

// Info returns the document header and every component's attributes. A legacy
// document without a header is dated from its oldest component.
func (s *ContentDocumentService) Info(ctx context.Context, repoID, docKey string) (*Document, error) {
	repo, err := s.repo(ctx, repoID, false)
	if err != nil {
		return nil, err
	}
	if err := s.docKey(docKey); err != nil {
		return nil, err
	}
	hasHeader, ids, err := s.components(ctx, repo, docKey)
	if err != nil {
		return nil, err
	}
	if !hasHeader && len(ids) == 0 {
		return nil, notFound(docKey)
	}
	doc := &Document{Repository: repoID, Key: docKey, DocProt: DocProtServerSetting}
	if hasHeader {
		attrs, err := repo.Storage.GetObjectAttributes(ctx, repo.Key(docKey, HeaderComponent))
		if err != nil {
			return nil, err
		}
		doc.DocProt = DocProtOf(attrs)
		doc.DateC, doc.TimeC, doc.DateM, doc.TimeM = attrs[AttrDateC], attrs[AttrTimeC], attrs[AttrDateM], attrs[AttrTimeM]
	}
	for _, id := range ids {
		attrs, err := repo.Storage.GetObjectAttributes(ctx, repo.Key(docKey, id))
		if err != nil {
			return nil, err
		}
		c := componentFromAttrs(id, attrs)
		doc.Components = append(doc.Components, c)
		if !hasHeader && (doc.DateC == "" || c.DateC+c.TimeC < doc.DateC+doc.TimeC) {
			doc.DateC, doc.TimeC = c.DateC, c.TimeC
		}
		if !hasHeader && c.DateM+c.TimeM > doc.DateM+doc.TimeM {
			doc.DateM, doc.TimeM = c.DateM, c.TimeM
		}
	}
	return doc, nil
}

// Open streams one component's content.
func (s *ContentDocumentService) Open(ctx context.Context, repoID, docKey, id string) (io.ReadCloser, error) {
	repo, err := s.repo(ctx, repoID, false)
	if err != nil {
		return nil, err
	}
	if err := s.docKey(docKey); err != nil {
		return nil, err
	}
	if err := compID(id); err != nil {
		return nil, err
	}
	return repo.Storage.GetObject(ctx, repo.Key(docKey, id))
}

// Read returns one component's content and attributes from the same write.
func (s *ContentDocumentService) Read(ctx context.Context, repoID, docKey, id string) ([]byte, *Component, error) {
	repo, err := s.repo(ctx, repoID, false)
	if err != nil {
		return nil, nil, err
	}
	if err := s.docKey(docKey); err != nil {
		return nil, nil, err
	}
	if err := compID(id); err != nil {
		return nil, nil, err
	}
	c, err := repo.Storage.GetObjectAndAttributes(ctx, repo.Key(docKey, id))
	if err != nil {
		return nil, nil, err
	}
	comp := componentFromAttrs(id, c.GetAttributes())
	comp.Length = int64(len(c.GetContent()))
	return c.GetContent(), &comp, nil
}

// List returns up to limit document keys of the repository (0 means all),
// skipping reserved keys. Order is the backend's; there is no paging.
func (s *ContentDocumentService) List(ctx context.Context, repoID string, limit int) ([]string, error) {
	repo, err := s.repo(ctx, repoID, false)
	if err != nil {
		return nil, err
	}
	fetch := 0
	if limit > 0 {
		fetch = limit + len(s.Repos.Reserved)
	}
	names, err := repo.Storage.ListPrefixes(ctx, repo.Definition.Prefix(), fetch)
	if err != nil {
		return nil, err
	}
	keys := names[:0]
	for _, n := range names {
		if !s.Repos.IsReserved(n) {
			keys = append(keys, n)
		}
	}
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return keys, nil
}
