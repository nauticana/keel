package document

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/scan"
	"github.com/nauticana/keel/storage"
)

const maxTitle = 200

// DocumentService stores partner documents: the file goes to the repository
// its document_type names as a one-component dms document, the record to
// partner_document. Objects are written first, then the row; a failed row
// removes the objects. The row and any supersession change in one transaction.
type DocumentService struct {
	DB      port.DatabaseRepository
	Repos   *dms.ContentRepositoryService
	Docs    *dms.ContentDocumentService
	Scanner scan.ContentScanner // optional
	// OnStored runs inside Store's transaction after the row is written, so an
	// application updates its own tables atomically with the document (a
	// licence number on the holder's profile, an outbox event). An error
	// rolls the row back and removes the objects.
	OnStored func(ctx context.Context, tx port.TxQueryService, doc *PartnerDocument) error

	once sync.Once
	qs   port.QueryService
}

func (s *DocumentService) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	return s.qs
}

func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *DocumentService) documentType(ctx context.Context, id string) (*DocumentType, error) {
	res, err := s.query(ctx).Query(ctx, qGetType, id)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownType, id)
	}
	return documentTypeFromRow(id, res.Rows[0]), nil
}

// checkTenant refuses a repository owned by another partner.
func (s *DocumentService) checkTenant(ctx context.Context, contRepID string, partnerID int64) error {
	res, err := s.query(ctx).Query(ctx, qRepositoryOwner, contRepID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("%w: %s", dms.ErrRepositoryNotFound, contRepID)
	}
	if owner, ok := common.AsInt64OK(res.Rows[0][0]); ok && owner != partnerID {
		return fmt.Errorf("%w: %s", ErrTenantMismatch, contRepID)
	}
	return nil
}

// sniff returns the media type detected from the bytes, refusing one the
// type does not allow. The client's claim is never used.
func sniff(raw []byte, allowed []string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(http.DetectContentType(raw))
	if err != nil || !slices.Contains(allowed, mediaType) {
		return "", fmt.Errorf("%w: %s", ErrMediaType, mediaType)
	}
	return mediaType, nil
}

// Store writes a new version of a document of up.DocumentType. It starts
// pending when the type requires review, otherwise approved, superseding the
// previous approved version.
func (s *DocumentService) Store(ctx context.Context, up Upload) (*PartnerDocument, error) {
	if up.PartnerID == 0 || up.Body == nil {
		return nil, fmt.Errorf("document: partner and body are required")
	}
	typ, err := s.documentType(ctx, up.DocumentType)
	if err != nil {
		return nil, err
	}
	if err := s.checkTenant(ctx, typ.ContRepID, up.PartnerID); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(up.Body, typ.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("document: read upload: %w", err)
	}
	if int64(len(raw)) > typ.MaxBytes {
		return nil, ErrTooLarge
	}
	mediaType, err := sniff(raw, typ.MediaTypes)
	if err != nil {
		return nil, err
	}
	if s.Scanner != nil {
		if err := s.Scanner.Scan(ctx, raw); err != nil {
			return nil, err
		}
	}

	qs := s.query(ctx)
	doc := &PartnerDocument{
		ID: qs.GenID(), ContRepID: typ.ContRepID, PartnerID: up.PartnerID, UserID: up.UserID, DocumentType: typ.ID,
		Title: common.TruncateRunes(strings.TrimSpace(up.Title), maxTitle), FileName: common.TruncateRunes(storage.SanitizeFilename(up.FileName), maxTitle),
		DocumentNumber: up.DocumentNumber, ExpiresOn: up.ExpiresOn, OriginIP: up.OriginIP, UploadedBy: up.UploadedBy,
		Status: StatusApproved,
	}
	doc.DocKey = strconv.FormatInt(doc.ID, 10)
	if doc.Title == "" {
		doc.Title = doc.FileName
	}
	if typ.RequiresReview {
		doc.Status = StatusPending
	}
	comp := dms.ComponentInput{ID: DataComponent, ContentType: mediaType, Body: bytes.NewReader(raw)}
	if err := s.Docs.Create(ctx, doc.ContRepID, doc.DocKey, "", []dms.ComponentInput{comp}); !dms.Succeeded(err) {
		return nil, err
	}
	if err := s.insert(ctx, doc); err != nil {
		_ = s.Docs.Delete(ctx, doc.ContRepID, doc.DocKey)
		return nil, err
	}
	return doc, nil
}

func (s *DocumentService) insert(ctx context.Context, doc *PartnerDocument) error {
	return s.transact(ctx, func(tx port.TxQueryService) error {
		next, err := tx.Query(ctx, qNextVersion, doc.PartnerID, doc.DocumentType, nullableID(doc.UserID))
		if err != nil {
			return err
		}
		doc.VersionNo = int(common.AsInt64(next.Rows[0][0]))
		var expires any
		if !doc.ExpiresOn.IsZero() {
			expires = doc.ExpiresOn
		}
		if _, err := tx.Query(ctx, qInsert, doc.ID, doc.ContRepID, doc.DocKey, doc.PartnerID, doc.DocumentType, nullableID(doc.UserID),
			doc.Title, doc.FileName, doc.VersionNo, doc.DocumentNumber, expires, doc.OriginIP, nullableID(doc.UploadedBy), doc.Status); err != nil {
			return err
		}
		if doc.Status == StatusApproved {
			if _, err := tx.Query(ctx, qSupersede, doc.PartnerID, doc.DocumentType, nullableID(doc.UserID), doc.ID); err != nil {
				return err
			}
		}
		if s.OnStored != nil {
			return s.OnStored(ctx, tx, doc)
		}
		return nil
	})
}

func (s *DocumentService) transact(ctx context.Context, fn func(port.TxQueryService) error) error {
	tx, err := s.DB.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *DocumentService) lock(ctx context.Context, tx port.TxQueryService, partnerID, id int64) (*PartnerDocument, error) {
	res, err := tx.Query(ctx, qLock, partnerID, id)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	return documentFromRow(res.Rows[0]), nil
}

// Review approves or rejects a pending document. An approval supersedes the
// previously approved version of the same type and subject in the same
// transaction.
func (s *DocumentService) Review(ctx context.Context, partnerID, id, reviewerID int64, approve bool, notes string) error {
	return s.transact(ctx, func(tx port.TxQueryService) error {
		doc, err := s.lock(ctx, tx, partnerID, id)
		if err != nil {
			return err
		}
		if doc.Status != StatusPending {
			return fmt.Errorf("%w: %d is %s", ErrInvalidState, id, doc.Status)
		}
		status := StatusRejected
		if approve {
			status = StatusApproved
			if _, err := tx.Query(ctx, qSupersede, doc.PartnerID, doc.DocumentType, nullableID(doc.UserID), doc.ID); err != nil {
				return err
			}
		}
		_, err = tx.Query(ctx, qSetReview, status, reviewerID, notes, id)
		return err
	})
}

// Retire withdraws a document without a replacement. The objects stay for a
// retention job; the row is hidden from lists.
func (s *DocumentService) Retire(ctx context.Context, partnerID, id int64) error {
	return s.transact(ctx, func(tx port.TxQueryService) error {
		doc, err := s.lock(ctx, tx, partnerID, id)
		if err != nil {
			return err
		}
		if doc.Status == StatusRetired {
			return fmt.Errorf("%w: %d is already retired", ErrInvalidState, id)
		}
		_, err = tx.Query(ctx, qSetStatus, StatusRetired, id)
		return err
	})
}

func (s *DocumentService) Get(ctx context.Context, partnerID, id int64) (*PartnerDocument, error) {
	res, err := s.query(ctx).Query(ctx, qGet, partnerID, id)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	return documentFromRow(res.Rows[0]), nil
}

// Read returns the document and its content; Content carries the component attributes.
func (s *DocumentService) Read(ctx context.Context, partnerID, id int64) (*PartnerDocument, []byte, error) {
	doc, err := s.Get(ctx, partnerID, id)
	if err != nil {
		return nil, nil, err
	}
	content, comp, err := s.Docs.Read(ctx, doc.ContRepID, doc.DocKey, DataComponent)
	if err != nil {
		return nil, nil, err
	}
	doc.Content = comp
	return doc, content, nil
}

// Open streams the document's content.
func (s *DocumentService) Open(ctx context.Context, partnerID, id int64) (*PartnerDocument, io.ReadCloser, error) {
	doc, err := s.Get(ctx, partnerID, id)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.Docs.Open(ctx, doc.ContRepID, doc.DocKey, DataComponent)
	if err != nil {
		return nil, nil, err
	}
	return doc, r, nil
}

// SignedURL mints a short-lived read URL for the document's content.
func (s *DocumentService) SignedURL(ctx context.Context, partnerID, id int64, expirySeconds int) (string, error) {
	doc, err := s.Get(ctx, partnerID, id)
	if err != nil {
		return "", err
	}
	repo, err := s.Repos.Get(ctx, doc.ContRepID)
	if err != nil {
		return "", err
	}
	return repo.Storage.GetSignedURL(ctx, repo.Key(doc.DocKey, DataComponent), expirySeconds)
}

func (s *DocumentService) list(ctx context.Context, name string, args ...any) ([]*PartnerDocument, error) {
	res, err := s.query(ctx).Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	docs := make([]*PartnerDocument, 0, len(res.Rows))
	for _, r := range res.Rows {
		docs = append(docs, documentFromRow(r))
	}
	return docs, nil
}

// ListByPartner returns every non-retired document of the partner.
func (s *DocumentService) ListByPartner(ctx context.Context, partnerID int64) ([]*PartnerDocument, error) {
	return s.list(ctx, qListByPartner, partnerID)
}

// ListByUser returns every non-retired document about one member of the partner.
func (s *DocumentService) ListByUser(ctx context.Context, partnerID, userID int64) ([]*PartnerDocument, error) {
	return s.list(ctx, qListByUser, partnerID, userID)
}

// ByVersion resolves a document the way clients address it: subject, type and version.
func (s *DocumentService) ByVersion(ctx context.Context, partnerID, userID int64, documentType string, versionNo int) (*PartnerDocument, error) {
	docs, err := s.list(ctx, qByVersion, partnerID, nullableID(userID), documentType, versionNo)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%w: %s v%d", ErrNotFound, documentType, versionNo)
	}
	return docs[0], nil
}

// Latest returns the newest non-retired version of every type for a subject
// (userID 0 = the partner), the basis of a "missing / pending / rejected" summary.
func (s *DocumentService) Latest(ctx context.Context, partnerID, userID int64) ([]*PartnerDocument, error) {
	return s.list(ctx, qLatest, partnerID, nullableID(userID))
}

// ReviewedBy returns the documents a reviewer decided, newest first.
func (s *DocumentService) ReviewedBy(ctx context.Context, partnerID, reviewerID int64) ([]*PartnerDocument, error) {
	return s.list(ctx, qReviewedBy, partnerID, reviewerID)
}

// Pending is the partner's review queue, oldest upload first.
func (s *DocumentService) Pending(ctx context.Context, partnerID int64) ([]*PartnerDocument, error) {
	return s.list(ctx, qPending, partnerID)
}

// Approved returns the approved document of a type for a subject (userID 0 =
// the partner), or ErrNotFound.
func (s *DocumentService) Approved(ctx context.Context, partnerID, userID int64, documentType string) (*PartnerDocument, error) {
	docs, err := s.list(ctx, qApproved, partnerID, documentType, nullableID(userID))
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%w: no approved %s", ErrNotFound, documentType)
	}
	return docs[0], nil
}
