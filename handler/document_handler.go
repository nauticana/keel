package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/document"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/scan"
)

// DocumentStore is what DocumentHandler needs from document.DocumentService.
type DocumentStore interface {
	Store(ctx context.Context, up document.Upload) (*document.PartnerDocument, error)
	Get(ctx context.Context, partnerID, id int64) (*document.PartnerDocument, error)
	SignedURL(ctx context.Context, partnerID, id int64, expirySeconds int) (string, error)
	Review(ctx context.Context, partnerID, id, reviewerID int64, approve bool, notes string) error
}

var _ DocumentStore = (*document.DocumentService)(nil)

// DocumentHandler is the HTTP surface over document.DocumentService: a
// multipart upload, a signed preview URL and review. Each hook decides whether
// the session may act on that upload or document; return a *model.AppError to
// refuse. An endpoint whose hook is unset refuses every request.
type DocumentHandler struct {
	AbstractHandler
	Documents        DocumentStore
	Authorize        func(ctx context.Context, session *model.UserSession, up *document.Upload) error
	AuthorizeRead    func(ctx context.Context, session *model.UserSession, doc *document.PartnerDocument) error
	AuthorizeReview  func(ctx context.Context, session *model.UserSession, doc *document.PartnerDocument) error
	MaxBytes         int64 // request body cap; 0 uses dms_max_bytes
	SignedURLSeconds int
}

// Upload accepts multipart field "file" with the form fields document_type,
// title, document_number, expires_on (YYYY-MM-DD) and user_id (the subject;
// empty = the partner), and answers 201 with the stored document.
func (h *DocumentHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Documents == nil || h.Authorize == nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "document handler not configured")
		return
	}
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	maxBytes := h.MaxBytes
	if maxBytes <= 0 {
		maxBytes = config.Config().DmsMaxBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+multipartFramingAllowance)
	file, header, err := r.FormFile("file")
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		h.WriteError(w, http.StatusRequestEntityTooLarge, "Payload Too Large", "upload exceeds the size limit")
		return
	}
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "multipart field file is required")
		return
	}
	defer file.Close()
	up := document.Upload{
		PartnerID: partnerID, DocumentType: r.FormValue("document_type"), Title: r.FormValue("title"),
		FileName: header.Filename, DocumentNumber: r.FormValue("document_number"),
		OriginIP: common.TrustedClientIP(r), UploadedBy: int64(session.Id), Body: file,
	}
	if up.DocumentType == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "document_type is required")
		return
	}
	if v := r.FormValue("user_id"); v != "" {
		if up.UserID, err = strconv.ParseInt(v, 10, 64); err != nil {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "user_id must be an integer")
			return
		}
	}
	if v := r.FormValue("expires_on"); v != "" {
		if up.ExpiresOn, err = time.Parse(dms.DateFormat, v); err != nil {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "expires_on must be YYYY-MM-DD")
			return
		}
	}
	if err := h.Authorize(r.Context(), session, &up); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	doc, err := h.Documents.Store(r.Context(), up)
	if err != nil {
		h.writeDocumentError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusCreated, doc)
}

// Preview answers {url} with a short-lived signed read URL for ?id=.
func (h *DocumentHandler) Preview(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Documents == nil || h.AuthorizeRead == nil || h.SignedURLSeconds <= 0 {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "preview handler not configured")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "id is required")
		return
	}
	doc, ok := h.authorizedDocument(w, r, session, id, h.AuthorizeRead)
	if !ok {
		return
	}
	url, err := h.Documents.SignedURL(r.Context(), doc.PartnerID, doc.ID, h.SignedURLSeconds)
	if err != nil {
		h.writeDocumentError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]string{"url": url})
}

type documentReviewRequest struct {
	ID      int64  `json:"id,string"`
	Approve bool   `json:"approve"`
	Notes   string `json:"notes"`
}

// Review approves or rejects a pending document ({id, approve, notes}) with the
// session user as reviewer, and answers 204.
func (h *DocumentHandler) Review(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req documentReviewRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if h.Documents == nil || h.AuthorizeReview == nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "review handler not configured")
		return
	}
	doc, ok := h.authorizedDocument(w, r, session, req.ID, h.AuthorizeReview)
	if !ok {
		return
	}
	if err := h.Documents.Review(r.Context(), doc.PartnerID, doc.ID, int64(session.Id), req.Approve, req.Notes); err != nil {
		h.writeDocumentError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizedDocument loads the document from the session's partner and runs authorize on it.
func (h *DocumentHandler) authorizedDocument(w http.ResponseWriter, r *http.Request, session *model.UserSession, id int64,
	authorize func(context.Context, *model.UserSession, *document.PartnerDocument) error) (*document.PartnerDocument, bool) {
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return nil, false
	}
	doc, err := h.Documents.Get(r.Context(), partnerID, id)
	if err != nil {
		h.writeDocumentError(w, r, err)
		return nil, false
	}
	if err := authorize(r.Context(), session, doc); err != nil {
		h.WriteServiceError(w, r, err)
		return nil, false
	}
	return doc, true
}

func (h *DocumentHandler) writeDocumentError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, document.ErrNotFound):
		h.WriteError(w, http.StatusNotFound, "Not Found", err.Error())
	case errors.Is(err, document.ErrUnknownType):
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
	case errors.Is(err, document.ErrMediaType):
		h.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported Media Type", err.Error())
	case errors.Is(err, document.ErrTooLarge):
		h.WriteError(w, http.StatusRequestEntityTooLarge, "Payload Too Large", err.Error())
	case errors.Is(err, document.ErrInvalidState):
		h.WriteError(w, http.StatusConflict, "Conflict", err.Error())
	case errors.Is(err, document.ErrTenantMismatch), errors.Is(err, document.ErrSelfReview), errors.Is(err, scan.ErrContentRejected):
		h.WriteError(w, http.StatusForbidden, "Forbidden", err.Error())
	default:
		h.WriteServiceError(w, r, err)
	}
}
