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
	SignedURL(ctx context.Context, partnerID, id int64, expirySeconds int) (string, error)
}

// DocumentHandler is the HTTP surface over document.DocumentService: a
// multipart upload and a signed preview URL. Authorize decides whether the
// session may store the upload (its subject and type); return a
// *model.AppError to refuse.
type DocumentHandler struct {
	AbstractHandler
	Documents        DocumentStore
	Authorize        func(ctx context.Context, session *model.UserSession, up *document.Upload) error
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
	if h.Documents == nil || h.SignedURLSeconds <= 0 {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "preview handler not configured")
		return
	}
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "id is required")
		return
	}
	url, err := h.Documents.SignedURL(r.Context(), partnerID, id, h.SignedURLSeconds)
	if err != nil {
		h.writeDocumentError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]string{"url": url})
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
	case errors.Is(err, document.ErrTenantMismatch), errors.Is(err, scan.ErrContentRejected):
		h.WriteError(w, http.StatusForbidden, "Forbidden", err.Error())
	default:
		h.WriteServiceError(w, r, err)
	}
}
