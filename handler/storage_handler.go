package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/storage"
)

const multipartFramingAllowance = 1 << 20

func init() {
	RegisterErrorMessage(storage.ErrContentTypeNotAllowed, http.StatusUnsupportedMediaType, "upload_media_type", "This kind of file cannot be uploaded")
	RegisterErrorMessage(storage.ErrObjectTooLarge, http.StatusRequestEntityTooLarge, "upload_too_large", "The file exceeds the size limit")
}

// StorageHandler is the HTTP surface over storage.UploadService. The app
// injects where an upload lands and which object a preview request may read;
// both hooks authorize the caller and return a *model.AppError to refuse.
type StorageHandler struct {
	AbstractHandler
	Uploads *storage.UploadService
	// UploadKey returns the full object key for an upload; filename is sanitized.
	UploadKey func(ctx context.Context, session *model.UserSession, r *http.Request, filename string) (string, error)
	// PreviewKey returns the object key the request may read.
	PreviewKey func(ctx context.Context, session *model.UserSession, r *http.Request) (string, error)
}

// Upload accepts multipart field "file" and answers {key, contentType, url}
// where url is a short-lived signed read URL.
func (h *StorageHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Uploads == nil || h.UploadKey == nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "upload handler not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.Uploads.MaxBytes+multipartFramingAllowance)
	file, header, err := r.FormFile("file")
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		h.WriteServiceError(w, r, storage.ErrObjectTooLarge)
		return
	}
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "multipart field file is required")
		return
	}
	defer file.Close()
	key, err := h.UploadKey(r.Context(), session, r, storage.SanitizeFilename(header.Filename))
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	contentType, err := h.Uploads.Upload(r.Context(), key, file)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	url, err := h.Uploads.SignedURL(r.Context(), key)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusCreated, map[string]string{"key": key, "contentType": contentType, "url": url})
}

// Preview answers {url} with a short-lived signed read URL; it is never persisted.
func (h *StorageHandler) Preview(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Uploads == nil || h.PreviewKey == nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", "preview handler not configured")
		return
	}
	key, err := h.PreviewKey(r.Context(), session, r)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	url, err := h.Uploads.SignedURL(r.Context(), key)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]string{"url": url})
}
