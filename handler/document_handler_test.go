package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/document"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/scan"
)

type fakeDocuments struct {
	last     document.Upload
	body     []byte
	err      error
	reviewed []any
}

func (f *fakeDocuments) Store(_ context.Context, up document.Upload) (*document.PartnerDocument, error) {
	f.last = up
	f.body, _ = io.ReadAll(up.Body)
	if f.err != nil {
		return nil, f.err
	}
	return &document.PartnerDocument{ID: 42, PartnerID: up.PartnerID, DocumentType: up.DocumentType, Status: document.StatusPending}, nil
}

func (f *fakeDocuments) Get(_ context.Context, partnerID, id int64) (*document.PartnerDocument, error) {
	if id != 42 {
		return nil, document.ErrNotFound
	}
	return &document.PartnerDocument{ID: id, PartnerID: partnerID, UploadedBy: 3, Status: document.StatusPending}, nil
}

func (f *fakeDocuments) SignedURL(_ context.Context, partnerID, id int64, _ int) (string, error) {
	return "https://signed/" + document.StatusPending, nil
}

func (f *fakeDocuments) Review(_ context.Context, partnerID, id, reviewerID int64, approve bool, notes string) error {
	f.reviewed = []any{partnerID, id, reviewerID, approve, notes}
	return f.err
}

func multipartUpload(t *testing.T, fields map[string]string, file []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if file != nil {
		part, _ := mw.CreateFormFile("file", "licence.png")
		part.Write(file)
	}
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/documents/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	stashSession(r, &model.UserSession{Id: 3, PartnerId: 7})
	return r
}

func TestDocumentHandlerUpload(t *testing.T) {
	docs := &fakeDocuments{}
	authorized := false
	h := &DocumentHandler{Documents: docs, Authorize: func(_ context.Context, s *model.UserSession, up *document.Upload) error {
		authorized = s.Id == 3 && up.UserID == 5
		return nil
	}}
	w := httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF", "title": "Front", "user_id": "5", "expires_on": "2030-01-31"}, []byte("png")))
	if w.Code != http.StatusCreated || !authorized {
		t.Fatalf("upload: %d %s authorized=%v", w.Code, w.Body.String(), authorized)
	}
	up := docs.last
	if up.PartnerID != 7 || up.UploadedBy != 3 || up.UserID != 5 || up.DocumentType != "DF" || up.FileName != "licence.png" ||
		up.ExpiresOn.Year() != 2030 || string(docs.body) != "png" {
		t.Errorf("upload fields: %+v %q", up, docs.body)
	}

	w = httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF"}, nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing file: %d", w.Code)
	}
	h.MaxBytes = 2
	w = httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF"}, bytes.Repeat([]byte("x"), 1<<21)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", w.Code)
	}
	h.MaxBytes = 0
	docs.err = document.ErrMediaType
	w = httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF"}, []byte("x")))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("refused media type: %d", w.Code)
	}
	docs.err = fmt.Errorf("%w: Eicar-Signature FOUND", scan.ErrContentRejected)
	w = httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF"}, []byte("x")))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "Eicar") || !strings.Contains(w.Body.String(), "content_rejected") {
		t.Errorf("scanner refusal must not reach the client: %d %s", w.Code, w.Body.String())
	}
	h.Authorize = func(context.Context, *model.UserSession, *document.Upload) error {
		return model.NewForbidden("not yours")
	}
	docs.err = nil
	w = httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, map[string]string{"document_type": "DF"}, []byte("x")))
	if w.Code != http.StatusForbidden {
		t.Errorf("authorize refusal: %d", w.Code)
	}
}

func onlyUploader(_ context.Context, s *model.UserSession, doc *document.PartnerDocument) error {
	if doc.UploadedBy != int64(s.Id) {
		return model.NewForbidden("not yours")
	}
	return nil
}

func sessionRequest(method, target, body string, userID int) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	stashSession(r, &model.UserSession{Id: userID, PartnerId: 7})
	return r
}

func TestDocumentHandlerPreview(t *testing.T) {
	h := &DocumentHandler{Documents: &fakeDocuments{}, SignedURLSeconds: 60}
	w := httptest.NewRecorder()
	h.Preview(w, sessionRequest(http.MethodGet, "/documents/preview?id=42", "", 3))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("preview without AuthorizeRead must fail closed: %d", w.Code)
	}
	h.AuthorizeRead = onlyUploader
	w = httptest.NewRecorder()
	h.Preview(w, sessionRequest(http.MethodGet, "/documents/preview?id=42", "", 3))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://signed/") {
		t.Errorf("owner preview: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Preview(w, sessionRequest(http.MethodGet, "/documents/preview?id=42", "", 4))
	if w.Code != http.StatusForbidden {
		t.Errorf("another member's preview: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Preview(w, sessionRequest(http.MethodGet, "/documents/preview?id=41", "", 3))
	if w.Code != http.StatusNotFound {
		t.Errorf("missing document: %d", w.Code)
	}
}

func TestDocumentHandlerReview(t *testing.T) {
	docs := &fakeDocuments{}
	h := &DocumentHandler{Documents: docs}
	body := `{"id":"42","approve":true,"notes":"ok"}`
	w := httptest.NewRecorder()
	h.Review(w, sessionRequest(http.MethodPost, "/documents/review", body, 9))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("review without AuthorizeReview must fail closed: %d", w.Code)
	}
	h.AuthorizeReview = func(context.Context, *model.UserSession, *document.PartnerDocument) error { return nil }
	w = httptest.NewRecorder()
	h.Review(w, sessionRequest(http.MethodPost, "/documents/review", body, 9))
	if w.Code != http.StatusNoContent || fmt.Sprint(docs.reviewed) != "[7 42 9 true ok]" {
		t.Errorf("review: %d %v", w.Code, docs.reviewed)
	}
	for err, code := range map[error]int{document.ErrInvalidState: http.StatusConflict, document.ErrSelfReview: http.StatusForbidden} {
		docs.err = err
		w = httptest.NewRecorder()
		h.Review(w, sessionRequest(http.MethodPost, "/documents/review", body, 9))
		if w.Code != code {
			t.Errorf("%v: %d, want %d", err, w.Code, code)
		}
	}
}
