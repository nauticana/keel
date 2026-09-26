package handler

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/document"
	"github.com/nauticana/keel/model"
)

type fakeDocuments struct {
	last document.Upload
	body []byte
	err  error
}

func (f *fakeDocuments) Store(_ context.Context, up document.Upload) (*document.PartnerDocument, error) {
	f.last = up
	f.body, _ = io.ReadAll(up.Body)
	if f.err != nil {
		return nil, f.err
	}
	return &document.PartnerDocument{ID: 42, PartnerID: up.PartnerID, DocumentType: up.DocumentType, Status: document.StatusPending}, nil
}

func (f *fakeDocuments) SignedURL(_ context.Context, partnerID, id int64, _ int) (string, error) {
	return "https://signed/" + document.StatusPending, nil
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
