package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/storage"
)

type signingFiles struct{ *storage.StorageFile }

func (signingFiles) GetSignedURL(_ context.Context, key string, _ int) (string, error) {
	return "https://signed/" + key, nil
}

func newStorageHandler(t *testing.T) *StorageHandler {
	t.Helper()
	files, err := storage.NewStorageFile(storage.Spec{Mode: "file", Bucket: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return &StorageHandler{
		Uploads: &storage.UploadService{Storage: signingFiles{files}, MaxBytes: 64, ContentTypes: []string{"image/png"}, SignedURLSeconds: 60},
		UploadKey: func(_ context.Context, _ *model.UserSession, _ *http.Request, filename string) (string, error) {
			return "uploads/" + filename, nil
		},
	}
}

func TestStorageHandlerUpload(t *testing.T) {
	h := newStorageHandler(t)
	w := httptest.NewRecorder()
	h.Upload(w, multipartUpload(t, nil, []byte("\x89PNG\r\n\x1a\n")))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"key":"uploads/licence.png"`) {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
}

func TestStorageHandlerRefusalsAreClientSafe(t *testing.T) {
	cases := map[string]struct {
		body   []byte
		status int
		code   string
	}{
		"media type":    {[]byte("%PDF-1.7\n"), http.StatusUnsupportedMediaType, "upload_media_type"},
		"service cap":   {append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...), http.StatusRequestEntityTooLarge, "upload_too_large"},
		"request limit": {bytes.Repeat([]byte("x"), 2<<20), http.StatusRequestEntityTooLarge, "upload_too_large"},
	}
	for name, c := range cases {
		h := newStorageHandler(t)
		w := httptest.NewRecorder()
		h.Upload(w, multipartUpload(t, nil, c.body))
		problem := decodeProblem(t, w)
		if w.Code != c.status || problem.Code != c.code || strings.Contains(problem.Detail, "storage:") || strings.Contains(problem.Detail, "application/pdf") {
			t.Errorf("%s: %d %+v", name, w.Code, problem)
		}
	}
}
