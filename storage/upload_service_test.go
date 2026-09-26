package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type memoryStorage struct {
	ObjectStorage
	objects map[string][]byte
}

func (m *memoryStorage) PutObject(_ context.Context, key string, r io.Reader, _ string, _ map[string]string) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.objects[key] = b
	return nil
}

var pngHeader = []byte("\x89PNG\r\n\x1a\n")

func TestUploadServiceValidatesTypeAndSize(t *testing.T) {
	mem := &memoryStorage{objects: map[string][]byte{}}
	svc := &UploadService{Storage: mem, MaxBytes: 64, ContentTypes: []string{"image/png"}}
	ctx := context.Background()

	png := append(append([]byte{}, pngHeader...), bytes.Repeat([]byte{1}, 40)...)
	mediaType, err := svc.Upload(ctx, "k/ok.png", bytes.NewReader(png))
	if err != nil || mediaType != "image/png" || !bytes.Equal(mem.objects["k/ok.png"], png) {
		t.Fatalf("upload: %v %q", err, mediaType)
	}
	if _, err := svc.Upload(ctx, "k/x.txt", bytes.NewReader([]byte("plain text"))); !errors.Is(err, ErrContentTypeNotAllowed) {
		t.Fatalf("type err = %v", err)
	}
	big := append(append([]byte{}, pngHeader...), bytes.Repeat([]byte{1}, 100)...)
	if _, err := svc.Upload(ctx, "k/big.png", bytes.NewReader(big)); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("size err = %v", err)
	}
	if _, err := svc.Upload(ctx, "k/ok.png", bytes.NewReader(big)); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("overwrite size err = %v", err)
	}
	if _, stored := mem.objects["k/big.png"]; stored || !bytes.Equal(mem.objects["k/ok.png"], png) {
		t.Fatal("an oversized upload must store nothing and leave the existing object intact")
	}
}

func TestSanitizeFilename(t *testing.T) {
	for in, want := range map[string]string{
		"../../etc/passwd":    "passwd",
		`C:\docs\my file.pdf`: "my_file.pdf",
		".hidden":             "hidden",
		"":                    "file",
	} {
		if got := SanitizeFilename(in); got != want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
