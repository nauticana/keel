package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

func TestS3PublicURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		key  string
		want string
	}{
		{"custom domain", "https://media.example.com", "businesses/42/1.png", "https://media.example.com/businesses/42/1.png"},
		{"trailing slash trimmed", "https://media.example.com/", "a/b.jpg", "https://media.example.com/a/b.jpg"},
		{"leading slash on key", "https://pub-x.r2.dev", "/k.png", "https://pub-x.r2.dev/k.png"},
		{"empty base disables", "", "k.png", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &StorageS3{publicBaseURL: strings.TrimRight(tc.base, "/")}
			if got := s.PublicURL("ignored-bucket", tc.key); got != tc.want {
				t.Fatalf("PublicURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGCSPublicURL(t *testing.T) {
	s := &StorageGCS{}
	got := s.PublicURL("my-bucket", "/path/to/obj.png")
	want := "https://storage.googleapis.com/my-bucket/path/to/obj.png"
	if got != want {
		t.Fatalf("PublicURL = %q, want %q", got, want)
	}
}

func TestFactoryUnknownMode(t *testing.T) {
	if _, err := New(context.Background(), "nope"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestFactoryAzureRequiresAccountURL(t *testing.T) {
	orig := common.Config().StorageAccountURL
	t.Cleanup(func() { common.Config().StorageAccountURL = orig })
	common.Config().StorageAccountURL = ""
	_, err := New(context.Background(), "azure")
	if err == nil || !strings.Contains(err.Error(), "storage_account_url is required") {
		t.Fatalf("expected storage_account_url error, got %v", err)
	}
}
