package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
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
			if got := s.PublicURL(tc.key); got != tc.want {
				t.Fatalf("PublicURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGCSPublicURL(t *testing.T) {
	s := &StorageGCS{name: "my-bucket"}
	got := s.PublicURL("/path/to/obj.png")
	want := "https://storage.googleapis.com/my-bucket/path/to/obj.png"
	if got != want {
		t.Fatalf("PublicURL = %q, want %q", got, want)
	}
}

func TestFactoryUnknownMode(t *testing.T) {
	if _, err := New(context.Background(), Spec{Mode: "nope", Bucket: "b"}, nil); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestFactoryRequiresBucket(t *testing.T) {
	if _, err := New(context.Background(), Spec{Mode: "file", Bucket: " "}, nil); err == nil || !strings.Contains(err.Error(), "bucket is required") {
		t.Fatalf("expected bucket error, got %v", err)
	}
}

func TestFactoryNeverCreatesBucket(t *testing.T) {
	spec := Spec{Mode: "file", Bucket: t.TempDir() + "/missing"}
	if _, err := New(context.Background(), spec, nil); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if err := CreateBucket(context.Background(), spec, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), spec, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAzureAccountName(t *testing.T) {
	name, err := azureAccountName("https://acct.blob.core.windows.net/")
	if err != nil || name != "acct" {
		t.Fatalf("account = %q %v", name, err)
	}
	if _, err := azureAccountName("nope"); err == nil {
		t.Fatal("expected an error for a URL without a host")
	}
}

func TestAzurePublicURLKeepsKeySlashes(t *testing.T) {
	s := &StorageAzure{name: "docs", url: "https://acct.blob.core.windows.net/"}
	got := s.PublicURL("a b/c+d.pdf")
	want := "https://acct.blob.core.windows.net/docs/a%20b/c+d.pdf"
	if got != want {
		t.Fatalf("PublicURL = %q, want %q", got, want)
	}
}

func TestFactoryAzureRequiresAccountURL(t *testing.T) {
	_, err := New(context.Background(), Spec{Mode: "azure", Bucket: "c"}, nil)
	if err == nil || !strings.Contains(err.Error(), "AccountURL is required") {
		t.Fatalf("expected AccountURL error, got %v", err)
	}
}
