package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func newFileStore(t *testing.T) *StorageFile {
	t.Helper()
	s, err := NewStorageFile(Spec{Bucket: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func put(t *testing.T, s ObjectStorage, key, body string, attrs map[string]string) {
	t.Helper()
	if err := s.PutObject(context.Background(), key, strings.NewReader(body), "text/plain", attrs); err != nil {
		t.Fatal(err)
	}
}

func TestFileStorageRoundTrip(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	put(t, s, "K1/D1/data", "hello", map[string]string{"comp_id": "data", "note": "a=b=c"})

	r, err := s.GetObject(ctx, "K1/D1/data")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != "hello" {
		t.Fatalf("get: %q", got)
	}
	c, err := s.GetObjectAndAttributes(ctx, "K1/D1/data")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.GetContent(), []byte("hello")) || c.GetAttributes()["note"] != "a=b=c" {
		t.Errorf("component: %q %v", c.GetContent(), c.GetAttributes())
	}
}

func TestFileStorageSetAttributesReplaces(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	put(t, s, "K1/D1/data", "x", map[string]string{"a": "1", "b": "2"})
	if err := s.SetObjectAttributes(ctx, "K1/D1/data", map[string]string{"b": "3"}); err != nil {
		t.Fatal(err)
	}
	attrs, err := s.GetObjectAttributes(ctx, "K1/D1/data")
	if err != nil || len(attrs) != 1 || attrs["b"] != "3" {
		t.Fatalf("attrs: %v %v", attrs, err)
	}
	if err := s.SetObjectAttributes(ctx, "K1/D1/data", map[string]string{"bad": "line\nbreak"}); err == nil {
		t.Error("a newline in a value must be refused")
	}
}

func TestFileStorageListMatchesKeyPrefix(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	put(t, s, "K1/D1/data", "x", nil)
	put(t, s, "K1/D1/descr", "x", nil)
	put(t, s, "K1/D10/data", "x", nil)

	for prefix, want := range map[string][]string{
		"K1/D1/": {"K1/D1/data", "K1/D1/descr"},
		"K1/D1":  {"K1/D1/data", "K1/D1/descr", "K1/D10/data"},
		"":       {"K1/D1/data", "K1/D1/descr", "K1/D10/data"},
		"K2/":    nil,
	} {
		got, err := s.ListObjects(ctx, prefix, 0)
		if err != nil {
			t.Fatalf("list %q: %v", prefix, err)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("list %q = %v, want %v", prefix, got, want)
		}
	}
}

func TestFileStorageListLimitAndPrefixes(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	put(t, s, "K1/D1/data", "x", nil)
	put(t, s, "K1/D2/data", "x", nil)
	put(t, s, "K1/D2/descr", "x", nil)
	put(t, s, "K1/ClientKeys/S01", "x", nil)

	if keys, err := s.ListObjects(ctx, "K1/", 1); err != nil || len(keys) != 1 {
		t.Fatalf("limit 1: %v %v", keys, err)
	}
	for prefix, want := range map[string][]string{
		"K1/":  {"ClientKeys", "D1", "D2"},
		"K1/D": {"D1", "D2"},
		"":     {"K1"},
		"K2/":  nil,
	} {
		got, err := s.ListPrefixes(ctx, prefix, 0)
		if err != nil {
			t.Fatalf("prefixes %q: %v", prefix, err)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("prefixes %q = %v, want %v", prefix, got, want)
		}
	}
	if names, _ := s.ListPrefixes(ctx, "K1/", 2); len(names) != 2 {
		t.Errorf("prefixes limit: %v", names)
	}
}

func TestFileStoragePutIfAbsent(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	if err := s.PutObjectIfAbsent(ctx, "K1/D1/dochdr_", strings.NewReader(""), "", map[string]string{"a": "1"}); err != nil {
		t.Fatal(err)
	}
	err := s.PutObjectIfAbsent(ctx, "K1/D1/dochdr_", strings.NewReader("other"), "", map[string]string{"a": "2"})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second put: %v", err)
	}
	attrs, _ := s.GetObjectAttributes(ctx, "K1/D1/dochdr_")
	if attrs["a"] != "1" {
		t.Errorf("first write overwritten: %v", attrs)
	}
}

func TestFileStorageNotFound(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	if _, err := s.GetObject(ctx, "K1/NOPE/data"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := s.GetObjectAttributes(ctx, "K1/NOPE/data"); !errors.Is(err, ErrNotFound) {
		t.Errorf("attrs: %v", err)
	}
	if err := s.SetObjectAttributes(ctx, "K1/NOPE/data", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("set attrs: %v", err)
	}
	if err := s.DeleteObject(ctx, "K1/NOPE/data"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete: %v", err)
	}
}

func TestFileStorageDeleteKeepsNestedObjects(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	put(t, s, "K1", "parent", nil)
	put(t, s, "K1/child", "child", nil)
	if err := s.DeleteObject(ctx, "K1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetObject(ctx, "K1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted object still readable: %v", err)
	}
	if keys, _ := s.ListObjects(ctx, "", 0); !slices.Equal(keys, []string{"K1/child"}) {
		t.Errorf("nested object lost: %v", keys)
	}
}

func TestFileStorageRejectsEscapingKeys(t *testing.T) {
	s := newFileStore(t)
	for _, key := range []string{"../x", "K1/../../x", "", "/"} {
		if err := s.PutObject(context.Background(), key, strings.NewReader("x"), "", nil); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
}

func TestFileStorageServesNoURLs(t *testing.T) {
	s := newFileStore(t)
	if _, err := s.GetSignedURL(context.Background(), "k", 60); !errors.Is(err, ErrUnsupported) {
		t.Errorf("signed URL: %v", err)
	}
	if u := s.PublicURL("k"); u != "" {
		t.Errorf("public URL: %q", u)
	}
}
