package content

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/oauth/connect"
)

var _ AccessResolver = (*connect.CredentialStoreDB)(nil)

type fakeWriter struct {
	ref   ResourceRef
	field string
}

func (f *fakeWriter) ReadField(_ context.Context, ref ResourceRef, field string) (string, error) {
	f.ref, f.field = ref, field
	return "live value", nil
}

func (f *fakeWriter) UpdateField(context.Context, ResourceRef, string, string) (WriteResult, error) {
	return WriteResult{}, nil
}

type fakeAccess struct {
	err   error
	calls int
}

func (f *fakeAccess) ResolveAccess(context.Context, int64, string) (string, string, error) {
	f.calls++
	return "tok", "https://shop.example/admin/api/v1", f.err
}

func TestWritersSelectsByProvider(t *testing.T) {
	w := &fakeWriter{}
	writers := Writers{"shopify": w, "unwired": nil}
	if got, err := writers.For("shopify"); err != nil || got != w {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, provider := range []string{"wordpress", "unwired"} {
		if _, err := writers.For(provider); !errors.Is(err, ErrUnsupportedProvider) {
			t.Fatalf("%s: err = %v", provider, err)
		}
	}
}

func TestConnectionFieldReaderBuildsRefFromConnection(t *testing.T) {
	w := &fakeWriter{}
	r, err := NewConnectionFieldReader(&fakeAccess{}, Writers{"shopify": w})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.ReadField(context.Background(), 7, "shopify", "page", "gid://1", "title")
	if err != nil || got != "live value" {
		t.Fatalf("got %q, %v", got, err)
	}
	want := ResourceRef{Endpoint: "https://shop.example/admin/api/v1", Token: "tok", Kind: "page", ID: "gid://1"}
	if w.ref != want || w.field != "title" {
		t.Fatalf("ref = %+v field = %q", w.ref, w.field)
	}
}

func TestConnectionFieldReaderErrors(t *testing.T) {
	access := &fakeAccess{}
	r, err := NewConnectionFieldReader(access, Writers{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadField(context.Background(), 7, "shopify", "page", "1", "title"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("err = %v", err)
	}
	if access.calls != 0 {
		t.Fatal("resolved a token for a provider with no writer")
	}
	r, err = NewConnectionFieldReader(&fakeAccess{err: connect.ErrNoActiveConnection}, Writers{"shopify": &fakeWriter{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadField(context.Background(), 7, "shopify", "page", "1", "title"); !errors.Is(err, connect.ErrNoActiveConnection) {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewConnectionFieldReader(nil, Writers{}); err == nil {
		t.Fatal("nil access resolver accepted")
	}
}
