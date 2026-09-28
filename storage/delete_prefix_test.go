package storage

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestDeletePrefix(t *testing.T) {
	s := newFileStore(t)
	ctx := context.Background()
	for _, key := range []string{"user/1/a", "user/1/b/c", "user/10/a", "other/x"} {
		put(t, s, key, "x", nil)
	}
	n, err := DeletePrefix(ctx, s, "user/1/")
	if err != nil || n != 2 {
		t.Fatalf("deleted %d: %v", n, err)
	}
	left, _ := s.ListObjects(ctx, "", 0)
	slices.Sort(left)
	if !slices.Equal(left, []string{"other/x", "user/10/a"}) {
		t.Errorf("only the prefix is deleted: %v", left)
	}
	if n, err := DeletePrefix(ctx, s, "user/1/"); err != nil || n != 0 {
		t.Errorf("re-running is a no-op: %d %v", n, err)
	}
	for _, prefix := range []string{"", "/", "//"} {
		if _, err := DeletePrefix(ctx, s, prefix); !errors.Is(err, ErrEmptyPrefix) {
			t.Errorf("prefix %q must be refused: %v", prefix, err)
		}
	}
}

type stuckListing struct{ ObjectStorage }

func (stuckListing) ListObjects(_ context.Context, prefix string, limit int) ([]string, error) {
	keys := make([]string, limit)
	for i := range keys {
		keys[i] = prefix + "k"
	}
	return keys, nil
}
func (stuckListing) DeleteObject(context.Context, string) error { return ErrNotFound }

func TestDeletePrefixStopsOnStaleListing(t *testing.T) {
	if _, err := DeletePrefix(context.Background(), stuckListing{}, "p/"); err == nil {
		t.Fatal("a listing that never shrinks must end in an error, not a loop")
	}
}
