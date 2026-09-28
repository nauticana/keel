package recording

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRetentionSweeper_PurgesDueMediaAndHonorsHold(t *testing.T) {
	svc, store, _, stor := newService(t)
	ctx := context.Background()
	kept, keptToken := readySession(t, svc, "order:20")
	held, heldToken := readySession(t, svc, "order:21")
	old, _ := svc.Upload(ctx, kept.ID, 1, keptToken, "old", "video/mp4", strings.NewReader("x"))
	fresh, _ := svc.Upload(ctx, kept.ID, 1, keptToken, "fresh", "video/mp4", strings.NewReader("x"))
	heldMedia, _ := svc.Upload(ctx, held.ID, 1, heldToken, "old", "video/mp4", strings.NewReader("x"))
	store.media[old.ID][7] = time.Now().Add(-48 * time.Hour)
	store.media[heldMedia.ID][7] = time.Now().Add(-48 * time.Hour)

	sweeper := &RetentionSweeper{DB: svc.DB, Storage: stor, Retention: 24 * time.Hour,
		Hold: func(_ context.Context, s Session) (bool, error) { return s.ID == held.ID, nil }}
	n, err := sweeper.Sweep(ctx)
	if err != nil || n != 1 || len(stor.deleted) != 1 || stor.deleted[0] != old.ObjectKey {
		t.Fatalf("purged=%d deleted=%v err=%v", n, stor.deleted, err)
	}
	if store.media[old.ID][6] != MediaPurged || store.media[fresh.ID][6] != MediaReady || store.media[heldMedia.ID][6] != MediaReady {
		t.Fatal("wrong rows purged")
	}
	if _, err := svc.MediaURL(ctx, kept.ID, 1, old.ID, 60); !errors.Is(err, ErrMediaPurged) {
		t.Fatalf("purged media url: %v", err)
	}
	if n, err := sweeper.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep purged=%d err=%v", n, err)
	}
}

func TestRetentionSweeper_RequiresRetention(t *testing.T) {
	svc, _, _, stor := newService(t)
	if _, err := (&RetentionSweeper{DB: svc.DB, Storage: stor}).Sweep(context.Background()); err == nil {
		t.Fatal("zero retention accepted")
	}
}
