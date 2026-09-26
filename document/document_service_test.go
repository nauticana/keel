package document

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/scan"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func TestStoreReadAndTrace(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	doc, err := s.Store(ctx, upload("licence", 5, png))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Status != StatusPending || doc.VersionNo != 1 || doc.FileName != "front.png" || doc.DocKey == "" || doc.ContRepID != "docs" {
		t.Fatalf("stored: %+v", doc)
	}
	got, content, err := s.Read(ctx, 7, doc.ID)
	if err != nil || !bytes.Equal(content, png) {
		t.Fatalf("read: %v", err)
	}
	if got.Content == nil || got.Content.ContentType != "image/png" || got.Content.Length != int64(len(png)) || got.Content.Digest == "" {
		t.Errorf("content attributes: %+v", got.Content)
	}
	if got.OriginIP != "10.0.0.1" || got.UploadedBy != 3 || got.UserID != 5 {
		t.Errorf("trace: %+v", got)
	}
	if _, _, err := s.Read(ctx, 8, doc.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another partner must not read it: %v", err)
	}
}

func TestStoreRefusals(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	if _, err := s.Store(ctx, upload("nope", 0, png)); !errors.Is(err, ErrUnknownType) {
		t.Errorf("unknown type: %v", err)
	}
	if _, err := s.Store(ctx, upload("logo", 0, []byte("plain text"))); !errors.Is(err, ErrMediaType) {
		t.Errorf("wrong media type: %v", err)
	}
	if _, err := s.Store(ctx, upload("logo", 0, append(png, make([]byte, 100)...))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	if _, err := s.Store(ctx, upload("foreign", 0, png)); !errors.Is(err, ErrTenantMismatch) {
		t.Errorf("repository of another partner: %v", err)
	}
	s.Scanner = rejecting{}
	if _, err := s.Store(ctx, upload("logo", 0, png)); !errors.Is(err, scan.ErrContentRejected) {
		t.Errorf("scanner: %v", err)
	}
	if docs, _ := s.ListByPartner(ctx, 7); len(docs) != 0 {
		t.Errorf("a refused upload must leave no row: %d", len(docs))
	}
}

type rejecting struct{}

func (rejecting) Scan(context.Context, []byte) error { return scan.ErrContentRejected }

func TestApprovalSupersedesAndVersions(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	v1, _ := s.Store(ctx, upload("logo", 0, png)) // no review: approved at once
	v2, err := s.Store(ctx, upload("logo", 0, png))
	if err != nil || v2.VersionNo != 2 || v2.Status != StatusApproved {
		t.Fatalf("v2: %+v %v", v2, err)
	}
	if old, _ := s.Get(ctx, 7, v1.ID); old.Status != StatusSuperseded {
		t.Errorf("v1 must be superseded: %s", old.Status)
	}
	if cur, err := s.Approved(ctx, 7, 0, "logo"); err != nil || cur.ID != v2.ID {
		t.Errorf("approved: %+v %v", cur, err)
	}
	if _, err := s.Approved(ctx, 7, 0, "licence"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no approved licence yet: %v", err)
	}
}

func TestReviewWorkflow(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	first, _ := s.Store(ctx, upload("licence", 5, png))
	if err := s.Review(ctx, 7, first.ID, 9, true, ""); err != nil {
		t.Fatal(err)
	}
	if doc, _ := s.Get(ctx, 7, first.ID); doc.Status != StatusApproved || doc.ReviewerID != 9 || doc.ReviewedAt.IsZero() {
		t.Errorf("approved: %+v", doc)
	}
	if err := s.Review(ctx, 7, first.ID, 9, false, "again"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("reviewing twice: %v", err)
	}

	second, _ := s.Store(ctx, upload("licence", 5, png))
	if second.Status != StatusPending || second.VersionNo != 2 {
		t.Fatalf("second: %+v", second)
	}
	if err := s.Review(ctx, 7, second.ID, 9, false, "blurry"); err != nil {
		t.Fatal(err)
	}
	if doc, _ := s.Get(ctx, 7, second.ID); doc.Status != StatusRejected || doc.ReviewerNotes != "blurry" {
		t.Errorf("rejected: %+v", doc)
	}
	if cur, _ := s.Approved(ctx, 7, 5, "licence"); cur == nil || cur.ID != first.ID {
		t.Errorf("a rejection keeps the previous approval: %+v", cur)
	}

	third, _ := s.Store(ctx, upload("licence", 5, png))
	if err := s.Review(ctx, 7, third.ID, 9, true, ""); err != nil {
		t.Fatal(err)
	}
	if doc, _ := s.Get(ctx, 7, first.ID); doc.Status != StatusSuperseded || doc.SupersededAt.IsZero() {
		t.Errorf("an approval supersedes the previous one: %+v", doc)
	}
	if other, _ := s.Store(ctx, upload("licence", 6, png)); other.VersionNo != 1 {
		t.Errorf("versions are per subject: %+v", other)
	}
}

func TestClientAddressingAndReviewerQueries(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	v1, _ := s.Store(ctx, upload("licence", 5, png))
	v2, _ := s.Store(ctx, upload("licence", 5, png))
	logo, _ := s.Store(ctx, upload("logo", 0, png))
	_ = s.Review(ctx, 7, v1.ID, 9, true, "")

	if got, err := s.ByVersion(ctx, 7, 5, "licence", 2); err != nil || got.ID != v2.ID {
		t.Errorf("by version: %+v %v", got, err)
	}
	if _, err := s.ByVersion(ctx, 7, 5, "licence", 3); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing version: %v", err)
	}
	latest, _ := s.Latest(ctx, 7, 5)
	if len(latest) != 1 || latest[0].ID != v2.ID || latest[0].Status != StatusPending {
		t.Errorf("latest per type for the driver: %+v", latest)
	}
	if latest, _ := s.Latest(ctx, 7, 0); len(latest) != 1 || latest[0].ID != logo.ID {
		t.Errorf("latest per type for the partner: %+v", latest)
	}
	if reviewed, _ := s.ReviewedBy(ctx, 7, 9); len(reviewed) != 1 || reviewed[0].ID != v1.ID {
		t.Errorf("reviewed by: %+v", reviewed)
	}
	if pending, _ := s.Pending(ctx, 7); len(pending) != 1 || pending[0].ID != v2.ID {
		t.Errorf("review queue: %+v", pending)
	}
}

func TestOnStoredRunsInTheTransaction(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	var seen *PartnerDocument
	s.OnStored = func(_ context.Context, tx port.TxQueryService, doc *PartnerDocument) error {
		seen = doc
		if doc.VersionNo == 2 {
			return errors.New("profile update failed")
		}
		return nil
	}
	if _, err := s.Store(ctx, upload("logo", 0, png)); err != nil || seen == nil || seen.VersionNo != 1 {
		t.Fatalf("hook: %+v %v", seen, err)
	}
	if _, err := s.Store(ctx, upload("logo", 0, png)); err == nil || err.Error() != "profile update failed" {
		t.Fatalf("hook error must fail the store: %v", err)
	}
	if len(store.rows) != 1 {
		t.Errorf("a failed hook must leave no row: %d", len(store.rows))
	}
	if docs, _ := s.Docs.List(ctx, "docs", 0); len(docs) != 1 {
		t.Errorf("a failed hook must remove the objects: %v", docs)
	}
}

func TestRetire(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	doc, _ := s.Store(ctx, upload("logo", 0, png))
	if err := s.Retire(ctx, 7, doc.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, 7, doc.ID); !errors.Is(err, ErrInvalidState) {
		t.Errorf("retiring twice: %v", err)
	}
	if docs, _ := s.ListByPartner(ctx, 7); len(docs) != 0 {
		t.Errorf("retired documents are hidden from lists: %d", len(docs))
	}
	if _, content, err := s.Read(ctx, 7, doc.ID); err != nil || len(content) == 0 {
		t.Errorf("the object stays for a retention job: %v", err)
	}
	if err := s.Retire(ctx, 7, 12345); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}
