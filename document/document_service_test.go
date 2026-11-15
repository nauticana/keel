package document

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/approval"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/scan"
	"github.com/nauticana/keel/storage"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

var _ SeparationPolicy = (*approval.Service)(nil)

var (
	member = Subject{UserID: 5}
	unit   = Subject{SubjectKey: "org-unit:42"}
)

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
	if info, err := s.Docs.Info(ctx, doc.ContRepID, doc.DocKey); err != nil || info.DocProt != dms.DocProtServerSetting {
		t.Errorf("a partner document leaves the protection to the repository: %+v %v", info, err)
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
	s, store := newService(t)
	ctx := context.Background()
	v1, _ := s.Store(ctx, upload("logo", 0, png)) // no review: approved at once
	v2, err := s.Store(ctx, upload("logo", 0, png))
	if err != nil || v2.VersionNo != 2 || v2.Status != StatusApproved {
		t.Fatalf("v2: %+v %v", v2, err)
	}
	if old, _ := s.Get(ctx, 7, v1.ID); old.Status != StatusSuperseded {
		t.Errorf("v1 must be superseded: %s", old.Status)
	}
	if cur, err := s.Approved(ctx, 7, Subject{}, "logo"); err != nil || cur.ID != v2.ID {
		t.Errorf("approved: %+v %v", cur, err)
	}
	if store.groupLocks != 2 {
		t.Errorf("every approving store must lock its group: %d", store.groupLocks)
	}
	if _, err := s.Approved(ctx, 7, Subject{}, "licence"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no approved licence yet: %v", err)
	}
}

func TestReviewWorkflow(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	first, _ := s.Store(ctx, upload("licence", 5, png))
	store.groupLocks = 0
	if err := s.Review(ctx, 7, first.ID, 9, true, ""); err != nil {
		t.Fatal(err)
	}
	if store.groupLocks != 1 {
		t.Errorf("an approval must lock its group: %d", store.groupLocks)
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
	if cur, _ := s.Approved(ctx, 7, member, "licence"); cur == nil || cur.ID != first.ID {
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

func TestSelfReviewFollowsPolicy(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	doc, _ := s.Store(ctx, upload("licence", 5, png))
	if err := s.Review(ctx, 7, doc.ID, 3, true, ""); !errors.Is(err, approval.ErrSeparation) {
		t.Errorf("without a policy the uploader must not review: %v", err)
	}
	s.Policy = allowing{"other": true}
	if err := s.Review(ctx, 7, doc.ID, 3, true, ""); !errors.Is(err, approval.ErrSeparation) {
		t.Errorf("a policy for another type does not apply: %v", err)
	}
	if err := s.Review(ctx, 7, doc.ID, 9, true, ""); err != nil {
		t.Errorf("another reviewer may: %v", err)
	}
	s.Policy = allowing{"licence": true}
	own, _ := s.Store(ctx, upload("licence", 5, png))
	if err := s.Review(ctx, 7, own.ID, 3, true, ""); err != nil {
		t.Errorf("the policy allows the uploader: %v", err)
	}
}

func TestSubjectKeyVersionsIndependently(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	up := upload("licence", 0, png)
	up.Subject, up.Language = unit, "en-GB"
	v1, err := s.Store(ctx, up)
	if err != nil || v1.VersionNo != 1 || v1.SubjectKey != unit.SubjectKey || v1.Language != "en-GB" {
		t.Fatalf("v1: %+v %v", v1, err)
	}
	if other, _ := s.Store(ctx, upload("licence", 0, png)); other.VersionNo != 1 || other.SubjectKey != "" {
		t.Errorf("the partner's own document is another subject: %+v", other)
	}
	up.Body = bytesReader(png)
	v2, err := s.Store(ctx, up)
	if err != nil || v2.VersionNo != 2 {
		t.Fatalf("v2: %+v %v", v2, err)
	}
	for _, id := range []int64{v1.ID, v2.ID} {
		if err := s.Review(ctx, 7, id, 9, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	if old, _ := s.Get(ctx, 7, v1.ID); old.Status != StatusSuperseded {
		t.Errorf("v1 must be superseded: %s", old.Status)
	}
	if got, err := s.ByVersion(ctx, 7, unit, "licence", 2); err != nil || got.ID != v2.ID || got.UserID != 0 {
		t.Errorf("by version: %+v %v", got, err)
	}
	if docs, _ := s.ListBySubject(ctx, 7, unit); len(docs) != 2 {
		t.Errorf("list by subject: %d", len(docs))
	}
	if cur, _ := s.Approved(ctx, 7, Subject{}, "licence"); cur != nil {
		t.Errorf("an approval supersedes only its subject's version: %+v", cur)
	}
}

func TestStoreRefusesAnInvalidSubject(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	for _, bad := range []Upload{
		{Subject: Subject{UserID: 5, SubjectKey: "x"}},
		{Subject: Subject{SubjectKey: strings.Repeat("k", maxSubjectKey+1)}},
		{Subject: Subject{UserID: -1}},
		{Language: "en-GB-oxendict"},
	} {
		up := upload("logo", 0, png)
		up.Subject, up.Language = bad.Subject, bad.Language
		if _, err := s.Store(ctx, up); !errors.Is(err, ErrInvalidUpload) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestClientAddressingAndReviewerQueries(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	v1, _ := s.Store(ctx, upload("licence", 5, png))
	v2, _ := s.Store(ctx, upload("licence", 5, png))
	logo, _ := s.Store(ctx, upload("logo", 0, png))
	_ = s.Review(ctx, 7, v1.ID, 9, true, "")

	if got, err := s.ByVersion(ctx, 7, member, "licence", 2); err != nil || got.ID != v2.ID {
		t.Errorf("by version: %+v %v", got, err)
	}
	if _, err := s.ByVersion(ctx, 7, member, "licence", 3); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing version: %v", err)
	}
	latest, _ := s.Latest(ctx, 7, member)
	if len(latest) != 1 || latest[0].ID != v2.ID || latest[0].Status != StatusPending {
		t.Errorf("latest per type for the driver: %+v", latest)
	}
	if latest, _ := s.Latest(ctx, 7, Subject{}); len(latest) != 1 || latest[0].ID != logo.ID {
		t.Errorf("latest per type for the partner: %+v", latest)
	}
	if reviewed, _ := s.ReviewedBy(ctx, 7, 9); len(reviewed) != 1 || reviewed[0].ID != v1.ID {
		t.Errorf("reviewed by: %+v", reviewed)
	}
	if pending, _ := s.Pending(ctx, 7); len(pending) != 1 || pending[0].ID != v2.ID {
		t.Errorf("review queue: %+v", pending)
	}
}

func TestStoredHookRunsInTheTransaction(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	var seen *PartnerDocument
	s.Hooks = map[string]Hooks{"logo": {Stored: func(_ context.Context, tx port.TxQueryService, doc *PartnerDocument) error {
		seen = doc
		if doc.VersionNo == 2 {
			return errors.New("profile update failed")
		}
		return nil
	}}}
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

func TestSetTypeKeepsEveryApproval(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	a, _ := s.Store(ctx, upload("attachment", 0, png))
	b, err := s.Store(ctx, upload("attachment", 0, png))
	if err != nil || b.VersionNo != 2 {
		t.Fatalf("second attachment: %+v %v", b, err)
	}
	for _, id := range []int64{a.ID, b.ID} {
		if doc, _ := s.Get(ctx, 7, id); doc.Status != StatusApproved {
			t.Errorf("attachment %d must stay approved: %s", id, doc.Status)
		}
	}
}

func TestRetireAndSweep(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	doc, _ := s.Store(ctx, upload("logo", 0, png))
	cold, _ := s.Store(ctx, upload("cold", 0, png))
	for _, id := range []int64{doc.ID, cold.ID} {
		if err := s.Retire(ctx, 7, id); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.Get(ctx, 7, doc.ID); got.RetiredAt.IsZero() {
		t.Error("retire must stamp retired_at")
	}
	sweeper := &RetentionSweeper{DB: memRepo{store: store}, Docs: s.Docs}
	if _, err := sweeper.Sweep(ctx); err == nil {
		t.Fatal("a zero retention must be refused, not purge everything")
	}
	sweeper.After = time.Hour
	if n, err := sweeper.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("not due yet: %d %v", n, err)
	}

	cat := s.Repos.Catalog.(*catalog)
	cat.defs[2].Status = dms.StatusReadOnly
	if err := s.Repos.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	sweeper.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	n, err := sweeper.Sweep(ctx)
	if n != 1 || !errors.Is(err, dms.ErrRepositoryReadOnly) {
		t.Fatalf("one purged, the read-only one skipped and reported: %d %v", n, err)
	}
	if _, err := s.Docs.Info(ctx, doc.ContRepID, doc.DocKey); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("objects must be gone after the sweep: %v", err)
	}
	if row := store.rows[doc.ID]; row[20] == nil || row[14] != StatusRetired {
		t.Errorf("the row keeps its trace with purged_at: %v", row)
	}
	if _, err := s.Get(ctx, 7, doc.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a purged document is not found: %v", err)
	}
	if _, err := s.SignedURL(ctx, 7, doc.ID, 60); !errors.Is(err, ErrNotFound) {
		t.Errorf("no URL for a purged document: %v", err)
	}
	if n, _ := sweeper.Sweep(ctx); n != 0 {
		t.Errorf("a purged row is not swept again: %d", n)
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
		t.Errorf("the object stays until the sweeper runs: %v", err)
	}
	if err := s.Retire(ctx, 7, 12345); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}

const mediaDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

func TestStoreDOCXWithoutAllowingEveryZip(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	docx := zippedFiles(t, map[string]string{
		"[Content_Types].xml": `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/word/document.xml" ContentType="` + mediaDOCX + `.main+xml"/></Types>`,
		"word/document.xml": "",
	})
	doc, err := s.Store(ctx, upload("brief", 0, docx))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Read(ctx, 7, doc.ID); err != nil || got.Content.ContentType != mediaDOCX {
		t.Errorf("stored media type: %+v %v", got.Content, err)
	}
	if _, err := s.Store(ctx, upload("brief", 0, zippedFiles(t, map[string]string{"a.txt": "a"}))); !errors.Is(err, ErrMediaType) {
		t.Errorf("a plain zip must not pass as DOCX: %v", err)
	}
}

func zippedFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestQueriesDoNotBindIDsAsText(t *testing.T) {
	if got := strings.Count(queries[qLockGroup], "?::bigint::text"); got != 2 {
		t.Errorf("lock_group has %d bigint ID parameters, want 2: %s", got, queries[qLockGroup])
	}
	for name, sql := range queries {
		if strings.Contains(sql, "?::text") {
			t.Errorf("%s casts a placeholder to text: %s", name, sql)
		}
	}
}

func TestSweepKeepsLegalHoldSubject(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	held, _ := s.Store(ctx, upload("logo", 5, png))
	free, _ := s.Store(ctx, upload("attachment", 6, png))
	for _, id := range []int64{held.ID, free.ID} {
		if err := s.Retire(ctx, 7, id); err != nil {
			t.Fatal(err)
		}
	}
	store.heldUsers = map[int64]bool{5: true}
	sweeper := &RetentionSweeper{DB: memRepo{store: store}, Docs: s.Docs, After: time.Hour,
		Now: func() time.Time { return time.Now().Add(2 * time.Hour) }}
	if n, err := sweeper.Sweep(ctx); n != 1 || err != nil {
		t.Fatalf("only the unheld document is purged: %d %v", n, err)
	}
	if store.rows[held.ID][20] != nil {
		t.Fatal("a held subject's document must keep its objects")
	}
	if _, err := s.Docs.Info(ctx, held.ContRepID, held.DocKey); err != nil {
		t.Errorf("held objects must survive: %v", err)
	}
	store.heldUsers = nil
	if n, err := sweeper.Sweep(ctx); n != 1 || err != nil {
		t.Fatalf("released hold is swept on the next pass: %d %v", n, err)
	}
}

func TestReviewedHookRunsInTheTransaction(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	doc, _ := s.Store(ctx, upload("licence", 5, png))
	s.Hooks = map[string]Hooks{"licence": {Reviewed: func(_ context.Context, _ port.TxQueryService, reviewed *PartnerDocument) error {
		if reviewed.Status != StatusApproved || reviewed.ReviewerID != 9 {
			t.Errorf("hook saw %+v", reviewed)
		}
		return errors.New("approval submit failed")
	}}}
	if err := s.Review(ctx, 7, doc.ID, 9, true, ""); err == nil {
		t.Fatal("hook error must fail the review")
	}
	if got, _ := s.Get(ctx, 7, doc.ID); got.Status != StatusPending {
		t.Errorf("a failed hook must roll the review back: %s", got.Status)
	}
}

func TestHooksArePerType(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	s.Hooks = map[string]Hooks{"logo": {Stored: func(context.Context, port.TxQueryService, *PartnerDocument) error {
		return errors.New("logo only")
	}}}
	if _, err := s.Store(ctx, upload("attachment", 0, png)); err != nil {
		t.Fatalf("another type's hook must not run: %v", err)
	}
}

func TestApproveHookGatesTheApproval(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	doc, _ := s.Store(ctx, upload("licence", 5, png))
	refused := errors.New("content does not qualify")
	var seen []byte
	s.Hooks = map[string]Hooks{"licence": {Approve: func(_ context.Context, d *PartnerDocument, content []byte) error {
		seen = content
		return refused
	}}}
	if err := s.Review(ctx, 7, doc.ID, 9, true, ""); !errors.Is(err, refused) || !bytes.Equal(seen, png) {
		t.Fatalf("gate: %v, content %v", err, seen)
	}
	if got, _ := s.Get(ctx, 7, doc.ID); got.Status != StatusPending || len(store.events) != 0 {
		t.Fatalf("a refused approval writes nothing: %s", got.Status)
	}
	if err := s.Review(ctx, 7, doc.ID, 9, false, "no"); err != nil {
		t.Fatalf("a rejection does not pass the gate: %v", err)
	}
}

func TestReviewPublishesTheOutcome(t *testing.T) {
	s, store := newService(t)
	ctx := context.Background()
	s.Hooks = map[string]Hooks{"licence": {Publish: true}}
	approved, _ := s.Store(ctx, upload("licence", 5, png))
	rejected, _ := s.Store(ctx, upload("licence", 6, png))
	if err := s.Review(ctx, 7, approved.ID, 9, true, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Review(ctx, 7, rejected.ID, 9, false, ""); err != nil {
		t.Fatal(err)
	}
	if len(store.events) != 2 || store.events[0][4] != EventApproved || store.events[1][4] != EventRejected ||
		store.events[0][2] != "partner_document" || store.events[0][3] != strconv.FormatInt(approved.ID, 10) {
		t.Fatalf("events: %v", store.events)
	}
	payload := fmt.Sprint(store.events[0][5])
	if !strings.Contains(payload, `"status":"Y"`) || !strings.Contains(payload, `"reviewer_id":9`) || strings.Contains(payload, "origin_ip") || strings.Contains(payload, "file_name") {
		t.Fatalf("payload = %s, want the decision without the document's other columns", payload)
	}
}

func TestTextFormatsAreAdmittedByDeclaration(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	for typ, c := range map[string]struct {
		body string
		want string
	}{
		"notes": {"a,b\n1,2\n", "text/csv"},
		"data":  {`{"a":1}`, "application/json"},
	} {
		up := upload(typ, 0, []byte(c.body))
		doc, err := s.Store(ctx, up)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if _, comp, _ := s.Docs.Read(ctx, doc.ContRepID, doc.DocKey, DataComponent); comp.ContentType != c.want {
			t.Errorf("%s stored as %q, want %q", typ, comp.ContentType, c.want)
		}
	}
	if _, err := s.Store(ctx, upload("notes", 0, []byte("# Title\n\"quoted\" text"))); err != nil {
		t.Errorf("markdown is the next declared format: %v", err)
	}
	if _, err := s.Store(ctx, upload("data", 0, []byte("not json"))); !errors.Is(err, ErrMediaType) {
		t.Errorf("JSON must parse: %v", err)
	}
	if _, err := s.Store(ctx, upload("data", 0, []byte{'{', 0xff, '}'})); !errors.Is(err, ErrMediaType) {
		t.Errorf("text must be UTF-8: %v", err)
	}
}

func TestPartnerDocumentJSONNames(t *testing.T) {
	raw, err := json.Marshal(&PartnerDocument{ID: 1 << 60, ContRepID: "docs", Subject: Subject{UserID: 5}, Status: StatusPending, Content: &dms.Component{}})
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{`"id":"1152921504606846976"`, `"contrep_id":"docs"`, `"user_id":5`, `"status":"P"`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s lacks %s", got, want)
		}
	}
	for _, absent := range []string{"Content", "ContRepID", "reviewed_at", "subject_key"} {
		if strings.Contains(got, absent) {
			t.Errorf("%s carries %s", got, absent)
		}
	}
}
