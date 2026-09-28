package erasure

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nauticana/keel/user"
)

func TestRequestPlansAndReturnsTheOpenRequest(t *testing.T) {
	store := newMemStore(5, 6)
	s := newTestService(store, &memAccounts{}, activityClassifier())
	ctx := context.Background()
	plan, err := s.Request(ctx, 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Request.Status != StatusPending || plan.Request.UserID != 5 || len(plan.Items) != 3 || plan.Items[0].Table != "activity" {
		t.Fatalf("plan: %+v", plan)
	}
	again, err := s.Request(ctx, 5, 1)
	if err != nil || again.Request.ID != plan.Request.ID {
		t.Fatalf("an open request is returned, not duplicated: %+v %v", again, err)
	}
	if _, err := s.Request(ctx, 404, 1); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := s.PlaceHold(ctx, 6, "litigation", 1); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Request(ctx, 6, 6); held.Request.Status != StatusHeld {
		t.Errorf("a user under hold gets a held request: %+v", held.Request)
	}
}

func TestInvalidClassification(t *testing.T) {
	ctx := context.Background()
	noReason := &memClassifier{table: "activity", items: []Item{{Key: "1", Action: ActionHold}}}
	if _, err := newTestService(newMemStore(5), &memAccounts{}, noReason).Request(ctx, 5, 5); !errors.Is(err, ErrInvalidItem) {
		t.Errorf("a hold without reason: %v", err)
	}
	for _, set := range [][]Classifier{
		{&memClassifier{table: "a"}, &memClassifier{table: "a"}},
		{&memClassifier{table: "user_account"}},
		{&memClassifier{}},
	} {
		if _, err := newTestService(newMemStore(5), &memAccounts{}, set...).Request(ctx, 5, 5); !errors.Is(err, ErrInvalidClassifier) {
			t.Errorf("classifier set %v: %v", set, err)
		}
	}
}

func TestExecuteAuditsEveryRowAndKeepsPseudonymForHeldRows(t *testing.T) {
	store, accounts, activity := newMemStore(5), &memAccounts{}, activityClassifier()
	s := newTestService(store, accounts, activity)
	ctx := context.Background()
	plan, _ := s.Request(ctx, 5, 5)
	if err := s.Execute(ctx, plan.Request.ID, 5); err != nil {
		t.Fatal(err)
	}
	pseudonym := store.pseudonyms[5]
	if pseudonym == "" || !slices.Equal(activity.erased, []string{"D:1:", "A:2:" + pseudonym}) {
		t.Fatalf("delete, anonymize with the pseudonym, never touch the held row: %v", activity.erased)
	}
	if !slices.Equal(accounts.deleted, []int{5}) {
		t.Errorf("the account itself is erased last: %v", accounts.deleted)
	}
	audit, _ := s.Audit(ctx, plan.Request.ID)
	var got []string
	for _, e := range audit {
		got = append(got, e.Table+"/"+e.Key+"/"+string(e.Action)+"/"+e.Reason)
	}
	if !slices.Equal(got, []string{"activity/1/D/", "activity/2/A/", "activity/3/H/incident 17", "user_account/5/A/"}) {
		t.Errorf("audit: %v", got)
	}
	if !slices.Contains(store.catalogs, "erasure.activity") {
		t.Errorf("Erase runs on the classifier catalog bound to the transaction: %v", store.catalogs)
	}

	if err := s.Execute(ctx, plan.Request.ID, 5); err != nil || len(activity.erased) != 2 {
		t.Errorf("a re-run skips audited rows: %v %v", err, activity.erased)
	}
	who, err := s.ResolvePseudonym(ctx, pseudonym, 1, "court order 4")
	if err != nil || who != 5 || len(store.lookups) != 1 {
		t.Errorf("held data stays re-identifiable, with the lookup recorded: %d %v %v", who, err, store.lookups)
	}
}

func TestExecuteWithoutHeldRowsDropsPseudonym(t *testing.T) {
	store := newMemStore(5)
	activity := &memClassifier{table: "activity", items: []Item{{Key: "2", Action: ActionAnonymize}}}
	s := newTestService(store, &memAccounts{}, activity)
	ctx := context.Background()
	plan, _ := s.Request(ctx, 5, 5)
	if err := s.Execute(ctx, plan.Request.ID, 5); err != nil {
		t.Fatal(err)
	}
	if len(activity.erased) != 1 || strings.HasSuffix(activity.erased[0], ":") {
		t.Fatalf("anonymized with a pseudonym: %v", activity.erased)
	}
	if _, ok := store.pseudonyms[5]; ok {
		t.Error("with nothing retained the pseudonym mapping is destroyed")
	}
}

func TestExecuteResumesAfterFailure(t *testing.T) {
	store, accounts, activity := newMemStore(5), &memAccounts{}, activityClassifier()
	activity.failKey = "2"
	s := newTestService(store, accounts, activity)
	ctx := context.Background()
	plan, _ := s.Request(ctx, 5, 5)
	if err := s.Execute(ctx, plan.Request.ID, 5); err == nil {
		t.Fatal("the failing row must fail the run")
	}
	if len(store.audit) != 1 || len(accounts.deleted) != 0 || len(store.pseudonyms) != 0 {
		t.Fatalf("only the committed row is audited; the failed row's audit and pseudonym roll back: %v %v", store.audit, store.pseudonyms)
	}
	activity.failKey = ""
	if err := s.Execute(ctx, plan.Request.ID, 5); err != nil {
		t.Fatal(err)
	}
	if len(activity.erased) != 2 || activity.erased[0] != "D:1:" || len(store.audit) != 4 {
		t.Errorf("the re-run finishes without repeating row 1: %v %d", activity.erased, len(store.audit))
	}
}

func TestExecuteHonorsLegalHold(t *testing.T) {
	store, accounts, activity := newMemStore(5), &memAccounts{}, activityClassifier()
	s := newTestService(store, accounts, activity)
	ctx := context.Background()
	plan, _ := s.Request(ctx, 5, 5)
	holdID, err := s.PlaceHold(ctx, 5, "litigation", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(ctx, plan.Request.ID, 5); !errors.Is(err, user.ErrLegalHold) || len(activity.erased) != 0 {
		t.Fatalf("a held user is not erased: %v %v", err, activity.erased)
	}
	if err := s.ReleaseHold(ctx, holdID, 1); err != nil {
		t.Fatal(err)
	}
	activity.onErase = func(Item) { store.holds[99] = &holdRow{userID: 5, reason: "new incident"} }
	if err := s.Execute(ctx, plan.Request.ID, 5); !errors.Is(err, user.ErrLegalHold) {
		t.Fatalf("a hold placed mid-run stops the next row: %v", err)
	}
	if len(activity.erased) != 1 || len(accounts.deleted) != 0 {
		t.Errorf("rows after the hold and the account are kept: %v %v", activity.erased, accounts.deleted)
	}
}

func TestLegalHolds(t *testing.T) {
	s := newTestService(newMemStore(5), &memAccounts{})
	ctx := context.Background()
	if _, err := s.PlaceHold(ctx, 5, "", 1); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("a hold needs a reason: %v", err)
	}
	id, _ := s.PlaceHold(ctx, 5, "regulator inquiry", 1)
	if holds, _ := s.Holds(ctx, 5); len(holds) != 1 || holds[0].ID != id || holds[0].Reason != "regulator inquiry" {
		t.Fatalf("holds: %+v", holds)
	}
	if err := s.ReleaseHold(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseHold(ctx, id, 2); !errors.Is(err, ErrHoldNotFound) {
		t.Errorf("released twice: %v", err)
	}
	if holds, _ := s.Holds(ctx, 5); len(holds) != 0 {
		t.Errorf("released holds are not listed: %+v", holds)
	}
}

func TestResolvePseudonymRefusals(t *testing.T) {
	s := newTestService(newMemStore(5), &memAccounts{})
	ctx := context.Background()
	if _, err := s.ResolvePseudonym(ctx, "abc", 1, ""); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("a lookup needs a reason: %v", err)
	}
	if _, err := s.ResolvePseudonym(ctx, "abc", 1, "audit"); !errors.Is(err, ErrUnknownPseudonym) {
		t.Errorf("unknown pseudonym: %v", err)
	}
}

func TestCancel(t *testing.T) {
	store, accounts := newMemStore(5, 6), &memAccounts{}
	s := newTestService(store, accounts)
	ctx := context.Background()
	plan, _ := s.Request(ctx, 5, 5)
	if err := s.Execute(ctx, plan.Request.ID, 6); !errors.Is(err, ErrRequestUser) {
		t.Fatalf("mismatched request user: %v", err)
	}
	if err := s.Cancel(ctx, plan.Request.ID); err != nil {
		t.Fatal(err)
	}
	if req, _ := s.Get(ctx, plan.Request.ID); req.Status != StatusCancelled {
		t.Errorf("cancelled: %+v", req)
	}
	if err := s.Cancel(ctx, plan.Request.ID); !errors.Is(err, ErrNotCancellable) {
		t.Errorf("a finished request cannot be cancelled: %v", err)
	}
	if err := s.Execute(ctx, plan.Request.ID, 5); !errors.Is(err, ErrNotExecutable) || len(accounts.deleted) != 0 {
		t.Errorf("a cancelled request cannot erase its user: %v, deleted %v", err, accounts.deleted)
	}
	if err := s.Cancel(ctx, 404); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown request: %v", err)
	}
}
