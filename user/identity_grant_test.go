package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/logger"
)

type revokeCall struct {
	issuer, sealed string
	commits        int
}

type fakeRevoker struct {
	store *memStore
	calls []revokeCall
	err   error
}

func (f *fakeRevoker) RevokeGrant(_ context.Context, issuer, sealed string) error {
	f.calls = append(f.calls, revokeCall{issuer, sealed, f.store.commits})
	return f.err
}

type errorJournal struct {
	logger.ApplicationLogger
	errors []string
}

func (j *errorJournal) Error(log string) { j.errors = append(j.errors, log) }

func appleIdentity(grant string) ExternalIdentity {
	return ExternalIdentity{Provider: "apple", Issuer: AppleIssuer, Subject: "apple-sub", Grant: grant}
}

func TestDeleteAccountRevokesIdentityGrantsAfterCommit(t *testing.T) {
	store := newMemStore()
	s := newLocalUserService(t, store)
	revoker := &fakeRevoker{store: store}
	s.GrantRevoker = revoker
	session, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	commits := store.commits
	if err := s.DeleteAccount(session.Id, "requested"); err != nil {
		t.Fatal(err)
	}
	want := []revokeCall{{AppleIssuer, "sealed-1", commits + 1}}
	if len(revoker.calls) != 1 || revoker.calls[0] != want[0] {
		t.Fatalf("the stored grant is revoked once, after the deletion commits: %+v", revoker.calls)
	}
	if len(store.grants) != 0 {
		t.Errorf("the grant leaves with its link: %v", store.grants)
	}
}

func TestDeleteAccountJournalsFailedRevocation(t *testing.T) {
	store := newMemStore()
	s := newLocalUserService(t, store)
	journal := &errorJournal{}
	s.GrantRevoker, s.Journal = &fakeRevoker{store: store, err: errors.New("apple down")}, journal
	session, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccount(session.Id, "requested"); err != nil {
		t.Fatalf("a failed revocation does not undo the deletion: %v", err)
	}
	if !store.deleted[session.Id] || len(journal.errors) != 1 || !strings.Contains(journal.errors[0], "apple down") {
		t.Fatalf("deleted and journaled: deleted=%v journal=%v", store.deleted[session.Id], journal.errors)
	}
}

func TestDeleteAccountJournalsGrantWithoutRevoker(t *testing.T) {
	store := newMemStore()
	s := newLocalUserService(t, store)
	journal := &errorJournal{}
	s.Journal = journal
	session, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccount(session.Id, "requested"); err != nil {
		t.Fatal(err)
	}
	if len(journal.errors) != 1 || !strings.Contains(journal.errors[0], "no GrantRevoker") {
		t.Fatalf("an unrevocable grant is journaled: %v", journal.errors)
	}
}

func TestDeleteAccountUnderLegalHoldRevokesNothing(t *testing.T) {
	store := newMemStore()
	s := newLocalUserService(t, store)
	revoker := &fakeRevoker{store: store}
	s.GrantRevoker = revoker
	session, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	store.holds[session.Id] = true
	if err := s.DeleteAccount(session.Id, "requested"); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("want ErrLegalHold, got %v", err)
	}
	if len(revoker.calls) != 0 || store.grants[AppleIssuer+"|apple-sub"] != "sealed-1" {
		t.Fatalf("a refused deletion keeps the grant: calls=%v grants=%v", revoker.calls, store.grants)
	}
}

func TestSignInReplacesStoredGrantOnlyWhenOneIsPresented(t *testing.T) {
	store := newMemStore()
	s := newLocalUserService(t, store)
	if _, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-1"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetOrCreateUserFromSocial(appleIdentity(""), nil); err != nil {
		t.Fatal(err)
	}
	key := AppleIssuer + "|apple-sub"
	if store.grants[key] != "sealed-1" {
		t.Fatalf("a sign-in without a grant keeps the stored one: %q", store.grants[key])
	}
	if _, _, err := s.GetOrCreateUserFromSocial(appleIdentity("sealed-2"), nil); err != nil {
		t.Fatal(err)
	}
	if store.grants[key] != "sealed-2" {
		t.Fatalf("a newer grant replaces the stored one: %q", store.grants[key])
	}
}

func TestLinkExternalIdentityStoresGrant(t *testing.T) {
	store := newMemStore()
	store.addAccount(5, "ada@example.com", UserStatusActive)
	s := newLocalUserService(t, store)
	if err := s.LinkExternalIdentity(5, appleIdentity("sealed-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkExternalIdentity(5, appleIdentity("sealed-2")); err != nil {
		t.Fatal(err)
	}
	if got := store.grants[AppleIssuer+"|apple-sub"]; got != "sealed-2" {
		t.Fatalf("relinking the held identity refreshes its grant: %q", got)
	}
}
