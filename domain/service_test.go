package domain

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/port"
)

const (
	partnerA = int64(10)
	partnerB = int64(20)
	userA    = int64(1)
	userB    = int64(2)
)

type txtResolver map[string][]string

func (r txtResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return r[name], nil
}

func setup(verifiers ...DomainVerifier) (*Service, *memStore) {
	store := newStore()
	store.addDomain(partnerA, "https://www.Example.com/", userA)
	store.addDomain(partnerB, "example.com", userB)
	return &Service{DB: memRepo{store: store}, Verifiers: verifiers}, store
}

func TestDNSChallengeConfirmAndRecheckLifecycle(t *testing.T) {
	ctx := context.Background()
	dns := txtResolver{}
	svc, store := setup(&DNSTXTVerifier{Resolver: dns})
	var lapsed []*Verification
	svc.OnLapsed = func(_ context.Context, v *Verification) error { lapsed = append(lapsed, v); return nil }

	ch, err := svc.Challenge(ctx, partnerA, userA, "https://www.Example.com/", MethodDNSTXT, "")
	if err != nil {
		t.Fatal(err)
	}
	if ch.DomainName != "example.com" || ch.RecordName != "example.com" || ch.RecordValue != TXTValue(ch.Token) {
		t.Fatalf("challenge = %+v", ch)
	}
	if _, err := svc.Confirm(ctx, partnerA, userA, "https://www.Example.com/", MethodDNSTXT, ""); !errors.Is(err, ErrDomainNotProven) {
		t.Fatalf("unpublished record: %v", err)
	}
	dns["example.com"] = []string{"v=spf1 -all", ch.RecordValue}
	v, err := svc.Confirm(ctx, partnerA, userA, "https://www.Example.com/", MethodDNSTXT, "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Method != MethodDNSTXT || v.DomainName != "example.com" || v.VerifiedBy != userA || !v.Current() {
		t.Fatalf("verification = %+v", v)
	}
	if len(store.challenges) != 0 {
		t.Fatal("confirmed challenge must be consumed")
	}
	if holder, err := svc.IdentityHolder(ctx, "EXAMPLE.com."); err != nil || holder != partnerA {
		t.Fatalf("IdentityHolder = %d, %v", holder, err)
	}

	cfg := config.Config()
	store.tick(cfg.DomainRecheckInterval)
	if sum, err := svc.Recheck(ctx, 10); err != nil || sum.Held != 1 {
		t.Fatalf("held recheck = %+v, %v", sum, err)
	}

	delete(dns, "example.com")
	store.tick(cfg.DomainRecheckInterval)
	if sum, err := svc.Recheck(ctx, 10); err != nil || sum.Failing != 1 {
		t.Fatalf("first failure = %+v, %v", sum, err)
	}
	if _, err := svc.IdentityHolder(ctx, "example.com"); err != nil {
		t.Fatalf("failing evidence stays current within grace: %v", err)
	}
	store.tick(cfg.DomainRecheckGrace)
	if sum, err := svc.Recheck(ctx, 10); err != nil || sum.Lapsed != 1 {
		t.Fatalf("past grace = %+v, %v", sum, err)
	}
	if len(lapsed) != 1 || lapsed[0].LapsedAt.IsZero() {
		t.Fatalf("OnLapsed = %+v", lapsed)
	}
	if _, err := svc.IdentityHolder(ctx, "example.com"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("lapsed evidence must stop routing: %v", err)
	}
}

func TestRecheckTransientFailureIsNoVerdict(t *testing.T) {
	ctx := context.Background()
	dt := &fakeVerifier{method: MethodDNSTXT}
	svc, store := setup(dt)
	if _, err := svc.RecordTx(ctx, mustTx(t, svc), partnerA, userA, "https://www.Example.com/", &Evidence{method: MethodDNSTXT, domainName: "example.com", tokenHash: "h"}); err != nil {
		t.Fatal(err)
	}
	dt.err = errors.New("SERVFAIL")
	store.tick(config.Config().DomainRecheckInterval + config.Config().DomainRecheckGrace)
	sum, err := svc.Recheck(ctx, 10)
	if err == nil || sum.Errored != 1 || sum.Lapsed != 0 {
		t.Fatalf("transient = %+v, %v", sum, err)
	}
	if r := store.rows[0]; !r.current() || r.lastErr != "SERVFAIL" || !r.failing.IsZero() {
		t.Fatalf("row after transient failure = %+v", r)
	}
	if dt.proofs[0].TokenHash != "h" {
		t.Fatal("recheck must present the stored token hash")
	}
}

func mustTx(t *testing.T, svc *Service) port.TxQueryService {
	t.Helper()
	tx, err := svc.DB.BeginTx(context.Background(), TxQueries())
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestIdentityEvidenceIsExclusiveAcrossPartners(t *testing.T) {
	ctx := context.Background()
	svc, _ := setup(&fakeVerifier{method: MethodGoogleWorkspace, ref: "example.com"}, &fakeVerifier{method: MethodVerifiedEmail})
	if _, err := svc.Verify(ctx, partnerA, userA, "https://www.Example.com/", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, partnerB, userB, "example.com", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); !errors.Is(err, ErrDomainHeld) {
		t.Fatalf("second identity holder: %v", err)
	}
	if _, err := svc.Verify(ctx, partnerB, userB, "example.com", MethodVerifiedEmail, DomainProof{}); err != nil {
		t.Fatalf("non-identity methods are not exclusive: %v", err)
	}
	holders, err := svc.Holders(ctx, "example.com", []string{MethodGoogleWorkspace, MethodVerifiedEmail})
	if err != nil || len(holders) != 2 {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	if _, err := svc.Cancel(ctx, partnerA, userA, "https://www.Example.com/", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, partnerB, userB, "example.com", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); err != nil {
		t.Fatalf("after cancellation the domain is free: %v", err)
	}
}

func TestRepeatedVerificationRefreshesThenAppendsAfterCancel(t *testing.T) {
	ctx := context.Background()
	svc, store := setup(&fakeVerifier{method: MethodVerifiedEmail})
	url := "https://www.Example.com/"
	for range 2 {
		if _, err := svc.Verify(ctx, partnerA, userA, url, MethodVerifiedEmail, DomainProof{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.rows) != 1 {
		t.Fatalf("re-proving a current method appends: %d rows", len(store.rows))
	}
	methods, err := svc.Cancel(ctx, partnerA, userA, url, MethodVerifiedEmail)
	if err != nil || len(methods) != 1 || store.rows[0].cancelledBy != userA {
		t.Fatalf("Cancel = %v, %v", methods, err)
	}
	if _, err := svc.Cancel(ctx, partnerA, userA, url, MethodVerifiedEmail); !errors.Is(err, ErrNoVerification) {
		t.Fatalf("second cancel: %v", err)
	}
	if _, err := svc.Verify(ctx, partnerA, userA, url, MethodVerifiedEmail, DomainProof{}); err != nil {
		t.Fatal(err)
	}
	history, err := svc.History(ctx, partnerA, url, 0)
	if err != nil || len(history) != 2 || !history[0].Current() || history[1].Current() {
		t.Fatalf("History = %+v, %v", history, err)
	}
	if current, _ := svc.Current(ctx, partnerA, url, []string{MethodVerifiedEmail}); len(current) != 1 {
		t.Fatalf("Current = %v", current)
	}
	if current, _ := svc.Current(ctx, partnerA, url, nil); len(current) != 0 {
		t.Fatal("no accepted methods honors nothing")
	}
}

func TestAuthorizationAndDomainChecks(t *testing.T) {
	ctx := context.Background()
	svc, store := setup(&fakeVerifier{method: MethodVerifiedEmail})
	store.addDomain(partnerA, "gmail.com")
	store.addDomain(partnerA, "co.uk")
	cases := []struct {
		partner, user int64
		url, method   string
		want          error
	}{
		{partnerA, userB, "https://www.Example.com/", MethodVerifiedEmail, ErrNotMember},
		{0, userA, "https://www.Example.com/", MethodVerifiedEmail, ErrNotMember},
		{partnerA, userA, "other.com", MethodVerifiedEmail, ErrDomainNotFound},
		{partnerA, userA, "example.com", MethodVerifiedEmail, ErrDomainNotFound},
		{partnerA, userA, "gmail.com", MethodVerifiedEmail, ErrInvalidDomain},
		{partnerA, userA, "co.uk", MethodVerifiedEmail, ErrInvalidDomain},
		{partnerA, userA, "https://www.Example.com/", MethodGoogleHD, ErrUnknownMethod},
		{partnerA, userA, "https://www.Example.com/", MethodDNSTXT, ErrUnknownMethod},
	}
	for _, c := range cases {
		if _, err := svc.Verify(ctx, c.partner, c.user, c.url, c.method, DomainProof{}); !errors.Is(err, c.want) {
			t.Errorf("Verify(%d, %d, %q, %s) = %v, want %v", c.partner, c.user, c.url, c.method, err, c.want)
		}
	}
	if len(store.rows) != 0 {
		t.Fatal("refused verifications must not write")
	}
}

func TestEmailCodeChallenge(t *testing.T) {
	ctx := context.Background()
	svc, store := setup(EmailCodeVerifier{})
	url := "https://www.Example.com/"
	for _, bad := range []string{"owner@other.com", "owner@gmail.com", "x", "a@example.com, b@evil.com"} {
		if _, err := svc.Challenge(ctx, partnerA, userA, url, MethodEmailCode, bad); !errors.Is(err, ErrRecipient) {
			t.Errorf("recipient %q: %v", bad, err)
		}
	}
	ch, err := svc.Challenge(ctx, partnerA, userA, url, MethodEmailCode, " Owner@Shop.Example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Recipient != "owner@shop.example.com" || len(ch.Token) != codeDigits || ch.RecordValue != "" {
		t.Fatalf("challenge = %+v", ch)
	}
	if _, err := svc.Challenge(ctx, partnerA, userA, url, MethodEmailCode, "owner@example.com"); !errors.Is(err, ErrCooldown) {
		t.Fatalf("reissue inside cooldown: %v", err)
	}
	if store.challenges[key(partnerA, url, MethodEmailCode)].hash == ch.Token {
		t.Fatal("the code must be stored hashed")
	}
	limit := config.Config().DomainChallengeAttempts
	for i := range limit {
		if _, err := svc.Confirm(ctx, partnerA, userA, url, MethodEmailCode, fmt.Sprintf("x%d", i)); !errors.Is(err, ErrDomainNotProven) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if _, err := svc.Confirm(ctx, partnerA, userA, url, MethodEmailCode, ch.Token); !errors.Is(err, ErrTooManyTries) {
		t.Fatalf("after %d wrong codes: %v", limit, err)
	}
	for range 10 {
		_, _ = svc.Confirm(ctx, partnerA, userA, url, MethodEmailCode, ch.Token)
	}
	if attempts := store.challenges[key(partnerA, url, MethodEmailCode)].attempts; attempts != int64(limit+1) {
		t.Fatalf("attempts = %d, want capped at %d", attempts, limit+1)
	}
	store.tick(config.Config().DomainChallengeCooldown)
	ch, err = svc.Challenge(ctx, partnerA, userA, url, MethodEmailCode, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Confirm(ctx, partnerA, userA, url, MethodEmailCode, ch.Token); err != nil {
		t.Fatalf("right code after reissue: %v", err)
	}
	store.tick(config.Config().DomainCodeTTL)
	if _, err := svc.Confirm(ctx, partnerA, userA, url, MethodEmailCode, ch.Token); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("consumed challenge: %v", err)
	}
}

func TestChallengeExpires(t *testing.T) {
	ctx := context.Background()
	svc, store := setup(&DNSTXTVerifier{Resolver: txtResolver{}})
	if _, err := svc.Challenge(ctx, partnerA, userA, "https://www.Example.com/", MethodDNSTXT, ""); err != nil {
		t.Fatal(err)
	}
	store.tick(config.Config().DomainChallengeTTL)
	if _, err := svc.Confirm(ctx, partnerA, userA, "https://www.Example.com/", MethodDNSTXT, ""); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expired challenge: %v", err)
	}
}

// A downstream proves the domain before its partner exists, then records the
// evidence in the transaction that creates the partner.
func TestCheckThenRecordTxInCallerTransaction(t *testing.T) {
	ctx := context.Background()
	svc, store := setup(VerifiedEmailVerifier{})
	ev, err := svc.Check(ctx, "new.example.org", MethodVerifiedEmail, DomainProof{Email: "Boss@New.Example.org", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(ctx, "new.example.org", MethodVerifiedEmail, DomainProof{Email: "boss@new.example.org"}); !errors.Is(err, ErrDomainNotProven) {
		t.Fatalf("unverified email: %v", err)
	}
	tx := mustTx(t, svc)
	store.addDomain(30, "new.example.org", 3)
	if _, err := svc.RecordTx(ctx, tx, 30, 3, "new.example.org", &Evidence{method: MethodVerifiedEmail, domainName: "other.org"}); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("evidence for another domain: %v", err)
	}
	v, err := svc.RecordTx(ctx, tx, 30, 3, "new.example.org", ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if v.PartnerID != 30 || v.Method != MethodVerifiedEmail {
		t.Fatalf("recorded = %+v", v)
	}
	if got, _ := svc.Domains(ctx, 30, []string{MethodVerifiedEmail}); len(got) != 1 {
		t.Fatalf("Domains = %v", got)
	}
	for name := range TxQueries() {
		if !strings.HasPrefix(name, "dv_") && name != guard.QueryLock {
			t.Fatalf("query %q would collide with a caller's map", name)
		}
	}
}

func TestOneTransactionRecordsSeveralMethods(t *testing.T) {
	ctx := context.Background()
	svc, _ := setup(VerifiedEmailVerifier{}, GoogleHDVerifier{})
	proof := DomainProof{Email: "a@example.com", EmailVerified: true, HostedDomain: "example.com"}
	tx := mustTx(t, svc)
	for _, method := range []string{MethodVerifiedEmail, MethodGoogleHD} {
		ev, err := svc.Check(ctx, "https://www.Example.com/", method, proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.RecordTx(ctx, tx, partnerA, userA, "https://www.Example.com/", ev); err != nil {
			t.Fatalf("%s in the same transaction: %v", method, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRecordTxRefusesUncheckedEvidence(t *testing.T) {
	svc, _ := setup()
	for _, ev := range []*Evidence{nil, {}} {
		if _, err := svc.RecordTx(context.Background(), mustTx(t, svc), partnerA, userA, "https://www.Example.com/", ev); !errors.Is(err, ErrUnknownMethod) {
			t.Fatalf("RecordTx(%v) = %v", ev, err)
		}
	}
}

func TestCheckDoesNotTrustCallerPartnerID(t *testing.T) {
	verifier := &fakeVerifier{method: MethodVerifiedEmail}
	svc := &Service{Verifiers: []DomainVerifier{verifier}}
	if _, err := svc.Check(context.Background(), "example.org", MethodVerifiedEmail, DomainProof{PartnerID: 99}); err != nil {
		t.Fatal(err)
	}
	if got := verifier.proofs[0].PartnerID; got != 0 {
		t.Fatalf("Check passed caller partner ID %d to verifier", got)
	}
}

func TestIdentityMethodsReturnsACopy(t *testing.T) {
	methods := IdentityMethods()
	methods[0] = MethodEmailCode
	if isIdentityMethod(MethodEmailCode) || !isIdentityMethod(MethodDNSTXT) {
		t.Fatal("caller mutation changed the identity-method policy")
	}
}

// A provider error is not a verdict, so evidence that only errors never
// lapses; it must still stop holding the domain once it has not passed a
// check for domain_identity_max_age.
func TestIdentityEvidenceGoesStaleWithoutAPassingCheck(t *testing.T) {
	ctx := context.Background()
	gw := &fakeVerifier{method: MethodGoogleWorkspace}
	svc, store := setup(gw)
	svc.AccessToken = func(context.Context, *Verification) (string, error) { return "t", nil }
	if _, err := svc.Verify(ctx, partnerA, userA, "https://www.Example.com/", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	gw.err = errors.New("http status 403")
	cfg := config.Config()
	for elapsed := time.Duration(0); elapsed < cfg.DomainIdentityMaxAge; elapsed += cfg.DomainRecheckInterval {
		if holder, err := svc.IdentityHolder(ctx, "example.com"); err != nil || holder != partnerA {
			t.Fatalf("after %s of errors: %d, %v", elapsed, holder, err)
		}
		store.tick(cfg.DomainRecheckInterval)
		if sum, _ := svc.Recheck(ctx, 10); sum.Errored != 1 || sum.Lapsed != 0 {
			t.Fatalf("provider error must not be a verdict: %+v", sum)
		}
	}
	if _, err := svc.IdentityHolder(ctx, "example.com"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("stale evidence still routes: %v", err)
	}
	if !store.rows[0].current() {
		t.Fatal("stale evidence is not lapsed; a passing check revives it")
	}
	if _, err := svc.Verify(ctx, partnerB, userB, "example.com", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); !errors.Is(err, gw.err) {
		t.Fatalf("partner B check: %v", err)
	}
	gw.err = nil
	if _, err := svc.Verify(ctx, partnerB, userB, "example.com", MethodGoogleWorkspace, DomainProof{AccessToken: "t"}); err != nil {
		t.Fatalf("stale evidence must not block the real owner: %v", err)
	}
	if holder, err := svc.IdentityHolder(ctx, "example.com"); err != nil || holder != partnerB {
		t.Fatalf("new holder = %d, %v", holder, err)
	}
	if store.rows[0].current() {
		t.Fatal("the superseded evidence must lapse, or a later passing check would leave two holders")
	}
}

func TestRecheckOnlyWiredAndGrantedMethods(t *testing.T) {
	svc := &Service{Verifiers: []DomainVerifier{&fakeVerifier{method: MethodGoogleWorkspace}, &fakeVerifier{method: MethodVerifiedEmail}, &fakeVerifier{method: MethodHTTPFile}}}
	if got := svc.recheckable(); len(got) != 1 || got[0] != MethodHTTPFile {
		t.Fatalf("without AccessToken = %v", got)
	}
	svc.AccessToken = func(context.Context, *Verification) (string, error) { return "t", nil }
	if got := svc.recheckable(); len(got) != 2 {
		t.Fatalf("with AccessToken = %v", got)
	}
	if _, err := svc.Recheck(context.Background(), 0); err == nil {
		t.Fatal("a non-positive limit must be refused")
	}
}

func TestRecheckProviderEvidenceUsesFreshGrant(t *testing.T) {
	ctx := context.Background()
	gw := &fakeVerifier{method: MethodGoogleWorkspace}
	svc, store := setup(gw)
	svc.AccessToken = func(_ context.Context, v *Verification) (string, error) {
		if v.VerifiedBy != userA {
			return "", errors.New("wrong subject")
		}
		return "fresh", nil
	}
	if _, err := svc.Verify(ctx, partnerA, userA, "https://www.Example.com/", MethodGoogleWorkspace, DomainProof{AccessToken: "first"}); err != nil {
		t.Fatal(err)
	}
	if got := gw.proofs[0].PartnerID; got != partnerA {
		t.Fatalf("Verify partner ID = %d, want %d", got, partnerA)
	}
	store.tick(time.Duration(config.Config().DomainRecheckInterval))
	if sum, err := svc.Recheck(ctx, 10); err != nil || sum.Held != 1 {
		t.Fatalf("recheck = %+v, %v", sum, err)
	}
	if gw.proofs[1].AccessToken != "fresh" {
		t.Fatalf("recheck proof = %+v", gw.proofs[1])
	}
}

func TestMailboxOnDomain(t *testing.T) {
	cases := map[[2]string]error{
		{"a@example.com", "https://www.example.com"}: nil,
		{"a@mail.example.com", "shop.example.com"}:   nil,
		{"a@gmail.com", "example.com"}:               ErrRecipient,
		{"a@example.org", "example.com"}:             ErrRecipient,
		{"a@example.com", "gmail.com"}:               ErrInvalidDomain,
		{"", "example.com"}:                          ErrRecipient,
	}
	for in, want := range cases {
		if err := MailboxOnDomain(in[0], in[1]); !errors.Is(err, want) {
			t.Errorf("MailboxOnDomain(%q, %q) = %v, want %v", in[0], in[1], err, want)
		}
	}
}
