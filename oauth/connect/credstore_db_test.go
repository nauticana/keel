package connect

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
)

type qcall struct {
	name string
	args []any
}

// fakeQS records queries and returns canned results by query name.
type fakeQS struct {
	calls []qcall
	next  map[string]*model.QueryResult
	err   error // when set, every Query returns it
}

func (f *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, qcall{name, args})
	if f.err != nil {
		return nil, f.err
	}
	if r, ok := f.next[name]; ok {
		return r, nil
	}
	return &model.QueryResult{}, nil
}
func (f *fakeQS) GenID() int64 { return 1 }

func (f *fakeQS) last(name string) (qcall, bool) {
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].name == name {
			return f.calls[i], true
		}
	}
	return qcall{}, false
}

func newTestStore(t *testing.T) (*CredentialStoreDB, *fakeQS) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	qs := &fakeQS{next: map[string]*model.QueryResult{}}
	return &CredentialStoreDB{kek: key, qs: qs}, qs
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	sealed, err := s.seal("refresh-tok")
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.IsSealed(sealed) {
		t.Fatalf("expected sealed envelope, got %q", sealed)
	}
	if got, err := s.open(sealed); err != nil || got != "refresh-tok" {
		t.Fatalf("open = %q, %v; want refresh-tok", got, err)
	}
	// Legacy plaintext passes through unchanged.
	if got, err := s.open("plain"); err != nil || got != "plain" {
		t.Fatalf("plaintext passthrough = %q, %v", got, err)
	}
	// Empty stays empty.
	if got, err := s.open(""); err != nil || got != "" {
		t.Fatalf("empty open = %q, %v", got, err)
	}
}

func TestOpenWrongKeyIsHardError(t *testing.T) {
	s1, _ := newTestStore(t)
	s2, _ := newTestStore(t) // different KEK
	sealed, _ := s1.seal("secret")
	got, err := s2.open(sealed)
	if err == nil {
		t.Fatalf("wrong-key open should error, got %q", got)
	}
	if got != "" {
		t.Fatalf("wrong-key open must not leak ciphertext, got %q", got)
	}
}

func TestUpsertConnectionSealsAndScopesEntity(t *testing.T) {
	s, qs := newTestStore(t)
	ctx := client.WithEntity(context.Background(), 42)
	if err := s.UpsertConnection(ctx, 7, "square", "O", "the-token", "https://api"); err != nil {
		t.Fatal(err)
	}
	c, ok := qs.last(qUpsertConnection)
	if !ok {
		t.Fatal("no upsert query issued")
	}
	if c.args[0].(int64) != 7 || c.args[1].(int64) != 42 || c.args[2].(string) != "square" || c.args[3].(string) != "O" {
		t.Fatalf("scope args wrong: %v", c.args[:4])
	}
	sealed := c.args[4].(string)
	if opened, err := s.open(sealed); !crypto.IsSealed(sealed) || err != nil || opened != "the-token" {
		t.Fatalf("credential not sealed: %q (%v)", sealed, err)
	}
	if c.args[5].(string) != "https://api" {
		t.Fatalf("api_endpoint arg = %v", c.args[5])
	}
}

func TestEntityDefaultsToTenantZero(t *testing.T) {
	s, qs := newTestStore(t)
	if err := s.UpdateConnectionStatus(context.Background(), 7, "square", "O", "E"); err != nil {
		t.Fatal(err)
	}
	c, _ := qs.last(qUpdateStatus)
	// args: status, partnerID, entityID, provider, connType
	if c.args[2].(int64) != 0 {
		t.Fatalf("untagged ctx should scope to entity 0, got %v", c.args[2])
	}
}

func TestGetConnectionCredentialsUnseals(t *testing.T) {
	s, qs := newTestStore(t)
	sealed, _ := s.seal("live-token")
	qs.next[qGetCredentials] = &model.QueryResult{Rows: [][]any{{sealed, "https://api"}}}
	cred, endpoint, err := s.GetConnectionCredentials(context.Background(), 7, "square")
	if err != nil {
		t.Fatal(err)
	}
	if cred != "live-token" || endpoint != "https://api" {
		t.Fatalf("got cred=%q endpoint=%q", cred, endpoint)
	}
}

func TestOAuthStateRoundTripAndMismatch(t *testing.T) {
	s, _ := newTestStore(t)
	nonceQS := &fakeQS{next: map[string]*model.QueryResult{}}
	s.Nonce = &NonceService{qs: nonceQS}

	// Create captures the payload it stored (arg[2] of the insert).
	if _, err := s.CreateOAuthState(context.Background(), 7, "square", map[string]string{client.StateEntityKey: "42", "shop": "x"}); err != nil {
		t.Fatal(err)
	}
	ins, _ := nonceQS.last(qNonceInsert)
	payload := ins.args[2].(string)

	// Consume returns that payload; provider match yields partner + extra.
	nonceQS.next[qNonceConsume] = &model.QueryResult{Rows: [][]any{{payload}}}
	pid, extra, err := s.ConsumeOAuthState(context.Background(), "state", "square")
	if err != nil {
		t.Fatal(err)
	}
	if pid != 7 || extra[client.StateEntityKey] != "42" || extra["shop"] != "x" {
		t.Fatalf("consumed pid=%d extra=%v", pid, extra)
	}

	// Provider mismatch is rejected.
	nonceQS.next[qNonceConsume] = &model.QueryResult{Rows: [][]any{{payload}}}
	if _, _, err := s.ConsumeOAuthState(context.Background(), "state", "clover"); err == nil {
		t.Fatal("expected provider mismatch error")
	}
}

// seedCred makes the Test-path read (credAndRev) return a sealed token at rev.
func seedCred(s *CredentialStoreDB, qs *fakeQS, token string, rev int64) {
	sealed, _ := s.seal(token)
	qs.next[qCredForRefresh] = &model.QueryResult{Rows: [][]any{{sealed, rev}}}
}

func TestRefreshAccessToken(t *testing.T) {
	// nil Refresher: returns the stored (decrypted) credential, stamps last_checked.
	s, qs := newTestStore(t)
	seedCred(s, qs, "stored", 3)
	got, err := s.RefreshAccessToken(context.Background(), 7, "meta")
	if err != nil || got != "stored" {
		t.Fatalf("nil refresher: got %q err %v", got, err)
	}
	if _, ok := qs.last(qTouchChecked); !ok {
		t.Fatal("nil refresher should stamp last_checked")
	}

	// success (no rotation): fresh token, completeCAS clears lease + stamps.
	s2, qs2 := newTestStore(t)
	seedCred(s2, qs2, "old", 3)
	s2.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) {
		return RefreshResult{AccessToken: "fresh"}, nil
	}
	if got, err := s2.RefreshAccessToken(context.Background(), 7, "google"); err != nil || got != "fresh" {
		t.Fatalf("success: got %q err %v", got, err)
	}
	if _, ok := qs2.last(qCompleteCAS); !ok {
		t.Fatal("success should completeCAS")
	}

	// rotation: new token sealed and CAS-written on the read rev.
	s3, qs3 := newTestStore(t)
	seedCred(s3, qs3, "old", 3)
	s3.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) {
		return RefreshResult{AccessToken: "at", RefreshToken: "rotated"}, nil
	}
	if _, err := s3.RefreshAccessToken(context.Background(), 7, "shopify"); err != nil {
		t.Fatal(err)
	}
	rot, ok := qs3.last(qRotateCAS)
	if !ok {
		t.Fatal("rotation should CAS-update cred_ref")
	}
	if sealed := rot.args[0].(string); !crypto.IsSealed(sealed) {
		t.Fatalf("rotated token not sealed: %q", sealed)
	}
	if rot.args[4].(int) != 3 {
		t.Fatalf("rotation should CAS on rev 3, got %v", rot.args[4])
	}

	// failure: error surfaces and status CAS-flips to 'E'.
	s4, qs4 := newTestStore(t)
	seedCred(s4, qs4, "old", 3)
	s4.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) {
		return RefreshResult{}, errors.New("invalid_grant")
	}
	if _, err := s4.RefreshAccessToken(context.Background(), 7, "google"); err == nil {
		t.Fatal("expected refresh error")
	}
	if _, ok := qs4.last(qMarkErroredCAS); !ok {
		t.Fatal("failure should CAS-mark errored")
	}
}

func TestRefreshAccessTokenRejectsEmptyToken(t *testing.T) {
	s, qs := newTestStore(t)
	seedCred(s, qs, "old", 1)
	s.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) { return RefreshResult{}, nil }
	if _, err := s.RefreshAccessToken(context.Background(), 7, "google"); err == nil {
		t.Fatal("empty access token should error")
	}
	if _, ok := qs.last(qMarkErroredCAS); !ok {
		t.Fatal("empty token should CAS-mark errored")
	}
}

// A worker that loses the atomic claim must not refresh (another replica owns it).
func TestRefreshDueSkipsWhenClaimLost(t *testing.T) {
	s, _ := newTestStore(t) // qClaim unseeded → 0 rows → claim lost
	called := false
	s.Refresh = func(_ context.Context, _, _ string) (RefreshResult, error) {
		called = true
		return RefreshResult{AccessToken: "x"}, nil
	}
	refreshed, err := s.RefreshDue(context.Background(), 7, "google", 4)
	if err != nil || refreshed {
		t.Fatalf("want (false,nil), got (%v,%v)", refreshed, err)
	}
	if called {
		t.Fatal("must not refresh when the claim is lost")
	}
}

func TestRefreshDueClaimsAndRefreshes(t *testing.T) {
	s, qs := newTestStore(t)
	sealed, _ := s.seal("the-token")
	qs.next[qClaim] = &model.QueryResult{Rows: [][]any{{sealed}}} // claim won
	var got string
	s.Refresh = func(_ context.Context, _, token string) (RefreshResult, error) {
		got = token
		return RefreshResult{AccessToken: "x"}, nil
	}
	refreshed, err := s.RefreshDue(context.Background(), 7, "google", 5)
	if err != nil || !refreshed {
		t.Fatalf("want (true,nil), got (%v,%v)", refreshed, err)
	}
	if got != "the-token" {
		t.Fatalf("should refresh the claimed cred_ref, got %q", got)
	}
	// completion CAS-targets the claimed rev (expectRev+1 = 6).
	if c, ok := qs.last(qCompleteCAS); !ok || c.args[3].(int) != 6 {
		t.Fatal("completion should CAS on the claimed rev")
	}
}

func TestListActiveCredentials(t *testing.T) {
	s, qs := newTestStore(t)
	qs.next[qListActive] = &model.QueryResult{Rows: [][]any{
		{int64(7), int64(0), "google", "O", int64(2)},
		{int64(7), int64(99), "square", "O", int64(8)},
	}}
	got, err := s.ListActiveCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].EntityID != 99 || got[1].Provider != "square" || got[1].Rev != 8 {
		t.Fatalf("parsed = %+v", got)
	}
}
