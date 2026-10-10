package actiontoken

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/idempotency"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type tokenRow struct {
	id               int64
	hash             string
	user, partner    int64
	binding          Binding
	expires, created time.Time
	claimed          bool
}

// memTable stands in for action_token and user_account.tokens_valid_after,
// driven by query name, with now as the store clock.
type memTable struct {
	rows    []*tokenRow
	revoked map[int64]time.Time
	now     time.Time
	nextID  int64
	err     error
}

func (m *memTable) GenID() int64 { return 0 }

func (m *memTable) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := &model.QueryResult{}
	switch name {
	case qPrune:
		kept := m.rows[:0]
		for _, r := range m.rows {
			if r.claimed || r.user != args[0].(int64) || r.expires.After(m.now) {
				kept = append(kept, r)
			}
		}
		m.rows = kept
	case qInsert:
		partner, _ := args[2].(int64)
		m.nextID++
		m.rows = append(m.rows, &tokenRow{
			id: m.nextID, hash: args[0].(string), user: args[1].(int64), partner: partner,
			binding: Binding{args[3].(string), args[4].(string), args[5].(string)},
			expires: m.now.Add(time.Duration(args[6].(int64)) * time.Second), created: m.now,
		})
	case qClaim:
		b := Binding{args[1].(string), args[2].(string), args[3].(string)}
		for _, r := range m.rows {
			cutoff, revoked := m.revoked[r.user]
			if r.hash == args[0] && r.binding == b &&
				(r.claimed || (r.expires.After(m.now) && (!revoked || r.created.After(cutoff)))) {
				r.claimed = true
				out.Rows = append(out.Rows, []any{r.id, r.user, r.partner, r.binding.Action, r.binding.ResourceKey, r.binding.Digest})
			}
		}
	case qLoad:
		for _, r := range m.rows {
			if r.id == args[0] && r.claimed {
				out.Rows = append(out.Rows, []any{r.id, r.user, r.partner, r.binding.Action, r.binding.ResourceKey, r.binding.Digest})
			}
		}
	}
	return out, nil
}

type memRepo struct {
	port.DatabaseRepository
	table *memTable
}

func (r memRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.table
}

type failCompleteLedger struct {
	*idempotency.MemoryLedger
	err error
}

func (l *failCompleteLedger) Complete(ctx context.Context, key, fence string, result []byte) error {
	if l.err != nil {
		err := l.err
		l.err = nil
		return err
	}
	return l.MemoryLedger.Complete(ctx, key, fence, result)
}

var (
	approver = port.UserRef{UserID: 7, PartnerID: 3}
	decision = Binding{Action: "approve", ResourceKey: "approval:42", Digest: "d1"}
)

func newService() (*Service, *memTable) {
	table := &memTable{now: time.Now(), revoked: map[int64]time.Time{}}
	return &Service{DB: memRepo{table: table}, Ledger: &idempotency.MemoryLedger{}}, table
}

func mint(t *testing.T, s *Service) string {
	t.Helper()
	token, err := s.Mint(context.Background(), approver, decision, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func counting(n *int, result []byte, err error) Run {
	return func(context.Context, Claim) ([]byte, error) { *n++; return result, err }
}

func TestMintStoresOnlyTheHash(t *testing.T) {
	s, table := newService()
	token := mint(t, s)
	if len(token) != 64 || table.rows[0].hash != common.Sha256Hex(token) || strings.Contains(table.rows[0].hash, token) {
		t.Fatalf("stored %q for token %q", table.rows[0].hash, token)
	}
}

func TestMintRejectsIncompleteInput(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	for _, tc := range []struct {
		user port.UserRef
		b    Binding
		ttl  time.Duration
	}{
		{port.UserRef{}, decision, time.Hour},
		{approver, Binding{ResourceKey: "r", Digest: "d"}, time.Hour},
		{approver, Binding{Action: "a", Digest: "d"}, time.Hour},
		{approver, Binding{Action: "a", ResourceKey: "r"}, time.Hour},
		{approver, Binding{Action: strings.Repeat("a", maxAction+1), ResourceKey: "r", Digest: "d"}, time.Hour},
		{approver, decision, time.Millisecond},
	} {
		if _, err := s.Mint(ctx, tc.user, tc.b, tc.ttl); err == nil {
			t.Errorf("Mint(%+v, %+v, %v) accepted", tc.user, tc.b, tc.ttl)
		}
	}
}

func TestMintPrunesExpiredUnclaimedTokens(t *testing.T) {
	s, table := newService()
	mint(t, s)
	claimed := mint(t, s)
	if _, err := s.Redeem(context.Background(), claimed, decision, counting(new(int), nil, nil)); err != nil {
		t.Fatal(err)
	}
	table.now = table.now.Add(2 * time.Hour)
	mint(t, s)
	if len(table.rows) != 2 || !table.rows[0].claimed {
		t.Fatalf("rows after prune = %d, want the claim and the new token", len(table.rows))
	}
}

func TestRedeemRunsOnceAndReplaysTheResult(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	token := mint(t, s)
	runs := 0
	var got Claim
	run := func(_ context.Context, c Claim) ([]byte, error) { runs++; got = c; return []byte("approved"), nil }
	for i := 0; i < 2; i++ {
		result, err := s.Redeem(ctx, token, decision, run)
		if err != nil || string(result) != "approved" {
			t.Fatalf("redeem %d = %q, %v", i, result, err)
		}
	}
	if runs != 1 || got.User != approver || got.Binding != decision || got.ID == 0 {
		t.Fatalf("runs = %d, claim = %+v", runs, got)
	}
}

func TestRedeemRefusesWithoutConsuming(t *testing.T) {
	s, table := newService()
	ctx := context.Background()
	token := mint(t, s)
	runs := 0
	for name, tc := range map[string]struct {
		token string
		b     Binding
	}{
		"malformed":      {"not-a-token", decision},
		"unknown":        {strings.Repeat("a", 64), decision},
		"other action":   {token, Binding{"reject", decision.ResourceKey, decision.Digest}},
		"other resource": {token, Binding{decision.Action, "approval:43", decision.Digest}},
		"changed digest": {token, Binding{decision.Action, decision.ResourceKey, "d2"}},
	} {
		if _, err := s.Redeem(ctx, tc.token, tc.b, counting(&runs, nil, nil)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if runs != 0 || table.rows[0].claimed {
		t.Fatalf("refused redemptions ran %d times or consumed the token", runs)
	}
	if _, err := s.Redeem(ctx, token, decision, counting(&runs, nil, nil)); err != nil || runs != 1 {
		t.Fatalf("matching redeem after refusals: runs = %d, err = %v", runs, err)
	}
}

func TestRedeemRefusesExpiredAndRevokedTokens(t *testing.T) {
	s, table := newService()
	ctx := context.Background()
	expired := mint(t, s)
	table.now = table.now.Add(time.Hour)
	if _, err := s.Redeem(ctx, expired, decision, counting(new(int), nil, nil)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired: err = %v", err)
	}
	revoked := mint(t, s)
	table.revoked[approver.UserID] = table.now.Add(time.Second)
	if _, err := s.Redeem(ctx, revoked, decision, counting(new(int), nil, nil)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked: err = %v", err)
	}
}

func TestClaimedTokenReplaysAfterExpiry(t *testing.T) {
	s, table := newService()
	ctx := context.Background()
	token := mint(t, s)
	runs := 0
	if _, err := s.Redeem(ctx, token, decision, counting(&runs, []byte("ok"), nil)); err != nil {
		t.Fatal(err)
	}
	table.now = table.now.Add(2 * time.Hour)
	if result, err := s.Redeem(ctx, token, decision, counting(&runs, nil, nil)); err != nil || string(result) != "ok" || runs != 1 {
		t.Fatalf("replay after expiry = %q, %v, runs %d", result, err, runs)
	}
}

func TestFailureIsRecorded(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	token := mint(t, s)
	runs := 0
	for i := 0; i < 2; i++ {
		_, err := s.Redeem(ctx, token, decision, counting(&runs, nil, &Failure{Reason: "forbidden"}))
		var f *Failure
		if !errors.As(err, &f) || f.Reason != "forbidden" {
			t.Fatalf("redeem %d: err = %v", i, err)
		}
	}
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

func TestUnknownOutcomeBlocksUntilReconciled(t *testing.T) {
	s, table := newService()
	ctx := context.Background()
	token := mint(t, s)
	runs := 0
	if _, err := s.Redeem(ctx, token, decision, counting(&runs, nil, errors.New("timeout"))); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("err = %v, want ErrUnknownOutcome", err)
	} else if u := new(UnknownOutcome); !errors.As(err, &u) || u.ClaimID != table.rows[0].id {
		t.Fatalf("err = %#v, want claim %d", err, table.rows[0].id)
	}
	if _, err := s.Redeem(ctx, token, decision, counting(&runs, nil, nil)); !errors.Is(err, ErrUnknownOutcome) || runs != 1 {
		t.Fatalf("retry: err = %v, runs = %d", err, runs)
	}
	var got Claim
	result, err := s.Reconcile(ctx, table.rows[0].id, func(_ context.Context, c Claim) ([]byte, error) {
		got = c
		return []byte("found"), nil
	})
	if err != nil || string(result) != "found" || got.User != approver || got.Binding != decision {
		t.Fatalf("reconcile = %q, %v, claim %+v", result, err, got)
	}
	if result, err := s.Redeem(ctx, token, decision, counting(&runs, nil, nil)); err != nil || string(result) != "found" || runs != 1 {
		t.Fatalf("after reconcile = %q, %v, runs %d", result, err, runs)
	}
	if _, err := s.Reconcile(ctx, table.rows[0].id, counting(&runs, nil, nil)); !errors.Is(err, idempotency.ErrInvalidTransition) {
		t.Fatalf("reconcile of a completed claim: err = %v", err)
	}
	if _, err := s.Reconcile(ctx, 99, counting(&runs, nil, nil)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reconcile of an unknown claim: err = %v", err)
	}
}

func TestCompleteErrorCanBeReconciled(t *testing.T) {
	s, table := newService()
	s.Ledger = &failCompleteLedger{MemoryLedger: &idempotency.MemoryLedger{}, err: errors.New("write lost")}
	token := mint(t, s)
	if _, err := s.Redeem(context.Background(), token, decision, counting(new(int), []byte("done"), nil)); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("redeem: err = %v", err)
	}
	result, err := s.Reconcile(context.Background(), table.rows[0].id, counting(new(int), []byte("confirmed"), nil))
	if err != nil || string(result) != "confirmed" {
		t.Fatalf("reconcile = %q, %v", result, err)
	}
}

func TestFailedResultWriteReleasesClaim(t *testing.T) {
	s, _ := newService()
	s.Ledger = &failCompleteLedger{MemoryLedger: &idempotency.MemoryLedger{}, err: errors.New("write lost")}
	token := mint(t, s)
	if _, err := s.Redeem(context.Background(), token, decision, counting(new(int), nil, &Failure{Reason: "denied"})); err == nil {
		t.Fatal("record failure succeeded")
	}
	runs := 0
	if _, err := s.Redeem(context.Background(), token, decision, counting(&runs, nil, &Failure{Reason: "denied"})); err == nil || runs != 1 {
		t.Fatalf("retry: runs = %d, err = %v", runs, err)
	}
}

func TestOversizedResultsAreNotStored(t *testing.T) {
	s, table := newService()
	token := mint(t, s)
	tooLarge := make([]byte, MaxResultBytes+1)
	if _, err := s.Redeem(context.Background(), token, decision, counting(new(int), tooLarge, nil)); !errors.Is(err, ErrResultTooLarge) || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("successful oversized result: %v", err)
	}
	if _, err := s.Reconcile(context.Background(), table.rows[0].id, counting(new(int), []byte("small"), nil)); err != nil {
		t.Fatalf("reconcile oversized result: %v", err)
	}

	s, _ = newService()
	token = mint(t, s)
	failure := &Failure{Reason: strings.Repeat("x", MaxResultBytes+1)}
	if _, err := s.Redeem(context.Background(), token, decision, counting(new(int), nil, failure)); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("oversized failure: %v", err)
	}
	runs := 0
	if _, err := s.Redeem(context.Background(), token, decision, counting(&runs, nil, &Failure{Reason: "small"})); err == nil || runs != 1 {
		t.Fatalf("unrecorded failure did not run again: runs = %d, err = %v", runs, err)
	}
}

func TestPanicLeavesReconcilableClaim(t *testing.T) {
	s, table := newService()
	token := mint(t, s)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("run did not panic")
			}
		}()
		_, _ = s.Redeem(context.Background(), token, decision, func(context.Context, Claim) ([]byte, error) {
			panic("boom")
		})
	}()
	if _, err := s.Reconcile(context.Background(), table.rows[0].id, counting(new(int), nil, nil)); err != nil {
		t.Fatalf("reconcile after panic: %v", err)
	}
}

func TestReconcileFencesAbandonedInFlightClaim(t *testing.T) {
	s, table := newService()
	mint(t, s)
	table.rows[0].claimed = true
	stale, err := s.Ledger.Begin(context.Background(), ledgerKey(table.rows[0].id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reconcile(context.Background(), table.rows[0].id, counting(new(int), []byte("found"), nil)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := s.Ledger.Complete(context.Background(), ledgerKey(table.rows[0].id), stale.Fence, []byte("stale")); !errors.Is(err, idempotency.ErrInvalidTransition) {
		t.Fatalf("stale claim completed: %v", err)
	}
}

func TestConcurrentClaimSeesInFlight(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	token := mint(t, s)
	_, err := s.Redeem(ctx, token, decision, func(ctx context.Context, _ Claim) ([]byte, error) {
		if _, err := s.Redeem(ctx, token, decision, counting(new(int), nil, nil)); !errors.Is(err, ErrInFlight) {
			t.Errorf("nested redeem: err = %v, want ErrInFlight", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStoreErrorsSurface(t *testing.T) {
	s, table := newService()
	ctx := context.Background()
	token := mint(t, s)
	table.err = errors.New("db down")
	if _, err := s.Mint(ctx, approver, decision, time.Hour); !errors.Is(err, table.err) {
		t.Fatalf("mint: err = %v", err)
	}
	if _, err := s.Redeem(ctx, token, decision, counting(new(int), nil, nil)); !errors.Is(err, table.err) {
		t.Fatalf("redeem: err = %v", err)
	}
	if _, err := s.Redeem(ctx, token, decision, nil); err == nil {
		t.Fatal("nil run accepted")
	}
}

func TestMissingDependenciesReturnErrors(t *testing.T) {
	var s Service
	if _, err := s.Mint(context.Background(), approver, decision, time.Hour); err == nil {
		t.Fatal("Mint accepted a missing database")
	}
	s.DB = memRepo{table: &memTable{now: time.Now(), revoked: map[int64]time.Time{}}}
	if _, err := s.Redeem(context.Background(), strings.Repeat("a", 64), decision, counting(new(int), nil, nil)); err == nil {
		t.Fatal("Redeem accepted a missing ledger")
	}
}

func TestClaimSQLUsesStoreClockAndRevocation(t *testing.T) {
	claim := queries[qClaim]
	for _, want := range []string{"expires_at > CURRENT_TIMESTAMP", "claimed_at IS NOT NULL", "tokens_valid_after", "content_digest = ?", "RETURNING"} {
		if !strings.Contains(claim, want) {
			t.Errorf("claim SQL lacks %q", want)
		}
	}
	if !strings.Contains(queries[qInsert], "nextval('action_token_seq')") {
		t.Error("insert does not draw from action_token_seq")
	}
}
