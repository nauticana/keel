package actiontoken

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Ledger result prefixes: the action completed with the rest as its result, or
// failed with the rest as the reason.
const (
	completed = 'C'
	failed    = 'F'
)

// MaxResultBytes bounds the result or failure reason retained for replay.
const MaxResultBytes = 64 << 10

// Run performs the claimed action after fresh authorization. Results are
// limited to MaxResultBytes; *Failure proves the action did not happen.
type Run func(ctx context.Context, c Claim) ([]byte, error)

// Service keeps tokens in action_token and resolves each claim through Ledger
// under the key "action_token:<id>", so a claim runs at most once and every
// retry returns its recorded outcome. Only token hashes are stored.
type Service struct {
	DB     port.DatabaseRepository
	Ledger port.ReconciliationLedger

	once sync.Once
	qs   port.QueryService
}

func (s *Service) query(ctx context.Context) (port.QueryService, error) {
	if s == nil || s.DB == nil {
		return nil, errDatabase
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	if s.qs == nil {
		return nil, errDatabase
	}
	return s.qs, nil
}

// Mint returns a token authorizing b for user until ttl elapses on the store
// clock. Minting first prunes the user's expired unclaimed tokens.
func (s *Service) Mint(ctx context.Context, user port.UserRef, b Binding, ttl time.Duration) (string, error) {
	if user.UserID <= 0 || !b.valid() || ttl < time.Second {
		return "", fmt.Errorf("actiontoken: user, action, resource key, digest and a ttl of at least one second are required")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	qs, err := s.query(ctx)
	if err != nil {
		return "", err
	}
	if _, err := qs.Query(ctx, qPrune, user.UserID); err != nil {
		return "", err
	}
	var partner any
	if user.PartnerID > 0 {
		partner = user.PartnerID
	}
	if _, err := qs.Query(ctx, qInsert, common.Sha256Hex(token), user.UserID, partner,
		b.Action, b.ResourceKey, b.Digest, int64(ttl/time.Second)); err != nil {
		return "", err
	}
	return token, nil
}

// Redeem claims token for b and runs it once. A retry of a claimed token never
// runs again: it returns the recorded result or *Failure, ErrInFlight, or
// ErrUnknownOutcome. An expired, revoked, malformed or mismatched token is
// ErrInvalid and is not consumed.
func (s *Service) Redeem(ctx context.Context, token string, b Binding, run Run) ([]byte, error) {
	if run == nil {
		return nil, errNoRun
	}
	if len(token) != 64 || !b.valid() {
		return nil, ErrInvalid
	}
	if _, err := hex.DecodeString(token); err != nil {
		return nil, ErrInvalid
	}
	c, ok, err := s.claim(ctx, qClaim, common.Sha256Hex(token), b.Action, b.ResourceKey, b.Digest)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalid
	}
	entry, err := s.Ledger.Begin(ctx, ledgerKey(c.ID))
	if err != nil {
		return nil, err
	}
	if entry.State != model.LedgerNew {
		return recorded(c.ID, entry)
	}
	return s.settle(ctx, c, entry.Fence, run)
}

// Reconcile fences an abandoned claim and records what happened. Call it only
// after normal execution is no longer authoritative.
func (s *Service) Reconcile(ctx context.Context, claimID int64, run Run) ([]byte, error) {
	if run == nil {
		return nil, errNoRun
	}
	if claimID <= 0 {
		return nil, ErrInvalid
	}
	c, ok, err := s.claim(ctx, qLoad, claimID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalid
	}
	fence, err := s.Ledger.ReclaimForReconciliation(ctx, ledgerKey(claimID))
	if err != nil {
		return nil, err
	}
	return s.settle(ctx, c, fence, run)
}

func (s *Service) settle(ctx context.Context, c Claim, fence string, run Run) ([]byte, error) {
	key := ledgerKey(c.ID)
	result, err := run(ctx, c)
	var f *Failure
	switch {
	case err == nil && len(result) > MaxResultBytes:
		markErr := s.Ledger.MarkUnknown(context.WithoutCancel(ctx), key, fence)
		return nil, unknown(c.ID, ErrResultTooLarge, markErr)
	case err == nil:
		if cerr := s.Ledger.Complete(context.WithoutCancel(ctx), key, fence, append([]byte{completed}, result...)); cerr != nil {
			markErr := s.Ledger.MarkUnknown(context.WithoutCancel(ctx), key, fence)
			return nil, unknown(c.ID, cerr, markErr)
		}
		return result, nil
	case errors.As(err, &f):
		if len(f.Reason) > MaxResultBytes {
			return s.releaseFailure(ctx, c.ID, key, fence, f, ErrResultTooLarge)
		}
		if cerr := s.Ledger.Complete(context.WithoutCancel(ctx), key, fence, append([]byte{failed}, f.Reason...)); cerr != nil {
			return s.releaseFailure(ctx, c.ID, key, fence, f, cerr)
		}
		return nil, f
	default:
		markErr := s.Ledger.MarkUnknown(context.WithoutCancel(ctx), key, fence)
		return nil, unknown(c.ID, err, markErr)
	}
}

func (s *Service) releaseFailure(ctx context.Context, id int64, key, fence string, failure *Failure, cause error) ([]byte, error) {
	if err := s.Ledger.Release(context.WithoutCancel(ctx), key, fence); err != nil {
		return nil, unknown(id, failure, cause, err)
	}
	return nil, errors.Join(failure, cause)
}

func recorded(id int64, e model.LedgerEntry) ([]byte, error) {
	switch {
	case e.State == model.LedgerInFlight:
		return nil, ErrInFlight
	case e.State == model.LedgerUnknown:
		return nil, unknown(id)
	case len(e.Result) > 0 && e.Result[0] == completed:
		return e.Result[1:], nil
	case len(e.Result) > 0 && e.Result[0] == failed:
		return nil, &Failure{Reason: string(e.Result[1:])}
	}
	return nil, fmt.Errorf("actiontoken: claim %d has a malformed ledger entry", id)
}

func ledgerKey(id int64) string { return "action_token:" + strconv.FormatInt(id, 10) }

func (s *Service) claim(ctx context.Context, query string, args ...any) (Claim, bool, error) {
	if s == nil || s.Ledger == nil {
		return Claim{}, false, errLedger
	}
	qs, err := s.query(ctx)
	if err != nil {
		return Claim{}, false, err
	}
	res, err := qs.Query(ctx, query, args...)
	if err != nil {
		return Claim{}, false, err
	}
	if res == nil {
		return Claim{}, false, errors.New("actiontoken: database returned no result")
	}
	if len(res.Rows) == 0 {
		return Claim{}, false, nil
	}
	row := res.Rows[0]
	if len(row) != 6 {
		return Claim{}, false, errors.New("actiontoken: database returned a malformed claim")
	}
	return Claim{
		ID:      common.AsInt64(row[0]),
		User:    port.UserRef{UserID: common.AsInt64(row[1]), PartnerID: common.AsInt64(row[2])},
		Binding: Binding{Action: common.AsString(row[3]), ResourceKey: common.AsString(row[4]), Digest: common.AsString(row[5])},
	}, true, nil
}
