package payment

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

const (
	qRefundByID            = "payment_refund_by_id"
	qRefundByKey           = "payment_refund_by_key"
	qRefundBalanceID       = "payment_refund_balance_id"
	qRefundInsertBalance   = "payment_refund_insert_balance"
	qRefundLockBalance     = "payment_refund_lock_balance"
	qRefundTotals          = "payment_refund_totals"
	qRefundInsert          = "payment_refund_insert"
	qRefundApprove         = "payment_refund_approve"
	qRefundReject          = "payment_refund_reject"
	qRefundClaim           = "payment_refund_claim"
	qRefundRecordAccepted  = "payment_refund_record_accepted"
	qRefundRecordDeclined  = "payment_refund_record_declined"
	qRefundRecordError     = "payment_refund_record_error"
	qRefundApplyCumulative = "payment_refund_apply_cumulative"
)

const refundRecordSelect = `
SELECT r.id, b.provider, b.payment_id, b.currency, r.requester_id, r.approver_id,
       r.reason, r.amount_minor, r.provider_amount_minor, r.idempotency_key,
       r.status, r.provider_refund_id, r.last_error, r.attempt_count,
       r.created_at, r.decided_at, r.executed_at, r.first_attempt_at
  FROM refund_request r
  JOIN refund_balance b ON b.id = r.refund_balance_id`

var refundQueries = map[string]string{
	qRefundByID:      refundRecordSelect + ` WHERE r.id = ?`,
	qRefundByKey:     refundRecordSelect + ` WHERE r.idempotency_key = ?`,
	qRefundBalanceID: `SELECT id FROM refund_balance WHERE provider = ? AND payment_id = ?`,
	qRefundInsertBalance: `
INSERT INTO refund_balance (id, provider, payment_id, currency, captured_minor, refunded_minor)
VALUES (?, ?, ?, ?, ?, 0)
ON CONFLICT (provider, payment_id) DO NOTHING`,
	qRefundLockBalance: `
SELECT id, currency, captured_minor, refunded_minor
  FROM refund_balance
 WHERE provider = ? AND payment_id = ?
   FOR UPDATE`,
	qRefundTotals: `
SELECT status, COALESCE(SUM(COALESCE(provider_amount_minor, amount_minor)), 0)::BIGINT
  FROM refund_request
 WHERE refund_balance_id = ? AND status IN ('P', 'A', 'S')
 GROUP BY status`,
	qRefundInsert: `
INSERT INTO refund_request
 (id, refund_balance_id, requester_id, reason, amount_minor, idempotency_key, status)
VALUES (?, ?, ?, ?, ?, ?, 'P')
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING id`,
	qRefundApprove: `
UPDATE refund_request
   SET status = 'A', approver_id = ?, decided_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status = 'P' AND requester_id <> ?
RETURNING id`,
	qRefundReject: `
UPDATE refund_request
   SET status = 'F', approver_id = ?, decided_at = CURRENT_TIMESTAMP, last_error = ?
 WHERE id = ? AND status IN ('P', 'A')
RETURNING id`,
	qRefundClaim: `
UPDATE refund_request
   SET attempt_count = attempt_count + 1, last_error = NULL,
       first_attempt_at = COALESCE(first_attempt_at, CURRENT_TIMESTAMP)
 WHERE id = ? AND status = 'A'
   AND (first_attempt_at IS NULL OR first_attempt_at > CURRENT_TIMESTAMP - make_interval(secs => ?))
RETURNING id`,
	// F is included so a provider-accepted refund wins over a concurrent Reject.
	qRefundRecordAccepted: `
UPDATE refund_request
   SET status = 'S', provider_refund_id = ?, provider_amount_minor = ?,
       last_error = ?, executed_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status IN ('A', 'F')`,
	qRefundRecordDeclined: `
UPDATE refund_request
   SET status = 'F', provider_refund_id = ?, last_error = ?, executed_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status = 'A'`,
	qRefundRecordError: `
UPDATE refund_request SET last_error = ? WHERE id = ? AND status = 'A'`,
	qRefundApplyCumulative: `
UPDATE refund_balance
   SET refunded_minor = ?, updated_at = CURRENT_TIMESTAMP
 WHERE id = ?`,
}

// BaseRefundService stores refund requests in refund_request and the
// provider-confirmed refunded total per payment in refund_balance. Balance
// checks run under the balance row lock; provider calls run outside any
// transaction.
type BaseRefundService struct {
	DB       port.DatabaseRepository
	Provider string
	Client   RefundClient
	Captures CaptureReader
	// IdempotencyWindow is how long the provider dedupes a key; zero means 24h.
	IdempotencyWindow time.Duration

	qsOnce sync.Once
	qs     port.QueryService
}

func NewBaseRefundService(db port.DatabaseRepository, provider string, client RefundClient, captures CaptureReader) *BaseRefundService {
	return &BaseRefundService{DB: db, Provider: provider, Client: client, Captures: captures}
}

func (s *BaseRefundService) queryService(ctx context.Context) port.QueryService {
	s.qsOnce.Do(func() { s.qs = s.DB.GetQueryService(ctx, refundQueries) })
	return s.qs
}

type refundBalance struct {
	id            int64
	currency      string
	capturedMinor int64
	refundedMinor int64
}

func (s *BaseRefundService) Request(ctx context.Context, in RefundInstruction) (RefundRecord, error) {
	in.Currency = strings.ToUpper(strings.TrimSpace(in.Currency))
	switch {
	case in.PaymentID == "", in.IdempotencyKey == "", in.RequesterID <= 0:
		return RefundRecord{}, fmt.Errorf("%w: payment, requester and idempotency key are required", ErrRefundInvalidInstruction)
	case in.AmountMinor <= 0:
		return RefundRecord{}, fmt.Errorf("%w: amount must be positive", ErrRefundInvalidInstruction)
	case len(in.Currency) != 3:
		return RefundRecord{}, fmt.Errorf("%w: currency must be an ISO 4217 code", ErrRefundInvalidInstruction)
	}
	if rec, found, err := s.byKey(ctx, in.IdempotencyKey); err != nil || found {
		if err != nil {
			return RefundRecord{}, err
		}
		return s.sameInstruction(rec, in)
	}
	if err := s.ensureBalance(ctx, s.Provider, in.PaymentID); err != nil {
		return RefundRecord{}, err
	}
	id, err := s.reserve(ctx, in)
	if err != nil {
		return RefundRecord{}, err
	}
	if id == 0 {
		rec, found, err := s.byKey(ctx, in.IdempotencyKey)
		if err != nil {
			return RefundRecord{}, err
		}
		if !found {
			return RefundRecord{}, fmt.Errorf("refund: request %q vanished after idempotency conflict", in.IdempotencyKey)
		}
		return s.sameInstruction(rec, in)
	}
	return s.Get(ctx, id)
}

func (s *BaseRefundService) sameInstruction(rec RefundRecord, in RefundInstruction) (RefundRecord, error) {
	if rec.Provider != s.Provider || rec.PaymentID != in.PaymentID || rec.AmountMinor != in.AmountMinor ||
		rec.Currency != in.Currency || rec.RequesterID != in.RequesterID {
		return RefundRecord{}, ErrRefundIdempotencyConflict
	}
	return rec, nil
}

// reserve returns 0 when a concurrent Request inserted the same idempotency key first.
func (s *BaseRefundService) reserve(ctx context.Context, in RefundInstruction) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, refundQueries)
	if err != nil {
		return 0, fmt.Errorf("refund: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	bal, err := lockRefundBalance(ctx, tx, s.Provider, in.PaymentID)
	if err != nil {
		return 0, err
	}
	if bal.currency != in.Currency {
		return 0, fmt.Errorf("%w: %s, payment is %s", ErrRefundCurrencyMismatch, in.Currency, bal.currency)
	}
	res, err := tx.Query(ctx, qRefundTotals, bal.id)
	if err != nil {
		return 0, fmt.Errorf("refund: totals: %w", err)
	}
	var open, succeeded int64
	for _, row := range res.Rows {
		if common.AsString(row[0]) == RefundRequestSucceeded {
			succeeded += common.AsInt64(row[1])
		} else {
			open += common.AsInt64(row[1])
		}
	}
	// Provider refunds made outside this service surface only in refundedMinor.
	remaining := bal.capturedMinor - max(bal.refundedMinor, succeeded) - open
	if in.AmountMinor > remaining {
		return 0, fmt.Errorf("%w: requested %d, remaining %d", ErrRefundExceedsBalance, in.AmountMinor, max(remaining, 0))
	}
	res, err = tx.Query(ctx, qRefundInsert, tx.GenID(), bal.id, in.RequesterID, common.NullIfEmpty(in.Reason), in.AmountMinor, in.IdempotencyKey)
	if err != nil {
		return 0, fmt.Errorf("refund: insert request: %w", err)
	}
	var id int64
	if len(res.Rows) > 0 {
		id = common.AsInt64(res.Rows[0][0])
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("refund: commit: %w", err)
	}
	committed = true
	return id, nil
}

func (s *BaseRefundService) ensureBalance(ctx context.Context, provider, paymentID string) error {
	res, err := s.queryService(ctx).Query(ctx, qRefundBalanceID, provider, paymentID)
	if err != nil {
		return fmt.Errorf("refund: read balance: %w", err)
	}
	if len(res.Rows) > 0 {
		return nil
	}
	captured, err := s.Captures.CapturedAmount(ctx, paymentID)
	if err != nil {
		return fmt.Errorf("refund: %w", err)
	}
	if len(captured.Currency) != 3 || captured.AmountMinor < 0 {
		return ErrRefundCapturedAmountAbsent
	}
	qs := s.queryService(ctx)
	if _, err := qs.Query(ctx, qRefundInsertBalance, qs.GenID(), provider, paymentID,
		strings.ToUpper(captured.Currency), captured.AmountMinor); err != nil {
		return fmt.Errorf("refund: create balance: %w", err)
	}
	return nil
}

func lockRefundBalance(ctx context.Context, tx port.TxQueryService, provider, paymentID string) (refundBalance, error) {
	res, err := tx.Query(ctx, qRefundLockBalance, provider, paymentID)
	if err != nil {
		return refundBalance{}, fmt.Errorf("refund: lock balance: %w", err)
	}
	if len(res.Rows) == 0 {
		return refundBalance{}, fmt.Errorf("refund: balance for %s/%s missing", provider, paymentID)
	}
	row := res.Rows[0]
	return refundBalance{
		id:            common.AsInt64(row[0]),
		currency:      common.AsString(row[1]),
		capturedMinor: common.AsInt64(row[2]),
		refundedMinor: common.AsInt64(row[3]),
	}, nil
}

func (s *BaseRefundService) Approve(ctx context.Context, requestID, approverID int64) (RefundRecord, error) {
	res, err := s.queryService(ctx).Query(ctx, qRefundApprove, approverID, requestID, approverID)
	if err != nil {
		return RefundRecord{}, fmt.Errorf("refund: approve: %w", err)
	}
	rec, err := s.Get(ctx, requestID)
	if err != nil || len(res.Rows) > 0 {
		return rec, err
	}
	switch {
	case rec.Status == RefundRequestPending && rec.RequesterID == approverID:
		return RefundRecord{}, ErrRefundSelfApproval
	case rec.Status == RefundRequestApproved && rec.ApproverID == approverID:
		return rec, nil
	}
	return RefundRecord{}, fmt.Errorf("%w: status %s", ErrRefundInvalidState, rec.Status)
}

func (s *BaseRefundService) Reject(ctx context.Context, requestID, actorID int64, note string) (RefundRecord, error) {
	res, err := s.queryService(ctx).Query(ctx, qRefundReject, actorID, common.NullIfEmpty(note), requestID)
	if err != nil {
		return RefundRecord{}, fmt.Errorf("refund: reject: %w", err)
	}
	rec, err := s.Get(ctx, requestID)
	if err != nil || len(res.Rows) > 0 {
		return rec, err
	}
	if rec.Status == RefundRequestFailed && rec.ApproverID == actorID {
		return rec, nil
	}
	return RefundRecord{}, fmt.Errorf("%w: status %s", ErrRefundInvalidState, rec.Status)
}

func (s *BaseRefundService) Execute(ctx context.Context, requestID int64) (RefundRecord, error) {
	qs := s.queryService(ctx)
	window := s.IdempotencyWindow
	if window <= 0 {
		window = 24 * time.Hour
	}
	res, err := qs.Query(ctx, qRefundClaim, requestID, window.Seconds())
	if err != nil {
		return RefundRecord{}, fmt.Errorf("refund: claim: %w", err)
	}
	rec, err := s.Get(ctx, requestID)
	if err != nil {
		return RefundRecord{}, err
	}
	if len(res.Rows) == 0 {
		switch rec.Status {
		case RefundRequestSucceeded:
			return rec, nil
		case RefundRequestApproved:
			// An earlier ambiguous attempt may have refunded; a resubmit past the window would not be deduped.
			return rec, fmt.Errorf("%w: first attempt %s", ErrRefundNeedsReconciliation, rec.FirstAttemptAt.Format(time.RFC3339))
		}
		return rec, fmt.Errorf("%w: status %s", ErrRefundNotApproved, rec.Status)
	}
	result, callErr := s.Client.CreateRefund(ctx, RefundRequest{
		PaymentID:      rec.PaymentID,
		AmountMinor:    rec.AmountMinor,
		Currency:       rec.Currency,
		IdempotencyKey: rec.IdempotencyKey,
		Metadata:       map[string]string{"refund_request_id": strconv.FormatInt(rec.ID, 10)},
	})
	if callErr == nil && (result.RefundID == "" || result.AmountMinor <= 0 || result.Status == "") {
		callErr = errors.New("provider returned an incomplete refund result")
	}
	var outcome error
	switch {
	case errors.Is(callErr, ErrRefundAmountMismatch):
		note := fmt.Sprintf("provider refunded %d, requested %d", result.AmountMinor, rec.AmountMinor)
		_, err = qs.Query(ctx, qRefundRecordAccepted, result.RefundID, result.AmountMinor, note, requestID)
		outcome = ErrRefundAmountMismatch
	case callErr != nil:
		_, err = qs.Query(ctx, qRefundRecordError, callErr.Error(), requestID)
		outcome = fmt.Errorf("refund: execute: %w", callErr)
	case result.Status == RefundFailed:
		_, err = qs.Query(ctx, qRefundRecordDeclined, common.NullIfEmpty(result.RefundID), "provider declined", requestID)
		outcome = ErrRefundProviderDeclined
	default:
		_, err = qs.Query(ctx, qRefundRecordAccepted, result.RefundID, result.AmountMinor, nil, requestID)
	}
	if err != nil {
		return rec, errors.Join(fmt.Errorf("refund: record provider outcome: %w", err), outcome)
	}
	return s.withRecord(ctx, requestID, outcome)
}

func (s *BaseRefundService) withRecord(ctx context.Context, requestID int64, outcome error) (RefundRecord, error) {
	rec, err := s.Get(ctx, requestID)
	if err != nil {
		return rec, errors.Join(err, outcome)
	}
	return rec, outcome
}

// ApplyRefundEvent converts a cumulative provider refund total into the delta
// not yet applied. Stale or replayed totals yield a zero delta.
func (s *BaseRefundService) ApplyRefundEvent(ctx context.Context, event *PaymentEvent) (RefundDelta, error) {
	switch {
	case event == nil || !event.RefundCumulative:
		return RefundDelta{}, ErrRefundEventNotCumulative
	case event.Provider != s.Provider:
		return RefundDelta{}, fmt.Errorf("refund: event provider %q, service provider %q", event.Provider, s.Provider)
	case event.PaymentID == "":
		return RefundDelta{}, fmt.Errorf("refund: event %s has no payment id", event.ProviderEventID)
	case event.MinorUnits > 0:
		return RefundDelta{}, fmt.Errorf("refund: event %s cumulative total is positive", event.ProviderEventID)
	}
	if err := s.ensureBalance(ctx, event.Provider, event.PaymentID); err != nil {
		return RefundDelta{}, err
	}
	tx, err := s.DB.BeginTx(ctx, refundQueries)
	if err != nil {
		return RefundDelta{}, fmt.Errorf("refund: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	bal, err := lockRefundBalance(ctx, tx, event.Provider, event.PaymentID)
	if err != nil {
		return RefundDelta{}, err
	}
	if event.Currency != "" && !strings.EqualFold(event.Currency, bal.currency) {
		return RefundDelta{}, fmt.Errorf("%w: event %s, payment %s", ErrRefundCurrencyMismatch, event.Currency, bal.currency)
	}
	delta := RefundDelta{Provider: event.Provider, PaymentID: event.PaymentID, Currency: bal.currency, CumulativeMinor: bal.refundedMinor}
	if cumulative := -event.MinorUnits; cumulative > bal.refundedMinor {
		if _, err := tx.Query(ctx, qRefundApplyCumulative, cumulative, bal.id); err != nil {
			return RefundDelta{}, fmt.Errorf("refund: apply cumulative: %w", err)
		}
		delta.CumulativeMinor, delta.DeltaMinor = cumulative, cumulative-bal.refundedMinor
	}
	if err := tx.Commit(ctx); err != nil {
		return RefundDelta{}, fmt.Errorf("refund: commit: %w", err)
	}
	committed = true
	return delta, nil
}

func (s *BaseRefundService) Get(ctx context.Context, requestID int64) (RefundRecord, error) {
	res, err := s.queryService(ctx).Query(ctx, qRefundByID, requestID)
	if err != nil {
		return RefundRecord{}, fmt.Errorf("refund: read request: %w", err)
	}
	if len(res.Rows) == 0 {
		return RefundRecord{}, ErrRefundRequestNotFound
	}
	return refundRecordFromRow(res.Rows[0]), nil
}

func (s *BaseRefundService) byKey(ctx context.Context, key string) (RefundRecord, bool, error) {
	res, err := s.queryService(ctx).Query(ctx, qRefundByKey, key)
	if err != nil {
		return RefundRecord{}, false, fmt.Errorf("refund: read request: %w", err)
	}
	if len(res.Rows) == 0 {
		return RefundRecord{}, false, nil
	}
	return refundRecordFromRow(res.Rows[0]), true, nil
}

func refundRecordFromRow(row []any) RefundRecord {
	optionalInt := func(v any) int64 { n, _ := common.AsInt64OK(v); return n }
	return RefundRecord{
		ID:                  common.AsInt64(row[0]),
		Provider:            common.AsString(row[1]),
		PaymentID:           common.AsString(row[2]),
		Currency:            common.AsString(row[3]),
		RequesterID:         common.AsInt64(row[4]),
		ApproverID:          optionalInt(row[5]),
		Reason:              common.AsString(row[6]),
		AmountMinor:         common.AsInt64(row[7]),
		ProviderAmountMinor: optionalInt(row[8]),
		IdempotencyKey:      common.AsString(row[9]),
		Status:              common.AsString(row[10]),
		ProviderRefundID:    common.AsString(row[11]),
		LastError:           common.AsString(row[12]),
		AttemptCount:        int(common.AsInt64(row[13])),
		CreatedAt:           common.AsTime(row[14]),
		DecidedAt:           common.AsTime(row[15]),
		ExecutedAt:          common.AsTime(row[16]),
		FirstAttemptAt:      common.AsTime(row[17]),
	}
}

var _ RefundService = (*BaseRefundService)(nil)
