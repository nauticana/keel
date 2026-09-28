package payment

import (
	"context"
	"errors"
	"time"

	"github.com/nauticana/keel/port"
)

// Refund request status values stored in refund_request.status.
const (
	RefundRequestPending   = "P" // awaiting approval; reserves balance
	RefundRequestApproved  = "A" // approved; Execute submits it, retries keep it here
	RefundRequestSucceeded = "S" // accepted by the provider
	RefundRequestFailed    = "F" // rejected, or declined by the provider; releases balance
)

var (
	ErrRefundRequestNotFound      = errors.New("refund: request not found")
	ErrRefundExceedsBalance       = errors.New("refund: amount exceeds the remaining refundable balance")
	ErrRefundCurrencyMismatch     = errors.New("refund: currency differs from the payment currency")
	ErrRefundIdempotencyConflict  = errors.New("refund: idempotency key reused for a different refund")
	ErrRefundSelfApproval         = errors.New("refund: requester cannot approve their own refund")
	ErrRefundInvalidState         = errors.New("refund: request is not in a state that allows this action")
	ErrRefundNotApproved          = errors.New("refund: request is not approved")
	ErrRefundProviderDeclined     = errors.New("refund: provider declined the refund")
	ErrRefundEventNotCumulative   = errors.New("refund: event does not carry a cumulative refunded total")
	ErrRefundInvalidInstruction   = errors.New("refund: invalid refund instruction")
	ErrRefundCapturedAmountAbsent = errors.New("refund: captured amount unavailable")
	ErrRefundBalanceNotPrepared   = errors.New("refund: payment balance must be prepared before starting the transaction")
	ErrRefundNeedsReconciliation  = errors.New("refund: earlier attempt is outside the provider idempotency window; reconcile before retrying")
)

// RefundInstruction asks for a partial or full refund of a captured payment.
// IdempotencyKey makes Request retry-safe and is reused as the provider key.
type RefundInstruction struct {
	PaymentID      string
	RequesterID    int64
	AmountMinor    int64
	Currency       string
	Reason         string
	IdempotencyKey string
}

type RefundRecord struct {
	ID                  int64
	Provider            string
	PaymentID           string
	Currency            string
	RequesterID         int64
	ApproverID          int64
	Reason              string
	AmountMinor         int64
	ProviderAmountMinor int64 // zero until the provider reports an amount
	IdempotencyKey      string
	Status              string
	ProviderRefundID    string
	LastError           string
	AttemptCount        int
	CreatedAt           time.Time
	DecidedAt           time.Time
	ExecutedAt          time.Time
	FirstAttemptAt      time.Time
}

// RefundDelta is the provider refund observed by one cumulative event.
// DeltaMinor is the positive amount newly refunded since the last applied total.
type RefundDelta struct {
	Provider        string
	PaymentID       string
	Currency        string
	CumulativeMinor int64
	DeltaMinor      int64
}

// RefundService bounds refunds by the captured amount, records approval and
// executes them at the provider. Allocating a refund to domain amounts is the
// caller's job.
type RefundService interface {
	Request(ctx context.Context, in RefundInstruction) (RefundRecord, error)
	Approve(ctx context.Context, requestID, approverID int64) (RefundRecord, error)
	Reject(ctx context.Context, requestID, actorID int64, note string) (RefundRecord, error)
	// Execute is retry-safe within the provider idempotency window, after which
	// it returns ErrRefundNeedsReconciliation. An ErrRefundAmountMismatch result
	// is recorded as succeeded with the provider amount and never resubmitted.
	Execute(ctx context.Context, requestID int64) (RefundRecord, error)
	Get(ctx context.Context, requestID int64) (RefundRecord, error)
	ListByPayment(ctx context.Context, paymentID string) ([]RefundRecord, error)
	PreparePayment(ctx context.Context, paymentID string) error
	ApplyRefundEvent(ctx context.Context, event *PaymentEvent) (RefundDelta, error)
	ApplyRefundEventTx(ctx context.Context, tx port.TxQueryService, event *PaymentEvent) (RefundDelta, error)
}
