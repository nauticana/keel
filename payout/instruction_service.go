package payout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nauticana/keel/logger"
)

// InstructionService records payout instructions, dispatches them through
// the partner's provider and applies provider transfer outcomes to them.
// Every state change commits in a short store transaction; provider calls
// run between transactions, never inside one.
type InstructionService struct {
	Store     InstructionStore
	Providers ProviderResolver
	Allocator Allocator
	Journal   logger.ApplicationLogger

	// DispatchRetention bounds retrying an unresolved dispatch under its
	// provider idempotency key (Stripe retains keys ~24h); zero never retries.
	DispatchRetention time.Duration
	Now               func() time.Time
}

func NewInstructionService(store InstructionStore, providers ProviderResolver, allocator Allocator, journal logger.ApplicationLogger) *InstructionService {
	return &InstructionService{
		Store:             store,
		Providers:         providers,
		Allocator:         allocator,
		Journal:           journal,
		DispatchRetention: 20 * time.Hour,
		Now:               func() time.Time { return time.Now().UTC() },
	}
}

// Create records the instruction and allocates it against the payee's
// earnings in one transaction. Replaying a key returns the original
// instruction without allocating again; reusing it for a different payout
// is ErrIdempotencyKeyReused.
func (s *InstructionService) Create(ctx context.Context, req InstructionRequest) (*Instruction, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	var out *Instruction
	err := s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr := req.instruction()
		instr.CreatedAt = s.now()
		inserted, err := tx.Insert(ctx, instr)
		if err != nil {
			return err
		}
		if !inserted {
			existing, err := tx.FindByKey(ctx, req.PartnerID, req.IdempotencyKey)
			if err != nil {
				return err
			}
			if !req.sameAs(existing) {
				return fmt.Errorf("%w: %q", ErrIdempotencyKeyReused, req.IdempotencyKey)
			}
			out = existing
			return nil
		}
		if err := s.Allocator.Allocate(ctx, tx.Queries(), instr); err != nil {
			return fmt.Errorf("allocate payout instruction: %w", err)
		}
		out = instr
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Execute dispatches a new or failed instruction on a new leg, or retries
// the in-flight leg under its own key (resuming only the missing payout
// leg once funding is recorded). Other states are returned unchanged; a
// provider error is returned alongside the recorded instruction.
func (s *InstructionService) Execute(ctx context.Context, id int64) (*Instruction, error) {
	plan, current, err := s.claimDispatch(ctx, id)
	if err != nil || plan == nil {
		return current, err
	}
	result, callErr := s.dispatch(ctx, plan)
	return s.recordDispatch(ctx, id, plan.leg.LegNo, result, callErr)
}

func (s *InstructionService) claimDispatch(ctx context.Context, id int64) (*dispatchPlan, *Instruction, error) {
	var plan *dispatchPlan
	var current *Instruction
	unresolved := false
	err := s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr, err := tx.Lock(ctx, id)
		if err != nil {
			return err
		}
		current = instr
		switch instr.Status {
		case InstructionNew, InstructionFailed:
			plan, err = s.openLeg(ctx, tx, instr)
			return err
		case InstructionDispatching:
			leg := instr.liveLeg()
			if leg == nil || leg.Status != LegDispatching {
				return fmt.Errorf("%w: instruction %d dispatching without a dispatching leg", ErrTransferConflict, id)
			}
			provider, err := s.Providers.ByCode(leg.Provider)
			if err != nil {
				return err
			}
			_, canResume := provider.(PayoutResumer)
			switch {
			case leg.FundingID == "" && s.now().Sub(leg.CreatedAt) > s.DispatchRetention:
				unresolved = true
				return s.review(ctx, tx, instr, ErrDispatchUnresolved.Error())
			case leg.FundingID != "" && !canResume:
				unresolved = true
				return s.review(ctx, tx, instr, fmt.Sprintf("provider %s cannot resume a funded payout", leg.Provider))
			}
			leg.Attempts++
			if err := tx.UpdateLeg(ctx, id, leg); err != nil {
				return err
			}
			plan = &dispatchPlan{instr: instr, leg: *leg, provider: provider}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if unresolved {
		return nil, current, fmt.Errorf("payout instruction %d: %w", id, ErrDispatchUnresolved)
	}
	return plan, current, nil
}

func (s *InstructionService) openLeg(ctx context.Context, tx InstructionTx, instr *Instruction) (*dispatchPlan, error) {
	provider, err := s.Providers.ForPartner(ctx, instr.PartnerID)
	if err != nil {
		return nil, err
	}
	dest, err := tx.Destination(ctx, instr.UserID, instr.PartnerID)
	if err != nil {
		return nil, err
	}
	if err := dest.payableBy(provider.Code(), instr.Currency); err != nil {
		return nil, err
	}
	legNo := instr.nextLegNo()
	leg := InstructionLeg{
		LegNo:             legNo,
		Provider:          provider.Code(),
		BankInfoID:        dest.BankInfoID,
		ProviderAccountID: dest.ProviderAccountID,
		AmountMinor:       instr.AmountMinor,
		IdempotencyKey:    fmt.Sprintf("payout-instruction-%d-%d", instr.ID, legNo),
		Status:            LegDispatching,
		Attempts:          1,
		CreatedAt:         s.now(),
	}
	if err := tx.InsertLeg(ctx, instr.ID, &leg); err != nil {
		return nil, err
	}
	instr.Legs = append(instr.Legs, leg)
	instr.Status = InstructionDispatching
	instr.FailureReason = ""
	if err := tx.UpdateStatus(ctx, instr); err != nil {
		return nil, err
	}
	return &dispatchPlan{instr: instr, leg: leg, provider: provider}, nil
}

func (s *InstructionService) dispatch(ctx context.Context, plan *dispatchPlan) (*InstantPayoutResult, error) {
	in := InstantPayoutInput{
		UserID:            plan.instr.UserID,
		PartnerID:         plan.instr.PartnerID,
		ProviderAccountID: plan.leg.ProviderAccountID,
		Amount:            plan.leg.AmountMinor,
		Currency:          plan.instr.Currency,
		IdempotencyKey:    plan.leg.IdempotencyKey,
	}
	if plan.leg.FundingID != "" {
		return plan.provider.(PayoutResumer).ResumePayout(ctx, in, plan.leg.FundingID)
	}
	return plan.provider.RequestInstantPayout(ctx, in)
}

func (s *InstructionService) recordDispatch(ctx context.Context, id int64, legNo int, result *InstantPayoutResult, callErr error) (*Instruction, error) {
	var out *Instruction
	err := s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr, err := tx.Lock(ctx, id)
		if err != nil {
			return err
		}
		out = instr
		leg := instr.leg(legNo)
		if leg == nil {
			return fmt.Errorf("payout instruction %d: leg %d vanished", id, legNo)
		}
		if leg.Status != LegDispatching {
			return nil // an event or a concurrent executor already recorded it
		}
		if result != nil {
			if leg.FundingID == "" {
				leg.FundingID = result.ProviderFundingID
			}
			if leg.PayoutID == "" {
				leg.PayoutID = result.ProviderPayoutID
			}
		}
		providerStatus := ""
		if callErr != nil {
			leg.FailureReason = callErr.Error()
		} else if result != nil {
			providerStatus = result.Status
		}
		switch {
		case callErr != nil && leg.FundingID == "" && leg.PayoutID == "" && dispatchRejected(callErr):
			return s.applyOutcome(ctx, tx, instr, leg, PayoutEventTransferFailed, 0, 0)
		case leg.PayoutID == "":
			return tx.UpdateLeg(ctx, id, leg) // ambiguous or funding-only: retried or resumed by Execute
		case providerStatus == "paid":
			return s.applyOutcome(ctx, tx, instr, leg, PayoutEventTransferPaid, 0, 0)
		case providerStatus == "failed":
			return s.applyOutcome(ctx, tx, instr, leg, PayoutEventTransferFailed, 0, 0)
		case providerStatus == "returned":
			return s.applyOutcome(ctx, tx, instr, leg, PayoutEventTransferReturned, 0, 0)
		}
		leg.Status = LegPending
		instr.Status = InstructionPending
		if err := tx.UpdateLeg(ctx, id, leg); err != nil {
			return err
		}
		return tx.UpdateStatus(ctx, instr)
	})
	if err != nil {
		return nil, err
	}
	if callErr == nil && result != nil && result.ProviderPayoutID == "" && result.ProviderFundingID == "" {
		callErr = fmt.Errorf("payout instruction %d: provider returned no transfer id", id)
	}
	return out, callErr
}

// dispatchRejected reports errors whose provider contract guarantees no
// transfer was created, so a new leg with a new key cannot double-pay.
func dispatchRejected(err error) bool {
	return errors.Is(err, ErrInsufficientBalance) ||
		errors.Is(err, ErrInstantPayoutUnavailable) ||
		errors.Is(err, ErrNotImplemented)
}

// ApplyTransferEvent moves the leg named by ev.ProviderTransferID on
// ev.Provider. The event id record, leg and instruction state and any
// Allocator posting commit together, and reversals apply as a cumulative
// total, so a replayed or re-polled event never posts twice.
func (s *InstructionService) ApplyTransferEvent(ctx context.Context, ev *PayoutWebhookEvent) error {
	if ev == nil || ev.Provider == "" || ev.ProviderTransferID == "" {
		return fmt.Errorf("payout: transfer event requires provider and transfer id")
	}
	switch ev.Type {
	case PayoutEventTransferPaid, PayoutEventTransferFailed, PayoutEventTransferReturned, PayoutEventTransferReversed:
	default:
		return fmt.Errorf("payout: %q is not a transfer event", ev.Type)
	}
	return s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr, err := tx.LockByTransfer(ctx, ev.Provider, ev.ProviderTransferID)
		if err != nil {
			return err
		}
		leg := instr.legByTransfer(ev.Provider, ev.ProviderTransferID)
		if leg == nil {
			return fmt.Errorf("%w: %s transfer %s", ErrInstructionNotFound, ev.Provider, ev.ProviderTransferID)
		}
		if ev.RawEventID != "" {
			duplicate, err := tx.RecordEvent(ctx, instr.ID, leg.LegNo, ev)
			if err != nil || duplicate {
				return err
			}
		}
		return s.applyOutcome(ctx, tx, instr, leg, ev.Type, ev.AmountMinor, ev.AmountReversedMinor)
	})
}

func (s *InstructionService) applyOutcome(ctx context.Context, tx InstructionTx, instr *Instruction, leg *InstructionLeg, outcome PayoutWebhookEventType, amountMinor, reversedMinor int64) error {
	conflict := func() error {
		return fmt.Errorf("%w: %s on instruction %d leg %d in state %s", ErrTransferConflict, outcome, instr.ID, leg.LegNo, leg.Status)
	}
	if outcome == PayoutEventTransferFailed && leg.Status == LegSettled {
		outcome = PayoutEventTransferReturned // a provider may fail a payout after reporting it paid
	}
	switch outcome {
	case PayoutEventTransferPaid:
		switch leg.Status {
		case LegSettled, LegReversed:
			return nil
		case LegDispatching, LegPending:
			leg.Status = LegSettled
			instr.Status = InstructionSettled
		default:
			return conflict()
		}
	case PayoutEventTransferFailed:
		switch {
		case leg.Status == LegFailed:
			return nil
		case leg.Status != LegDispatching && leg.Status != LegPending:
			return conflict()
		}
		leg.Status = LegFailed
		instr.Status = InstructionFailed
		instr.FailureReason = fmt.Sprintf("leg %d %s", leg.LegNo, outcome)
	case PayoutEventTransferReturned:
		switch {
		case leg.Status == LegReturned:
			return nil
		case leg.Status == LegFailed || leg.Status == LegReversed || leg.ReversedMinor > 0:
			return conflict()
		}
		leg.Status = LegReturned
		instr.Status = InstructionFailed
		instr.FailureReason = fmt.Sprintf("leg %d %s", leg.LegNo, outcome)
	case PayoutEventTransferReversed:
		if leg.Status == LegFailed || leg.Status == LegReturned {
			return conflict()
		}
		if amountMinor > 0 && amountMinor != leg.AmountMinor {
			return fmt.Errorf("%w: event amount %d, leg amount %d", ErrTransferConflict, amountMinor, leg.AmountMinor)
		}
		total := reversedMinor
		if total == 0 {
			total = leg.AmountMinor
		}
		if total > leg.AmountMinor {
			return fmt.Errorf("%w: %d of %d on instruction %d leg %d", ErrReversalExceedsLeg, total, leg.AmountMinor, instr.ID, leg.LegNo)
		}
		delta := total - leg.ReversedMinor
		if delta <= 0 {
			return nil
		}
		leg.ReversedMinor = total
		if total == leg.AmountMinor {
			leg.Status = LegReversed
			instr.Status = InstructionReversed
		}
		if err := s.Allocator.Release(ctx, tx.Queries(), instr, delta, ReleaseReversed); err != nil {
			return fmt.Errorf("release reversed payout: %w", err)
		}
	}
	if err := tx.UpdateLeg(ctx, instr.ID, leg); err != nil {
		return err
	}
	return tx.UpdateStatus(ctx, instr)
}

// Cancel releases a new or failed instruction's allocation back to earnings.
func (s *InstructionService) Cancel(ctx context.Context, id int64) error {
	return s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr, err := tx.Lock(ctx, id)
		if err != nil {
			return err
		}
		if instr.Status != InstructionNew && instr.Status != InstructionFailed {
			return fmt.Errorf("%w: instruction %d in state %s", ErrInstructionNotCancellable, id, instr.Status)
		}
		instr.Status = InstructionCancelled
		if err := s.Allocator.Release(ctx, tx.Queries(), instr, instr.AmountMinor, ReleaseCancelled); err != nil {
			return fmt.Errorf("release cancelled payout: %w", err)
		}
		return tx.UpdateStatus(ctx, instr)
	})
}

// Reconcile resolves an in-flight instruction without a webhook: a
// dispatching one is re-executed, a pending one is settled from the
// provider's payout status. Reversals carry amounts only on provider
// events, so a polled reversal is reported, not applied.
func (s *InstructionService) Reconcile(ctx context.Context, id int64) error {
	var instr *Instruction
	if err := s.Store.InTx(ctx, func(tx InstructionTx) error {
		var err error
		instr, err = tx.Lock(ctx, id)
		return err
	}); err != nil {
		return err
	}
	switch instr.Status {
	case InstructionDispatching:
		_, err := s.Execute(ctx, id)
		return err
	case InstructionPending:
	default:
		return nil
	}
	leg := instr.liveLeg()
	if leg == nil || leg.PayoutID == "" {
		return fmt.Errorf("%w: pending instruction %d has no payout transfer", ErrTransferConflict, id)
	}
	provider, err := s.Providers.ByCode(leg.Provider)
	if err != nil {
		return err
	}
	status, err := provider.GetPayoutStatus(ctx, leg.PayoutID)
	if err != nil {
		return fmt.Errorf("payout instruction %d: status: %w", id, err)
	}
	var outcome PayoutWebhookEventType
	switch status.Status {
	case "paid":
		outcome = PayoutEventTransferPaid
	case "failed":
		outcome = PayoutEventTransferFailed
	case "returned":
		outcome = PayoutEventTransferReturned
	case "reversed":
		return fmt.Errorf("payout instruction %d: provider reports reversed; apply the provider's reversal event", id)
	default:
		return nil
	}
	return s.ApplyTransferEvent(ctx, &PayoutWebhookEvent{Type: outcome, Provider: leg.Provider, ProviderTransferID: leg.PayoutID})
}

// ReconcileInFlight reconciles instructions left dispatching or pending
// since before updatedBefore, up to limit.
func (s *InstructionService) ReconcileInFlight(ctx context.Context, updatedBefore time.Time, limit int) error {
	ids, err := s.Store.InFlight(ctx, updatedBefore, limit)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := s.Reconcile(ctx, id); err != nil {
			s.logError(err.Error())
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *InstructionService) review(ctx context.Context, tx InstructionTx, instr *Instruction, reason string) error {
	instr.Status = InstructionReview
	instr.FailureReason = reason
	s.logError(fmt.Sprintf("payout instruction %d parked for review: %s", instr.ID, reason))
	return tx.UpdateStatus(ctx, instr)
}

func (s *InstructionService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *InstructionService) logError(message string) {
	if s.Journal != nil {
		s.Journal.Error(message)
	}
}

var _ TransferEventSink = (*InstructionService)(nil)
