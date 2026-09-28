package payout

import (
	"context"
	"fmt"
	"strings"
)

type ReviewResolution string

const (
	ReviewConfirmedPaid     ReviewResolution = "paid"
	ReviewConfirmedFailed   ReviewResolution = "failed"
	ReviewConfirmedReturned ReviewResolution = "returned"
	ReviewConfirmedReversed ReviewResolution = "reversed"
)

type ReviewResolutionRequest struct {
	Outcome           ReviewResolution `json:"outcome"`
	ActorID           int64            `json:"-"`
	Note              string           `json:"note"`
	ProviderReference string           `json:"provider_reference"`
	ReversedMinor     int64            `json:"reversed_minor"`
}

type ReviewResolutionRecord struct {
	InstructionID     int64
	LegNo             int
	Outcome           ReviewResolution
	ActorID           int64
	Note              string
	ProviderReference string
	ReversedMinor     int64
}

func (r *ReviewResolutionRequest) validate() error {
	r.Note = strings.TrimSpace(r.Note)
	r.ProviderReference = strings.TrimSpace(r.ProviderReference)
	if r.ActorID <= 0 || r.Note == "" || len(r.Note) > 500 || r.ProviderReference == "" || len(r.ProviderReference) > 255 {
		return ErrInvalidReviewResolution
	}
	switch r.Outcome {
	case ReviewConfirmedPaid, ReviewConfirmedFailed, ReviewConfirmedReturned:
		if r.ReversedMinor != 0 {
			return ErrInvalidReviewResolution
		}
	case ReviewConfirmedReversed:
		if r.ReversedMinor <= 0 {
			return ErrInvalidReviewResolution
		}
	default:
		return ErrInvalidReviewResolution
	}
	return nil
}

// ResolveReview records an operator-confirmed provider outcome and leaves
// failed or returned instructions available for a separate retry or cancel.
func (s *InstructionService) ResolveReview(ctx context.Context, id int64, req ReviewResolutionRequest) (*Instruction, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	var out *Instruction
	err := s.Store.InTx(ctx, func(tx InstructionTx) error {
		instr, err := tx.Lock(ctx, id)
		if err != nil {
			return err
		}
		if instr.Status != InstructionReview {
			return fmt.Errorf("%w: instruction %d in state %s", ErrInstructionNotReviewable, id, instr.Status)
		}
		if len(instr.Legs) == 0 {
			return fmt.Errorf("%w: instruction %d has no payout leg", ErrInvalidReviewResolution, id)
		}
		leg := &instr.Legs[len(instr.Legs)-1]
		if (req.Outcome == ReviewConfirmedFailed || req.Outcome == ReviewConfirmedReturned) && leg.ReversedMinor > 0 {
			return fmt.Errorf("%w: leg %d already released %d by reversal", ErrInvalidReviewResolution, leg.LegNo, leg.ReversedMinor)
		}
		switch req.Outcome {
		case ReviewConfirmedPaid:
			leg.Status = LegSettled
			instr.Status = InstructionSettled
			instr.FailureReason = ""
		case ReviewConfirmedFailed:
			leg.Status = LegFailed
			instr.Status = InstructionFailed
			instr.FailureReason = fmt.Sprintf("leg %d manually confirmed failed", leg.LegNo)
		case ReviewConfirmedReturned:
			leg.Status = LegReturned
			instr.Status = InstructionFailed
			instr.FailureReason = fmt.Sprintf("leg %d manually confirmed returned", leg.LegNo)
		case ReviewConfirmedReversed:
			if req.ReversedMinor <= leg.ReversedMinor {
				return fmt.Errorf("%w: reversed amount must exceed the recorded %d", ErrInvalidReviewResolution, leg.ReversedMinor)
			}
			if req.ReversedMinor > leg.AmountMinor {
				return fmt.Errorf("%w: %d of %d on instruction %d leg %d", ErrReversalExceedsLeg, req.ReversedMinor, leg.AmountMinor, id, leg.LegNo)
			}
			delta := req.ReversedMinor - leg.ReversedMinor
			leg.ReversedMinor = req.ReversedMinor
			leg.Status = LegSettled
			instr.Status = InstructionSettled
			instr.FailureReason = ""
			if req.ReversedMinor == leg.AmountMinor {
				leg.Status = LegReversed
				instr.Status = InstructionReversed
			}
			if err := s.Allocator.Release(ctx, tx.Queries(), instr, delta, ReleaseReversed); err != nil {
				return fmt.Errorf("release manually confirmed reversal: %w", err)
			}
		}
		if err := tx.UpdateLeg(ctx, id, leg); err != nil {
			return err
		}
		if err := tx.UpdateStatus(ctx, instr); err != nil {
			return err
		}
		if err := tx.RecordResolution(ctx, ReviewResolutionRecord{
			InstructionID: id, LegNo: leg.LegNo, Outcome: req.Outcome, ActorID: req.ActorID,
			Note: req.Note, ProviderReference: req.ProviderReference, ReversedMinor: req.ReversedMinor,
		}); err != nil {
			return err
		}
		out = instr
		return nil
	})
	return out, err
}
