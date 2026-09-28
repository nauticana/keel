package payout

import "time"

// Instruction status codes stored in payout_instruction.status. Failed
// keeps the allocation: Execute retries on a new leg, Cancel releases it.
const (
	InstructionNew         = "N"
	InstructionDispatching = "D"
	InstructionPending     = "P"
	InstructionSettled     = "S"
	InstructionFailed      = "F"
	InstructionReversed    = "V"
	InstructionCancelled   = "X"
	InstructionReview      = "M"
)

// Instruction is one idempotent payout of AmountMinor to a partner's payee,
// executed through one or more provider legs.
type Instruction struct {
	ID             int64            `json:"id"`
	PartnerID      int64            `json:"partnerId"`
	UserID         int64            `json:"userId"`
	Currency       string           `json:"currency"`
	AmountMinor    int64            `json:"amountMinor"`
	IdempotencyKey string           `json:"idempotencyKey"`
	Status         string           `json:"status"`
	FailureReason  string           `json:"failureReason,omitempty"`
	CreatedAt      time.Time        `json:"createdAt"`
	Legs           []InstructionLeg `json:"legs"`
}

func (i *Instruction) leg(legNo int) *InstructionLeg {
	for n := range i.Legs {
		if i.Legs[n].LegNo == legNo {
			return &i.Legs[n]
		}
	}
	return nil
}

func (i *Instruction) legByTransfer(provider, transferID string) *InstructionLeg {
	for n := range i.Legs {
		l := &i.Legs[n]
		if l.Provider == provider && (l.PayoutID == transferID || l.FundingID == transferID) {
			return l
		}
	}
	return nil
}

// liveLeg is the leg still awaiting a provider outcome; at most one exists.
func (i *Instruction) liveLeg() *InstructionLeg {
	for n := range i.Legs {
		if s := i.Legs[n].Status; s == LegDispatching || s == LegPending {
			return &i.Legs[n]
		}
	}
	return nil
}

func (i *Instruction) nextLegNo() int {
	next := 1
	for _, l := range i.Legs {
		if l.LegNo >= next {
			next = l.LegNo + 1
		}
	}
	return next
}
