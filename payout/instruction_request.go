package payout

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
)

const maxInstructionKeyLength = 200

// InstructionRequest asks for a payout; IdempotencyKey is unique per partner.
type InstructionRequest struct {
	PartnerID      int64
	UserID         int64
	Currency       string
	AmountMinor    int64
	IdempotencyKey string
}

func (r InstructionRequest) validate() error {
	switch {
	case r.PartnerID <= 0 || r.UserID <= 0:
		return fmt.Errorf("%w: partner and payee are required", ErrInvalidInstruction)
	case r.AmountMinor <= 0:
		return fmt.Errorf("%w: amount must be positive, got %d", ErrInvalidInstruction, r.AmountMinor)
	case r.IdempotencyKey == "" || len(r.IdempotencyKey) > maxInstructionKeyLength:
		return fmt.Errorf("%w: idempotency key must be 1-%d bytes", ErrInvalidInstruction, maxInstructionKeyLength)
	}
	if _, ok := common.CurrencyExponent(strings.ToUpper(r.Currency)); !ok {
		return fmt.Errorf("%w: unknown currency %q", ErrInvalidInstruction, r.Currency)
	}
	return nil
}

func (r InstructionRequest) instruction() *Instruction {
	return &Instruction{
		PartnerID:      r.PartnerID,
		UserID:         r.UserID,
		Currency:       strings.ToUpper(r.Currency),
		AmountMinor:    r.AmountMinor,
		IdempotencyKey: r.IdempotencyKey,
		Status:         InstructionNew,
	}
}

func (r InstructionRequest) sameAs(existing *Instruction) bool {
	return existing.UserID == r.UserID &&
		existing.AmountMinor == r.AmountMinor &&
		strings.EqualFold(existing.Currency, r.Currency)
}
