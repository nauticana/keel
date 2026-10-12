package payout

import (
	"fmt"
	"strings"
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
	code := normalizeCurrency(r.Currency)
	if len(code) != 3 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return fmt.Errorf("%w: currency %q is not an ISO 4217 code", ErrInvalidInstruction, r.Currency)
	}
	return nil
}

func (r InstructionRequest) instruction() *Instruction {
	return &Instruction{
		PartnerID:      r.PartnerID,
		UserID:         r.UserID,
		Currency:       normalizeCurrency(r.Currency),
		AmountMinor:    r.AmountMinor,
		IdempotencyKey: r.IdempotencyKey,
		Status:         InstructionNew,
	}
}

func (r InstructionRequest) sameAs(existing *Instruction) bool {
	return existing.UserID == r.UserID &&
		existing.AmountMinor == r.AmountMinor &&
		existing.Currency == normalizeCurrency(r.Currency)
}

func normalizeCurrency(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }
