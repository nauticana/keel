package payout

import "time"

// Leg status codes stored in payout_instruction_leg.status.
const (
	LegDispatching = "D"
	LegPending     = "P"
	LegSettled     = "S"
	LegFailed      = "F"
	LegReturned    = "R"
	LegReversed    = "V"
)

// InstructionLeg is one provider dispatch of an instruction under its own
// provider idempotency key. FundingID and PayoutID name the provider's
// funding and bank-payout transfers (equal on single-step providers).
type InstructionLeg struct {
	LegNo             int       `json:"legNo"`
	Provider          string    `json:"provider"`
	BankInfoID        int64     `json:"bankInfoId"`
	ProviderAccountID string    `json:"providerAccountId"`
	AmountMinor       int64     `json:"amountMinor"`
	IdempotencyKey    string    `json:"idempotencyKey"`
	FundingID         string    `json:"fundingId,omitempty"`
	PayoutID          string    `json:"payoutId,omitempty"`
	Status            string    `json:"status"`
	ReversedMinor     int64     `json:"reversedMinor"`
	Attempts          int       `json:"attempts"`
	FailureReason     string    `json:"failureReason,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
}
