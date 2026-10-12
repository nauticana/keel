package payment

// DeclineReason is a provider-neutral reason for a declined charge or
// authorization, safe to show the payer. Empty means the failure carried no
// provider decline code.
type DeclineReason string

const (
	DeclineInsufficientFunds    DeclineReason = "insufficient_funds"
	DeclineExpiredCard          DeclineReason = "expired_card"
	DeclineIncorrectCVC         DeclineReason = "incorrect_cvc"
	DeclineCardDeclined         DeclineReason = "card_declined"
	DeclineProcessingError      DeclineReason = "processing_error"
	DeclineAuthenticationFailed DeclineReason = "authentication_failed"
	DeclineOther                DeclineReason = "other"
)
