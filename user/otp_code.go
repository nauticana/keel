package user

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
)

// NewOTPCode returns a random six-digit code with no leading zero.
func NewOTPCode() (string, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(900000))
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
}
