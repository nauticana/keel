package payout

import (
	"fmt"
	"strings"
)

// Destination is the payee's active user_bank_info version as a payout target.
type Destination struct {
	BankInfoID        int64
	Provider          string
	ProviderAccountID string
	Currency          string
	Onboarded         bool
}

func (d *Destination) payableBy(providerCode, currency string) error {
	switch {
	case d == nil:
		return fmt.Errorf("%w: no active bank info", ErrDestinationNotPayable)
	case d.Provider != providerCode:
		return fmt.Errorf("%w: bank info provider %q, partner provider %q", ErrDestinationNotPayable, d.Provider, providerCode)
	case !strings.EqualFold(d.Currency, currency):
		return fmt.Errorf("%w: destination currency %q, instruction currency %q", ErrDestinationNotPayable, d.Currency, currency)
	case d.ProviderAccountID == "" || !d.Onboarded:
		return fmt.Errorf("%w: provider onboarding not completed", ErrDestinationNotPayable)
	}
	return nil
}
