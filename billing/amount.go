package billing

import (
	"fmt"
	"strconv"

	"github.com/nauticana/keel/common"
)

// decimalAmount is minor as the exact major-unit decimal a NUMERIC display
// column stores; an unknown currency fails rather than assuming two decimals.
func decimalAmount(minor int64, currency string) (string, error) {
	decimal, ok := common.FormatMinorUnits(minor, currency)
	if !ok {
		return "", fmt.Errorf("billing: unknown currency %q", currency)
	}
	return decimal, nil
}

// FillAmount sets the display Amount from AmountMinor.
func (p *PlanPrice) FillAmount() error {
	decimal, err := decimalAmount(p.AmountMinor, p.Currency)
	if err != nil {
		return err
	}
	p.Amount, err = strconv.ParseFloat(decimal, 64)
	return err
}
