package billing

import (
	"strconv"

	"github.com/nauticana/keel/common"
)

// majorAmount is the display-only major-unit projection of minor units at the
// currency's exponent; money math stays in minor units.
func majorAmount(minor int64, exponent int16) (float64, error) {
	decimal, err := common.FormatMinorUnits(minor, int(exponent))
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(decimal, 64)
}

// FillAmount sets the display Amount from AmountMinor and Exponent.
func (p *PlanPrice) FillAmount() (err error) {
	p.Amount, err = majorAmount(p.AmountMinor, p.Exponent)
	return err
}
