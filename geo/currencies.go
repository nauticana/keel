package geo

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// ErrUnknownCurrency means the code is not in the currency table.
var ErrUnknownCurrency = errors.New("geo: unknown currency")

const qCurrencies = "currency_exponents"

var currencyQueries = map[string]string{
	qCurrencies: `SELECT code, exponent FROM currency`,
}

// Currencies converts money by the exponents of keel's currency table, read
// once on first use since the catalog is seed data.
type Currencies struct {
	DB port.DatabaseRepository

	mu        sync.Mutex
	qs        port.QueryService
	exponents map[string]int
}

// Exponent is the code's number of minor-unit digits.
func (c *Currencies) Exponent(ctx context.Context, code string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exponents == nil {
		exponents, err := c.load(ctx)
		if err != nil {
			return 0, err
		}
		c.exponents = exponents
	}
	exponent, ok := c.exponents[code]
	if !ok {
		return 0, fmt.Errorf("%w %q", ErrUnknownCurrency, code)
	}
	return exponent, nil
}

// Parse converts a decimal amount ("19.99") to minor units of code.
func (c *Currencies) Parse(ctx context.Context, amount, code string) (int64, error) {
	exponent, err := c.Exponent(ctx, code)
	if err != nil {
		return 0, err
	}
	return common.ParseMinorUnits(amount, exponent)
}

// Format renders minor units of code as a decimal amount, without the code.
func (c *Currencies) Format(ctx context.Context, minor int64, code string) (string, error) {
	exponent, err := c.Exponent(ctx, code)
	if err != nil {
		return "", err
	}
	return common.FormatMinorUnits(minor, exponent)
}

func (c *Currencies) load(ctx context.Context) (map[string]int, error) {
	if c.qs == nil {
		if c.DB == nil {
			return nil, errors.New("geo: no database configured")
		}
		c.qs = c.DB.GetQueryService(ctx, currencyQueries)
	}
	res, err := c.qs.Query(ctx, qCurrencies)
	if err != nil {
		return nil, fmt.Errorf("geo: read currencies: %w", err)
	}
	exponents := make(map[string]int, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) != 2 {
			return nil, fmt.Errorf("geo: currency query returned %d columns", len(row))
		}
		code := common.AsString(row[0])
		exponent, ok := common.AsInt64OK(row[1])
		if !ok || exponent < 0 || exponent > common.MaxCurrencyExponent {
			return nil, fmt.Errorf("geo: currency %q: %w: %v", code, common.ErrCurrencyExponent, row[1])
		}
		exponents[code] = int(exponent)
	}
	return exponents, nil
}
