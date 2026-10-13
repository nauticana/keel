package geo

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

func newCurrencies(rows ...[]any) (*Currencies, *fakeQS) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qCurrencies: {Rows: rows}}}
	return &Currencies{qs: qs}, qs
}

func TestCurrenciesConvertByTheCatalogExponent(t *testing.T) {
	c, qs := newCurrencies([]any{"USD", int64(2)}, []any{"JPY", int16(0)}, []any{"BHD", int64(3)})
	ctx := context.Background()
	if got, err := c.Format(ctx, 123456, "USD"); err != nil || got != "1234.56" {
		t.Errorf("USD = %q, %v", got, err)
	}
	if got, err := c.Format(ctx, 123456, "JPY"); err != nil || got != "123456" {
		t.Errorf("JPY = %q, %v", got, err)
	}
	if got, err := c.Parse(ctx, "1.250", "BHD"); err != nil || got != 1250 {
		t.Errorf("BHD = %d, %v", got, err)
	}
	if _, err := c.Parse(ctx, "1.5", "JPY"); err == nil {
		t.Error("JPY with a fraction must fail")
	}
	if _, err := c.Exponent(ctx, "XXX"); !errors.Is(err, ErrUnknownCurrency) {
		t.Errorf("unknown currency = %v", err)
	}
	if len(qs.calls) != 1 {
		t.Errorf("catalog read %d times, want once", len(qs.calls))
	}
}

func TestCurrenciesRefuseAnOutOfRangeRowAndRetry(t *testing.T) {
	c, qs := newCurrencies([]any{"XXX", int64(9)})
	if _, err := c.Exponent(context.Background(), "XXX"); !errors.Is(err, common.ErrCurrencyExponent) {
		t.Fatalf("err = %v", err)
	}
	qs.rows[qCurrencies] = &model.QueryResult{Rows: [][]any{{"XXX", int64(2)}}}
	if got, err := c.Exponent(context.Background(), "XXX"); err != nil || got != 2 {
		t.Fatalf("after a failed load = %d, %v", got, err)
	}
}

func TestCurrenciesRefuseMalformedRows(t *testing.T) {
	c, _ := newCurrencies([]any{"USD"})
	if _, err := c.Exponent(context.Background(), "USD"); err == nil {
		t.Fatal("short currency row must fail")
	}
}

func TestCurrenciesWithoutDatabaseFail(t *testing.T) {
	if _, err := (&Currencies{}).Exponent(context.Background(), "USD"); err == nil {
		t.Fatal("no database must fail")
	}
}
