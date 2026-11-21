package geo

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

func newCatalog() (*Catalog, *fakeQS) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{
		qCatalogCountries:  {Rows: [][]any{{"CA", "Canada"}, {"TR", "Turkey"}, {"US", "United States"}}},
		qCatalogStates:     {Rows: [][]any{{"US", "AL", "Alabama"}, {"US", "AK", "Alaska"}}},
		qCatalogCurrencies: {Rows: [][]any{{"JPY", "Yen", int16(0)}, {"USD", "US Dollar", int64(2)}}},
	}}
	return &Catalog{qs: qs}, qs
}

func TestCatalogListsCodesWithCaptions(t *testing.T) {
	c, qs := newCatalog()
	ctx := context.Background()
	countries, err := c.Countries(ctx)
	if err != nil || len(countries) != 3 || countries[2] != (CatalogEntry{"US", "United States"}) {
		t.Fatalf("countries = %v, %v", countries, err)
	}
	states, err := c.States(ctx, "US")
	if err != nil || len(states) != 2 || states[0] != (CatalogEntry{"AL", "Alabama"}) {
		t.Fatalf("US states = %v, %v", states, err)
	}
	if states, err := c.States(ctx, "TR"); err != nil || states == nil || len(states) != 0 {
		t.Fatalf("a country without states = %v, %v; want an empty list", states, err)
	}
	if _, err := c.States(ctx, "XX"); !errors.Is(err, ErrUnknownCountry) {
		t.Fatalf("unknown country = %v", err)
	}
	currencies, err := c.Currencies(ctx)
	if err != nil || len(currencies) != 2 || currencies[1] != (CurrencyEntry{"USD", "US Dollar", 2}) {
		t.Fatalf("currencies = %v, %v", currencies, err)
	}
	if len(qs.calls) != 3 {
		t.Errorf("catalog read with %d queries, want 3 once", len(qs.calls))
	}
}

func TestCatalogRefusesBadRowsAndRetries(t *testing.T) {
	c, qs := newCatalog()
	qs.rows[qCatalogCurrencies] = &model.QueryResult{Rows: [][]any{{"XXX", "Bad", int64(9)}}}
	if _, err := c.Countries(context.Background()); !errors.Is(err, common.ErrCurrencyExponent) {
		t.Fatalf("out-of-range exponent = %v", err)
	}
	qs.rows[qCatalogCurrencies] = &model.QueryResult{Rows: [][]any{{"XXX", "Fixed", int64(2)}}}
	if got, err := c.Currencies(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("after a failed load = %v, %v", got, err)
	}
}

func TestCatalogRefusesAStateOfAnUnknownCountry(t *testing.T) {
	c, qs := newCatalog()
	qs.rows[qCatalogStates] = &model.QueryResult{Rows: [][]any{{"ZZ", "AA", "Nowhere"}}}
	if _, err := c.Countries(context.Background()); !errors.Is(err, ErrUnknownCountry) {
		t.Fatalf("orphan state = %v", err)
	}
}

func TestCatalogWithoutDatabaseFails(t *testing.T) {
	if _, err := (&Catalog{}).Currencies(context.Background()); err == nil {
		t.Fatal("no database must fail")
	}
}
