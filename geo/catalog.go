package geo

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// ErrUnknownCountry means the code is not in the country table.
var ErrUnknownCountry = errors.New("geo: unknown country")

const (
	qCatalogCountries  = "catalog_countries"
	qCatalogStates     = "catalog_states"
	qCatalogCurrencies = "catalog_currencies"
)

var catalogQueries = map[string]string{
	qCatalogCountries:  `SELECT id, caption FROM country ORDER BY caption, id`,
	qCatalogStates:     `SELECT country_id, id, caption FROM state ORDER BY country_id, caption, id`,
	qCatalogCurrencies: `SELECT code, caption, exponent FROM currency ORDER BY code`,
}

// Catalog serves keel's country, state and currency tables to clients that
// pick a code by caption. The tables are seed data, read once on first use; a
// failed read is retried on the next call.
type Catalog struct {
	DB port.DatabaseRepository

	mu         sync.Mutex
	qs         port.QueryService
	loaded     bool
	countries  []CatalogEntry
	states     map[string][]CatalogEntry
	currencies []CurrencyEntry
}

// Countries lists every country ordered by caption.
func (c *Catalog) Countries(ctx context.Context) ([]CatalogEntry, error) {
	if err := c.load(ctx); err != nil {
		return nil, err
	}
	return c.countries, nil
}

// States lists the states of country ordered by caption; a country without
// seeded states has an empty list.
func (c *Catalog) States(ctx context.Context, country string) ([]CatalogEntry, error) {
	if err := c.load(ctx); err != nil {
		return nil, err
	}
	states, ok := c.states[country]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownCountry, country)
	}
	return states, nil
}

// Currencies lists every currency ordered by code.
func (c *Catalog) Currencies(ctx context.Context) ([]CurrencyEntry, error) {
	if err := c.load(ctx); err != nil {
		return nil, err
	}
	return c.currencies, nil
}

func (c *Catalog) load(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return nil
	}
	if c.qs == nil {
		if c.DB == nil {
			return errors.New("geo: no database configured")
		}
		c.qs = c.DB.GetQueryService(ctx, catalogQueries)
	}
	countries, states, err := c.readRegions(ctx)
	if err != nil {
		return err
	}
	currencies, err := c.readCurrencies(ctx)
	if err != nil {
		return err
	}
	c.countries, c.states, c.currencies, c.loaded = countries, states, currencies, true
	return nil
}

func (c *Catalog) readRegions(ctx context.Context) ([]CatalogEntry, map[string][]CatalogEntry, error) {
	res, err := c.qs.Query(ctx, qCatalogCountries)
	if err != nil {
		return nil, nil, fmt.Errorf("geo: read countries: %w", err)
	}
	countries := make([]CatalogEntry, 0, len(res.Rows))
	states := make(map[string][]CatalogEntry, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) != 2 {
			return nil, nil, fmt.Errorf("geo: country query returned %d columns", len(row))
		}
		code := common.AsString(row[0])
		countries = append(countries, CatalogEntry{Code: code, Caption: common.AsString(row[1])})
		states[code] = []CatalogEntry{}
	}
	if res, err = c.qs.Query(ctx, qCatalogStates); err != nil {
		return nil, nil, fmt.Errorf("geo: read states: %w", err)
	}
	for _, row := range res.Rows {
		if len(row) != 3 {
			return nil, nil, fmt.Errorf("geo: state query returned %d columns", len(row))
		}
		country := common.AsString(row[0])
		if _, ok := states[country]; !ok {
			return nil, nil, fmt.Errorf("%w %q of a state", ErrUnknownCountry, country)
		}
		states[country] = append(states[country], CatalogEntry{Code: common.AsString(row[1]), Caption: common.AsString(row[2])})
	}
	return countries, states, nil
}

func (c *Catalog) readCurrencies(ctx context.Context) ([]CurrencyEntry, error) {
	res, err := c.qs.Query(ctx, qCatalogCurrencies)
	if err != nil {
		return nil, fmt.Errorf("geo: read currencies: %w", err)
	}
	currencies := make([]CurrencyEntry, 0, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) != 3 {
			return nil, fmt.Errorf("geo: currency query returned %d columns", len(row))
		}
		code := common.AsString(row[0])
		exponent, ok := common.AsInt64OK(row[2])
		if !ok || exponent < 0 || exponent > common.MaxCurrencyExponent {
			return nil, fmt.Errorf("geo: currency %q: %w: %v", code, common.ErrCurrencyExponent, row[2])
		}
		currencies = append(currencies, CurrencyEntry{Code: code, Caption: common.AsString(row[1]), Exponent: int16(exponent)})
	}
	return currencies, nil
}
