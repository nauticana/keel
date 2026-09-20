package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nauticana/keel/common"
)

const DefaultCrUXEndpoint = "https://chromeuxreport.googleapis.com/v1/records:queryRecord"

type CrUXFormFactor string

const (
	CrUXFormFactorPhone   CrUXFormFactor = "PHONE"
	CrUXFormFactorDesktop CrUXFormFactor = "DESKTOP"
	CrUXFormFactorTablet  CrUXFormFactor = "TABLET"
)

// CrUXNoValue marks a metric CrUX did not publish; it needs minimum traffic per metric.
const CrUXNoValue = -1

// ErrCrUXNoData means CrUX publishes no record for the URL or origin — an
// absence of signal, not a failure.
var ErrCrUXNoData = errors.New("reference: crux has no field data")

// CrUXRecord holds p75 values: LCP, INP, FCP and TTFB in milliseconds, CLS
// unitless. A metric is CrUXNoValue when CrUX did not publish it.
type CrUXRecord struct {
	URL        string
	FormFactor CrUXFormFactor
	Origin     string // origin CrUX resolved the query to
	// HasURLLevelData is false when the record is the origin-wide aggregate.
	HasURLLevelData bool

	LCP  float64
	CLS  float64
	INP  float64
	FCP  float64
	TTFB float64
}

// CrUXClient reads the Chrome UX Report API. Records change monthly, so callers
// may cache per (url, form factor) freely.
type CrUXClient struct {
	APIKey
	Endpoint string // empty = DefaultCrUXEndpoint
}

// RecordForURL returns URL-level data, falling back to the origin aggregate
// when the page alone has too little traffic. An empty formFactor means phone.
func (c *CrUXClient) RecordForURL(ctx context.Context, pageURL string, formFactor CrUXFormFactor) (CrUXRecord, error) {
	rec, err := c.query(ctx, "url", pageURL, formFactor)
	if err == nil {
		rec.URL, rec.HasURLLevelData = pageURL, true
		return rec, nil
	}
	if !errors.Is(err, ErrCrUXNoData) {
		return CrUXRecord{}, err
	}
	return c.RecordForOrigin(ctx, pageURL, formFactor)
}

// RecordForOrigin returns the origin-wide aggregate; target is a URL or a bare origin.
func (c *CrUXClient) RecordForOrigin(ctx context.Context, target string, formFactor CrUXFormFactor) (CrUXRecord, error) {
	rec, err := c.query(ctx, "origin", originOf(target), formFactor)
	if err != nil {
		return CrUXRecord{}, err
	}
	rec.URL = target
	return rec, nil
}

type cruxResponse struct {
	Record struct {
		Key struct {
			Origin string `json:"origin"`
		} `json:"key"`
		Metrics map[string]struct {
			Percentiles struct {
				// CrUX sends timings as strings and CLS as a number.
				P75 json.Number `json:"p75"`
			} `json:"percentiles"`
		} `json:"metrics"`
	} `json:"record"`
}

func (r *cruxResponse) p75(names ...string) float64 {
	for _, name := range names {
		if m, ok := r.Record.Metrics[name]; ok {
			if v, err := m.Percentiles.P75.Float64(); err == nil {
				return v
			}
		}
	}
	return CrUXNoValue
}

func (c *CrUXClient) query(ctx context.Context, keyField, keyValue string, formFactor CrUXFormFactor) (CrUXRecord, error) {
	headers, err := c.headers(ctx)
	if err != nil {
		return CrUXRecord{}, err
	}
	if formFactor == "" {
		formFactor = CrUXFormFactorPhone
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultCrUXEndpoint
	}
	body, _, err := common.RequestJSON(ctx, http.MethodPost, endpoint, headers,
		map[string]string{keyField: keyValue, "formFactor": string(formFactor)})
	if common.HTTPStatus(err) == http.StatusNotFound {
		return CrUXRecord{}, ErrCrUXNoData
	}
	if err != nil {
		return CrUXRecord{}, fmt.Errorf("crux: %w", err)
	}
	var resp cruxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return CrUXRecord{}, fmt.Errorf("crux: decode: %w", err)
	}
	return CrUXRecord{
		FormFactor: formFactor,
		Origin:     resp.Record.Key.Origin,
		LCP:        resp.p75("largest_contentful_paint"),
		CLS:        resp.p75("cumulative_layout_shift"),
		INP:        resp.p75("interaction_to_next_paint"),
		FCP:        resp.p75("first_contentful_paint"),
		TTFB:       resp.p75("experimental_time_to_first_byte", "time_to_first_byte"),
	}, nil
}

// originOf reduces a URL to scheme://host, which CrUX matches exactly
// (https://example.com and https://www.example.com are different origins).
func originOf(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return target
	}
	return u.Scheme + "://" + u.Host
}
