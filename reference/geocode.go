package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
)

const DefaultGoogleGeocodeEndpoint = "https://maps.googleapis.com/maps/api/geocode/json"

// How exactly a result locates the address. A centroid is not a location:
// ranking by proximity from a city centroid turns a measurement into noise, so
// callers state the precision they need and reject anything coarser.
const (
	GeocodeRooftop         = "ROOFTOP"
	GeocodeInterpolated    = "RANGE_INTERPOLATED"
	GeocodeGeometricCenter = "GEOMETRIC_CENTER"
	GeocodeApproximate     = "APPROXIMATE"
)

var geocodePrecisionRank = map[string]int{
	GeocodeApproximate:     1,
	GeocodeGeometricCenter: 2,
	GeocodeInterpolated:    3,
	GeocodeRooftop:         4,
}

var (
	// ErrNoGeocodeMatch: the provider resolved nothing for the input — an
	// absence of signal, not a failure.
	ErrNoGeocodeMatch = errors.New("reference: no geocode match")
	// ErrGeocodeQuotaExceeded: the provider's quota or rate limit; retry later.
	ErrGeocodeQuotaExceeded = errors.New("reference: geocoding quota exceeded")
)

// Coordinates is a WGS-84 point.
type Coordinates struct {
	Latitude  float64
	Longitude float64
}

// AddressComponents is the provider's normalized reading of the address. State
// and Country are the short codes keel's geo vocabulary uses.
type AddressComponents struct {
	Street     string
	City       string
	County     string
	State      string
	Country    string
	PostalCode string
}

// GeocodeResult is one resolved address.
type GeocodeResult struct {
	Coordinates
	Precision        string
	FormattedAddress string
	Components       AddressComponents
	PlaceID          string // provider's own id for the place
}

// PrecisionAtLeast reports whether the result is at least as exact as min. An
// unrecognized precision is never good enough.
func (r GeocodeResult) PrecisionAtLeast(min string) bool {
	want, ok := geocodePrecisionRank[min]
	if !ok {
		return false
	}
	return geocodePrecisionRank[r.Precision] >= want
}

// Geocoder resolves an address to a point and back. It is an interface so an
// app can pick Google, Mapbox or Nominatim without its callers changing.
type Geocoder interface {
	Geocode(ctx context.Context, address string) (GeocodeResult, error)
	Reverse(ctx context.Context, lat, lng float64) (GeocodeResult, error)
}

// GoogleGeocodeClient reads the Google Geocoding API, which authenticates by
// query parameter rather than the header the other Google clients use.
type GoogleGeocodeClient struct {
	APIKey
	Endpoint string // empty = DefaultGoogleGeocodeEndpoint
	Region   string // optional ccTLD bias, e.g. "us"
	Language string // optional response language
}

var _ Geocoder = (*GoogleGeocodeClient)(nil)

func (c *GoogleGeocodeClient) Geocode(ctx context.Context, address string) (GeocodeResult, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return GeocodeResult{}, fmt.Errorf("reference: geocode address required")
	}
	return c.query(ctx, url.Values{"address": {address}})
}

func (c *GoogleGeocodeClient) Reverse(ctx context.Context, lat, lng float64) (GeocodeResult, error) {
	if lat < -90 || lat > 90 || lng < -180 || lng > 180 {
		return GeocodeResult{}, fmt.Errorf("reference: coordinates %f,%f are out of range", lat, lng)
	}
	latlng := strconv.FormatFloat(lat, 'f', -1, 64) + "," + strconv.FormatFloat(lng, 'f', -1, 64)
	return c.query(ctx, url.Values{"latlng": {latlng}})
}

type googleGeocodeResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message"`
	Results      []struct {
		FormattedAddress string `json:"formatted_address"`
		PlaceID          string `json:"place_id"`
		Components       []struct {
			LongName  string   `json:"long_name"`
			ShortName string   `json:"short_name"`
			Types     []string `json:"types"`
		} `json:"address_components"`
		Geometry struct {
			LocationType string `json:"location_type"`
			Location     struct {
				Lat float64 `json:"lat"`
				Lng float64 `json:"lng"`
			} `json:"location"`
		} `json:"geometry"`
	} `json:"results"`
}

// query builds the request URL at call time from the non-secret parameters plus
// the key, so no configured value ever holds the secret.
func (c *GoogleGeocodeClient) query(ctx context.Context, params url.Values) (GeocodeResult, error) {
	key, err := c.value(ctx)
	if err != nil {
		return GeocodeResult{}, err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultGoogleGeocodeEndpoint
	}
	if c.Region != "" {
		params.Set("region", c.Region)
	}
	if c.Language != "" {
		params.Set("language", c.Language)
	}
	params.Set("key", key)
	body, _, err := common.RequestJSON(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil, nil)
	if err != nil {
		return GeocodeResult{}, fmt.Errorf("reference: geocode: %w", withoutRequestURL(err))
	}
	var resp googleGeocodeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return GeocodeResult{}, fmt.Errorf("reference: decode geocode response: %w", err)
	}
	// The Geocoding API reports failures inside a 200 body.
	switch resp.Status {
	case "OK":
	case "ZERO_RESULTS":
		return GeocodeResult{}, ErrNoGeocodeMatch
	case "OVER_QUERY_LIMIT", "OVER_DAILY_LIMIT":
		return GeocodeResult{}, fmt.Errorf("%w: %s", ErrGeocodeQuotaExceeded, resp.Status)
	default:
		return GeocodeResult{}, fmt.Errorf("reference: geocode %s: %s", resp.Status, resp.ErrorMessage)
	}
	if len(resp.Results) == 0 {
		return GeocodeResult{}, ErrNoGeocodeMatch
	}
	top := resp.Results[0]
	out := GeocodeResult{
		Coordinates:      Coordinates{Latitude: top.Geometry.Location.Lat, Longitude: top.Geometry.Location.Lng},
		Precision:        top.Geometry.LocationType,
		FormattedAddress: top.FormattedAddress,
		PlaceID:          top.PlaceID,
	}
	var streetNumber, route string
	for _, comp := range top.Components {
		for _, kind := range comp.Types {
			switch kind {
			case "street_number":
				streetNumber = comp.LongName
			case "route":
				route = comp.LongName
			case "locality":
				out.Components.City = comp.LongName
			case "postal_town":
				if out.Components.City == "" { // UK and similar: no locality
					out.Components.City = comp.LongName
				}
			case "administrative_area_level_2":
				out.Components.County = comp.LongName
			case "administrative_area_level_1":
				out.Components.State = comp.ShortName
			case "country":
				out.Components.Country = comp.ShortName
			case "postal_code":
				out.Components.PostalCode = comp.LongName
			}
		}
	}
	out.Components.Street = strings.TrimSpace(streetNumber + " " + route)
	return out, nil
}
