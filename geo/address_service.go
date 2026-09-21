// Package geo fills the geographic columns of keel's tenant tables from a
// reference.Geocoder. The country / state / county vocabulary those columns
// reference is keel's; turning an address into a point is a vendor call with no
// product logic in it. Geo-grid construction, ranking by point and how far a
// grid spreads stay with the app.
package geo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/reference"
)

// ErrAddressNotFound means the partner has no such partner_address row.
var ErrAddressNotFound = errors.New("geo: no such partner address")

// ErrPrecisionTooCoarse means the geocoder placed the address less exactly than
// MinPrecision requires — a city centroid written into latitude/longitude reads
// like a real location to every later query.
var ErrPrecisionTooCoarse = errors.New("geo: geocode precision too coarse")

// ErrIncompleteCoordinates means only one coordinate is stored; replacing it
// with a geocoder result would overwrite source data.
var ErrIncompleteCoordinates = errors.New("geo: partner address has incomplete coordinates")

const (
	qAddressRead   = "partner_address_read"
	qAddressCoords = "partner_address_set_coordinates"
)

var addressQueries = map[string]string{
	qAddressRead: `
SELECT latitude, longitude, COALESCE(city, ''), COALESCE(state, ''),
       COALESCE(country, ''), COALESCE(zipcode, '')
  FROM partner_address
 WHERE partner_id = ? AND address = ?`,

	// Only an unset pair is filled: a value the tenant or their provider
	// supplied outranks anything a geocoder guesses.
	qAddressCoords: `
UPDATE partner_address
   SET latitude = ?, longitude = ?
 WHERE partner_id = ? AND address = ?
   AND latitude IS NULL AND longitude IS NULL
RETURNING latitude, longitude`,
}

// AddressService fills partner_address.latitude / longitude, which nothing else
// in keel writes. Which addresses are worth geocoding, and when, is the app's.
type AddressService struct {
	DB       port.DatabaseRepository
	Geocoder reference.Geocoder
	// MinPrecision is the coarsest acceptable placement; empty means
	// reference.GeocodeGeometricCenter — exact enough to sit on the property,
	// not a locality centroid.
	MinPrecision string

	once sync.Once
	qs   port.QueryService
}

func (s *AddressService) queries(ctx context.Context) (port.QueryService, error) {
	s.once.Do(func() {
		if s.DB != nil {
			s.qs = s.DB.GetQueryService(ctx, addressQueries)
		}
	})
	if s.qs == nil {
		return nil, fmt.Errorf("geo: no database configured")
	}
	return s.qs, nil
}

func (s *AddressService) minPrecision() string {
	if s.MinPrecision == "" {
		return reference.GeocodeGeometricCenter
	}
	return s.MinPrecision
}

// EnsureCoordinates returns the address's coordinates, geocoding and storing
// them when the row has none. A row that already carries a point is returned
// untouched and costs no vendor call.
func (s *AddressService) EnsureCoordinates(ctx context.Context, partnerID int64, address string) (reference.Coordinates, error) {
	qs, err := s.queries(ctx)
	if err != nil {
		return reference.Coordinates{}, err
	}
	res, err := qs.Query(ctx, qAddressRead, partnerID, address)
	if err != nil {
		return reference.Coordinates{}, fmt.Errorf("geo: read address: %w", err)
	}
	if len(res.Rows) == 0 {
		return reference.Coordinates{}, fmt.Errorf("%w: partner %d", ErrAddressNotFound, partnerID)
	}
	row := res.Rows[0]
	if row[0] != nil && row[1] != nil {
		return reference.Coordinates{Latitude: common.AsFloat64(row[0]), Longitude: common.AsFloat64(row[1])}, nil
	}
	if row[0] != nil || row[1] != nil {
		return reference.Coordinates{}, ErrIncompleteCoordinates
	}
	if s.Geocoder == nil {
		return reference.Coordinates{}, fmt.Errorf("geo: no geocoder configured")
	}
	result, err := s.Geocoder.Geocode(ctx, fullAddress(address, row))
	if err != nil {
		return reference.Coordinates{}, err
	}
	if !result.PrecisionAtLeast(s.minPrecision()) {
		return reference.Coordinates{}, fmt.Errorf("%w: %q is %s, want at least %s",
			ErrPrecisionTooCoarse, address, result.Precision, s.minPrecision())
	}
	updated, err := qs.Query(ctx, qAddressCoords, result.Latitude, result.Longitude, partnerID, address)
	if err != nil {
		return reference.Coordinates{}, fmt.Errorf("geo: store coordinates: %w", err)
	}
	if len(updated.Rows) == 0 {
		return s.storedCoordinates(ctx, qs, partnerID, address)
	}
	return result.Coordinates, nil
}

// storedCoordinates returns what a concurrent writer stored: the guarded
// update lost, and theirs stands.
func (s *AddressService) storedCoordinates(ctx context.Context, qs port.QueryService, partnerID int64, address string) (reference.Coordinates, error) {
	res, err := qs.Query(ctx, qAddressRead, partnerID, address)
	if err != nil {
		return reference.Coordinates{}, fmt.Errorf("geo: re-read address: %w", err)
	}
	if len(res.Rows) == 0 {
		return reference.Coordinates{}, fmt.Errorf("%w: partner %d", ErrAddressNotFound, partnerID)
	}
	if res.Rows[0][0] == nil || res.Rows[0][1] == nil {
		return reference.Coordinates{}, ErrIncompleteCoordinates
	}
	return reference.Coordinates{Latitude: common.AsFloat64(res.Rows[0][0]), Longitude: common.AsFloat64(res.Rows[0][1])}, nil
}

// fullAddress assembles what the geocoder is asked to resolve: the street line
// alone is ambiguous in every country.
func fullAddress(address string, row []any) string {
	parts := []string{address}
	for _, i := range []int{2, 3, 5, 4} { // city, state, zipcode, country
		if v := strings.TrimSpace(common.AsString(row[i])); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", ")
}
