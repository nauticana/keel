package geo

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/reference"
)

type qcall struct {
	name string
	args []any
}

type fakeQS struct {
	calls []qcall
	rows  map[string]*model.QueryResult
	then  map[string]*model.QueryResult // answer from the second call on
}

func (f *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	repeat := f.called(name)
	f.calls = append(f.calls, qcall{name, args})
	if r, ok := f.then[name]; ok && repeat {
		return r, nil
	}
	if r, ok := f.rows[name]; ok {
		return r, nil
	}
	return &model.QueryResult{}, nil
}
func (f *fakeQS) GenID() int64 { return 1 }

func (f *fakeQS) argsFor(name string) []any {
	for _, c := range f.calls {
		if c.name == name {
			return c.args
		}
	}
	return nil
}

func (f *fakeQS) called(name string) bool { return f.argsFor(name) != nil }

var _ port.QueryService = (*fakeQS)(nil)

// fakeGeocoder answers with a canned result and records what it was asked.
type fakeGeocoder struct {
	result reference.GeocodeResult
	err    error
	asked  string
	calls  int
}

func (g *fakeGeocoder) Geocode(_ context.Context, address string) (reference.GeocodeResult, error) {
	g.asked, g.calls = address, g.calls+1
	return g.result, g.err
}

func (g *fakeGeocoder) Reverse(context.Context, float64, float64) (reference.GeocodeResult, error) {
	return g.result, g.err
}

var _ reference.Geocoder = (*fakeGeocoder)(nil)

func newService(qs *fakeQS, g reference.Geocoder) *AddressService {
	s := &AddressService{Geocoder: g}
	s.qs = qs
	s.once.Do(func() {})
	return s
}

func addressRow(lat, lng any) *model.QueryResult {
	return &model.QueryResult{Rows: [][]any{{lat, lng, "Mountain View", "CA", "US", "94043"}}}
}

func TestEnsureCoordinatesGeocodesAndStores(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{
		qAddressRead:   addressRow(nil, nil),
		qAddressCoords: {Rows: [][]any{{int64(7)}}},
	}}
	geocoder := &fakeGeocoder{result: reference.GeocodeResult{
		Coordinates: reference.Coordinates{Latitude: 37.4224, Longitude: -122.0841},
		Precision:   reference.GeocodeRooftop,
	}}

	got, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "1600 Amphitheatre Pkwy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Latitude != 37.4224 || got.Longitude != -122.0841 {
		t.Fatalf("coordinates = %+v", got)
	}
	// The street line alone is ambiguous: the row's city/state/zip/country ride along.
	if geocoder.asked != "1600 Amphitheatre Pkwy, Mountain View, CA, 94043, US" {
		t.Fatalf("geocoded %q", geocoder.asked)
	}
	args := qs.argsFor(qAddressCoords)
	if args[0].(float64) != 37.4224 || args[2].(int64) != 7 {
		t.Fatalf("store args = %v", args)
	}
}

// A row that already carries a point costs no vendor call.
func TestEnsureCoordinatesKeepsExisting(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qAddressRead: addressRow(1.5, 2.5)}}
	geocoder := &fakeGeocoder{}

	got, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "addr")
	if err != nil {
		t.Fatal(err)
	}
	if got.Latitude != 1.5 || got.Longitude != 2.5 {
		t.Fatalf("coordinates = %+v", got)
	}
	if geocoder.calls != 0 {
		t.Error("an address with coordinates must not be geocoded")
	}
	if qs.called(qAddressCoords) {
		t.Error("nothing should have been written")
	}
}

func TestEnsureCoordinatesRejectsIncompleteStoredPair(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qAddressRead: addressRow(1.5, nil)}}
	geocoder := &fakeGeocoder{}
	_, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "addr")
	if !errors.Is(err, ErrIncompleteCoordinates) {
		t.Fatalf("err = %v, want ErrIncompleteCoordinates", err)
	}
	if geocoder.calls != 0 || qs.called(qAddressCoords) {
		t.Fatal("incomplete source coordinates must not be replaced")
	}
}

// Another worker stored a point between the read and the guarded write: theirs stands.
func TestEnsureCoordinatesReturnsConcurrentWrite(t *testing.T) {
	qs := &fakeQS{
		rows: map[string]*model.QueryResult{qAddressRead: addressRow(nil, nil)},
		then: map[string]*model.QueryResult{qAddressRead: addressRow(9.5, 8.5)},
	}
	geocoder := &fakeGeocoder{result: reference.GeocodeResult{
		Coordinates: reference.Coordinates{Latitude: 1, Longitude: 2}, Precision: reference.GeocodeRooftop,
	}}
	got, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "addr")
	if err != nil {
		t.Fatal(err)
	}
	if got.Latitude != 9.5 || got.Longitude != 8.5 {
		t.Fatalf("coordinates = %+v, want the stored pair", got)
	}
}

// A centroid written into latitude/longitude reads like a real location later.
func TestEnsureCoordinatesRejectsCoarsePrecision(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qAddressRead: addressRow(nil, nil)}}
	geocoder := &fakeGeocoder{result: reference.GeocodeResult{
		Coordinates: reference.Coordinates{Latitude: 37.3, Longitude: -122.0},
		Precision:   reference.GeocodeApproximate,
	}}

	_, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "addr")
	if !errors.Is(err, ErrPrecisionTooCoarse) {
		t.Fatalf("err = %v, want ErrPrecisionTooCoarse", err)
	}
	if qs.called(qAddressCoords) {
		t.Error("a rejected geocode must not be stored")
	}
}

func TestEnsureCoordinatesHonorsMinPrecision(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{
		qAddressRead: addressRow(nil, nil), qAddressCoords: {Rows: [][]any{{1.0, 2.0}}},
	}}
	geocoder := &fakeGeocoder{result: reference.GeocodeResult{Precision: reference.GeocodeApproximate}}
	s := newService(qs, geocoder)
	s.MinPrecision = reference.GeocodeApproximate

	if _, err := s.EnsureCoordinates(context.Background(), 7, "addr"); err != nil {
		t.Fatalf("an explicit floor of APPROXIMATE should accept it: %v", err)
	}
}

func TestEnsureCoordinatesSurfacesGeocodeFailure(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qAddressRead: addressRow(nil, nil)}}
	geocoder := &fakeGeocoder{err: reference.ErrNoGeocodeMatch}

	if _, err := newService(qs, geocoder).EnsureCoordinates(context.Background(), 7, "addr"); !errors.Is(err, reference.ErrNoGeocodeMatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureCoordinatesUnknownAddress(t *testing.T) {
	s := newService(&fakeQS{}, &fakeGeocoder{})
	if _, err := s.EnsureCoordinates(context.Background(), 7, "nope"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("err = %v, want ErrAddressNotFound", err)
	}
}

func TestEnsureCoordinatesWithoutGeocoder(t *testing.T) {
	qs := &fakeQS{rows: map[string]*model.QueryResult{qAddressRead: addressRow(nil, nil)}}
	s := newService(qs, nil)
	if _, err := s.EnsureCoordinates(context.Background(), 7, "addr"); err == nil {
		t.Error("an unconfigured geocoder must fail loudly")
	}
}

func TestAddressServiceWithoutDatabase(t *testing.T) {
	s := &AddressService{}
	if _, err := s.EnsureCoordinates(context.Background(), 7, "addr"); err == nil {
		t.Error("an unconfigured service must fail loudly")
	}
}
