package reference

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const usAddressReply = `{"status":"OK","results":[{
 "formatted_address":"1600 Amphitheatre Pkwy, Mountain View, CA 94043, USA",
 "place_id":"ChIJ_place",
 "address_components":[
  {"long_name":"1600","short_name":"1600","types":["street_number"]},
  {"long_name":"Amphitheatre Parkway","short_name":"Amphitheatre Pkwy","types":["route"]},
  {"long_name":"Mountain View","short_name":"Mountain View","types":["locality","political"]},
  {"long_name":"Santa Clara County","short_name":"Santa Clara County","types":["administrative_area_level_2"]},
  {"long_name":"California","short_name":"CA","types":["administrative_area_level_1"]},
  {"long_name":"United States","short_name":"US","types":["country","political"]},
  {"long_name":"94043","short_name":"94043","types":["postal_code"]}],
 "geometry":{"location_type":"ROOFTOP","location":{"lat":37.4224,"lng":-122.0841}}}]}`

// geocodeStub records the query it was called with and answers with reply.
type geocodeStub struct {
	reply  string
	status int
	got    url.Values
}

func (g *geocodeStub) client(t *testing.T) *GoogleGeocodeClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.got = r.URL.Query()
		if g.status != 0 {
			w.WriteHeader(g.status)
		}
		_, _ = w.Write([]byte(g.reply))
	}))
	t.Cleanup(srv.Close)
	return &GoogleGeocodeClient{APIKey: testKey, Endpoint: srv.URL}
}

func TestGeocodeParsesComponents(t *testing.T) {
	stub := &geocodeStub{reply: usAddressReply}
	res, err := stub.client(t).Geocode(context.Background(), " 1600 Amphitheatre Pkwy ")
	if err != nil {
		t.Fatal(err)
	}
	if res.Latitude != 37.4224 || res.Longitude != -122.0841 {
		t.Fatalf("coordinates = %+v", res.Coordinates)
	}
	if res.Precision != GeocodeRooftop || res.PlaceID != "ChIJ_place" {
		t.Fatalf("result = %+v", res)
	}
	want := AddressComponents{
		Street: "1600 Amphitheatre Parkway", City: "Mountain View", County: "Santa Clara County",
		State: "CA", Country: "US", PostalCode: "94043",
	}
	if res.Components != want {
		t.Fatalf("components = %+v, want %+v", res.Components, want)
	}
	// The key travels as a query parameter (this API takes no key header) and
	// is built at call time, never configured into the endpoint.
	if stub.got.Get("key") != "k-123" || stub.got.Get("address") != "1600 Amphitheatre Pkwy" {
		t.Fatalf("query = %v", stub.got)
	}
}

func TestGeocodeReverse(t *testing.T) {
	stub := &geocodeStub{reply: usAddressReply}
	client := stub.client(t)
	if _, err := client.Reverse(context.Background(), 37.4224, -122.0841); err != nil {
		t.Fatal(err)
	}
	if stub.got.Get("latlng") != "37.4224,-122.0841" {
		t.Fatalf("latlng = %q", stub.got.Get("latlng"))
	}
	if _, err := client.Reverse(context.Background(), 91, 0); err == nil {
		t.Error("out-of-range latitude should be refused before the call")
	}
}

// The Geocoding API reports failures inside a 200 body, so status drives the
// outcome: nothing found is an absence, a quota refusal is retryable, and
// anything else is a plain error.
func TestGeocodeStatusMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"zero results": {`{"status":"ZERO_RESULTS","results":[]}`, ErrNoGeocodeMatch},
		"empty ok":     {`{"status":"OK","results":[]}`, ErrNoGeocodeMatch},
		"over limit":   {`{"status":"OVER_QUERY_LIMIT"}`, ErrGeocodeQuotaExceeded},
	} {
		stub := &geocodeStub{reply: tc.body}
		if _, err := stub.client(t).Geocode(context.Background(), "x"); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	stub := &geocodeStub{reply: `{"status":"REQUEST_DENIED","error_message":"bad key"}`}
	_, err := stub.client(t).Geocode(context.Background(), "x")
	if err == nil || errors.Is(err, ErrNoGeocodeMatch) {
		t.Errorf("REQUEST_DENIED should be a plain error, got %v", err)
	}
}

func TestGeocodeRequiresAddressAndKey(t *testing.T) {
	stub := &geocodeStub{reply: usAddressReply}
	if _, err := stub.client(t).Geocode(context.Background(), "  "); err == nil {
		t.Error("empty address should be refused")
	}
	unkeyed := &GoogleGeocodeClient{}
	if _, err := unkeyed.Geocode(context.Background(), "x"); !errors.Is(err, ErrNoAPIKey) {
		t.Errorf("err = %v, want ErrNoAPIKey", err)
	}
}

func TestPrecisionAtLeast(t *testing.T) {
	rooftop := GeocodeResult{Precision: GeocodeRooftop}
	centroid := GeocodeResult{Precision: GeocodeApproximate}
	if !rooftop.PrecisionAtLeast(GeocodeGeometricCenter) || !rooftop.PrecisionAtLeast(GeocodeRooftop) {
		t.Error("rooftop should satisfy anything")
	}
	if centroid.PrecisionAtLeast(GeocodeGeometricCenter) {
		t.Error("a centroid must not pass a geometric-center floor")
	}
	if (GeocodeResult{Precision: "SOMETHING_NEW"}).PrecisionAtLeast(GeocodeApproximate) {
		t.Error("an unrecognized precision is never good enough")
	}
}
