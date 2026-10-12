package klaviyo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

const testKey = "pk_secret_key"

func server(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Klaviyo-API-Key "+testKey || r.Header.Get("revision") != Revision {
			t.Errorf("headers %v", r.Header)
		}
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL + "/"}
}

func TestCreateEventIsIdempotentOnUniqueID(t *testing.T) {
	var got map[string]any
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/events/" || r.Header.Get("Content-Type") != "application/vnd.api+json" {
			t.Errorf("%s %s %v", r.Method, r.URL.Path, r.Header)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	})
	err := c.CreateEvent(context.Background(), testKey, Event{
		Metric: "Lead Created", UniqueID: "lead-77", Time: time.Date(2026, 9, 20, 18, 0, 0, 0, time.FixedZone("x", 3*3600)),
		Properties: map[string]any{"funnel": "install"},
		Profile:    Profile{Email: "sam@example.com", FirstName: "Sam", Location: &Location{City: "Irvine"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs := got["data"].(map[string]any)["attributes"].(map[string]any)
	profile := attrs["profile"].(map[string]any)["data"].(map[string]any)["attributes"].(map[string]any)
	metric := attrs["metric"].(map[string]any)["data"].(map[string]any)["attributes"].(map[string]any)
	if attrs["unique_id"] != "lead-77" || attrs["time"] != "2026-09-20T15:00:00Z" || attrs["properties"].(map[string]any)["funnel"] != "install" || metric["name"] != "Lead Created" {
		t.Fatalf("attributes = %v", attrs)
	}
	if profile["email"] != "sam@example.com" || profile["location"].(map[string]any)["city"] != "Irvine" {
		t.Fatalf("profile = %v", profile)
	}
	if _, present := profile["phone_number"]; present {
		t.Fatalf("empty fields must be omitted: %v", profile)
	}
}

func TestCreateEventRefusesBadInputBeforeAnyCall(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	ok := Event{Metric: "m", UniqueID: "u", Profile: Profile{Email: "a@x.com"}}
	cases := map[string]func(*Event) string{
		"key":      func(*Event) string { return "" },
		"metric":   func(e *Event) string { e.Metric = " "; return testKey },
		"uniqueID": func(e *Event) string { e.UniqueID = ""; return testKey },
		"identity": func(e *Event) string { e.Profile = Profile{FirstName: "x"}; return testKey },
		"phone":    func(e *Event) string { e.Profile.PhoneNumber = "(949) 555-0100"; return testKey },
	}
	for name, mutate := range cases {
		ev := ok
		key := mutate(&ev)
		if err := c.CreateEvent(context.Background(), key, ev); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestProviderErrorIsTypedAndKeepsTheKeyOut(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"errors":[{"code":"throttled"}]}`)
	})
	err := c.CreateEvent(context.Background(), testKey, Event{Metric: "m", UniqueID: "u", Profile: Profile{ExternalID: "7"}})
	var se *common.HTTPStatusError
	if !errors.As(err, &se) || !se.RateLimited() || se.Header.Get("Retry-After") != "12" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("error leaks the key: %v", err)
	}
	c = server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	if _, err := c.AccountCurrency(context.Background(), testKey); common.HTTPStatus(err) != http.StatusBadRequest {
		t.Fatalf("err = %v", err)
	}
}

func TestAccountCurrency(t *testing.T) {
	for body, want := range map[string]string{
		`{"data":[{"attributes":{"preferred_currency":"usd"}}]}`: "USD",
		`{"data":[{"attributes":{"preferred_currency":"XX1"}}]}`: "",
		`{"data":[]}`:   "",
		`{"data":[{"at`: "",
	} {
		c := server(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/accounts/" {
				t.Errorf("path %s", r.URL.Path)
			}
			_, _ = io.WriteString(w, body)
		})
		got, err := c.AccountCurrency(context.Background(), testKey)
		if want == "" {
			if !errors.Is(err, ErrMalformedResponse) {
				t.Errorf("%s: got %q err %v", body, got, err)
			}
		} else if got != want || err != nil {
			t.Errorf("%s: got %q err %v", body, got, err)
		}
	}
}

func TestMetricIDFollowsPagesAndStopsAtTheMatch(t *testing.T) {
	pages := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.URL.Query().Get("page[cursor]") == "" {
			_, _ = io.WriteString(w, `{"data":[{"id":"M1","attributes":{"name":"Opened Email"}}],"links":{"next":"`+serverURL(r)+`/metrics/?page%5Bcursor%5D=2"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"M2","attributes":{"name":"Placed Order"}}],"links":{"next":"`+serverURL(r)+`/metrics/?page%5Bcursor%5D=3"}}`)
	})
	id, err := c.MetricID(context.Background(), testKey, "Placed Order")
	if err != nil || id != "M2" || pages != 2 {
		t.Fatalf("id %q err %v pages %d", id, err, pages)
	}
}

func serverURL(r *http.Request) string { return "http://" + r.Host }

func TestMetricIDNotFound(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"M1","attributes":{"name":"Opened Email"}}],"links":{"next":null}}`)
	})
	if _, err := c.MetricID(context.Background(), testKey, "Placed Order"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestListingIsBounded(t *testing.T) {
	pages := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		_, _ = io.WriteString(w, `{"data":[],"links":{"next":"`+serverURL(r)+`/flows/?page%5Bcursor%5D=x"}}`)
	})
	if _, err := c.FlowNames(context.Background(), testKey); !errors.Is(err, ErrTooManyPages) || pages != config.Config().OutboundMaxPages {
		t.Fatalf("err %v pages %d", err, pages)
	}
}

func TestListingIsBoundedByItems(t *testing.T) {
	limit := config.Config().OutboundMaxItems
	config.Config().OutboundMaxItems = 1
	t.Cleanup(func() { config.Config().OutboundMaxItems = limit })
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"F1"},{"id":"F2"}],"links":{}}`)
	})
	if _, err := c.FlowNames(context.Background(), testKey); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("err = %v", err)
	}
}

func TestListingNeverSendsTheKeyToAnotherOrigin(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("key sent to a foreign origin: %v", r.Header)
	}))
	defer foreign.Close()
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[],"links":{"next":"`+foreign.URL+`/flows/"}}`)
	})
	if _, err := c.FlowNames(context.Background(), testKey); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestCampaignNamesFiltersByChannel(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/campaigns/" || r.URL.Query().Get("filter") != "equals(messages.channel,'email')" {
			t.Errorf("%s ? %s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"C1","attributes":{"name":"Fall promo"}}],"links":{}}`)
	})
	names, err := c.CampaignNames(context.Background(), testKey, ChannelEmail)
	if err != nil || names["C1"] != "Fall promo" {
		t.Fatalf("names %v err %v", names, err)
	}
	if _, err := c.CampaignNames(context.Background(), testKey, "email')"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

func TestFlowValuesKeepsDecimalsExact(t *testing.T) {
	var got map[string]any
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/flow-values-reports/" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"data":{"attributes":{"results":[
		 {"groupings":{"flow_id":"F1","send_channel":"email"},"statistics":{"conversion_value":1200.10,"conversions":2,"recipients":40}},
		 {"groupings":{"flow_id":"F1","send_channel":"sms"},"statistics":{"conversion_value":0.1,"conversions":1,"recipients":null}}]}}}`)
	})
	rows, err := c.FlowValues(context.Background(), testKey, ValuesQuery{
		Statistics: []string{StatConversionValue, StatConversions, StatRecipients}, Timeframe: Timeframe{Key: "last_30_days"}, ConversionMetricID: "M2",
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs := got["data"].(map[string]any)["attributes"].(map[string]any)
	if got["data"].(map[string]any)["type"] != "flow-values-report" || attrs["conversion_metric_id"] != "M2" || attrs["timeframe"].(map[string]any)["key"] != "last_30_days" {
		t.Fatalf("request = %v", got)
	}
	if len(rows) != 2 || rows[0].Groupings["flow_id"] != "F1" || rows[0].Statistics[StatConversionValue] != "1200.10" || rows[1].Statistics[StatConversionValue] != "0.1" || rows[1].Statistics[StatRecipients] != "" {
		t.Fatalf("rows = %+v", rows)
	}
	if minor, err := common.ParseMinorUnits(rows[0].Statistics[StatConversionValue], 2); err != nil || minor != 120010 {
		t.Fatalf("minor %d err %v", minor, err)
	}
}

func TestCampaignValuesSendsAnAbsoluteTimeframe(t *testing.T) {
	var got map[string]any
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/campaign-values-reports/" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"data":{"attributes":{"results":[]}}}`)
	})
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rows, err := c.CampaignValues(context.Background(), testKey, ValuesQuery{
		Statistics: []string{StatConversionValue}, Timeframe: Timeframe{Start: start, End: start.AddDate(0, 1, 0)}, ConversionMetricID: "M2",
	})
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	tf := got["data"].(map[string]any)["attributes"].(map[string]any)["timeframe"].(map[string]any)
	if tf["start"] != "2026-09-01T00:00:00Z" || tf["end"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("timeframe = %v", tf)
	}
}

func TestValuesRefusesBadQueries(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	now := time.Now()
	for name, q := range map[string]ValuesQuery{
		"no timeframe":  {Statistics: []string{StatConversions}, ConversionMetricID: "M"},
		"both":          {Statistics: []string{StatConversions}, ConversionMetricID: "M", Timeframe: Timeframe{Key: "k", Start: now, End: now.Add(time.Hour)}},
		"inverted":      {Statistics: []string{StatConversions}, ConversionMetricID: "M", Timeframe: Timeframe{Start: now, End: now}},
		"no statistics": {ConversionMetricID: "M", Timeframe: Timeframe{Key: "k"}},
		"no metric":     {Statistics: []string{StatConversions}, Timeframe: Timeframe{Key: "k"}},
	} {
		if _, err := c.FlowValues(context.Background(), testKey, q); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestValuesMalformedJSON(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"attributes":{"results":[{"statistics":{"conversion_value":"abc"}}]}}}`)
	})
	_, err := c.FlowValues(context.Background(), testKey, ValuesQuery{Statistics: []string{StatConversionValue}, Timeframe: Timeframe{Key: "k"}, ConversionMetricID: "M"})
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v", err)
	}
}

func TestZeroClientUsesTheKlaviyoEndpoint(t *testing.T) {
	if (&Client{}).base() != APIBaseURL {
		t.Fatal("zero client base")
	}
}

func TestIsE164(t *testing.T) {
	for phone, want := range map[string]bool{"+19495550100": true, "+1": false, "9495550100": false, "+0123456789": false, "": false} {
		if IsE164(phone) != want {
			t.Errorf("IsE164(%q) != %v", phone, want)
		}
	}
}
