package meta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

func server(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL}, srv
}

func TestInsightsFollowsPagingWithTheCallersToken(t *testing.T) {
	var srv *httptest.Server
	c, srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Header.Get("Authorization") != "Bearer tok" || q.Has("access_token") || r.URL.Path != "/v23.0/act_9/insights" {
			t.Errorf("request = %s", r.URL)
		}
		if q.Get("after") == "" {
			if q.Get("level") != "ad" || q.Get("time_increment") != "1" || !strings.Contains(q.Get("time_range"), `"since":"2026-09-01"`) {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `{"data":[{"ad_id":"1","date_start":"2026-09-01","spend":"12.34","impressions":"1000","reach":"400",
			 "frequency":"2.5","actions":[{"action_type":"lead","value":"3"}],"action_values":[{"action_type":"lead","value":"45.60"}]}],
			 "paging":{"next":"`+srv.URL+`/v23.0/act_9/insights?access_token=stale&after=c1"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"ad_id":"2","date_start":"2026-09-02","spend":"0"}],"paging":{}}`)
	})
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rows, err := c.Insights(context.Background(), "tok", "act_9", InsightsQuery{Level: "ad", Since: since, Until: since.AddDate(0, 0, 1), Daily: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Spend != "12.34" || rows[0].Reach != 400 || rows[0].Impressions != 1000 ||
		rows[0].Actions[0].Value != "3" || rows[0].ActionValues[0].Value != "45.60" || rows[1].AdID != "2" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestInsightsQueryValidation(t *testing.T) {
	c, _ := server(t, func(http.ResponseWriter, *http.Request) { t.Error("request sent") })
	ctx := context.Background()
	now := time.Now()
	for name, q := range map[string]InsightsQuery{
		"no level":       {DatePreset: "last_7d"},
		"no window":      {Level: "ad"},
		"both":           {Level: "ad", DatePreset: "last_7d", Since: now, Until: now},
		"reversed range": {Level: "ad", Since: now, Until: now.AddDate(0, 0, -1)},
	} {
		if _, err := c.Insights(ctx, "tok", "9", q); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := c.Insights(ctx, "tok", "9/../me", InsightsQuery{Level: "ad", DatePreset: "last_7d"}); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.AdAccounts(ctx, ""); !errors.Is(err, ErrNoAccessToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestPagingStopsAtMaxPages(t *testing.T) {
	calls := 0
	var srv *httptest.Server
	c, srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintf(w, `{"data":[{"account_id":"%d"}],"paging":{"next":"%s/v23.0/me/adaccounts?after=%d"}}`, calls, srv.URL, calls)
	})
	setLimit(t, &config.Config().OutboundMaxPages, 3)
	_, err := c.AdAccounts(context.Background(), "tok")
	if !errors.Is(err, ErrPageLimit) || calls != 3 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}

func TestPagingStopsAtMaxItems(t *testing.T) {
	var srv *httptest.Server
	c, srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"1"},{"id":"2"}],"paging":{"next":"`+srv.URL+`/v23.0/me/accounts?after=x"}}`)
	})
	setLimit(t, &config.Config().OutboundMaxItems, 3)
	if _, err := c.Pages(context.Background(), "tok"); !errors.Is(err, ErrPageLimit) {
		t.Fatalf("err = %v", err)
	}
}

func setLimit(t *testing.T, limit *int, n int) {
	saved := *limit
	*limit = n
	t.Cleanup(func() { *limit = saved })
}

func TestPagingRefusesAForeignNextLink(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"1"}],"paging":{"next":"https://evil.example/v23.0/me/accounts?after=x"}}`)
	})
	if _, err := c.Pages(context.Background(), "tok"); !errors.Is(err, ErrForeignPagingURL) {
		t.Fatalf("err = %v", err)
	}
}

func TestPagesKeepTheirTokenOutOfStrings(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v23.0/me/accounts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"P1","name":"Shop","access_token":"page-secret"}]}`)
	})
	pages, err := c.Pages(context.Background(), "tok")
	if err != nil || len(pages) != 1 || pages[0].AccessToken != "page-secret" {
		t.Fatalf("pages = %v, err = %v", pages, err)
	}
	if s := fmt.Sprintf("%v %+v", pages[0], pages); strings.Contains(s, "page-secret") {
		t.Fatalf("formatted page leaks its token: %s", s)
	}
}

func TestErrorStatusDecodesGraphErrorWithoutLeakingTheToken(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"Error validating access token","type":"OAuthException","code":190,"error_subcode":463,"fbtrace_id":"T1"}}`)
	})
	_, err := c.AdAccounts(context.Background(), "secret-token")
	if apiErr, ok := errors.AsType[*APIError](err); !ok || !apiErr.TokenInvalid() || apiErr.Throttled() || apiErr.Subcode != 463 || apiErr.TraceID != "T1" {
		t.Fatalf("err = %v", err)
	}
	if se, ok := errors.AsType[*common.HTTPStatusError](err); !ok || se.Status != http.StatusBadRequest {
		t.Fatalf("does not unwrap to the status error: %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestThrottledCodes(t *testing.T) {
	for _, code := range []int{4, 17, 32, 613, 80000, 80014} {
		if !(&APIError{Code: code}).Throttled() {
			t.Errorf("code %d not throttled", code)
		}
	}
	if (&APIError{Code: 100}).Throttled() {
		t.Error("code 100 throttled")
	}
}

func TestTransportErrorDropsTheTokenFromTheURL(t *testing.T) {
	c, srv := server(t, func(http.ResponseWriter, *http.Request) {})
	srv.Close()
	_, err := c.AdAccounts(context.Background(), "secret-token")
	if _, ok := errors.AsType[*url.Error](err); err == nil || strings.Contains(err.Error(), "secret-token") || !ok {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedJSONIsAnError(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"data":[`) })
	if _, err := c.AdAccounts(context.Background(), "tok"); err == nil {
		t.Fatal("want decode error")
	}
	c2, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"ad_id":"1","impressions":"lots"}]}`)
	})
	if _, err := c2.Insights(context.Background(), "tok", "9", InsightsQuery{Level: "ad", DatePreset: "last_7d"}); err == nil {
		t.Fatal("a non-numeric count must fail")
	}
}

func TestLeadsFiltersAfterSinceAndParsesTime(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v23.0/77/leads" || r.Header.Get("Authorization") != "Bearer page-tok" || r.URL.Query().Has("access_token") {
			t.Errorf("request = %s", r.URL)
		}
		if !strings.Contains(r.URL.Query().Get("filtering"), `"GREATER_THAN"`) {
			t.Errorf("no since filter: %s", r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"L1","created_time":"2026-09-20T15:04:05+0000","campaign_name":"Kits",
		 "field_data":[{"name":"FULL_NAME","values":[" Sam Rivera "]},{"name":"email","values":["sam@example.com"]}]}]}`)
	})
	leads, err := c.Leads(context.Background(), "page-tok", "77", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 1 || leads[0].Field("full_name") != "Sam Rivera" || leads[0].FormID != "77" ||
		!leads[0].CreatedAt.Equal(time.Date(2026, 9, 20, 15, 4, 5, 0, time.UTC)) {
		t.Fatalf("leads = %+v", leads)
	}
}

func TestLeadsRejectsAMalformedCreatedTime(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"L1","created_time":"yesterday"}]}`)
	})
	if _, err := c.Leads(context.Background(), "page-tok", "77", time.Time{}); err == nil {
		t.Fatal("want parse error")
	}
}

func TestLeadFormsAndAdCreative(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v23.0/5/leadgen_forms":
			_, _ = io.WriteString(w, `{"data":[{"id":"F1","name":"Quote","status":"ACTIVE"},{"id":"F2","status":"ARCHIVED"}]}`)
		case "/v23.0/42":
			if r.URL.Query().Get("fields") != "creative{id,body,title}" {
				t.Errorf("fields = %s", r.URL.Query().Get("fields"))
			}
			_, _ = io.WriteString(w, `{"id":"42","creative":{"id":"C1","body":"Primary","title":"Headline"}}`)
		default:
			t.Errorf("path = %s", r.URL.Path)
		}
	})
	forms, err := c.LeadForms(context.Background(), "page-tok", "5")
	if err != nil || len(forms) != 2 || forms[1].Status != "ARCHIVED" {
		t.Fatalf("forms = %+v, err = %v", forms, err)
	}
	creative, err := c.AdCreative(context.Background(), "tok", "42")
	if err != nil || creative.Body != "Primary" || creative.Title != "Headline" {
		t.Fatalf("creative = %+v, err = %v", creative, err)
	}
}

func TestSendEvents(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v23.0/123/events" || r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Has("access_token") {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		raw, _ := io.ReadAll(r.Body)
		for _, want := range []string{`"value":19.99`, `"em":["`, `"lead_id":555`, `"action_source":"system_generated"`} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("body lacks %s: %s", want, raw)
			}
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal(raw, &body)
		_, _ = fmt.Fprintf(w, `{"events_received":%d,"fbtrace_id":"T"}`, len(body.Data))
	})
	event := Event{EventName: "Purchase", EventTime: 1_700_000_000, EventID: "sale-1", ActionSource: "system_generated",
		UserData:   UserData{Email: []string{HashEmail("A@B.com")}, LeadID: 555},
		CustomData: &CustomData{Value: "19.99", Currency: "USD"}}
	res, err := c.SendEvents(context.Background(), "tok", "123", []Event{event})
	if err != nil || res.EventsReceived != 1 || res.TraceID != "T" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestSendEventsReportsShortAcknowledgement(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"events_received":0}`) })
	event := Event{EventName: "Lead", EventTime: 1, ActionSource: "system_generated", UserData: UserData{LeadID: 1}}
	if _, err := c.SendEvents(context.Background(), "tok", "123", []Event{event}); !errors.Is(err, ErrEventsNotReceived) {
		t.Fatalf("err = %v", err)
	}
}

func TestSendEventsValidation(t *testing.T) {
	c, _ := server(t, func(http.ResponseWriter, *http.Request) { t.Error("request sent") })
	ctx := context.Background()
	ok := Event{EventName: "Lead", EventTime: 1, ActionSource: "system_generated", UserData: UserData{LeadID: 1}}
	if _, err := c.SendEvents(ctx, "tok", "123", nil); !errors.Is(err, ErrNoEvents) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.SendEvents(ctx, "tok", "123", make([]Event, MaxEventsPerRequest+1)); !errors.Is(err, ErrTooManyEvents) {
		t.Fatalf("err = %v", err)
	}
	noKey := ok
	noKey.UserData = UserData{}
	if _, err := c.SendEvents(ctx, "tok", "123", []Event{noKey}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.SendEvents(ctx, "tok", "px", []Event{ok}); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.SendEvents(ctx, "", "123", []Event{ok}); !errors.Is(err, ErrNoAccessToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestHashNormalization(t *testing.T) {
	if HashEmail("  John.Doe@Gmail.COM ") != common.Sha256Hex("john.doe@gmail.com") {
		t.Fatal("HashEmail must trim and lower-case, and keep gmail dots")
	}
	for _, bad := range []string{"", "nobody", "a@", "@b", "a@b@c"} {
		if HashEmail(bad) != "" {
			t.Errorf("%q hashed", bad)
		}
	}
	got, err := HashPhone("+1 (415) 555-2671", "")
	if err != nil || got != common.Sha256Hex("14155552671") {
		t.Fatalf("HashPhone = %q, %v", got, err)
	}
	if got, err := HashPhone("020 7946 0958", "GB"); err != nil || got != common.Sha256Hex("442079460958") {
		t.Fatalf("national with region = %q, %v", got, err)
	}
	if _, err := HashPhone("415 555 2671", ""); !errors.Is(err, ErrInvalidPhone) {
		t.Fatalf("national without region: err = %v", err)
	}
	if got := ClickID(time.UnixMilli(1_700_000_000_123), "abc"); got != "fb.1.1700000000123.abc" {
		t.Fatalf("ClickID = %q", got)
	}
}
