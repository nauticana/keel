package googleads

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, DeveloperToken: "dev-secret"}
}

type customerRow struct {
	Customer struct {
		CurrencyCode string `json:"currencyCode"`
	} `json:"customer"`
	Metrics struct {
		CostMicros int64 `json:"costMicros,string"`
	} `json:"metrics"`
}

func TestSearchSendsTheAdsHeadersAndJoinsBatches(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v25/customers/1234567890/googleAds:searchStream" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("developer-token") != "dev-secret" || r.Header.Get("login-customer-id") != "9998887777" ||
			r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("headers = %v", r.Header)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !strings.Contains(body["query"], "FROM customer") {
			t.Errorf("query = %q", body["query"])
		}
		_, _ = io.WriteString(w, `[{"results":[{"customer":{"currencyCode":"JPY"},"metrics":{"costMicros":"1250000"}}]},{"results":[{"customer":{"currencyCode":"USD"}}]}]`)
	})
	c.LoginCustomerID = "999-888-7777"
	rows, err := Search[customerRow](context.Background(), c, "tok", "123-456-7890", "SELECT customer.currency_code FROM customer")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %+v, err = %v", rows, err)
	}
	if rows[0].Customer.CurrencyCode != "JPY" || rows[0].Metrics.CostMicros != 1250000 || rows[1].Customer.CurrencyCode != "USD" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestVersionIsConfigurable(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v99/customers:listAccessibleCustomers" || r.Method != http.MethodGet {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"resourceNames":["customers/111","customers/222"]}`)
	})
	c.Version = "v99"
	ids, err := c.AccessibleCustomers(context.Background(), "tok")
	if err != nil || len(ids) != 2 || ids[0] != "111" || ids[1] != "222" {
		t.Fatalf("ids = %v, err = %v", ids, err)
	}
}

func TestMissingCredentialsMakeNoCall(t *testing.T) {
	called := false
	c := server(t, func(http.ResponseWriter, *http.Request) { called = true })
	ctx := context.Background()
	if _, err := (&Client{BaseURL: c.BaseURL}).AccessibleCustomers(ctx, "tok"); !errors.Is(err, ErrNoDeveloperToken) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.AccessibleCustomers(ctx, " "); !errors.Is(err, ErrNoAccessToken) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Search[customerRow](ctx, c, "tok", "12/../34", "SELECT x FROM y"); !errors.Is(err, ErrInvalidCustomerID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Search[customerRow](ctx, c, "tok", "1", " "); !errors.Is(err, ErrEmptyQuery) {
		t.Fatalf("err = %v", err)
	}
	c.LoginCustomerID = "abc"
	if _, err := c.AccessibleCustomers(ctx, "tok"); !errors.Is(err, ErrInvalidCustomerID) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Fatal("a request was sent")
	}
}

func TestErrorStatusDecodesGoogleAdsFailure(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("request-id", "hdr-id")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `[{"error":{"code":403,"message":"The caller does not have permission","status":"PERMISSION_DENIED",
		 "details":[{"@type":"type.googleapis.com/google.ads.googleads.v25.errors.GoogleAdsFailure",
		 "errors":[{"errorCode":{"authorizationError":"DEVELOPER_TOKEN_NOT_APPROVED"},"message":"The developer token is not approved."}],
		 "requestId":"req-1"}]}}]`)
	})
	_, err := Search[customerRow](context.Background(), c, "secret-token", "1", "SELECT a FROM campaign")
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	if apiErr.HTTPStatus != 403 || apiErr.Status != "PERMISSION_DENIED" || apiErr.RequestID != "req-1" ||
		len(apiErr.Failures) != 1 || apiErr.Failures[0].Code != "DEVELOPER_TOKEN_NOT_APPROVED" || apiErr.Failures[0].Category != "authorizationError" {
		t.Fatalf("apiErr = %+v", apiErr)
	}
	if se, ok := errors.AsType[*common.HTTPStatusError](err); !ok || !se.Unauthorized() {
		t.Fatalf("not classified as unauthorized: %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "dev-secret") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	if !strings.Contains(err.Error(), "FROM campaign") || strings.Contains(err.Error(), "SELECT") {
		t.Fatalf("error should name the resource only: %v", err)
	}
}

func TestErrorStatusWithoutEnvelopeKeepsRequestIDHeader(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("request-id", "hdr-id")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `upstream down`)
	})
	_, err := c.AccessibleCustomers(context.Background(), "tok")
	apiErr, isAPI := errors.AsType[*APIError](err)
	se, isStatus := errors.AsType[*common.HTTPStatusError](err)
	if !isAPI || apiErr.RequestID != "hdr-id" || !isStatus || !se.Transient() {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedJSONIsAnError(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"results":`) })
	if _, err := Search[customerRow](context.Background(), c, "tok", "1", "SELECT a FROM b"); err == nil {
		t.Fatal("want decode error")
	}
	if _, err := c.AccessibleCustomers(context.Background(), "tok"); err == nil {
		t.Fatal("want decode error")
	}
	if _, err := c.UploadClickConversions(context.Background(), "tok", "1", []ClickConversion{{GCLID: "g"}}); err == nil {
		t.Fatal("want decode error")
	}
}

func TestUploadReportsPartialFailuresByIndex(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v25/customers/1234567890:uploadClickConversions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		for _, want := range []string{`"partialFailure":true`, `"conversionValue":12.50`, `"gclid":"G1"`, `"hashedEmail":"`, `"adUserData":"GRANTED"`} {
			if !strings.Contains(body, want) {
				t.Errorf("body lacks %s: %s", want, body)
			}
		}
		_, _ = io.WriteString(w, `{"partialFailureError":{"code":3,"message":"Unparseable gclid.",
		 "details":[{"@type":"type.googleapis.com/google.ads.googleads.v25.errors.GoogleAdsFailure",
		 "errors":[{"errorCode":{"conversionUploadError":"UNPARSEABLE_GCLID"},"message":"Unparseable gclid.",
		 "location":{"fieldPathElements":[{"fieldName":"conversions","index":0},{"fieldName":"gclid"}]}}]}]},
		 "results":[{},{"conversionAction":"customers/1/conversionActions/2"}]}`)
	})
	failures, err := c.UploadClickConversions(context.Background(), "tok", "123-456-7890", []ClickConversion{
		{ConversionAction: "customers/1234567890/conversionActions/2", ConversionDateTime: "2026-09-01 10:00:00+00:00",
			ConversionValue: "12.50", CurrencyCode: "USD", GCLID: "G1", Consent: &Consent{AdUserData: "GRANTED"}},
		{ConversionAction: "customers/1234567890/conversionActions/2", UserIdentifiers: []UserIdentifier{{HashedEmail: HashEmail("a@b.com")}}},
	})
	if err != nil || len(failures) != 1 {
		t.Fatalf("failures = %+v, err = %v", failures, err)
	}
	f := failures[0]
	if f.Index != 0 || f.Code != "UNPARSEABLE_GCLID" || f.Category != "conversionUploadError" || !errors.Is(f, ErrConversionRejected) {
		t.Fatalf("failure = %+v", f)
	}
}

func TestUploadWithoutDetailsStillReportsTheMessage(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"partialFailureError":{"code":3,"message":"bad row"}}`)
	})
	failures, err := c.UploadClickConversions(context.Background(), "tok", "1", []ClickConversion{{GCLID: "g"}})
	if err != nil || len(failures) != 1 || failures[0].Index != -1 || failures[0].Message != "bad row" {
		t.Fatalf("failures = %+v, err = %v", failures, err)
	}
}

func TestUploadAcceptedHasNoFailures(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"gclid":"g"}]}`)
	})
	failures, err := c.UploadClickConversions(context.Background(), "tok", "1", []ClickConversion{{GCLID: "g"}})
	if err != nil || failures != nil {
		t.Fatalf("failures = %+v, err = %v", failures, err)
	}
}

func TestUploadBounds(t *testing.T) {
	c := server(t, func(http.ResponseWriter, *http.Request) { t.Error("request sent") })
	ctx := context.Background()
	if _, err := c.UploadClickConversions(ctx, "tok", "1", nil); !errors.Is(err, ErrNoConversions) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.UploadClickConversions(ctx, "tok", "1", make([]ClickConversion, MaxConversionsPerUpload+1)); !errors.Is(err, ErrTooManyConversions) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.UploadClickConversions(ctx, "tok", "1", []ClickConversion{{ConversionValue: "NaN"}}); err == nil {
		t.Fatal("a non-numeric value must not be sent")
	}
}

func TestHashNormalization(t *testing.T) {
	if got := NormalizeEmail("  John.Doe@GoogleMail.com "); got != "johndoe@googlemail.com" {
		t.Fatalf("NormalizeEmail = %q", got)
	}
	if got := NormalizeEmail("Jo.Hn@Example.com"); got != "jo.hn@example.com" {
		t.Fatalf("NormalizeEmail = %q", got)
	}
	for _, bad := range []string{"", "nobody", "@x.com", "a@", "a@b@c"} {
		if NormalizeEmail(bad) != "" || HashEmail(bad) != "" {
			t.Errorf("%q should not normalize", bad)
		}
	}
	if HashEmail("J.Doe@gmail.com") != common.Sha256Hex("jdoe@gmail.com") {
		t.Fatal("HashEmail does not hash the normalized form")
	}
	got, err := HashPhone("+1 (415) 555-2671", "")
	if err != nil || got != common.Sha256Hex("+14155552671") {
		t.Fatalf("HashPhone = %q, %v", got, err)
	}
	if got, err := HashPhone("(415) 555-2671", "us"); err != nil || got != common.Sha256Hex("+14155552671") {
		t.Fatalf("national with region = %q, %v", got, err)
	}
	if _, err := HashPhone("415 555 2671", ""); !errors.Is(err, ErrInvalidPhone) {
		t.Fatalf("national number without region: err = %v", err)
	}
	if _, err := HashPhone("+1 555", ""); !errors.Is(err, ErrInvalidPhone) || strings.Contains(err.Error(), "555") {
		t.Fatalf("invalid number: err = %v", err)
	}
}
