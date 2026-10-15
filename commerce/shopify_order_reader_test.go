package commerce

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

type exponents map[string]int

func (e exponents) Exponent(_ context.Context, code string) (int, error) {
	if x, ok := e[code]; ok {
		return x, nil
	}
	return 0, errors.New("unknown currency")
}

type recordingClock struct {
	clock.System
	slept []time.Duration
}

func (c *recordingClock) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	return nil
}

func money(amount, code string) map[string]any {
	return map[string]any{"shopMoney": map[string]any{"amount": amount, "currencyCode": code}}
}

func shopifyOrderNode(id, status, total string) map[string]any {
	node := map[string]any{
		"id": id, "name": "#1001", "currencyCode": "USD", "test": false, "taxesIncluded": false,
		"createdAt": "2026-10-01T10:00:00Z", "processedAt": "2026-10-01T10:00:05Z", "cancelledAt": nil,
		"updatedAt":        "2026-10-02T09:00:00Z",
		"subtotalPriceSet": money("90.0", "USD"), "totalDiscountsSet": money("10.00", "USD"),
		"totalShippingPriceSet": money("5", "USD"), "totalTaxSet": money("7.20", "USD"),
		"totalPriceSet": money(total, "USD"), "totalRefundedSet": money("0.0", "USD"),
	}
	if status != "" {
		node["displayFinancialStatus"] = status
	}
	return node
}

// shopifyStub answers each request with the next scripted body.
func shopifyStub(t *testing.T, bodies ...any) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var requests []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/api/2026-10/graphql.json" || r.Header.Get("X-Shopify-Access-Token") != "shpat_1" {
			t.Errorf("request %s token=%q", r.URL.Path, r.Header.Get("X-Shopify-Access-Token"))
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		requests = append(requests, req)
		if len(bodies) == 0 {
			t.Fatal("unexpected extra request")
		}
		body := bodies[0]
		bodies = bodies[1:]
		if status, ok := body.(int); ok {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func newReader(clk clock.Clock) *ShopifyOrderReader {
	return &ShopifyOrderReader{
		Currencies:    exponents{"USD": 2, "JPY": 0},
		Clock:         clk,
		checkEndpoint: func(string) error { return nil },
	}
}

func ordersBody(next string, nodes ...map[string]any) map[string]any {
	return map[string]any{"data": map[string]any{"orders": map[string]any{
		"pageInfo": map[string]any{"hasNextPage": next != "", "endCursor": next},
		"nodes":    nodes,
	}}}
}

func TestShopifyOrderReader_ReadsPage(t *testing.T) {
	srv, requests := shopifyStub(t, ordersBody("cur_2", shopifyOrderNode("gid://shopify/Order/1", "PARTIALLY_REFUNDED", "102.200")))
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	page, err := newReader(nil).Orders(context.Background(), "shpat_1", srv.URL+"/admin/api/2026-10", since, "cur_1")
	if err != nil {
		t.Fatal(err)
	}
	if page.Next != "cur_2" || len(page.Orders) != 1 {
		t.Fatalf("page = %+v", page)
	}
	o := page.Orders[0]
	want := Order{
		ID: "gid://shopify/Order/1", Name: "#1001", Currency: "USD",
		SubtotalMinor: 9000, DiscountsMinor: 1000, ShippingMinor: 500, TaxMinor: 720, TotalMinor: 10220,
		Status:      StatusPartiallyRefunded,
		OrderedAt:   time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		ProcessedAt: time.Date(2026, 10, 1, 10, 0, 5, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
	}
	if o != want {
		t.Fatalf("order = %+v\nwant    %+v", o, want)
	}
	vars := (*requests)[0]["variables"].(map[string]any)
	if vars["query"] != "updated_at:>='2026-01-01T00:00:00Z'" || vars["first"] != float64(100) || vars["after"] != "cur_1" {
		t.Fatalf("variables = %v", vars)
	}
}

func TestShopifyOrderReader_WaitsOutThrottle(t *testing.T) {
	throttled := map[string]any{
		"errors":     []any{map[string]any{"message": "Throttled", "extensions": map[string]any{"code": "THROTTLED"}}},
		"extensions": map[string]any{"cost": map[string]any{"requestedQueryCost": 202, "throttleStatus": map[string]any{"currentlyAvailable": 50, "restoreRate": 50}}},
	}
	srv, requests := shopifyStub(t, throttled, http.StatusTooManyRequests, ordersBody(""))
	clk := &recordingClock{}
	page, err := newReader(clk).Orders(context.Background(), "shpat_1", srv.URL+"/admin/api/2026-10", time.Time{}, "")
	if err != nil || page.Next != "" || len(*requests) != 3 {
		t.Fatalf("page=%+v err=%v requests=%d", page, err, len(*requests))
	}
	if len(clk.slept) != 2 || clk.slept[0] != 4*time.Second || clk.slept[1] != time.Second {
		t.Fatalf("waits = %v", clk.slept)
	}

	always := []any{throttled, throttled, throttled}
	srv, _ = shopifyStub(t, always...)
	reader := newReader(&recordingClock{})
	reader.MaxWaits = 2
	if _, err := reader.Orders(context.Background(), "shpat_1", srv.URL+"/admin/api/2026-10", time.Time{}, ""); !errors.Is(err, ErrThrottled) {
		t.Fatalf("err = %v, want ErrThrottled", err)
	}
}

func TestShopifyOrderReader_Refusals(t *testing.T) {
	denied := map[string]any{"errors": []any{map[string]any{"message": "no", "extensions": map[string]any{"code": "ACCESS_DENIED"}}}}
	mismatch := shopifyOrderNode("gid://shopify/Order/2", "PAID", "92.20")
	mismatch["totalTaxSet"] = money("7.20", "EUR")
	for name, tc := range map[string]struct {
		body any
		want error
	}{
		"access denied":    {denied, ErrAccessDenied},
		"unauthorized":     {http.StatusUnauthorized, ErrAccessDenied},
		"unknown status":   {ordersBody("", shopifyOrderNode("gid://shopify/Order/3", "MYSTERY", "92.20")), ErrRejected},
		"currency differs": {ordersBody("", mismatch), ErrRejected},
		"excess precision": {ordersBody("", shopifyOrderNode("gid://shopify/Order/4", "PAID", "92.201")), ErrRejected},
		"orders omitted":   {map[string]any{"data": map[string]any{}}, ErrRejected},
		"next without cursor": {map[string]any{"data": map[string]any{"orders": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": true, "endCursor": ""}, "nodes": []any{}}}}, ErrRejected},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := shopifyStub(t, tc.body)
			if _, err := newReader(&recordingClock{}).Orders(context.Background(), "shpat_1", srv.URL+"/admin/api/2026-10", time.Time{}, ""); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestShopifyOrderReader_NoStatusAndInputs(t *testing.T) {
	srv, _ := shopifyStub(t, ordersBody("", shopifyOrderNode("gid://shopify/Order/5", "", "92.20")))
	page, err := newReader(nil).Orders(context.Background(), "shpat_1", srv.URL+"/admin/api/2026-10", time.Time{}, "")
	if err != nil || page.Orders[0].Status != "" {
		t.Fatalf("no status: %+v %v", page, err)
	}
	r := newReader(nil)
	if _, err := r.Orders(context.Background(), "", srv.URL, time.Time{}, ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("no token: %v", err)
	}
	r.PageSize = 251
	if _, err := r.Orders(context.Background(), "shpat_1", srv.URL, time.Time{}, ""); err == nil {
		t.Fatal("accepted page size 251")
	}
	if _, err := (&ShopifyOrderReader{}).Orders(context.Background(), "shpat_1", srv.URL, time.Time{}, ""); err == nil {
		t.Fatal("read without a currency catalog")
	}
}

// The token only ever goes to an https *.myshopify.com Admin API endpoint.
func TestShopifyEndpoint(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"https://shop-1.myshopify.com/admin/api/2026-10":      true,
		"https://SHOP-1.myshopify.com/admin/api/2026-10/":     true,
		"http://shop-1.myshopify.com/admin/api/2026-10":       false,
		"https://evil.example.com/admin/api/2026-10":          false,
		"https://evil.com#.myshopify.com/admin/api/2026-10":   false,
		"https://shop-1.myshopify.com:8443/admin/api/2026-10": false,
		"https://user@shop-1.myshopify.com/admin/api/2026-10": false,
		"https://shop-1.myshopify.com/admin/api/2026-10?x=1":  false,
		"https://shop-1.myshopify.com/admin/api/2026-10/more": false,
		"https://shop-1.myshopify.com/other":                  false,
	} {
		if err := shopifyEndpoint(endpoint); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", endpoint, err, ok)
		}
	}
}

func TestThrottleWaitBounds(t *testing.T) {
	huge := shopifyThrottle{RequestedQueryCost: 1e9}
	huge.ThrottleStatus.RestoreRate = 1
	if got := throttleWait(huge); got != maxThrottleWait {
		t.Fatalf("huge cost wait = %v", got)
	}
	if got := throttleWait(shopifyThrottle{}); got != time.Second {
		t.Fatalf("no rate wait = %v", got)
	}
}
