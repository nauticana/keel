package commerce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/client"
)

// CurrencyExponents gives a currency's minor-unit digits; *geo.Currencies satisfies it.
type CurrencyExponents interface {
	Exponent(ctx context.Context, code string) (int, error)
}

// ShopifyOrderReader reads orders through the Admin GraphQL orders query. The
// token needs read_orders; without read_all_orders Shopify silently returns
// only the last 60 days. The API version is part of the endpoint
// (https://<shop>.myshopify.com/admin/api/<version>).
type ShopifyOrderReader struct {
	Currencies CurrencyExponents
	PageSize   int         // orders per page; 0 = 100, at most 250
	MaxWaits   int         // throttle waits per page; 0 = 5
	Clock      clock.Clock // nil = clock.System{}

	checkEndpoint func(string) error // nil = shopifyEndpoint
}

var _ OrderReader = (*ShopifyOrderReader)(nil)

const shopifyOrdersQuery = `query Orders($first: Int!, $after: String, $query: String!) {
  orders(first: $first, after: $after, query: $query, sortKey: UPDATED_AT) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id name currencyCode test taxesIncluded displayFinancialStatus
      createdAt processedAt cancelledAt updatedAt
      subtotalPriceSet { shopMoney { amount currencyCode } }
      totalDiscountsSet { shopMoney { amount currencyCode } }
      totalShippingPriceSet { shopMoney { amount currencyCode } }
      totalTaxSet { shopMoney { amount currencyCode } }
      totalPriceSet { shopMoney { amount currencyCode } }
      totalRefundedSet { shopMoney { amount currencyCode } }
    }
  }
}`

var shopifyStatuses = map[string]FinancialStatus{
	"PENDING":            StatusPending,
	"AUTHORIZED":         StatusAuthorized,
	"PAID":               StatusPaid,
	"PARTIALLY_PAID":     StatusPartiallyPaid,
	"PARTIALLY_REFUNDED": StatusPartiallyRefunded,
	"REFUNDED":           StatusRefunded,
	"VOIDED":             StatusVoided,
	"EXPIRED":            StatusExpired,
}

type shopifyMoneySet struct {
	ShopMoney struct {
		Amount       string `json:"amount"`
		CurrencyCode string `json:"currencyCode"`
	} `json:"shopMoney"`
}

type shopifyOrder struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	CurrencyCode           string          `json:"currencyCode"`
	Test                   bool            `json:"test"`
	TaxesIncluded          bool            `json:"taxesIncluded"`
	DisplayFinancialStatus *string         `json:"displayFinancialStatus"`
	CreatedAt              time.Time       `json:"createdAt"`
	ProcessedAt            time.Time       `json:"processedAt"`
	CancelledAt            *time.Time      `json:"cancelledAt"`
	UpdatedAt              time.Time       `json:"updatedAt"`
	Subtotal               shopifyMoneySet `json:"subtotalPriceSet"`
	Discounts              shopifyMoneySet `json:"totalDiscountsSet"`
	Shipping               shopifyMoneySet `json:"totalShippingPriceSet"`
	Tax                    shopifyMoneySet `json:"totalTaxSet"`
	Total                  shopifyMoneySet `json:"totalPriceSet"`
	Refunded               shopifyMoneySet `json:"totalRefundedSet"`
}

type shopifyOrdersData struct {
	Orders *struct {
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
		Nodes []shopifyOrder `json:"nodes"`
	} `json:"orders"`
}

func (r *ShopifyOrderReader) Orders(ctx context.Context, token, endpoint string, updatedSince time.Time, after string) (OrderPage, error) {
	if r.Currencies == nil {
		return OrderPage{}, errors.New("commerce: ShopifyOrderReader needs Currencies")
	}
	if token == "" {
		return OrderPage{}, fmt.Errorf("%w: no access token", ErrAccessDenied)
	}
	check := r.checkEndpoint
	if check == nil {
		check = shopifyEndpoint
	}
	if err := check(endpoint); err != nil {
		return OrderPage{}, err
	}
	pageSize := r.PageSize
	switch {
	case pageSize == 0:
		pageSize = 100
	case pageSize < 0 || pageSize > 250:
		return OrderPage{}, fmt.Errorf("commerce: PageSize %d outside 1..250", pageSize)
	}
	vars := map[string]any{
		"first": pageSize,
		"query": "",
	}
	if !updatedSince.IsZero() {
		vars["query"] = "updated_at:>='" + updatedSince.UTC().Format(time.RFC3339) + "'"
	}
	if after != "" {
		vars["after"] = after
	}
	var data shopifyOrdersData
	if err := r.query(ctx, token, strings.TrimRight(endpoint, "/")+"/graphql.json", vars, &data); err != nil {
		return OrderPage{}, err
	}
	if data.Orders == nil {
		return OrderPage{}, fmt.Errorf("%w: response omitted orders", ErrRejected)
	}
	page := OrderPage{Orders: make([]Order, 0, len(data.Orders.Nodes))}
	for _, node := range data.Orders.Nodes {
		order, err := r.order(ctx, node)
		if err != nil {
			return OrderPage{}, fmt.Errorf("%w: order %s: %w", ErrRejected, node.ID, err)
		}
		page.Orders = append(page.Orders, order)
	}
	if data.Orders.PageInfo.HasNextPage {
		if data.Orders.PageInfo.EndCursor == "" {
			return OrderPage{}, fmt.Errorf("%w: next page without a cursor", ErrRejected)
		}
		page.Next = data.Orders.PageInfo.EndCursor
	}
	return page, nil
}

func (r *ShopifyOrderReader) order(ctx context.Context, n shopifyOrder) (Order, error) {
	if n.ID == "" || n.Name == "" || n.CurrencyCode == "" || n.CreatedAt.IsZero() || n.UpdatedAt.IsZero() {
		return Order{}, errors.New("missing id, name, currency, createdAt, or updatedAt")
	}
	exponent, err := r.Currencies.Exponent(ctx, n.CurrencyCode)
	if err != nil {
		return Order{}, err
	}
	o := Order{
		ID: n.ID, Name: n.Name, Currency: n.CurrencyCode, Test: n.Test, TaxesIncluded: n.TaxesIncluded,
		OrderedAt: n.CreatedAt, ProcessedAt: n.ProcessedAt, UpdatedAt: n.UpdatedAt,
	}
	if n.CancelledAt != nil {
		o.CancelledAt = *n.CancelledAt
	}
	if n.DisplayFinancialStatus != nil {
		status, ok := shopifyStatuses[*n.DisplayFinancialStatus]
		if !ok {
			return Order{}, fmt.Errorf("unknown financial status %q", *n.DisplayFinancialStatus)
		}
		o.Status = status
	}
	for _, m := range []struct {
		set  shopifyMoneySet
		into *int64
		name string
	}{
		{n.Subtotal, &o.SubtotalMinor, "subtotal"},
		{n.Discounts, &o.DiscountsMinor, "discounts"},
		{n.Shipping, &o.ShippingMinor, "shipping"},
		{n.Tax, &o.TaxMinor, "tax"},
		{n.Total, &o.TotalMinor, "total"},
		{n.Refunded, &o.RefundedMinor, "refunded"},
	} {
		if m.set.ShopMoney.CurrencyCode != n.CurrencyCode {
			return Order{}, fmt.Errorf("%s in %q, order in %q", m.name, m.set.ShopMoney.CurrencyCode, n.CurrencyCode)
		}
		minor, err := common.ParseMinorUnits(trimFraction(m.set.ShopMoney.Amount), exponent)
		if err != nil {
			return Order{}, fmt.Errorf("%s: %w", m.name, err)
		}
		*m.into = minor
	}
	return o, nil
}

// trimFraction drops trailing fractional zeros ("20.0" → "20", "19.990" →
// "19.99"), so only real excess precision fails ParseMinorUnits.
func trimFraction(amount string) string {
	if !strings.Contains(amount, ".") {
		return amount
	}
	amount = strings.TrimRight(amount, "0")
	return strings.TrimSuffix(amount, ".")
}

type shopifyThrottle struct {
	RequestedQueryCost float64 `json:"requestedQueryCost"`
	ThrottleStatus     struct {
		CurrentlyAvailable float64 `json:"currentlyAvailable"`
		RestoreRate        float64 `json:"restoreRate"`
	} `json:"throttleStatus"`
}

// query runs one GraphQL request, waiting out Shopify's query-cost throttle
// up to MaxWaits times.
func (r *ShopifyOrderReader) query(ctx context.Context, token, url string, vars map[string]any, out any) error {
	maxWaits := r.MaxWaits
	if maxWaits == 0 {
		maxWaits = 5
	}
	clk := r.Clock
	if clk == nil {
		clk = clock.System{}
	}
	for attempt := 0; ; attempt++ {
		raw, _, err := common.RequestJSON(ctx, http.MethodPost, url,
			map[string]string{"X-Shopify-Access-Token": token},
			map[string]any{"query": shopifyOrdersQuery, "variables": vars})
		wait := time.Duration(0)
		if err != nil {
			status, ok := errors.AsType[*common.HTTPStatusError](err)
			switch {
			case ok && status.Unauthorized():
				return fmt.Errorf("%w: %w", ErrAccessDenied, err)
			case ok && status.RateLimited():
				wait = time.Second
			default:
				return err
			}
		} else {
			var env struct {
				Data   json.RawMessage `json:"data"`
				Errors []struct {
					Message    string `json:"message"`
					Extensions struct {
						Code string `json:"code"`
					} `json:"extensions"`
				} `json:"errors"`
				Extensions struct {
					Cost shopifyThrottle `json:"cost"`
				} `json:"extensions"`
			}
			if err := json.Unmarshal(raw, &env); err != nil {
				return fmt.Errorf("%w: decode shopify response: %w", ErrRejected, err)
			}
			if len(env.Errors) == 0 {
				if err := json.Unmarshal(env.Data, out); err != nil {
					return fmt.Errorf("%w: decode shopify orders: %w", ErrRejected, err)
				}
				return nil
			}
			throttled := false
			for _, e := range env.Errors {
				switch e.Extensions.Code {
				case "ACCESS_DENIED":
					return fmt.Errorf("%w: %s", ErrAccessDenied, e.Message)
				case "THROTTLED":
					throttled = true
				}
			}
			if !throttled {
				return fmt.Errorf("%w: shopify graphql: %s", ErrRejected, env.Errors[0].Message)
			}
			wait = throttleWait(env.Extensions.Cost)
		}
		if attempt >= maxWaits {
			return fmt.Errorf("%w after %d waits", ErrThrottled, attempt)
		}
		if err := clk.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// maxThrottleWait bounds one wait whatever cost Shopify reports.
const maxThrottleWait = time.Minute

// throttleWait is how long the bucket needs to refill the requested cost;
// one second when Shopify reports no usable rate.
func throttleWait(c shopifyThrottle) time.Duration {
	missing := c.RequestedQueryCost - c.ThrottleStatus.CurrentlyAvailable
	if c.ThrottleStatus.RestoreRate <= 0 || !(missing > 0) {
		return time.Second
	}
	seconds := math.Ceil(missing / c.ThrottleStatus.RestoreRate)
	if seconds >= maxThrottleWait.Seconds() {
		return maxThrottleWait
	}
	return time.Duration(seconds) * time.Second
}

// shopifyEndpoint accepts only an https *.myshopify.com Admin API endpoint, so
// the access token never travels to another host.
func shopifyEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: endpoint is not an https Shopify Admin API URL", ErrRejected)
	}
	host, err := client.CanonicalShopDomain(u.Hostname())
	version := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/admin/api/"), "/")
	if err != nil || !strings.EqualFold(host, u.Hostname()) || version == u.Path || version == "" || strings.Contains(version, "/") || version == "." || version == ".." {
		return fmt.Errorf("%w: endpoint is not an https Shopify Admin API URL", ErrRejected)
	}
	return nil
}
