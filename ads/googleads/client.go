// Package googleads is a transport client for the REST interface of the
// Google Ads API: accessible customers, GAQL search and offline click
// conversion upload. Each call carries the partner's OAuth access token; the
// developer token comes from the caller's keystore.
package googleads

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
)

const (
	APIBaseURL = "https://googleads.googleapis.com"
	APIVersion = "v25"
)

// Client is one API version's REST surface. LoginCustomerID is the manager
// account a call is made through when the partner's account is managed.
// BaseURL and Version fall back to APIBaseURL and APIVersion.
type Client struct {
	BaseURL         string
	Version         string
	DeveloperToken  string
	LoginCustomerID string
}

func (c *Client) base() string {
	base, version := c.BaseURL, c.Version
	if base == "" {
		base = APIBaseURL
	}
	if version == "" {
		version = APIVersion
	}
	return strings.TrimRight(base, "/") + "/" + version
}

func (c *Client) headers(token string) (map[string]string, error) {
	if c.DeveloperToken == "" {
		return nil, ErrNoDeveloperToken
	}
	if strings.TrimSpace(token) == "" {
		return nil, ErrNoAccessToken
	}
	h := map[string]string{"Authorization": "Bearer " + token, "developer-token": c.DeveloperToken}
	if c.LoginCustomerID != "" {
		id, err := CustomerID(c.LoginCustomerID)
		if err != nil {
			return nil, fmt.Errorf("login customer: %w", err)
		}
		h["login-customer-id"] = id
	}
	return h, nil
}

func (c *Client) post(ctx context.Context, op, token, path string, payload any) ([]byte, error) {
	h, err := c.headers(token)
	if err != nil {
		return nil, err
	}
	body, _, err := common.RequestJSON(ctx, http.MethodPost, c.base()+path, h, payload)
	if err != nil {
		return nil, wrapError(op, err)
	}
	return body, nil
}

// CustomerID strips the dashes a customer id is often written with and
// rejects anything that is not a run of digits.
func CustomerID(id string) (string, error) {
	digits := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return "", fmt.Errorf("%w: %q", ErrInvalidCustomerID, id)
	}
	return digits, nil
}

// AccessibleCustomers lists the customer ids the grant can reach, without the
// "customers/" prefix.
func (c *Client) AccessibleCustomers(ctx context.Context, token string) ([]string, error) {
	h, err := c.headers(token)
	if err != nil {
		return nil, err
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet, c.base()+"/customers:listAccessibleCustomers", h, nil)
	if err != nil {
		return nil, wrapError("list accessible customers", err)
	}
	var resp struct {
		ResourceNames []string `json:"resourceNames"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("googleads: decode accessible customers: %w", err)
	}
	out := make([]string, 0, len(resp.ResourceNames))
	for _, name := range resp.ResourceNames {
		out = append(out, strings.TrimPrefix(name, "customers/"))
	}
	return out, nil
}

// Search runs one GAQL query through googleAds:searchStream and decodes every
// result row into a T shaped like the API's JSON (camelCase fields; int64
// metrics and micros arrive as JSON strings, so tag them `json:",string"`).
// The response is bounded by outbound_max_response_size.
func Search[T any](ctx context.Context, c *Client, token, customerID, query string) ([]T, error) {
	id, err := CustomerID(customerID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(query) == "" {
		return nil, ErrEmptyQuery
	}
	op := "search " + queryResource(query)
	body, err := c.post(ctx, op, token, "/customers/"+id+"/googleAds:searchStream", map[string]string{"query": query})
	if err != nil {
		return nil, err
	}
	var batches []struct {
		Results []T `json:"results"`
	}
	if err := json.Unmarshal(body, &batches); err != nil {
		return nil, fmt.Errorf("googleads: decode %s: %w", op, err)
	}
	var out []T
	for _, b := range batches {
		out = append(out, b.Results...)
	}
	return out, nil
}

// queryResource names a query by its FROM resource for error messages, so the
// whole GAQL text is not repeated in logs.
func queryResource(query string) string {
	fields := strings.Fields(query)
	for i, f := range fields {
		if strings.EqualFold(f, "FROM") && i+1 < len(fields) {
			return "FROM " + fields[i+1]
		}
	}
	return "query"
}
