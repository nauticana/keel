// Package klaviyo calls the Klaviyo REST API with a caller-supplied private API
// key: event push, metric and object listings, account currency and values
// reports.
package klaviyo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

const (
	APIBaseURL = "https://a.klaviyo.com/api"
	Revision   = "2026-07-15"
)

// Client is safe for concurrent use; the zero value calls APIBaseURL. Responses
// are bounded by outbound_max_response_size and non-2xx statuses surface as
// *common.HTTPStatusError, Retry-After included.
type Client struct {
	BaseURL string
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return APIBaseURL
}

func headers(apiKey string) map[string]string {
	return map[string]string{
		"Authorization": "Klaviyo-API-Key " + apiKey,
		"revision":      Revision,
		"Accept":        "application/vnd.api+json",
		"Content-Type":  "application/vnd.api+json",
	}
}

func checkKey(apiKey string) error {
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("%w: blank API key", ErrInvalidArgument)
	}
	return nil
}

// CreateEvent records ev and creates or updates its profile.
func (c *Client) CreateEvent(ctx context.Context, apiKey string, ev Event) error {
	if err := checkKey(apiKey); err != nil {
		return err
	}
	p := ev.Profile
	switch {
	case strings.TrimSpace(ev.Metric) == "":
		return fmt.Errorf("%w: blank event metric", ErrInvalidArgument)
	case strings.TrimSpace(ev.UniqueID) == "":
		return fmt.Errorf("%w: blank event unique_id", ErrInvalidArgument)
	case p.Email == "" && p.PhoneNumber == "" && p.ExternalID == "":
		return fmt.Errorf("%w: profile has no email, phone number or external id", ErrInvalidArgument)
	case p.PhoneNumber != "" && !IsE164(p.PhoneNumber):
		return fmt.Errorf("%w: profile phone number is not E.164", ErrInvalidArgument)
	}
	properties := ev.Properties
	if properties == nil {
		properties = map[string]any{}
	}
	attributes := map[string]any{
		"properties": properties,
		"unique_id":  ev.UniqueID,
		"metric":     map[string]any{"data": map[string]any{"type": "metric", "attributes": map[string]any{"name": ev.Metric}}},
		"profile":    map[string]any{"data": map[string]any{"type": "profile", "attributes": p}},
	}
	if !ev.Time.IsZero() {
		attributes["time"] = ev.Time.UTC().Format(time.RFC3339)
	}
	payload := map[string]any{"data": map[string]any{"type": "event", "attributes": attributes}}
	if _, _, err := common.RequestJSON(ctx, http.MethodPost, c.base()+"/events/", headers(apiKey), payload); err != nil {
		return fmt.Errorf("klaviyo: create event %s: %w", ev.Metric, err)
	}
	return nil
}

// AccountCurrency is the account's preferred ISO 4217 currency, upper case.
func (c *Client) AccountCurrency(ctx context.Context, apiKey string) (string, error) {
	if err := checkKey(apiKey); err != nil {
		return "", err
	}
	var resp struct {
		Data []struct {
			Attributes struct {
				PreferredCurrency string `json:"preferred_currency"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.get(ctx, apiKey, c.base()+"/accounts/", &resp); err != nil {
		return "", err
	}
	if len(resp.Data) == 0 {
		return "", fmt.Errorf("%w: no account", ErrMalformedResponse)
	}
	code := strings.ToUpper(strings.TrimSpace(resp.Data[0].Attributes.PreferredCurrency))
	if len(code) != 3 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return "", fmt.Errorf("%w: account currency %q is not an ISO 4217 code", ErrMalformedResponse, code)
	}
	return code, nil
}

// MetricID finds a metric by its exact name; ErrNotFound when the account has none.
func (c *Client) MetricID(ctx context.Context, apiKey, name string) (string, error) {
	if err := checkKey(apiKey); err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: blank metric name", ErrInvalidArgument)
	}
	id := ""
	err := c.list(ctx, apiKey, "/metrics/?fields[metric]=name", func(itemID, itemName string) bool {
		if itemName == name {
			id = itemID
			return false
		}
		return true
	})
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("%w: metric %q", ErrNotFound, name)
	}
	return id, nil
}

// FlowNames maps every flow ID to its name.
func (c *Client) FlowNames(ctx context.Context, apiKey string) (map[string]string, error) {
	return c.names(ctx, apiKey, "/flows/?fields[flow]=name")
}

// CampaignNames maps every campaign ID on channel to its name; Klaviyo requires the channel.
func (c *Client) CampaignNames(ctx context.Context, apiKey, channel string) (map[string]string, error) {
	if strings.TrimSpace(channel) == "" || strings.ContainsAny(channel, "'()") {
		return nil, fmt.Errorf("%w: campaign channel %q", ErrInvalidArgument, channel)
	}
	return c.names(ctx, apiKey, "/campaigns/?fields[campaign]=name&filter="+url.QueryEscape("equals(messages.channel,'"+channel+"')"))
}

// FlowValues runs a flow values report; rows are grouped by flow_id, flow_message_id and send_channel.
func (c *Client) FlowValues(ctx context.Context, apiKey string, q ValuesQuery) ([]ValuesResult, error) {
	return c.values(ctx, apiKey, "flow-values-report", q)
}

// CampaignValues runs a campaign values report; rows are grouped by campaign_id, campaign_message_id and send_channel.
func (c *Client) CampaignValues(ctx context.Context, apiKey string, q ValuesQuery) ([]ValuesResult, error) {
	return c.values(ctx, apiKey, "campaign-values-report", q)
}

func (c *Client) values(ctx context.Context, apiKey, report string, q ValuesQuery) ([]ValuesResult, error) {
	if err := checkKey(apiKey); err != nil {
		return nil, err
	}
	timeframe, err := q.Timeframe.payload()
	if err != nil {
		return nil, err
	}
	if len(q.Statistics) == 0 || strings.TrimSpace(q.ConversionMetricID) == "" {
		return nil, fmt.Errorf("%w: %s needs statistics and a conversion metric", ErrInvalidArgument, report)
	}
	attributes := map[string]any{
		"statistics":           q.Statistics,
		"timeframe":            timeframe,
		"conversion_metric_id": q.ConversionMetricID,
	}
	if q.Filter != "" {
		attributes["filter"] = q.Filter
	}
	payload := map[string]any{"data": map[string]any{"type": report, "attributes": attributes}}
	body, _, err := common.RequestJSON(ctx, http.MethodPost, c.base()+"/"+report+"s/", headers(apiKey), payload)
	if err != nil {
		return nil, fmt.Errorf("klaviyo: %s: %w", report, err)
	}
	var resp struct {
		Data struct {
			Attributes struct {
				Results []struct {
					Groupings  map[string]string      `json:"groupings"`
					Statistics map[string]json.Number `json:"statistics"`
				} `json:"results"`
			} `json:"attributes"`
		} `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedResponse, report, err)
	}
	out := make([]ValuesResult, 0, len(resp.Data.Attributes.Results))
	for _, r := range resp.Data.Attributes.Results {
		stats := make(map[string]string, len(r.Statistics))
		for k, v := range r.Statistics {
			stats[k] = v.String()
		}
		out = append(out, ValuesResult{Groupings: r.Groupings, Statistics: stats})
	}
	return out, nil
}

func (t Timeframe) payload() (map[string]string, error) {
	switch {
	case t.Key != "" && t.Start.IsZero() && t.End.IsZero():
		return map[string]string{"key": t.Key}, nil
	case t.Key == "" && !t.Start.IsZero() && t.End.After(t.Start):
		return map[string]string{"start": t.Start.UTC().Format(time.RFC3339), "end": t.End.UTC().Format(time.RFC3339)}, nil
	}
	return nil, fmt.Errorf("%w: timeframe needs a key or a start before its end", ErrInvalidArgument)
}

func (c *Client) names(ctx context.Context, apiKey, first string) (map[string]string, error) {
	if err := checkKey(apiKey); err != nil {
		return nil, err
	}
	out := map[string]string{}
	err := c.list(ctx, apiKey, first, func(id, name string) bool {
		out[id] = name
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// list walks a JSON:API listing through links.next until visit returns false.
// A next link is followed only on the base URL's own origin, so a hostile
// response cannot redirect the API key elsewhere.
func (c *Client) list(ctx context.Context, apiKey, first string, visit func(id, name string) bool) error {
	origin, err := url.Parse(c.base())
	if err != nil {
		return fmt.Errorf("%w: base URL: %v", ErrInvalidArgument, err)
	}
	next := c.base() + first
	maxPages, maxItems, items := config.Config().OutboundMaxPages, config.Config().OutboundMaxItems, 0
	for range maxPages {
		var page struct {
			Data []struct {
				ID         string `json:"id"`
				Attributes struct {
					Name string `json:"name"`
				} `json:"attributes"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := c.get(ctx, apiKey, next, &page); err != nil {
			return err
		}
		items += len(page.Data)
		if items > maxItems {
			return fmt.Errorf("%w: %s after %d items", ErrTooManyItems, pathOf(first), maxItems)
		}
		for _, d := range page.Data {
			if !visit(d.ID, d.Attributes.Name) {
				return nil
			}
		}
		if page.Links.Next == "" {
			return nil
		}
		link, err := url.Parse(page.Links.Next)
		if err != nil || link.Scheme != origin.Scheme || link.Host != origin.Host {
			return fmt.Errorf("%w: next link leaves %s", ErrMalformedResponse, origin.Host)
		}
		next = link.String()
	}
	return fmt.Errorf("%w: %s after outbound_max_pages (%d)", ErrTooManyPages, pathOf(first), maxPages)
}

func (c *Client) get(ctx context.Context, apiKey, target string, into any) error {
	body, _, err := common.RequestJSON(ctx, http.MethodGet, target, headers(apiKey), nil)
	if err != nil {
		return fmt.Errorf("klaviyo: GET %s: %w", pathOf(target), err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%w: GET %s: %v", ErrMalformedResponse, pathOf(target), err)
	}
	return nil
}

func pathOf(target string) string {
	path, _, _ := strings.Cut(target, "?")
	return path
}
