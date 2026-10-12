// Package meta is a transport client for Meta's Graph API: ad accounts,
// insights, Pages with their tokens, Instant Form leads, ad creative and the
// Conversions API. Each call carries the token that authorizes it: the
// partner's user token for ad accounts, a Page token for that Page's leads.
package meta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

const (
	APIBaseURL = "https://graph.facebook.com"
	APIVersion = "v23.0"
	pageSize   = "100"
)

// Client is one Graph API version. outbound_max_pages and outbound_max_items
// bound every paged read; one that would exceed either fails with ErrPageLimit.
type Client struct {
	BaseURL string
	Version string
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

// endpoint builds a Graph URL. Credentials travel only in the Authorization
// header, never in URLs that may be logged by proxies or tracing.
func (c *Client) endpoint(token, path string, params url.Values) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", ErrNoAccessToken
	}
	if params == nil {
		params = url.Values{}
	}
	target := c.base() + path
	if query := params.Encode(); query != "" {
		target += "?" + query
	}
	return target, nil
}

func (c *Client) do(ctx context.Context, op, method, token, target string, payload any) ([]byte, error) {
	body, _, err := common.RequestJSON(ctx, method, target, map[string]string{"Authorization": "Bearer " + token}, payload)
	if err != nil {
		return nil, wrapError(op, err)
	}
	return body, nil
}

// object reads one Graph node into out.
func (c *Client) object(ctx context.Context, op, token, path string, params url.Values, out any) error {
	target, err := c.endpoint(token, path, params)
	if err != nil {
		return err
	}
	body, err := c.do(ctx, op, http.MethodGet, token, target, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("meta: decode %s: %w", op, err)
	}
	return nil
}

// list follows a Graph edge's cursor pages and decodes every item into T.
// A next link must stay on the client's own host, so the token is never sent
// elsewhere.
func list[T any](ctx context.Context, c *Client, op, token, path string, params url.Values) ([]T, error) {
	maxPages, maxItems := config.Config().OutboundMaxPages, config.Config().OutboundMaxItems
	if params == nil {
		params = url.Values{}
	}
	if params.Get("limit") == "" {
		params.Set("limit", pageSize)
	}
	next, err := c.endpoint(token, path, params)
	if err != nil {
		return nil, err
	}
	var out []T
	for range maxPages {
		body, err := c.do(ctx, op, http.MethodGet, token, next, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Data   []T `json:"data"`
			Paging struct {
				Next string `json:"next"`
			} `json:"paging"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("meta: decode %s: %w", op, err)
		}
		out = append(out, page.Data...)
		if len(out) > maxItems {
			return nil, fmt.Errorf("%w: %s has more than %d items", ErrPageLimit, op, maxItems)
		}
		if page.Paging.Next == "" || len(page.Data) == 0 {
			return out, nil
		}
		if next, err = c.nextPage(page.Paging.Next); err != nil {
			return nil, fmt.Errorf("meta: %s: %w", op, err)
		}
	}
	return nil, fmt.Errorf("%w: %s has more than %d pages", ErrPageLimit, op, maxPages)
}

func (c *Client) nextPage(next string) (string, error) {
	base, err := url.Parse(c.base())
	if err != nil {
		return "", err
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
		return "", ErrForeignPagingURL
	}
	q := u.Query()
	q.Del("access_token")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// graphID accepts a numeric Graph id, so a caller-supplied id cannot change
// the request path.
func graphID(kind, id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.Trim(id, "0123456789") != "" {
		return "", fmt.Errorf("%w: %s %q", ErrInvalidID, kind, id)
	}
	return id, nil
}

// wrapError maps a RequestJSON failure without letting the token out: a
// status error becomes an *APIError, and a transport error loses the query.
func wrapError(op string, err error) error {
	var se *common.HTTPStatusError
	if errors.As(err, &se) {
		apiErr := newAPIError(se)
		if errors.Is(err, common.ErrResponseTooLarge) {
			return fmt.Errorf("meta: %s: %w", op, errors.Join(apiErr, common.ErrResponseTooLarge))
		}
		return fmt.Errorf("meta: %s: %w", op, apiErr)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("meta: %s: %w", op, &url.Error{Op: ue.Op, URL: redactURL(ue.URL), Err: ue.Err})
	}
	return fmt.Errorf("meta: %s: %w", op, err)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted]"
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}
