package reference

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
)

const (
	DefaultIndexNowEndpoint = "https://api.indexnow.org/indexnow"
	IndexNowMaxURLs         = 10000
)

var (
	ErrIndexNowBadRequest  = errors.New("reference: indexnow rejected the request format")
	ErrIndexNowKeyInvalid  = errors.New("reference: indexnow key not valid for the host")
	ErrIndexNowURLMismatch = errors.New("reference: indexnow urls do not belong to the host or the key file does not match")
	ErrIndexNowRateLimited = errors.New("reference: indexnow rate limited")
	// ErrIndexNowKeyNotServed: IndexNow will refuse every submission for the host.
	ErrIndexNowKeyNotServed = errors.New("reference: indexnow key file is not served by the host")
)

// IndexNowClient notifies IndexNow search engines of changed URLs. The key must
// also be served by the host, at /<key>.txt or at KeyLocation.
type IndexNowClient struct {
	APIKey
	Endpoint    string // empty = DefaultIndexNowEndpoint
	KeyLocation string // empty = the protocol default https://<host>/<key>.txt
}

type indexNowRequest struct {
	Host        string   `json:"host"`
	Key         string   `json:"key"`
	KeyLocation string   `json:"keyLocation,omitempty"`
	URLList     []string `json:"urlList"`
}

// Submit posts urls for host in batches of IndexNowMaxURLs and stops at the
// first failed batch.
func (c *IndexNowClient) Submit(ctx context.Context, host string, urls []string) error {
	if host == "" {
		return fmt.Errorf("reference: indexnow host required")
	}
	if len(urls) == 0 {
		return nil
	}
	key, err := c.value(ctx)
	if err != nil {
		return err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultIndexNowEndpoint
	}
	for start := 0; start < len(urls); start += IndexNowMaxURLs {
		batch := urls[start:min(start+IndexNowMaxURLs, len(urls))]
		payload := indexNowRequest{Host: host, Key: key, KeyLocation: c.KeyLocation, URLList: batch}
		if _, _, err := common.RequestJSON(ctx, http.MethodPost, endpoint, nil, payload); err != nil {
			return indexNowError(err)
		}
	}
	return nil
}

// VerifyKeyFile reads the key file back from host and compares it to the key.
// A missing or mismatched file, or a KeyLocation on another host, is
// ErrIndexNowKeyNotServed; a transient failure is not, so a caller never
// records an outage as a verdict.
func (c *IndexNowClient) VerifyKeyFile(ctx context.Context, host string) error {
	if host == "" {
		return fmt.Errorf("reference: indexnow host required")
	}
	key, err := c.value(ctx)
	if err != nil {
		return err
	}
	location, err := c.keyFileURL(host, key)
	if err != nil {
		return err
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet, location, map[string]string{"Accept": "text/plain, */*"}, nil)
	if err != nil {
		var status *common.HTTPStatusError
		if errors.As(err, &status) && status.Permanent() {
			return fmt.Errorf("%w: %s: http status %d", ErrIndexNowKeyNotServed, host, status.Status)
		}
		return fmt.Errorf("reference: indexnow key file of %s: %w", host, withoutRequestURL(err))
	}
	// Whitespace only: verifying more leniently than IndexNow would pass a host it refuses.
	if strings.TrimSpace(string(body)) != key {
		return fmt.Errorf("%w: %s serves a different key", ErrIndexNowKeyNotServed, host)
	}
	return nil
}

func (c *IndexNowClient) keyFileURL(host, key string) (string, error) {
	if c.KeyLocation == "" {
		return "https://" + host + "/" + url.PathEscape(key) + ".txt", nil
	}
	parsed, err := url.Parse(c.KeyLocation)
	if err != nil || !strings.EqualFold(parsed.Host, host) {
		return "", fmt.Errorf("%w: key location is not on %s", ErrIndexNowKeyNotServed, host)
	}
	return c.KeyLocation, nil
}

// withoutRequestURL keeps the key, part of the default key file URL, out of error text.
func withoutRequestURL(err error) error {
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		return requestErr.Err
	}
	return err
}

func indexNowError(err error) error {
	sentinel := map[int]error{
		http.StatusBadRequest:          ErrIndexNowBadRequest,
		http.StatusForbidden:           ErrIndexNowKeyInvalid,
		http.StatusUnprocessableEntity: ErrIndexNowURLMismatch,
		http.StatusTooManyRequests:     ErrIndexNowRateLimited,
	}[common.HTTPStatus(err)]
	if sentinel == nil {
		return fmt.Errorf("reference: indexnow: %w", err)
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}
