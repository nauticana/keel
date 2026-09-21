package reference

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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
