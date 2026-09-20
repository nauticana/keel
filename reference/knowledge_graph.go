package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
)

const DefaultKGEndpoint = "https://kgsearch.googleapis.com/v1/entities:search"

// KGMatch is the top Knowledge Graph result; MID is empty when nothing matched.
type KGMatch struct {
	MID         string // bare machine id, e.g. /m/0dl567
	Name        string
	Types       []string // Schema.org types
	Description string
	URL         string
	// Score is KG's unbounded log-scale resultScore: rank candidates with it,
	// never threshold it.
	Score float64
}

// KGClient searches the Google Knowledge Graph.
type KGClient struct {
	APIKey
	Endpoint string // empty = DefaultKGEndpoint
}

// FindEntity returns the best match for query, optionally restricted to
// Schema.org types. No match is an empty KGMatch, not an error.
func (c *KGClient) FindEntity(ctx context.Context, query string, types []string) (KGMatch, error) {
	headers, err := c.headers(ctx)
	if err != nil {
		return KGMatch{}, err
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return KGMatch{}, nil
	}
	params := url.Values{"query": {query}, "limit": {"5"}, "languages": {"en"}, "types": types}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultKGEndpoint
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet, endpoint+"?"+params.Encode(), headers, nil)
	if err != nil {
		return KGMatch{}, fmt.Errorf("kg: %w", err)
	}
	var resp struct {
		ItemListElement []struct {
			ResultScore float64 `json:"resultScore"`
			Result      struct {
				ID                  string   `json:"@id"`
				Name                string   `json:"name"`
				Type                []string `json:"@type"`
				URL                 string   `json:"url"`
				Description         string   `json:"description"`
				DetailedDescription struct {
					ArticleBody string `json:"articleBody"`
				} `json:"detailedDescription"`
			} `json:"result"`
		} `json:"itemListElement"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return KGMatch{}, fmt.Errorf("kg: decode: %w", err)
	}
	if len(resp.ItemListElement) == 0 {
		return KGMatch{}, nil
	}
	top := resp.ItemListElement[0]
	description := top.Result.Description
	if description == "" {
		description = top.Result.DetailedDescription.ArticleBody
	}
	return KGMatch{
		MID:         strings.TrimPrefix(top.Result.ID, "kg:"),
		Name:        top.Result.Name,
		Types:       top.Result.Type,
		Description: description,
		URL:         top.Result.URL,
		Score:       top.ResultScore,
	}, nil
}
