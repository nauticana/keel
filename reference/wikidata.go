package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
)

const (
	DefaultWikidataEndpoint = "https://www.wikidata.org/w/api.php"
	wikidataSearchLimit     = 5
)

// ErrNoUserAgent: Wikimedia requires API consumers to identify themselves.
var ErrNoUserAgent = errors.New("reference: wikidata client needs a UserAgent")

// WikidataMatch is the top search result; QID is empty when nothing matched.
type WikidataMatch struct {
	QID         string
	Label       string
	Description string
	URL         string
	// Confidence is 1/candidates (floor 1/wikidataSearchLimit): the search is
	// string-matched, so more candidates means a more ambiguous name.
	Confidence float64
}

// WikidataClient searches Wikidata entities by name; the API needs no key.
type WikidataClient struct {
	UserAgent string // e.g. "AppName/1.0 (https://app.example; ops@app.example)"
	Endpoint  string // empty = DefaultWikidataEndpoint
}

// FindEntity returns the top candidate for name. No match is an empty
// WikidataMatch, not an error.
func (c *WikidataClient) FindEntity(ctx context.Context, name string) (WikidataMatch, error) {
	if c.UserAgent == "" {
		return WikidataMatch{}, ErrNoUserAgent
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return WikidataMatch{}, nil
	}
	params := url.Values{
		"action": {"wbsearchentities"}, "search": {name}, "language": {"en"}, "uselang": {"en"},
		"type": {"item"}, "limit": {fmt.Sprint(wikidataSearchLimit)}, "format": {"json"},
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultWikidataEndpoint
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet, endpoint+"?"+params.Encode(),
		map[string]string{"User-Agent": c.UserAgent}, nil)
	if err != nil {
		return WikidataMatch{}, fmt.Errorf("wikidata: %w", err)
	}
	var resp struct {
		Search []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			Description string `json:"description"`
			ConceptURI  string `json:"concepturi"`
		} `json:"search"`
		// The action API reports failures in a 200 body.
		Error *struct {
			Code string `json:"code"`
			Info string `json:"info"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return WikidataMatch{}, fmt.Errorf("wikidata: decode: %w", err)
	}
	if resp.Error != nil {
		return WikidataMatch{}, fmt.Errorf("wikidata: %s: %s", resp.Error.Code, resp.Error.Info)
	}
	if len(resp.Search) == 0 {
		return WikidataMatch{}, nil
	}
	top := resp.Search[0]
	return WikidataMatch{
		QID:         top.ID,
		Label:       top.Label,
		Description: top.Description,
		URL:         top.ConceptURI,
		Confidence:  max(1/float64(len(resp.Search)), 1.0/wikidataSearchLimit),
	}, nil
}
