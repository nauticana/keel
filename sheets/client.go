// Package sheets reads and writes Google Sheets cell values over the Sheets API
// v4 with a caller-supplied OAuth access token.
package sheets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
)

const APIBaseURL = "https://sheets.googleapis.com/v4"

// Client is safe for concurrent use; the zero value calls APIBaseURL. Responses
// are bounded by outbound_max_response_size and non-2xx statuses surface as
// *common.HTTPStatusError.
type Client struct {
	BaseURL string
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return APIBaseURL
}

func (c *Client) spreadsheetURL(spreadsheetID string) string {
	return c.base() + "/spreadsheets/" + url.PathEscape(spreadsheetID)
}

func (c *Client) valuesURL(spreadsheetID, a1Range string) string {
	return c.spreadsheetURL(spreadsheetID) + "/values/" + url.PathEscape(a1Range)
}

func authorization(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func validate(token, spreadsheetID string, a1Ranges ...string) error {
	switch {
	case strings.TrimSpace(token) == "":
		return fmt.Errorf("%w: blank access token", ErrInvalidArgument)
	case strings.TrimSpace(spreadsheetID) == "":
		return fmt.Errorf("%w: blank spreadsheet ID", ErrInvalidArgument)
	}
	for i, a1 := range a1Ranges {
		if strings.TrimSpace(a1) == "" {
			return fmt.Errorf("%w: blank range at %d", ErrInvalidArgument, i)
		}
	}
	return nil
}

// Read returns the rows of an A1 range as displayed; short rows are not padded.
// QuoteSheet(sheet) reads the whole sheet.
func (c *Client) Read(ctx context.Context, token, spreadsheetID, a1Range string) ([][]string, error) {
	if err := validate(token, spreadsheetID, a1Range); err != nil {
		return nil, err
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet,
		c.valuesURL(spreadsheetID, a1Range)+"?majorDimension=ROWS&valueRenderOption=FORMATTED_VALUE", authorization(token), nil)
	if err != nil {
		return nil, fmt.Errorf("sheets: read %s: %w", a1Range, err)
	}
	var resp struct {
		Values [][]string `json:"values"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrMalformedResponse, a1Range, err)
	}
	return resp.Values, nil
}

// Write sets each cell as entered text, never as a formula, in one batch.
func (c *Client) Write(ctx context.Context, token, spreadsheetID string, cells []Cell) error {
	if len(cells) == 0 {
		return nil
	}
	data := make([]map[string]any, 0, len(cells))
	ranges := make([]string, 0, len(cells))
	for _, cell := range cells {
		ranges = append(ranges, cell.A1)
		data = append(data, map[string]any{"range": cell.A1, "values": [][]string{{cell.Value}}})
	}
	if err := validate(token, spreadsheetID, ranges...); err != nil {
		return err
	}
	_, _, err := common.RequestJSON(ctx, http.MethodPost, c.spreadsheetURL(spreadsheetID)+"/values:batchUpdate",
		authorization(token), map[string]any{"valueInputOption": "RAW", "data": data})
	if err != nil {
		return fmt.Errorf("sheets: write %d cells: %w", len(cells), err)
	}
	return nil
}

// Append inserts rows as entered text after the last row of the table at a1Range.
func (c *Client) Append(ctx context.Context, token, spreadsheetID, a1Range string, rows [][]string) error {
	if len(rows) == 0 {
		return nil
	}
	if err := validate(token, spreadsheetID, a1Range); err != nil {
		return err
	}
	_, _, err := common.RequestJSON(ctx, http.MethodPost,
		c.valuesURL(spreadsheetID, a1Range)+":append?valueInputOption=RAW&insertDataOption=INSERT_ROWS",
		authorization(token), map[string]any{"values": rows})
	if err != nil {
		return fmt.Errorf("sheets: append %d rows to %s: %w", len(rows), a1Range, err)
	}
	return nil
}
