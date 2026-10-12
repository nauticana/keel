package meta

import (
	"context"
	"net/url"
)

// AdAccount is one ad account the grant reaches. AccountID has no "act_" prefix.
type AdAccount struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Currency  string `json:"currency"`
}

// AdAccounts lists the ad accounts the user token reaches.
func (c *Client) AdAccounts(ctx context.Context, token string) ([]AdAccount, error) {
	return list[AdAccount](ctx, c, "ad accounts", token, "/me/adaccounts", url.Values{"fields": {"account_id,name,currency"}})
}
