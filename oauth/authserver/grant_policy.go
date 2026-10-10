package authserver

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nauticana/keel/port"
)

// grantPolicy bounds a user's standing grants: a new grant replaces the
// user's grants to other registrations of the same app, and the user holds at
// most maxPerUser grants.
type grantPolicy struct {
	clients        port.OAuthClientStore
	tokens         port.OAuthTokenStore
	replaceSameApp bool
	maxPerUser     int
}

// others splits the user's live grants to clients other than client into
// those of the same app and the rest. Without replaceSameApp every grant is
// in the rest.
func (p *grantPolicy) others(ctx context.Context, userID int64, client *port.OAuthClient) (sameApp, rest []string, err error) {
	ids, err := p.tokens.GrantClients(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	hosts := appHosts(client)
	for _, id := range ids {
		if id == client.ClientID {
			continue
		}
		if p.replaceSameApp && len(hosts) > 0 {
			other, err := p.clients.GetClient(ctx, id)
			if err != nil {
				return nil, nil, err
			}
			if other != nil && slices.ContainsFunc(appHosts(other), func(h string) bool { return slices.Contains(hosts, h) }) {
				sameApp = append(sameApp, id)
				continue
			}
		}
		rest = append(rest, id)
	}
	return sameApp, rest, nil
}

// admit refuses an authorization that would take the user past maxPerUser.
func (p *grantPolicy) admit(ctx context.Context, userID int64, client *port.OAuthClient) error {
	if p.maxPerUser <= 0 || !slices.Contains(client.GrantTypes, "refresh_token") {
		return nil
	}
	_, rest, err := p.others(ctx, userID, client)
	if err != nil {
		return err
	}
	return p.capped(rest, ErrOAuthAccessDenied)
}

// redeem rechecks the cap, since grants may have changed since the code was
// issued, and revokes the user's grants to other registrations of client's app.
func (p *grantPolicy) redeem(ctx context.Context, userID int64, client *port.OAuthClient) error {
	if !p.replaceSameApp && p.maxPerUser <= 0 {
		return nil
	}
	sameApp, rest, err := p.others(ctx, userID, client)
	if err != nil {
		return err
	}
	if p.maxPerUser > 0 {
		if err := p.capped(rest, ErrOAuthInvalidGrant); err != nil {
			return err
		}
	}
	for _, id := range sameApp {
		if err := p.tokens.RevokeGrant(ctx, userID, id); err != nil {
			return err
		}
	}
	return nil
}

func (p *grantPolicy) capped(rest []string, code oauthErr) error {
	if len(rest) < p.maxPerUser {
		return nil
	}
	return describedErr{code, "this account has authorized " + strconv.Itoa(len(rest)) + " apps, the most it may; disconnect one first"}
}

// appHosts are the lowercase redirect hosts that identify a client's app.
// Loopback hosts are shared by every native app, so they identify none.
func appHosts(c *port.OAuthClient) []string {
	var out []string
	for _, raw := range c.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
			continue
		}
		if !slices.Contains(out, host) {
			out = append(out, host)
		}
	}
	return out
}
