package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

var (
	ErrInvalidURL      = errors.New("partner domain: URL must be an absolute http(s) URL without credentials")
	ErrInvalidPartner  = errors.New("partner domain: partner ID must be positive")
	ErrNoPartnerDomain = errors.New("partner domain: partner has no domain")
	ErrURLNotOwned     = errors.New("partner domain: URL is outside the partner's domains")
	ErrDomainStore     = errors.New("partner domain: no database configured")
)

const qPartnerDomains = "partner_domain_list"

var partnerDomainQueries = map[string]string{
	qPartnerDomains: "SELECT domain_url FROM partner_domain WHERE partner_id = ? ORDER BY is_primary DESC, domain_url",
}

// PartnerDomainService answers whether a URL belongs to a partner's domains.
type PartnerDomainService struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

// Owns returns rawURL normalized (lowercase scheme and host, no fragment) when
// its host is one of the partner's domains or a subdomain of one; a leading
// "www." on a stored domain is ignored.
func (s *PartnerDomainService) Owns(ctx context.Context, partnerID int64, rawURL string) (string, error) {
	if partnerID <= 0 {
		return "", ErrInvalidPartner
	}
	u, host, err := parseHTTPURL(rawURL)
	if err != nil {
		return "", err
	}
	if s == nil || s.DB == nil {
		return "", ErrDomainStore
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, partnerDomainQueries) })
	if s.qs == nil {
		return "", ErrDomainStore
	}
	res, err := s.qs.Query(ctx, qPartnerDomains, partnerID)
	if err != nil {
		return "", fmt.Errorf("partner domain: list for partner %d: %w", partnerID, err)
	}
	if len(res.Rows) == 0 {
		return "", ErrNoPartnerDomain
	}
	for _, row := range res.Rows {
		domain, ok := domainHost(common.AsString(row[0]))
		if ok && (host == domain || strings.HasSuffix(host, "."+domain)) {
			return u.String(), nil
		}
	}
	return "", ErrURLNotOwned
}

func parseHTTPURL(rawURL string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.User != nil || u.Opaque != "" {
		return nil, "", ErrInvalidURL
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", ErrInvalidURL
	}
	host, ok := asciiHost(u.Hostname())
	if !ok {
		return nil, "", ErrInvalidURL
	}
	if port := u.Port(); port != "" {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
	u.Fragment, u.RawFragment = "", ""
	return u, host, nil
}

// domainHost reduces a stored domain_url ("Example.com", "https://www.example.com/")
// to its comparable host.
func domainHost(domainURL string) (string, bool) {
	u, err := url.Parse(common.WithScheme(strings.ToLower(strings.TrimSpace(domainURL))))
	if err != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	host, ok := asciiHost(u.Hostname())
	if !ok {
		return "", false
	}
	host = strings.TrimPrefix(host, "www.")
	return host, strings.Contains(host, ".")
}

// asciiHost lowercases, drops a trailing dot and maps IDNs to punycode, so
// look-alike spellings compare equal only when they are the same name.
func asciiHost(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", false
	}
	return ascii, true
}
