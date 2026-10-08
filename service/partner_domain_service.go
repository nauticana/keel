package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/domain"
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

// PartnerDomainService reads a partner's domains and answers whether a URL
// belongs to them.
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
	names, err := s.Names(ctx, partnerID)
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if domain.CoveredBy(host, name) {
			return u.String(), nil
		}
	}
	return "", ErrURLNotOwned
}

// Names returns the partner's domains as normalized names (see
// domain.DomainName), primary first; ErrNoPartnerDomain when it has none.
func (s *PartnerDomainService) Names(ctx context.Context, partnerID int64) ([]string, error) {
	stored, err := s.list(ctx, partnerID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(stored))
	for _, d := range stored {
		if name, ok := domain.DomainName(d); ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, ErrNoPartnerDomain
	}
	return names, nil
}

// Primary returns the partner's primary domain as stored, or its first domain
// when none is marked primary; ErrNoPartnerDomain when it has none.
func (s *PartnerDomainService) Primary(ctx context.Context, partnerID int64) (string, error) {
	stored, err := s.list(ctx, partnerID)
	if err != nil {
		return "", err
	}
	return stored[0], nil
}

func (s *PartnerDomainService) list(ctx context.Context, partnerID int64) ([]string, error) {
	if partnerID <= 0 {
		return nil, ErrInvalidPartner
	}
	if s == nil || s.DB == nil {
		return nil, ErrDomainStore
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, partnerDomainQueries) })
	if s.qs == nil {
		return nil, ErrDomainStore
	}
	res, err := s.qs.Query(ctx, qPartnerDomains, partnerID)
	if err != nil {
		return nil, fmt.Errorf("partner domain: list for partner %d: %w", partnerID, err)
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoPartnerDomain
	}
	stored := make([]string, len(res.Rows))
	for i, row := range res.Rows {
		stored[i] = common.AsString(row[0])
	}
	return stored, nil
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
	host, ok := domain.ASCIIHost(u.Hostname())
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
