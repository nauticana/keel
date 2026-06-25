package common

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// publicEmailDomains are free consumer mailboxes — a login from one proves no
// custom-domain ownership. Extend as needed.
var publicEmailDomains = map[string]bool{
	"gmail.com":      true,
	"googlemail.com": true,
}

// DomainFromEmail returns the lowercased domain part of an email, or "".
func DomainFromEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}

// HostFromURL returns a URL's lowercased host (no scheme, leading "www.", port, or path).
func HostFromURL(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "www.")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

// RegistrableDomain returns the eTLD+1 of a host/URL (shop.example.co.uk → example.co.uk).
func RegistrableDomain(hostOrURL string) string {
	h := HostFromURL(hostOrURL)
	if h == "" {
		return ""
	}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return reg
	}
	return h
}

// DomainsMatch reports whether two hosts share the same registrable domain.
func DomainsMatch(a, b string) bool {
	ra := RegistrableDomain(a)
	return ra != "" && ra == RegistrableDomain(b)
}

// IsPublicDomain reports whether a domain is a free/public email provider
// (gmail, …). The inverse — owning a custom domain — is !IsPublicDomain on a
// non-empty domain.
func IsPublicDomain(domain string) bool {
	return publicEmailDomains[strings.ToLower(strings.TrimSpace(domain))]
}
