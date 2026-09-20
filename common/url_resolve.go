package common

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const dnsLookupTimeout = 3 * time.Second

var ErrHostUnresolvable = errors.New("host does not resolve")

// WithScheme prepends https:// to a bare host, which url.Parse would otherwise
// read as a path with an empty hostname.
func WithScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://" + u
}

// ResolveURL returns rawURL when its host has DNS records, else the www.
// variant when that resolves (usedWWW = true), else ErrHostUnresolvable.
func ResolveURL(ctx context.Context, rawURL string) (resolved string, usedWWW bool, err error) {
	return resolveURL(ctx, rawURL, net.DefaultResolver.LookupHost)
}

type hostLookup func(ctx context.Context, host string) ([]string, error)

func resolveURL(ctx context.Context, rawURL string, lookup hostLookup) (string, bool, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", false, fmt.Errorf("parse %q: %w", rawURL, err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", false, fmt.Errorf("no host in URL %q", rawURL)
	}
	apexErr := hostResolves(ctx, host, lookup)
	if apexErr == nil {
		return rawURL, false, nil
	}
	if strings.HasPrefix(host, "www.") {
		return "", false, fmt.Errorf("%w: %q: %v", ErrHostUnresolvable, host, apexErr)
	}
	www := *parsed
	www.Host = "www." + parsed.Host
	if wwwErr := hostResolves(ctx, www.Hostname(), lookup); wwwErr != nil {
		return "", false, fmt.Errorf("%w: %q (%v) and its www. variant (%v)", ErrHostUnresolvable, host, apexErr, wwwErr)
	}
	return www.String(), true, nil
}

func hostResolves(ctx context.Context, host string, lookup hostLookup) error {
	ctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	addrs, err := lookup(ctx, host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses for %q", host)
	}
	return nil
}
