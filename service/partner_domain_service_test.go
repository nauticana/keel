package service

import (
	"context"
	"errors"
	"testing"
)

func ownsService(domains ...string) (*PartnerDomainService, *quotaFakeQS) {
	qs := newQuotaFakeQS()
	for _, d := range domains {
		qs.rows[qPartnerDomains] = append(qs.rows[qPartnerDomains], []any{d})
	}
	return &PartnerDomainService{DB: &quotaFakeRepo{qs: qs}}, qs
}

func TestPartnerDomainOwns(t *testing.T) {
	s, qs := ownsService("HTTPS://www.Example.com/", "shop.example.org.")
	for raw, want := range map[string]string{
		"https://example.com/a?b=1#frag":   "https://example.com/a?b=1",
		"HTTP://WWW.EXAMPLE.COM:8080/x":    "http://www.example.com:8080/x",
		"https://blog.example.com.":        "https://blog.example.com",
		"  https://shop.example.org/cart ": "https://shop.example.org/cart",
	} {
		got, err := s.Owns(context.Background(), 5, raw)
		if err != nil || got != want {
			t.Errorf("Owns(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if qs.calls[0].args[0] != int64(5) {
		t.Fatalf("queried partner %v", qs.calls[0].args)
	}
}

func TestPartnerDomainRefuses(t *testing.T) {
	s, _ := ownsService("example.com", "localhost")
	for raw, want := range map[string]error{
		"https://evilexample.com/":      ErrURLNotOwned,
		"https://example.com.evil.net/": ErrURLNotOwned,
		"https://example.org/":          ErrURLNotOwned,
		"http://localhost/":             ErrURLNotOwned,
		"https://example.com@evil.net/": ErrInvalidURL,
		"https://user:pw@example.com/":  ErrInvalidURL,
		"ftp://example.com/":            ErrInvalidURL,
		"javascript:alert(1)":           ErrInvalidURL,
		"example.com/path":              ErrInvalidURL,
		"//example.com/":                ErrInvalidURL,
		"https:///nohost":               ErrInvalidURL,
		"https://exаmple.com/":          ErrURLNotOwned, // Cyrillic а
		"https://%zz/":                  ErrInvalidURL,
		"":                              ErrInvalidURL,
	} {
		if _, err := s.Owns(context.Background(), 5, raw); !errors.Is(err, want) {
			t.Errorf("Owns(%q) = %v, want %v", raw, err, want)
		}
	}
	if _, err := s.Owns(context.Background(), 0, "https://example.com/"); !errors.Is(err, ErrInvalidPartner) {
		t.Fatalf("zero partner: %v", err)
	}

	none, _ := ownsService()
	if _, err := none.Owns(context.Background(), 5, "https://example.com/"); !errors.Is(err, ErrNoPartnerDomain) {
		t.Fatalf("no domains: %v", err)
	}

	broken, qs := ownsService("example.com")
	qs.errs[qPartnerDomains] = errors.New("db down")
	if _, err := broken.Owns(context.Background(), 5, "https://example.com/"); !errors.Is(err, qs.errs[qPartnerDomains]) {
		t.Fatalf("db error not surfaced: %v", err)
	}
	if _, err := (&PartnerDomainService{}).Owns(context.Background(), 5, "https://example.com/"); !errors.Is(err, ErrDomainStore) {
		t.Fatalf("zero service: %v", err)
	}
}
