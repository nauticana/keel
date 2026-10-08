package domain

import "testing"

func TestDomainFromEmail(t *testing.T) {
	for in, want := range map[string]string{
		"a@Example.com": "example.com", "x": "", "a@": "", " a@ex.io ": "ex.io",
	} {
		if got := DomainFromEmail(in); got != want {
			t.Errorf("DomainFromEmail(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHostFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.Example.com/path?x=1": "example.com",
		"http://Example.com:8080":          "example.com",
		"shop.example.co.uk/a":             "shop.example.co.uk",
		"":                                 "",
	} {
		if got := HostFromURL(in); got != want {
			t.Errorf("HostFromURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRegistrableDomainAndMatch(t *testing.T) {
	if got := RegistrableDomain("https://shop.example.co.uk/x"); got != "example.co.uk" {
		t.Errorf("RegistrableDomain=%q", got)
	}
	if !DomainsMatch("https://a.example.com", "b.example.com/p") {
		t.Error("same eTLD+1 should match")
	}
	if DomainsMatch("example.com", "example.org") {
		t.Error("different domains should not match")
	}
}

func TestIsPublicDomain(t *testing.T) {
	if !IsPublicDomain("Gmail.com") {
		t.Error("gmail should be public")
	}
	if IsPublicDomain("example.com") || IsPublicDomain("") {
		t.Error("custom/empty should not be public")
	}
}

func TestHostFromURLTrailingDot(t *testing.T) {
	for _, raw := range []string{"example.com.", "https://www.example.com./path", "example.com.:8443"} {
		if got := HostFromURL(raw); got != "example.com" {
			t.Errorf("HostFromURL(%q) = %q, want example.com", raw, got)
		}
	}
	if !DomainsMatch("example.com.", "example.com") {
		t.Error("trailing dot should not defeat DomainsMatch")
	}
}

func TestIsPublicDomainCoversMajorProviders(t *testing.T) {
	for _, d := range []string{"gmail.com", "yahoo.co.uk", "outlook.com", "icloud.com", "proton.me", "GMX.net"} {
		if !IsPublicDomain(d) {
			t.Errorf("IsPublicDomain(%q) = false, want true", d)
		}
	}
	if IsPublicDomain("rinovapergola.com") {
		t.Error("a custom domain must not be classified public")
	}
}

func TestDomainNameNormalizes(t *testing.T) {
	for in, want := range map[string]string{
		"Example.com":                    "example.com",
		"https://www.Example.com/path":   "example.com",
		"http://shop.example.co.uk:8080": "shop.example.co.uk",
		"bücher.de":                      "xn--bcher-kva.de",
		"example.com.":                   "example.com",
	} {
		if got, ok := DomainName(in); !ok || got != want {
			t.Errorf("DomainName(%q) = %q, %v want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "localhost", "127.0.0.1", "[2001:db8::1]", "ftp://example.com", "https://user:pw@example.com", "mailto:a@example.com"} {
		if got, ok := DomainName(in); ok {
			t.Errorf("DomainName(%q) = %q, want refusal", in, got)
		}
	}
}

func TestASCIIHost(t *testing.T) {
	if got, ok := ASCIIHost("BÜCHER.de."); !ok || got != "xn--bcher-kva.de" {
		t.Fatalf("ASCIIHost = %q, %v", got, ok)
	}
	if _, ok := ASCIIHost(""); ok {
		t.Fatal("empty host must be refused")
	}
}

func TestCoveredBy(t *testing.T) {
	for _, c := range []struct {
		name, parent string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"shop.example.com", "Example.COM.", true},
		{"evilexample.com", "example.com", false},
		{"example.com.evil.net", "example.com", false},
		{"example.com", "", false},
		{"example.com", "shop.example.com", false},
	} {
		if got := CoveredBy(c.name, c.parent); got != c.want {
			t.Errorf("CoveredBy(%q, %q) = %v, want %v", c.name, c.parent, got, c.want)
		}
	}
}
