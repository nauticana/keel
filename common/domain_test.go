package common

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
