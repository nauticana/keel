package domain

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

func notProven(err error) bool { return errors.Is(err, ErrDomainNotProven) }

type mxResolver map[string][]*net.MX

func (r mxResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if mx, ok := r[name]; ok {
		return mx, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestGoogleMXMatchesWholeLabels(t *testing.T) {
	v := &GoogleMXVerifier{Resolver: mxResolver{
		"example.com": {{Host: "ASPMX.L.GOOGLE.COM."}},
		"evil.com":    {{Host: "mx.evilgoogle.com."}},
		"self.com":    {{Host: "mail.self.com."}},
	}}
	proof := func(email, domain string, verified bool) DomainProof {
		return DomainProof{Email: email, EmailVerified: verified, Domain: domain}
	}
	if ref, err := v.Verify(context.Background(), proof("a@example.com", "shop.example.com", true)); err != nil || ref != "example.com" {
		t.Fatalf("Google MX = %q, %v", ref, err)
	}
	for _, p := range []DomainProof{
		proof("a@evil.com", "evil.com", true),
		proof("a@self.com", "self.com", true),
		proof("a@example.com", "example.com", false),
		proof("a@gmail.com", "gmail.com", true),
		proof("a@missing.com", "missing.com", true),
		proof("a@example.com", "other.com", true),
	} {
		if _, err := v.Verify(context.Background(), p); !notProven(err) {
			t.Errorf("%+v: %v", p, err)
		}
	}
}

func TestGoogleHDCoversDomainAndSubdomains(t *testing.T) {
	v := GoogleHDVerifier{}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "shop.example.com", HostedDomain: "Example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, hd := range []string{"", "ample.com", "shop.example.com.evil"} {
		if _, err := v.Verify(context.Background(), DomainProof{Domain: "example.com", HostedDomain: hd}); !notProven(err) {
			t.Errorf("hd %q: %v", hd, err)
		}
	}
}

func TestDNSTXTNeedsTheIssuedToken(t *testing.T) {
	hash := common.Sha256Hex("tok")
	v := &DNSTXTVerifier{Resolver: txtResolver{"example.com": {TXTValue("other"), "tok", "x" + TXTValue("tok")}}}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "example.com", TokenHash: hash}); !notProven(err) {
		t.Fatalf("token without its label: %v", err)
	}
	v.Resolver = txtResolver{"example.com": {" " + TXTValue("tok") + " "}}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "example.com", TokenHash: hash}); err != nil {
		t.Fatal(err)
	}
}

// fileServer serves FileURL for any host through one TLS listener.
func fileServer(t *testing.T, h http.HandlerFunc) *http.Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: transport}
}

func TestHTTPFileVerifier(t *testing.T) {
	hash := common.Sha256Hex("tok")
	proof := DomainProof{Domain: "example.com", TokenHash: hash}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		check   func(error) bool
	}{
		{"served", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/"+strings.TrimPrefix(FileURL("x.y"), "https://x.y/.well-known/") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprint(w, "tok\n")
		}, func(err error) bool { return err == nil }},
		{"other token", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "nope") }, notProven},
		{"too large", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "tok"+strings.Repeat(" ", httpFileMaxBytes))
		}, notProven},
		{"missing", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, notProven},
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			func(err error) bool { return err != nil && !notProven(err) }},
		{"redirect to www", func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "example.com" {
				http.Redirect(w, r, "https://www.example.com"+r.URL.Path, http.StatusFound)
				return
			}
			fmt.Fprint(w, "tok")
		}, func(err error) bool { return err == nil }},
		{"redirect off host", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://attacker.example.net/tok", http.StatusFound)
		}, notProven},
		{"redirect to http", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.com"+r.URL.Path, http.StatusFound)
		}, notProven},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &HTTPFileVerifier{Client: fileServer(t, c.handler)}
			if _, err := v.Verify(context.Background(), proof); !c.check(err) {
				t.Fatalf("Verify = %v", err)
			}
		})
	}
}

func TestDefaultHTTPClientRefusesInternalAddresses(t *testing.T) {
	for addr, public := range map[string]bool{
		"127.0.0.1:443": false, "10.1.2.3:443": false, "169.254.169.254:80": false, "100.64.0.1:443": false,
		"[::1]:443": false, "[::ffff:192.168.0.1]:443": false, "[fe80::1]:443": false,
		"8.8.8.8:443": true, "[2001:4860:4860::8888]:443": true,
	} {
		err := dialPublicOnly("tcp", addr, nil)
		if (err == nil) != public {
			t.Errorf("dialPublicOnly(%s) = %v, want public=%v", addr, err, public)
		}
	}
	if publicAddr(netip.Addr{}) {
		t.Fatal("the zero address is not public")
	}
}

// providerServer answers each path with a fixed status and body and requires the bearer token.
func providerServer(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func TestGoogleWorkspaceVerifier(t *testing.T) {
	ctx := context.Background()
	base := providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/ok":     reply(200, `{"domains":[{"domainName":"other.com","verified":true},{"domainName":"Example.com","verified":true},{"domainName":"pending.com","verified":false}]}`),
		"/denied": reply(403, `{"error":{"code":403}}`),
	})
	v := &GoogleWorkspaceVerifier{DomainsURL: base + "/ok"}
	if ref, err := v.Verify(ctx, DomainProof{Domain: "shop.example.com", AccessToken: "tok"}); err != nil || ref != "Example.com" {
		t.Fatalf("verified = %q, %v", ref, err)
	}
	if _, err := v.Verify(ctx, DomainProof{Domain: "pending.com", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("unverified domain: %v", err)
	}
	if _, err := v.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "expired"}); err == nil || notProven(err) {
		t.Fatalf("401 is a credential problem, not a verdict: %v", err)
	}
	if _, err := v.Verify(ctx, DomainProof{Domain: "example.com"}); err == nil || notProven(err) {
		t.Fatalf("missing grant: %v", err)
	}
	v.DomainsURL = base + "/denied"
	if _, err := v.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "tok"}); err == nil || notProven(err) {
		t.Fatalf("403 is not a proof verdict: %v", err)
	}
}

func TestMicrosoftEntraVerifier(t *testing.T) {
	ctx := context.Background()
	var base string
	base = providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/roles/admin":  reply(200, `{"value":[{"roleTemplateId":"`+strings.ToUpper(EntraGlobalAdministrator)+`"}]}`),
		"/roles/member": reply(200, `{"value":[{"roleTemplateId":"88d8e3e3-8f55-4a1e-953a-9b9898b8876b"}]}`),
		"/domains": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"value":[{"id":"contoso.onmicrosoft.com","isVerified":true}],"@odata.nextLink":"%s/domains2"}`, base)
		},
		"/domains2": reply(200, `{"value":[{"id":"example.com","isVerified":true}]}`),
		"/foreign":  reply(200, `{"value":[],"@odata.nextLink":"https://attacker.example.net/domains"}`),
	})
	v := &MicrosoftEntraVerifier{RolesURL: base + "/roles/admin", DomainsURL: base + "/domains"}
	if ref, err := v.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "tok"}); err != nil || ref != "example.com" {
		t.Fatalf("admin over a paged domain list = %q, %v", ref, err)
	}
	if _, err := v.Verify(ctx, DomainProof{Domain: "other.com", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("domain outside the tenant: %v", err)
	}
	custom := &MicrosoftEntraVerifier{RolesURL: base + "/roles/admin", DomainsURL: base + "/domains", AdminRoles: []string{strings.ToUpper(EntraGlobalAdministrator)}}
	if _, err := custom.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "tok"}); err != nil {
		t.Fatalf("configured role ids compare case-insensitively: %v", err)
	}
	member := &MicrosoftEntraVerifier{RolesURL: base + "/roles/member", DomainsURL: base + "/domains"}
	if _, err := member.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("member without an admin role: %v", err)
	}
	foreign := &MicrosoftEntraVerifier{RolesURL: base + "/roles/admin", DomainsURL: base + "/foreign"}
	if _, err := foreign.Verify(ctx, DomainProof{Domain: "example.com", AccessToken: "tok"}); err == nil || notProven(err) {
		t.Fatalf("next page on another host must not be followed: %v", err)
	}
}

func TestGoogleSiteVerifier(t *testing.T) {
	base := providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/resources": reply(200, `{"items":[
			{"id":"https://example.org/","site":{"type":"SITE","identifier":"https://example.org/"}},
			{"id":"dns://example.com","site":{"type":"INET_DOMAIN","identifier":"example.com"}}]}`),
	})
	v := &GoogleSiteVerifier{ResourcesURL: base + "/resources"}
	if ref, err := v.Verify(context.Background(), DomainProof{Domain: "www2.example.com", AccessToken: "tok"}); err != nil || ref != "dns://example.com" {
		t.Fatalf("domain property = %q, %v", ref, err)
	}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "example.org", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("URL-prefix property is not domain ownership: %v", err)
	}
}

func TestGoogleBusinessVerifier(t *testing.T) {
	base := providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/accounts": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("pageToken") == "" {
				fmt.Fprint(w, `{"accounts":[{"name":"accounts/1"}],"nextPageToken":"p2"}`)
				return
			}
			fmt.Fprint(w, `{"accounts":[{"name":"accounts/2"}]}`)
		},
		"/v1/accounts/1/locations": reply(200, `{"locations":[{"name":"locations/9","websiteUri":"https://www.example.com/","metadata":{"hasVoiceOfMerchant":false}}]}`),
		"/v1/accounts/2/locations": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("readMask") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"locations":[{"name":"locations/7","websiteUri":"https://www.example.com/menu","metadata":{"hasVoiceOfMerchant":true}}]}`)
		},
	})
	v := &GoogleBusinessVerifier{AccountsURL: base + "/accounts", LocationsURL: base + "/v1"}
	if ref, err := v.Verify(context.Background(), DomainProof{Domain: "example.com", AccessToken: "tok"}); err != nil || ref != "locations/7" {
		t.Fatalf("verified listing on the second account page = %q, %v", ref, err)
	}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "shop.example.com", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("listing names another host: %v", err)
	}
}

func TestEmailCodeVerifier(t *testing.T) {
	hash := common.Sha256Hex("123456")
	if _, err := (EmailCodeVerifier{}).Verify(context.Background(), DomainProof{TokenHash: hash, Response: " 123456 "}); err != nil {
		t.Fatal(err)
	}
	for _, response := range []string{"", "123457"} {
		if _, err := (EmailCodeVerifier{}).Verify(context.Background(), DomainProof{TokenHash: hash, Response: response}); !notProven(err) {
			t.Errorf("response %q: %v", response, err)
		}
	}
}

func TestGoogleWorkspaceAliasDomain(t *testing.T) {
	base := providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/ok": reply(200, `{"domains":[{"domainName":"example.com","verified":true,"domainAliases":[
			{"domainAliasName":"example.net","verified":true},{"domainAliasName":"pending.net","verified":false}]}]}`),
	})
	v := &GoogleWorkspaceVerifier{DomainsURL: base + "/ok"}
	if ref, err := v.Verify(context.Background(), DomainProof{Domain: "example.net", AccessToken: "tok"}); err != nil || ref != "example.net" {
		t.Fatalf("verified alias = %q, %v", ref, err)
	}
	if _, err := v.Verify(context.Background(), DomainProof{Domain: "pending.net", AccessToken: "tok"}); !notProven(err) {
		t.Fatalf("unverified alias: %v", err)
	}
}

func TestMicrosoftEntraRoleQuery(t *testing.T) {
	ctx := context.Background()
	var base string
	base = providerServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/roles": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("ConsistencyLevel") != "eventual" || r.URL.Query().Get("$count") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"value":[{"roleTemplateId":"`+EntraDomainNameAdministrator+`"}]}`)
		},
		"/hidden":  reply(200, `{"value":[{"@odata.type":"#microsoft.graph.directoryRole","roleTemplateId":null}]}`),
		"/domains": reply(200, `{"value":[{"id":"example.com","isVerified":true}]}`),
		"/endless": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"value":[],"@odata.nextLink":"%s/endless"}`, base)
		},
	})
	proof := DomainProof{Domain: "example.com", AccessToken: "tok"}
	ok := &MicrosoftEntraVerifier{RolesURL: base + "/roles?$count=true", DomainsURL: base + "/domains"}
	if _, err := ok.Verify(ctx, proof); err != nil {
		t.Fatalf("role query with its required header and count: %v", err)
	}
	for name, v := range map[string]*MicrosoftEntraVerifier{
		"unreadable role details": {RolesURL: base + "/hidden", DomainsURL: base + "/domains"},
		"truncated role listing":  {RolesURL: base + "/endless", DomainsURL: base + "/domains"},
		"truncated domain list":   {RolesURL: base + "/roles?$count=true", DomainsURL: base + "/endless"},
	} {
		if _, err := v.Verify(ctx, proof); err == nil || notProven(err) {
			t.Errorf("%s must not be a verdict: %v", name, err)
		}
	}
	if !strings.Contains(EntraRolesURL, "transitiveMemberOf/microsoft.graph.directoryRole?$count=true") {
		t.Fatalf("EntraRolesURL = %s", EntraRolesURL)
	}
}
