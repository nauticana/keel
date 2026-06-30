package claims

import (
	"strings"
	"testing"
)

func TestScopes(t *testing.T) {
	if got := Scopes(map[string]any{"scope": "a b c"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("scope string parse: %v", got)
	}
	if got := Scopes(map[string]any{"scp": []any{"x", "y"}}); strings.Join(got, ",") != "x,y" {
		t.Fatalf("scp array parse: %v", got)
	}
	if got := Scopes(map[string]any{"scp": "User.Read Mail.Read"}); strings.Join(got, ",") != "User.Read,Mail.Read" {
		t.Fatalf("Entra scp string parse: %v", got)
	}
	if got := Scopes(map[string]any{}); got != nil {
		t.Fatalf("no scope claim → nil, got %v", got)
	}
}

func TestAudience(t *testing.T) {
	if got := Audience("a"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("string aud: %v", got)
	}
	if got := Audience([]any{"a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("array aud: %v", got)
	}
	if got := Audience(nil); got != nil {
		t.Fatalf("nil aud → nil, got %v", got)
	}
}

func TestInt64(t *testing.T) {
	if Int64(int64(7)) != 7 || Int64(float64(7)) != 7 || Int64("x") != 0 {
		t.Fatal("Int64 must accept int64/float64 and zero everything else")
	}
}

func TestPartnerID(t *testing.T) {
	if id, ok := PartnerID(map[string]any{"partner_id": float64(42)}); id != 42 || !ok {
		t.Fatalf("partner_id float64: %d %v", id, ok)
	}
	if id, ok := PartnerID(map[string]any{"partner_id": int64(0)}); id != 0 || ok {
		t.Fatalf("zero partner_id must report not-present: %d %v", id, ok)
	}
	if _, ok := PartnerID(nil); ok {
		t.Fatal("nil claims → not present")
	}
}

func TestPrincipal(t *testing.T) {
	p, err := Principal(map[string]any{"sub": "user:1", "iss": "https://as", "aud": "https://r", "scope": "read write"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "user:1" || p.Issuer != "https://as" || len(p.Audience) != 1 || strings.Join(p.Scopes, ",") != "read,write" {
		t.Fatalf("principal: %+v", p)
	}
	if _, err := Principal(map[string]any{"iss": "https://as"}); err == nil {
		t.Fatal("missing sub must error")
	}
}
