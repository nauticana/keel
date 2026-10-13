package service

import (
	"context"
	"errors"
	"testing"
)

func newScopePolicy(rows ...string) (*ConstantScopePolicy, *quotaFakeQS) {
	qs := newQuotaFakeQS()
	for _, r := range rows {
		qs.rows[qConstantScopes] = append(qs.rows[qConstantScopes], []any{r})
	}
	return &ConstantScopePolicy{DB: &quotaFakeRepo{qs: qs}, Constant: "api_key_scope", Default: "read"}, qs
}

func TestConstantScopePolicy(t *testing.T) {
	p, qs := newScopePolicy("read", "write")
	ctx := context.Background()
	for asked, want := range map[string]string{"": "read", " ": "read", " write, read ,write": "write,read"} {
		if got, err := p.Policy(ctx, 0, 7, asked); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", asked, got, err, want)
		}
	}
	for _, asked := range []string{"admin", "read,", "read,admin"} {
		if _, err := p.Policy(ctx, 0, 7, asked); !errors.Is(err, ErrInvalidScopes) {
			t.Errorf("%q = %v", asked, err)
		}
	}
	if len(qs.calls) != 1 || qs.calls[0].args[0] != "api_key_scope" {
		t.Fatalf("catalog reads = %+v, want one", qs.calls)
	}
}

func TestConstantScopePolicyFailsClosed(t *testing.T) {
	ctx := context.Background()
	p, qs := newScopePolicy("read")
	qs.errs[qConstantScopes] = errors.New("db down")
	if _, err := p.Policy(ctx, 0, 7, "read"); err == nil || errors.Is(err, ErrInvalidScopes) {
		t.Fatalf("unreadable catalog = %v", err)
	}
	delete(qs.errs, qConstantScopes)
	if got, err := p.Policy(ctx, 0, 7, "read"); err != nil || got != "read" {
		t.Fatalf("a failed read must not be cached: %q, %v", got, err)
	}
	for _, rows := range [][]string{nil, {"write"}} {
		p, _ := newScopePolicy(rows...)
		if _, err := p.Policy(ctx, 0, 7, "write"); err == nil || errors.Is(err, ErrInvalidScopes) {
			t.Errorf("catalog %v = %v", rows, err)
		}
	}
	for _, rows := range [][][]any{{{}}, {{"read", "extra"}}, {{""}}} {
		p, qs := newScopePolicy()
		qs.rows[qConstantScopes] = rows
		if _, err := p.Policy(ctx, 0, 7, "read"); err == nil || errors.Is(err, ErrInvalidScopes) {
			t.Errorf("malformed catalog %v = %v", rows, err)
		}
	}
	p, _ = newScopePolicy("read")
	p.Default = ""
	if _, err := p.Policy(ctx, 0, 7, ""); !errors.Is(err, ErrInvalidScopes) {
		t.Fatalf("blank without a default = %v", err)
	}
}
