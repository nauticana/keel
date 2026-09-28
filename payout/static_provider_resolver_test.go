package payout

import (
	"context"
	"errors"
	"testing"
)

func TestStaticProviderResolver(t *testing.T) {
	p := &fakeProvider{code: ProviderCodeWise}
	r := NewStaticProviderResolver(p)
	if got, err := r.ForPartner(context.Background(), 9); err != nil || got != p {
		t.Fatalf("ForPartner=%v, %v", got, err)
	}
	if got, err := r.ByCode(ProviderCodeWise); err != nil || got != p {
		t.Fatalf("ByCode=%v, %v", got, err)
	}
	if _, err := r.ByCode(ProviderCodeAirwallex); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("other code err=%v, want ErrUnknownProvider", err)
	}
	empty := NewStaticProviderResolver(nil)
	if _, err := empty.ForPartner(context.Background(), 9); !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("nil provider err=%v", err)
	}
}

func TestSQLProviderResolver_ByCode(t *testing.T) {
	r := NewSQLProviderResolver(nil, &fakeProvider{code: ProviderCodeWise}, &fakeProvider{code: ProviderCodeStripeConnect})
	if got, err := r.ByCode(ProviderCodeStripeConnect); err != nil || got.Code() != ProviderCodeStripeConnect {
		t.Fatalf("ByCode=%v, %v", got, err)
	}
	if _, err := r.ByCode(ProviderCodeAirwallex); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unconfigured code err=%v, want ErrUnknownProvider", err)
	}
}
