package resource

import (
	"testing"

	"github.com/nauticana/keel/common"
)

func TestNewJWTValidatorFromFlags(t *testing.T) {
	i, j, a := *common.OAuthIssuer, *common.OAuthJWKSURL, *common.OAuthAudience
	t.Cleanup(func() {
		*common.OAuthIssuer, *common.OAuthJWKSURL, *common.OAuthAudience = i, j, a
	})

	set := func(issuer, jwks, aud string) {
		*common.OAuthIssuer, *common.OAuthJWKSURL, *common.OAuthAudience = issuer, jwks, aud
	}

	t.Run("disabled when issuer empty", func(t *testing.T) {
		set("", "", "")
		v, err := NewJWTValidatorFromFlags(nil)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if v != nil {
			t.Fatalf("validator = %#v, want true nil interface", v)
		}
	})

	t.Run("error when jwks url missing", func(t *testing.T) {
		set("https://issuer.example", "", "aud")
		if _, err := NewJWTValidatorFromFlags(nil); err == nil {
			t.Fatal("err = nil, want fail-fast error")
		}
	})

	t.Run("error when audience missing", func(t *testing.T) {
		set("https://issuer.example", "https://issuer.example/jwks", "")
		if _, err := NewJWTValidatorFromFlags(nil); err == nil {
			t.Fatal("err = nil, want fail-fast error")
		}
	})

	t.Run("ok when all set", func(t *testing.T) {
		set("https://issuer.example", "https://issuer.example/jwks", "aud")
		v, err := NewJWTValidatorFromFlags(nil)
		if err != nil || v == nil {
			t.Fatalf("v=%v err=%v, want non-nil validator, nil err", v, err)
		}
	})
}

func TestOAuthResourceMiddleware_NilValidatorPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic wiring a nil validator")
		}
	}()
	Middleware(nil, "", nil, nil)
}
