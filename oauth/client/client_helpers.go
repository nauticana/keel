package client

import (
	"context"
	"net/url"
	"strconv"
)

// StateEntityKey is the OAuth-state extra key carrying the entity scope across
// the consent redirect (see WithEntity).
const StateEntityKey = "entity_id"

// StatePKCEKey carries the PKCE verifier through the OAuth state (BaseProvider.UsePKCE).
const StatePKCEKey = "pkce_verifier"

// entityCtxKey scopes a credential to a specific business/entity within a
// partner (0 = tenant-wide). It rides the OAuth state across the consent
// redirect and the request context into the CredentialStore, so no interface
// method carries it explicitly — existing callers and providers stay at 0.
type entityCtxKey struct{}

// WithEntity tags ctx with the entity scope a CredentialStore should read.
func WithEntity(ctx context.Context, entityID int64) context.Context {
	return context.WithValue(ctx, entityCtxKey{}, entityID)
}

// EntityFromContext returns the entity scope tagged on ctx, or 0 (tenant-wide).
func EntityFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(entityCtxKey{}).(int64); ok {
		return v
	}
	return 0
}

// callbackQueryCtxKey carries the raw OAuth callback query into the persist flow
// so a provider's DeriveAPIEndpoint can read provider-specific params returned in
// the redirect (e.g. Clover's merchant_id) that are absent from the token response.
type callbackQueryCtxKey struct{}

// WithCallbackQuery tags ctx with the OAuth callback query. The connect handler
// sets it before Provider.Callback so DeriveAPIEndpoint can read the redirect's
// provider-specific params.
func WithCallbackQuery(ctx context.Context, q url.Values) context.Context {
	return context.WithValue(ctx, callbackQueryCtxKey{}, q)
}

// CallbackQueryFromContext returns the OAuth callback query tagged on ctx, or nil
// when unset (Values.Get on a nil map is safe and returns "").
func CallbackQueryFromContext(ctx context.Context) url.Values {
	if v, ok := ctx.Value(callbackQueryCtxKey{}).(url.Values); ok {
		return v
	}
	return nil
}

// entityFromExtra reads the entity scope an AuthURL stashed in the OAuth-state
// extra, defaulting to 0 when absent or unparsable.
func entityFromExtra(extra map[string]string) int64 {
	if extra == nil {
		return 0
	}
	id, _ := strconv.ParseInt(extra[StateEntityKey], 10, 64)
	return id
}
