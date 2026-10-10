# Authentication

API keys, OAuth, sessions, multi-factor authentication, OTP, and social sign-in.

## API Key Authentication

Keel ships an end-to-end API-key authentication stack for `/pubapi/*` traffic (REST) and standalone services (e.g. MCP servers built on [scout](https://github.com/nauticana/scout) exposed over Streamable HTTP). Three pieces, one chain:

```
X-API-Key header → APIKeyAuthMiddleware → APIKeyService.LookupKey → context-injected (partner_id, api_key_id, scopes, user_id)
```

### `service.APIKeyService` — key lifecycle + lookup cache

Manages issued keys: generates the user-visible string, stores its SHA-256 hash + prefix in the `api_key` table, and caches lookups in-process for one minute by default.

```go
apiKeys := &service.APIKeyService{
    DB:           db,
    QuotaService: quota,
    Journal:      journal,
    KeyPrefix:    "myapp_",  // required — panics at Init if empty
    // QuotaResource: "API_CALLS", // default
    // QuotaCaption:  "public-api", // default
}
apiKeys.Init(ctx)

// Issuing a key (typically from a JWT-authed admin handler):
plainKey, prefix, err := apiKeys.InsertKey(ctx, partnerID, userID, "production-key", "businesses,search", "203.0.113.0/24")
// plainKey is "myapp_<32-hex>"; show to user once and discard.
```

`KeyPrefix` is required. `ScopePolicy` can refuse generated-key scopes (`ErrInvalidScopes`, returned as 400 by the `generate` action); rotation preserves existing scopes. The last argument is the key's network allow-list, a CSV of CIDRs or addresses (at most `common.MaxCIDRList`); empty allows any address, and a malformed list is `common.ErrInvalidCIDRList`. `RestrictKey(ctx, keyID, partnerID, cidrs)` replaces it on an active key of the partner and evicts the cached entry. A partner holding `api_key_max_per_partner` usable keys gets `ErrAPIKeyLimit` (409 from `generate`); the count is serialized per partner, and rolling a key never counts against it. `LookupKey` caches by SHA-256 hash for `CacheTTL` and carries `UserID` (`0` for partner-only keys). `InvalidateKey` clears an entry on rotation or revocation.

### `service.APIKeyAuthMiddleware` — the reusable factory

Generic `func(http.Handler) http.Handler` factory that validates `X-API-Key`, looks up via `APIKeyService`, enforces expiry and the key's network allow-list against `common.TrustedClientIP` (403 outside it), touches `last_used` async, and injects `common.PartnerID / ApiKeyID / Scopes` into the request context, plus `common.UserID` when the key has a user, so `CallerSessionFromContext` reports the key's user. Quota is a separate concern: compose `service.QuotaMiddleware` after auth so one gate covers X-API-Key and OAuth alike. **No path gating** — wrap arbitrary subtrees yourself.

```go
auth := service.APIKeyAuthMiddleware(apiKeys, journal) // then: service.QuotaMiddleware(quota, "", "", journal)

// Two typical wirings:

// (1) Inside HttpBackend — gated to /pubapi/* automatically (next section).
// Standard REST setup; no extra code needed.

// (2) Standalone service that should auth every request — e.g. an MCP
// server exposed over Streamable HTTP at https://mcp.example.com/:
http.ListenAndServe(":8090", auth(myHandler))
```

The same context-key constants (`common.PartnerID` etc.) are read by `AbstractHandler.PartnerFromCtx`, `HasScope`, and `RequireScope` — so handlers downstream of either wiring use the same accessors.

### `service.HttpBackend.APIKeyMiddleware` — `/pubapi/*` path gate

`HttpBackend` automatically wraps the inbound chain with `APIKeyMiddleware`, which path-gates on `common.PubapiPrefix` and delegates to `APIKeyAuthMiddleware` for actual validation. Non-`/pubapi/*` requests pass through to `SSOMiddleware` (JWT auth). This is the standard wiring for any consumer using `HttpBackend.Run`:

```go
srv := service.HttpBackend{
    Journal:       journal,
    DB:            db,
    Secrets:       secrets,
    Origin:        config.Config().CORSOrigin,
    UserService:   userSvc,
    QuotaService:  quota,
    ApiKeyService: apiKeys,  // already constructed + Init'd
}
srv.Handle(myRoutes)
srv.Run(ctx)
```

For services that don't use `HttpBackend` (workers exposing healthchecks, MCP servers, etc.), use `APIKeyAuthMiddleware` directly per the example above.

### Configuration

| Source | Key | Purpose |
|---|---|---|
| Field | `APIKeyService.KeyPrefix` | Required. Per-product user-visible prefix (e.g., `"myapp_"`). |
| Field | `APIKeyService.QuotaResource` | Optional. Defaults to `"API_CALLS"`. The resource id passed to `QuotaService.LogUsage` and `CheckQuota`. |
| Field | `APIKeyService.QuotaCaption` | Optional. Defaults to `"public-api"`. The caption recorded in usage rows. |
| Field | `APIKeyService.ScopePolicy` | Optional. Refuses scopes at generation. |
| Flag | `api_key_max_per_partner` | Usable keys a partner may hold. Default `20`; `0` is unbounded. |
| Schema | `api_key` table + sequence | Already in keel's `schema/api_key_management/api_key.yml`. No project-side schema. |

### Database Table

| Table | Purpose |
|---|---|
| `api_key` | Issued keys: `id`, `partner_id`, `user_id` (NULL for a partner-only key), `key_name`, `key_prefix` (visible), `key_hash` (SHA-256), `scopes` (CSV), `allowed_cidrs` (CSV; NULL allows any address), `is_active`, `expires_at`, `last_used_at`. Keys are minted, rolled and restricted only through the `generate` (optional `allowed_cidrs`), `roll` and `restrict` (`API_KEY`/`RESTRICT`) table actions; the seed grants no generic insert or update. |

### `service.HttpBackend.CORSMiddleware` — cross-origin access

| Field | Purpose |
|---|---|
| `Origin` | Comma-separated origin allowlist, or `*`. Empty disables CORS. The request `Origin` is echoed back only when it matches. |
| `AllowCredentials` | Emits `Access-Control-Allow-Credentials: true`. Invalid with `Origin: "*"` — CORS is disabled and the misconfiguration is journaled. |
| `ExposeHeaders` | Response headers a cross-origin browser client may read, emitted as `Access-Control-Expose-Headers` whenever the origin is allowed. Without it the client sees only the CORS-safelisted headers and any custom header reads as `null`. |

```go
srv := service.HttpBackend{
    Origin:        config.Config().CORSOrigin,
    ExposeHeaders: []string{"X-Data-Source-Status", "X-Data-Source"},
}
```

## OAuth 2.1 Resource Server

For OAuth-based clients that won't send a custom `X-API-Key` — notably **ChatGPT Apps SDK** — keel validates access tokens issued by an external authorization server and publishes RFC 9728 discovery metadata. Sits beside the X-API-Key / JWT paths; nothing existing changes.

```
Authorization: Bearer <token> → resource.Middleware → TokenValidator (JWKS RS256) → context-injected (principal, subject, scopes, partner_id)
```

**Delegate the authorization server** (external mode). In this mode keel is the *resource server* (token validation + metadata) and does not issue tokens — front it with an IdP that provides OAuth 2.1 + PKCE + Dynamic Client Registration (Auth0, Stytch, WorkOS, Clerk, Keycloak), and keel verifies that IdP's RS256 tokens against its JWKS. To have keel issue its own tokens instead, use the local authorization server above.

### Wiring (standalone — e.g. an MCP server built on [scout](https://github.com/nauticana/scout))

```go
// 1. Validator from --oauth_* flags (nil when oauth_issuer is empty; error on misconfig).
validator, err := resource.NewJWTValidatorFromConfig(common.HTTPClient())
if err != nil { log.Fatal(err) }

// 2. Optional account-linking: map token subject → keel partner id (0 = unlinked).
resolve := func(ctx context.Context, p *port.TokenPrincipal) (int64, error) {
    return myDirectory.PartnerForSubject(ctx, p.Issuer, p.Subject)
}

// 3. Keyless metadata route + Bearer auth on the protected handler.
meta := resource.ProtectedResourceMetadataFromConfig()
mw := resource.Middleware(validator, meta.Resource+resource.ProtectedResourceMetadataPath, journal, resolve)

mux := http.NewServeMux()
mux.HandleFunc(resource.ProtectedResourceMetadataPath, resource.ProtectedResourceMetadataHandler(meta))
mux.Handle("/", mw(mcpHandler)) // tokens required on the MCP route; metadata stays keyless
http.ListenAndServe(":8091", mux)
```

Downstream handlers read identity with the same accessors as the X-API-Key path — `common.PartnerID` (when a resolver maps one) and `common.Scopes` (so `AbstractHandler.HasScope` / `RequireScope` work) — plus `resource.PrincipalFromContext(ctx)` for subject / issuer / raw claims.

### Configuration

| Flag | Purpose |
|---|---|
| `oauth_issuer` | AS issuer URL trusted by the validator. Empty = OAuth disabled. |
| `oauth_jwks_url` | JWKS URL for token signatures (often `<issuer>/.well-known/jwks.json`). |
| `oauth_audience` | Expected token audience = this resource's id (RFC 8707). |
| `oauth_resource` | Canonical resource URL in the metadata doc. Empty → `oauth_audience`. |
| `oauth_scopes_supported` | CSV scopes advertised in metadata. Optional. |
| `oauth_max_pending_clients` | Maximum pending open registrations. `0` is unbounded. |
| `oauth_replace_same_app_grant` | A new grant revokes the user's grants to other clients sharing its redirect host. Default `true`. |
| `oauth_max_grants_per_user` | Live grants a user may hold. Default `10`; `0` is unbounded. |

All non-secret. For multiple issuers, construct one `resource.JWTValidator` per issuer and dispatch on the token's `iss`.

### Session hand-off for bearer-token SPAs

`/oauth/authorize` authenticates through `OAuthASHandler.ResolveUser`, which needs a cookie session on the authorization server's host. An SPA that keeps its JWT in browser storage hands its session over instead:

```go
store := &authserver.SessionHandoffStoreDB{DB: db}
store.Init(ctx)
hs, err := authserver.NewSessionHandoff(store, as.Metadata().AuthorizationEndpoint)
asHandler := &handler.OAuthASHandler{ /* … */ Handoff: hs, UserService: users,
    ResolveUser: handler.HandoffSessionUser(hs, journal)}
```

When the login page receives `?return=`, the SPA posts `{"return": <value>}` with its bearer token to `POST /oauth/session/handoff` and navigates the browser to the returned `redirect`. `GET /oauth/session` redeems the single-use 60-second code, sets a 10-minute HttpOnly, Secure, SameSite=Lax cookie scoped to `/oauth`, and redirects (303) to the authorize URL. `return` must be this AS's own authorize URL and is bound to the code, so the flow is never an open redirect. Revoking the user's access tokens (logout everywhere, password change, account deletion) also ends a pending code and the cookie session. The SPA's origin must be allowed by the AS backend's CORS settings.

### Authorized clients (local authorization server)

`oauth.Setup.Grants` (`authserver.GrantService`) manages the clients a user has authorized. A grant is the live refresh tokens a client holds for a user; a client registered without the `refresh_token` grant has none.

- `List(ctx, userID)` returns each client with its name, scopes, first authorization and newest token.
- `Revoke(ctx, userID, clientID)` revokes every refresh token of the pair, or returns `ErrGrantNotFound`; it is serialized with refresh rotation, so a concurrent refresh cannot keep the grant alive.
- `Active(ctx, userID, clientID)` lets a resource server honor a revocation before the access token expires.
- `PurgeUnauthorizedClients(ctx, olderThan)` deletes, in batches, openly registered clients that never completed an authorization.

Dynamic registration gives every reconnect a new client, and a hosted assistant that drops its connection does not revoke it. With `oauth_replace_same_app_grant` on, redeeming a code revokes the user's grants to other clients of the same app, those sharing a non-loopback redirect host; consent alone replaces nothing, and loopback hosts, shared by every native app, never match. `oauth_max_grants_per_user` refuses an authorization past the cap with `access_denied` and an `error_description`, and rechecks it when the code is redeemed (`invalid_grant`); a reconnect of an app the user already holds is admitted. `prompt` is honored on the consent post as on the request. Direct composition sets `authserver.Config.ReplaceSameAppGrant` and `MaxGrantsPerUser`.

`oauth_max_pending_clients` bounds that pending set atomically. One more registration returns `ErrOAuthClientLimit` (`temporarily_unavailable`, 503). Direct composition uses `ClientStoreDB.MaxPending`. `authserver.UserIDFromSubject` parses the `user:<id>` token subject.

Open registration (`POST /oauth/register`, RFC 7591) admits public (`none`, PKCE) and confidential (`client_secret_basic`, `client_secret_post`) clients and always records `authorization_code` and `refresh_token`. A request for any other grant is refused, so `client_credentials` and token-exchange clients are created by the operator with `AuthorizationServer.Provision`, which the purge never deletes. Refusals return `invalid_client_metadata` or `invalid_redirect_uri` with an `error_description` naming the field, and are logged at warning level.

An unauthenticated `/authorize` redirects to `LoginURL` with `return` set to the absolute authorize URL built from the configured issuer, so a login page on another origin knows where to send the user back.

The consent page names the signed-in account (`ConsentView.Account`, set when `UserService` is) and, with `LoginURL` set, offers "Use a different account" (`ConsentView.SwitchAccount`; the form posts `switch_account=true`). That action, `prompt=login` and `prompt=select_account` end the hand-off session and redirect to `LoginURL?return=…&prompt=login` (or `select_account`). The return drops `prompt`, so the next authorize asks consent for whichever account signed in. The app's login page must ask for credentials when it receives `prompt`, even with a live session of its own. `prompt=none` answers `login_required` or, since consent is always asked, `consent_required`.

## Standards Compliance

Each row records what keel implements of an IETF or OASIS specification, what it leaves out, and why. keel does not knowingly contradict a MUST: a contradiction found is fixed, not documented. A change to a protocol surface updates these tables.

### Authorization server and resource server

| Specification | Status |
|---|---|
| RFC 6749 OAuth 2.0 | Authorization code, refresh token and client credentials grants. After the client and `redirect_uri` are known, every authorization error, `unsupported_response_type` included, returns to the `redirect_uri` with `state` and `iss`. A repeated parameter is `invalid_request`. A replayed code is refused and revokes the grant it issued. A refusal with a reason, such as the grant cap, carries `error_description`. A 401 `invalid_client` carries `WWW-Authenticate`; token responses carry `Cache-Control: no-store` and `Pragma: no-cache`. |
| RFC 6750 Bearer tokens | Header only. `resource.Middleware` answers 401 with a `Bearer` challenge, adding `error="invalid_token"` only when a token was sent; `resource.RequireScopes` answers 403 `insufficient_scope` with the missing `scope`. |
| RFC 7636 PKCE | `S256` is required on every authorization request. |
| RFC 7591 Dynamic client registration | Open registration of public and confidential clients for the interactive grants; refusals use `invalid_client_metadata` or `invalid_redirect_uri`. The response carries `client_id_issued_at` and, with a secret, `client_secret_expires_at` (`0`). Software statements are ignored, as `2.3 allows. |
| RFC 7592 Registration management | Not implemented: a registered client cannot read, update or delete its registration. Operators use `Provision`. |
| RFC 7009 Revocation | Refresh tokens revoke their rotation family. An access token revokes the grant it came from, so introspection and `GrantService.Active` report it ended; a resource server that validates only the signature honors it at expiry. |
| RFC 7662 Introspection | A client sees only its own tokens. A token whose grant is revoked is inactive. |
| RFC 8414 Server metadata | Served at `/.well-known/oauth-authorization-server`; `oauth_issuer` must therefore be an `https` origin without a path. The auth methods of the token, revocation and introspection endpoints and `response_modes_supported` are stated, not left to defaults. |
| RFC 8693 Token exchange | Access token for access token, bounded by the subject token and the client's scopes, with `issued_token_type`; operator-provisioned clients only. |
| RFC 8707 Resource indicators | `resource` must be the audience, `oauth_resource` or one of `oauth_resources`. At the token endpoint it must name the resource the grant was made for. One resource per request. |
| RFC 9207 Issuer identification | Every authorization response, including an error, carries `iss`. |
| RFC 9728 Protected resource metadata | Served by the resource server (`/.well-known/oauth-protected-resource`). |
| RFC 9068 JWT access tokens | Not claimed: access tokens are RS256 JWTs without the `at+jwt` type. |
| RFC 8252 Native apps | Loopback redirects match exactly, port included; a native client registers the port it listens on. Private-use URI schemes are refused. |
| RFC 7522 SAML 2.0 bearer assertions | Not implemented: neither the `saml2-bearer` grant nor SAML client authentication. Partner SAML sign-in is browser Web SSO, which ends in a keel session, not a token exchange. |
| RFC 8705 Mutual-TLS client authentication | Not implemented. |
| RFC 9126 Pushed authorization requests | Not implemented. |
| OpenID Connect Dynamic Registration | Not applicable: the server issues no ID tokens. |
| OpenID Connect Core `prompt` | Honored on `/oauth/authorize` without ID tokens: `none` answers `login_required` or `consent_required`, and combined with another value `invalid_request`; `login` and `select_account` end the authorization server session and return through `LoginURL`; `consent` is always in effect. `max_age` and `auth_time` are not supported. |

### Sign-in and token verification

| Specification | Status |
|---|---|
| RFC 7515 / 7517 / 7518 / 7519 JOSE and JWT | Algorithms are allowlisted per issuer; `none` and HMAC with public keys are refused. A token with a `crit` header is refused. RSA keys are at least 2048 bits. A JWK whose `use` is not `sig` is ignored. An unknown `kid` refreshes the key set at most every 30 s. `exp`, `nbf` and `iat` allow 60 s of clock skew. |
| OpenID Connect Core 1.0 | `state`, `nonce` and S256 PKCE on every request. An ID token's `iss` must match exactly and its `aud` must be only the client id, since keel trusts no other audience (`3.1.3.7); `azp`, when present, must be the client id, except for Google, whose mobile sign-in names the app's own client. |
| OpenID Connect Discovery 1.0 | The discovered issuer must equal the configured one, and every endpoint must be `https`. |
| RFC 7523 JWT client authentication | `private_key_jwt`: `iss` and `sub` are the client id, `aud` the token endpoint, a random `jti`, one-minute lifetime. |
| RFC 7009 Revocation (client) | Sign in with Apple: the refresh token redeemed at sign-in is revoked with `token_type_hint=refresh_token` when the account is deleted. The code's ID token is verified for signature, expiry, issuer, audience and subject before the refresh token is kept. |
| SAML 2.0 Web SSO (OASIS) | Signed responses or assertions, SHA-256 or stronger only. `InResponseTo` binds to the stored request; IdP-initiated sign-in is refused. Every audience restriction must name the SP entity id; a bearer confirmation must name the callback URL and be valid now; `Destination` and `Recipient` are checked. NameID is requested `unspecified`, and a transient NameID is never a subject. |
| RFC 6595 SAML SASL mechanism | Not applicable: keel serves HTTP. |

### Outbound connections

| Specification | Status |
|---|---|
| RFC 6749 OAuth 2.0 client | `state` is single-use and bound to the user and partner who started the flow (`10.12); the callback completes only through `/api/oauth/{provider}/complete` by that user. `client_secret_basic` form-encodes its values. A token response must carry an `access_token`, and a `token_type`, when present, must be `bearer`. |
| RFC 7636 PKCE | S256 for Google, X and any provider with `BaseProvider.UsePKCE`; the others rely on the bound `state` and the client secret. |

### Directory provisioning (SCIM)

| Specification | Status |
|---|---|
| RFC 7643 SCIM core schema | Users and Groups in the core schema, with the enterprise user extension accepted. `/Schemas` describes exactly the attributes keel keeps, with their mutability, uniqueness and case rules. |
| RFC 7644 SCIM protocol | Create, read, replace, PATCH and delete for Users and Groups; filters with `eq`, `ne`, `co`, `sw`, `ew`, `pr`, `and`, `or`, `not`; `attributes` and `excludedAttributes`; paging per `3.4.2.4. Errors use the SCIM error schema and the RFC's `scimType` values. Not implemented, as the RFC allows: sorting, ETags, `/Bulk` and `/.search`; `/Me` answers 501. |
| RFC 7642 SCIM concepts | Informational; keel is the service provider, and the partner's directory is the client. |
| SCIM authentication | Bearer tokens issued per partner (RFC 6750), stored as SHA-256. Mutual TLS (RFC 8705) is not implemented. |

## Two-Factor Authentication (2FA) & Trusted Devices

Keel includes built-in TOTP-based 2FA with trusted device management. The login endpoints (`LoginLocal`, `LoginGmail`) automatically check `TwoFactorEnabled` on the user session and return a conditional response.

### Trusted-device model

The "trusted device" credential is a **server-minted 32-byte secret** kept in an HttpOnly + Secure + SameSite=Strict cookie (default name `keel_td`). The DB stores only the secret's hex SHA256 — never the raw value — and `IsTrustedDevice` constant-time compares against the active rows for the user. This replaces the earlier "client-supplied fingerprint string" pattern, which had two weaknesses: the client picked the value (so a malicious client could re-use a known fingerprint across users), and the value was stored plaintext (so a DB leak handed an attacker direct bypass material).

Lifecycle:
1. `POST /public/2fa/verify` with `trustDevice:true` → server calls `UserService.RegisterTrustedDevice(userID, deviceName)`, which mints a fresh secret, stores its SHA256, and **returns the raw secret** to the handler. The handler immediately sets the `keel_td` cookie via `handler.DefaultTrustedDeviceCookie.Set(w, secret)`. The secret never appears in the JSON response body.
2. On the next `POST /public/login/local` (or `/public/login/gmail`), the handler reads the cookie via `handler.DefaultTrustedDeviceCookie.Get(r)` and passes the value to `IsTrustedDevice`, which hashes it and looks for a matching row. Match → skip 2FA.
3. `POST /api/user/trusted-device/revoke` removes the row; the next request from that device has no usable cookie.

The built-in handlers read `handler.DefaultTrustedDeviceCookie` directly; to change its name, path or TTL, assign a `&handler.TrustedDeviceCookie{Name, Path, TTL}` to that variable at composition time, before routes are served.

### Login Flow with 2FA

```
POST /public/login/local   (or /public/login/gmail)
  Cookie:  keel_td=<secret> (sent by browser when set during a previous 2FA verify)
  Request: { "username": "...", "password": "..." }

  // If 2FA NOT enabled (or keel_td cookie maps to a trusted row):
  Response: { "token": "jwt...", "refreshToken": "…", "userId": 1, "partnerId": 1, "menu": [...], "twoFactorRequired": false }

  // If 2FA enabled AND device NOT trusted:
  Response: { "twoFactorRequired": true, "loginToken": "12345678" }

  // If 2FA NOT enabled, stepup_new_device on AND device not recognized:
  Response: { "twoFactorRequired": true, "twoFactorMethod": "email", "loginToken": "12345678" }
```

When `twoFactorRequired` is `true`, the frontend redirects to a 2FA verification page and submits the code via the public verify endpoint. The verify request opts into device trust with `trustDevice:true` + an optional human-readable `deviceName`; on success the server sets the `keel_td` cookie.

### Refresh tokens

Every login path (`LoginLocal`, `LoginGoogle`, `VerifyOTP`, `LoginSocial`, `Verify2FA`, `VerifyBackupCode`) answers with an access `token` (JWT, `session_timeout` seconds) and a `refreshToken` (`refresh_token_ttl` seconds, default 30 days). Downstream login handlers mint the same pair with `AbstractHandler.SessionTokens(w, r, session)`, add their own fields to the returned map, and pass an error to `WriteServiceError`. A refresh is refused with 401 when the account is locked, expired or deleted, or when the session is older than the `SESSION_MAX_HOURS` policy (hours since sign-in; 0, the default, is unlimited). Each of these routes and `/public/register/exchange` also accepts an optional `sessionMaxDays` (1–3650) that ends the session that many days after sign-in however often it refreshes; it is read from the request that mints the tokens, so a 2FA client sends it again with the second factor. Without it the session renews as before. Custom login requests can embed `handler.SessionLimit` and assign `MaxAge()` to `session.SessionMaxAge`.

```
POST /public/token/refresh  { "refreshToken": "…" }
  200 { "token": "jwt...", "refreshToken": "<rotated>", "userId": 1, "partnerId": 1 }
  401 revoked, expired, or already rotated — log in again
POST /public/logout         { "refreshToken": "…" }   → 200, token revoked
```

Refresh rotates: the presented token is revoked and the response carries its replacement, so a replayed token fails. `/api/user/logout-everywhere`, 2FA changes, and password changes revoke every refresh token for the user; the access token stays valid until its own expiry.

### Sign-in sessions and devices

A sign-in starts a session whose id (`UserSession.SessionID`, the JWT `sid` claim) every rotated refresh token keeps. `UserService.CreateRefreshToken(session, device)` records the device: user agent, trusted client IP, and the SHA-256 of the `keel_device` cookie, a random value `SessionTokens` sets once per browser (HttpOnly, Secure, SameSite=Strict, 400 days; attributes come from `handler.DefaultDeviceCookie`, assigned at composition time like the trusted-device cookie). The cookie only recognizes a device; it grants nothing. A client that keeps no cookies is a new device at every sign-in.

- `GET /api/user/sessions` lists live sessions (`id`, `userAgent`, `clientIp`, `signInMethod`, `createdAt`, `lastSeenAt` of the latest refresh, `current`). keel has no IP geolocation; map `clientIp` to a place in the application if needed.
- `POST /api/user/sessions/revoke {"id"}` ends one session (204; 404 `session_not_found` for another user's or an ended one). Its access token lasts until `session_timeout`.
- `max_sessions_per_user` (default `0`, unbounded) ends the oldest sessions when a sign-in passes the cap.
- `UserService.SetSingleDevicePolicy(userID, on)` sets `user_account.single_device_session`; while on, every sign-in revokes the user's other sessions, so a high-trust account is signed in on exactly one device.
- `notify_new_device_signin` (default `true`) calls `LocalUserService.SignInNotifier.NewDeviceSignIn` when a user who has signed in before does so from an unrecognized device. The notice is best effort: a failure, or no notifier, is logged to `Journal` and the sign-in proceeds. `user.MailSignInNotifier{Mail, Brand}` sends it by email.
- `stepup_new_device` (default `false`) stops a sign-in that checks 2FA (password, Google, a hand-off not from an identity provider) of a user without 2FA on an unrecognized device: the response is `{"twoFactorRequired": true, "twoFactorMethod": "email", "loginToken"}`, `SignInNotifier.StepUpCode` sends a one-time code (`OTPPurposeStepUp`), and `POST /public/2fa/verify {"loginToken", "code"}` finishes the sign-in. Without a notifier the sign-in is refused with 503 `stepup_unavailable`. Users with 2FA already verify a second factor on any untrusted device. One-time-code, registration and tenant identity-provider sign-ins prove possession already and are not stepped up.
- `partner_signin_network` lists the networks a partner's users may sign in from; no rows allows any address. Sign-in and refresh from elsewhere are refused (`user.ErrSignInNetwork`, 403 `signin_network`; a refresh answers 401). Only keel sessions are checked: OAuth clients such as hosted AI apps call from their own networks with their own tokens. Administrators replace the whole list with the `replace` table action (`PARTNER_SIGNIN_NETWORK`/`REPLACE`, parameter `cidrs`), served by `handler.SignInNetworkActionHandler` over `user.SignInNetworkService`; a list that excludes the administrator's own address is refused (409 `signin_network_lockout`).

### Security Endpoints

**Public (no JWT required)** -- used during login-time 2FA verification:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/public/2fa/verify` | Verify the TOTP code, or the emailed step-up code, with `loginToken`; returns JWT on success |
| POST | `/public/2fa/backup-verify` | Verify backup code with `loginToken`, consumes the code |

**Authenticated (JWT required)** -- used for 2FA setup, device management, session revocation, and account deletion:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/user/2fa/setup` | Generate TOTP secret, QR URI, and 10 backup codes. **Side effect:** revokes all active refresh tokens (user re-auths on next refresh). |
| POST | `/api/user/2fa/verify` | Confirm 2FA setup by verifying a TOTP code |
| POST | `/api/user/2fa/disable` | Disable 2FA (requires the password and a current TOTP code). **Side effect:** revokes all active refresh tokens. |
| GET | `/api/user/trusted-device/list` | List trusted devices for the authenticated user |
| POST | `/api/user/trusted-device/revoke` | Revoke a trusted device by ID. **Side effect:** revokes all active refresh tokens. |
| GET | `/api/user/sessions` | List live sign-in sessions, marking the caller's |
| POST | `/api/user/sessions/revoke` | End one session by `id` |
| POST | `/api/user/logout-everywhere` | Revoke every active refresh token (user will re-auth on every device) |
| DELETE | `/api/user/account` | Soft-delete the caller's account (anonymize + cascade revoke). Body `{reason}` optional. Returns 204. |

2FA setup, logout-everywhere, account deletion and `LinkSocial` need re-authentication in the body (`handler.RecentAuth`): `password`, a current `twoFactorCode`, or a `reauthCode` sent by `POST /api/user/reauth/send` (below), so users who sign in only by one-time code or a social provider can still pass. A `reauthCode` is single-use, bound to the `reauth` purpose, and refused with 403 where the SSO policy refuses OTP sign-in.

**Self-service profile (`ProfileHandler`)** -- a logged-in user editing their own account. Construct with a `port.NotificationSender`; mount the routes returned by `GetAuthRoutes()` behind your JWT middleware. Name/locale apply immediately; email/phone are verify-before-apply (a code is sent to the NEW value, change lands on confirm). If `Notify` is nil, phone change returns 503 so email change can ship before an SMS provider is wired.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/user/profile` | Read own profile: `firstName`/`lastName`/`email`/`phoneNumber`/`language`/`twoFactorEnabled` |
| POST | `/api/user/profile` | Update own `firstName`/`lastName`/`locale` immediately |
| POST | `/api/user/profile/email` | Request email change — code sent to the new email. Body `{value}` |
| POST | `/api/user/profile/email/confirm` | Apply email change. Body `{value, code}` |
| POST | `/api/user/profile/phone` | Request phone change — code via SMS (503 if `Notify` unset). Body `{value}` |
| POST | `/api/user/profile/phone/confirm` | Apply phone change. Body `{value, code}` |

### Session security policy

Password changes, 2FA setup or removal, and trusted-device revocation invalidate every active refresh token for the user. `SingleDeviceOnly` enforces one active session by revoking other sessions at sign-in; `MaxActiveSessionsPerUser` bounds active sessions when multiple devices are allowed.

### Registering Public Routes

`PublicHandler.GetPublicRoutes()` returns the unauthenticated login, registration and password routes so a downstream mounts them in one call instead of listing each path. Routes whose handler needs `Secrets` (Google login) or `RegisterService` (registration, password forgot/change/reset, plans) are only included when that field is set, so a partially wired handler never mounts a route that would panic:

```go
publicHandler := handler.PublicHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
    RegisterService: registerSvc,
    Secrets: secrets, // Google OAuth client-secret provider
}
srv.Handle(publicHandler.GetPublicRoutes())
```

| Method | Route | Handler | Description |
|--------|-------|---------|-------------|
| POST | `/public/login/local` | `LoginLocal` | Username / password login |
| POST | `/public/login/gmail` | `LoginGoogle` | Google OAuth code login |
| POST | `/public/register` | `AddRegistrationRequest` | Start registration, emails the confirmation code |
| POST | `/public/register/confirm` | `ConfirmRegistration` | `?email=&code=` completes registration and returns the session tokens |
| POST | `/public/register/exchange` | `ExchangeHandoff` | `{code}` from `HandoffCode`; mounted when `Handoff` is set |
| GET | `/public/password/policy` | `GetPasswordPolicy` | Password rules for pre-submit validation |
| POST | `/public/token/refresh` | `RefreshToken` | `{refreshToken}` — rotates and returns a new pair; 401 on reuse |
| POST | `/public/logout` | `Logout` | `{refreshToken}` — revokes the token |
| POST | `/public/password/forgot` | `ChangePassword` | `{username}` — emails a reset code; 200 whether or not the user exists |
| POST | `/public/password/change` | `ChangePassword` | `{username, old_password, new_password}` — change after checking the old password |
| POST | `/public/password/reset` | `ConfirmPasswordChange` | `{username, code, new_password}` — completes the reset; `code` is a JSON string |
| GET | `/public/plans` | `ListPublicPlans` | Public plan catalog |

`forgot` and `change` share one handler: an empty `old_password` selects the reset-by-email path. Public routes sit under `/public`, outside the `/api` prefix that `SSOMiddleware` gates — a client calling `/api/v1/public/...` hits the bearer check, not the route.

`username` on login and on the three password routes is the account's
`user_name` or, when it contains `@`, its `user_email` (`user_name` wins).

This is an opt-in route map over existing handlers; it does not change their
request contracts. In particular, an `email` field on `forgot` and `{token, new_password}`
on `reset` are not supported by these handlers. Clients must use the documented
username/code flow or retain their application-specific adapter. Keep custom
routes instead of replacing them wholesale when their contracts differ.

### Registering Security Routes

`SecurityHandler` provides `GetPublicRoutes()` and `GetAuthRoutes()` methods that return route maps. Any project using keel can register them:

```go
securityHandler := handler.SecurityHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
}
srv.Handle(securityHandler.GetPublicRoutes())  // /public/2fa/*
srv.Handle(securityHandler.GetAuthRoutes())    // /api/user/2fa/*, /api/user/trusted-device/*
```

### Database Tables

These tables must exist (defined in `schema/core/`):

| Table | Purpose |
|-------|---------|
| `user_account` | `twofa_enabled`, `twofa_method`, `twofa_secret`, `twofa_backup_codes`, `twofa_enabled_at`, `passtext` (nullable — NULL = social/OTP-only), `deleted_at` (nullable — set by `DeleteAccount`), `status` (`A`/`X`/`E`/`S`/`I`/`D`). |
| `user_trusted_device` | `device_fingerprint`, `device_name`, `trusted_at`, `expires_at` (30-day), `last_seen_at` |
| `user_registration` | Reused for login tokens (`payload='LOGIN'`, 5-minute expiry) |

### Account-deletion semantics

`DeleteAccount` is a **soft delete**, not a hard DELETE. Ride history, invoices, payment records, audit rows — anything that FK's back to `user_account(id)` — stays pointing at the same row. What changes: PII is anonymized (`first_name`→`Deleted`, `last_name`→`User`, `user_email`→`deleted+<id>@local.invalid`, `phone`→NULL, `passtext`→NULL, 2FA cleared, `user_name`→`deleted-<id>`), status flips to `'D'`, `deleted_at` stamps, all refresh tokens revoked, trusted devices deleted, social-provider links deleted and the provider grants they kept revoked (see Revoking Sign in with Apple), `UserActivityDelete` history row written with the supplied reason.

`DeleteAccount` also sets `user_account.tokens_valid_after`, so `ParseJWT` rejects every access token issued before it (`RevokeAccessTokens` does this alone; nodes cache the cutoff for `access_revocation_cache_ttl` seconds and fail closed when it cannot be read). It refuses with `user.ErrLegalHold` (409 on the account endpoint) while `user_legal_hold` has an unreleased row for the user. For a full, audited erasure across application tables, see the `erasure` package.

Consumers that own domain tables cascading off `user_id` (e.g. profiles, history rows, payment records) should implement their own `DeleteAccount` wrapper that runs keel's method plus their cascade in a coordinated flow.

## OTP Authentication (Phone/Email)

Keel includes OTP-based authentication for mobile-first applications. Users can sign in or register using a one-time code. Phone numbers are first-class values: raw user input (e.g. `(416) 555-1234`, `416-555-1234`, `+14165551234`) is normalized to E.164 before lookup or insert, and phone registrations write to `user_account.phone` directly (no external-identity row).

### OTP Flow

```
1. POST /public/otp/send
     { "contact": "(416) 555-1234", "purpose": "register", "defaultRegion": "CA",
       "policyVersion": "v1", "consents": {"privacy_policy": true, "cross_border": true} }
   → server normalizes contact to "+14165551234", creates user with passtext=NULL
     (purpose=register only), records consent if ConsentService is registered.
   Response: { "otpToken": "<32-byte base64>" }

2. Backend generates 6-digit code, stores with 2-minute expiry, sends via NotificationService.

3. POST /public/otp/verify    { "otpToken": "<from step 1>", "code": "847291" }
   Response: { "token": "jwt...", "userId": 42, "partnerId": 1 }
```

`purpose` values: `login` (lookup-or-noop on unknown phone), `register` (lookup-or-create via `GetOrCreateUserByPhone`), `verify` (explicit contact verification). `defaultRegion` is the ISO country code used as a hint when parsing local-format numbers — defaults to `"US"`.

The `otpToken` is a server-issued opaque value (32 random bytes, base64-URL) bound in `Cache` to the user_id for `OTPTokenTTL` (5 minutes). Verify and Resend require the token; an attacker who guesses arbitrary user_ids cannot reach the verify path because the cache lookup fails. The login path returns the same response shape on unknown phone (no SMS dispatched), so an attacker cannot enumerate registered numbers by comparing 200 vs 404.

### OTP Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/public/otp/send` | Generate and send OTP. Rate limited per `otp_send_window` (default 10 min): `otp_send_per_contact` (default 3, keyed on the E.164 form so unnormalized variants share the quota) AND `otp_send_per_ip` (default 10, mitigates SMS-pumping across enumerated numbers). A cap of 0 disables it and journals a warning on every send. |
| POST | `/public/otp/verify` | Verify OTP code, returns JWT on success (max 5 attempts) |
| POST | `/public/otp/resend` | Clear and regenerate OTP for an existing session |
| POST | `/api/user/reauth/send` | Signed in: send a `reauthCode` to the email (default) or phone on file. Body `{"channel": "email"\|"phone"}`; returns `{channel, resendCountdownSec}`. Shares the per-contact and per-IP caps. |

### Registering OTP Routes

```go
otpHandler := handler.OTPHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
    NotificationSvc: notificationSvc,
    Cache:           cacheService,
    Brand:           "Acme", // shown in the OTP SMS/email; empty = brand-less
    // Optional overrides ("{code}" → the OTP). The SMS default already carries
    // "Reply STOP to opt out, HELP for help." for 10DLC; register that exact
    // string with your campaign, or pin it explicitly:
    // OTPSMSTemplate: "Your Acme code is {code}. Reply STOP to opt out, HELP for help.",
}
srv.Handle(map[string]func(w, r){
    "/public/otp/send":   otpHandler.SendOTP,
    "/public/otp/verify": otpHandler.VerifyOTP,
    "/public/otp/resend": otpHandler.ResendOTP,
})
srv.Handle(otpHandler.GetAuthRoutes())  // /api/user/reauth/send
```

### Database Tables

| Table | Purpose |
|-------|---------|
| `user_otp` | `user_id`, `code` (6-digit), `purpose`, `expires_at` (2 min), `attempts` (max 5) |

## Social Login (Google & Apple)

Keel supports social login via Google and Apple ID tokens. The handler verifies the token and passes a `user.ExternalIdentity` containing the exact issuer, subject, provider label, email claims and Google `hd`.

### Sign-in ladder

```
POST /public/login/social  { "provider": "google", "token": "eyJhbG..." }

1. Verify the ID token against the provider's JWKs (RS256, issuer, audience, nonce).
2. GetOrCreateUserFromSocial(identity, consent):
     a. Identity linked on (issuer, subject)?               → sign in that account.
     b. An account owns the email and Google or Apple
        verified it?                                       → link and sign in.
     c. An account owns the email otherwise?                → 409 identity_not_linked.
     d. No account                                          → create account + link atomically.
3. Return the token pair.
```

Google and Apple link to an existing account by verified email, whatever its mail domain (Gmail, a Google Workspace domain, or any other address they verified), so a user who registered with an email can sign in with either provider, provided the account proved that email (`user_account.email_verified_at`). An unverified email, an Apple private-relay address, or an email asserted by any other issuer never selects an account: the owner signs in another way and calls `LinkSocial`, which requires re-authentication (`RecentAuth`) and a fresh provider token. A new account stores the email only when Google or Apple verified it.

`email_verified_at` and `email_verification_method` (constant `email_verification_method`) are set when the user proves the mailbox: `O` email code, `R` registration confirmation, `C` contact change, `P` password reset, `G`/`A` an account created by Google or Apple, `X` a proof the application made and recorded with `MarkEmailVerified`, and `L` a legacy verified record. An email typed at phone signup or at email-OTP registration stays unverified until its code is entered, so a planted account cannot capture the real owner's Google or Apple sign-in. `UserService.MarkEmailVerified` records a proof made elsewhere.

`LoginGoogle` (`/public/login/gmail`, OAuth code) follows rules (a) to (c) through `GetUserFromExternal` and never creates an account. A locked, expired or deleted account is refused with `ErrAccountUnavailable` (403).

Socially created accounts carry `passtext = NULL`; a password login against such an account is rejected before bcrypt runs.

### Service API

```go
GetUserFromExternal(identity user.ExternalIdentity) (*model.UserSession, error)
GetOrCreateUserFromSocial(identity user.ExternalIdentity, signupConsent *user.SignupConsent) (session *model.UserSession, created bool, err error)
LinkExternalIdentity(userID int, identity user.ExternalIdentity) error
```

Errors: `ErrIdentityNotLinked` (409), `ErrIdentityLinked` (409: the identity belongs to another account, or the account already has one from this issuer), `ErrAccountUnavailable` (403), `ErrNoAccount`.

### Email normalization

Every email read/write goes through a private `normalizeEmail` helper (lowercase + trim) at the service boundary: `GetUserByEmail`, `GetOrCreateUserFromSocial`, `insertUserAccount`, and the `RegistrationService` paths (`SendConfirmation`, `Register`, `SendPasswordChangeConfirmation`, `ConfirmPasswordChange`). Result: `Foo@Gmail.com` at password signup and `foo@gmail.com` from a Google ID token collapse to the same canonical row instead of silently creating duplicates.

### Audit trail

Every social-create, social-re-auth, phone-create, and phone-re-auth path now writes a `user_account_history` row:

- `UserActivityCreate` with object name `social:<provider>` or `phone` on first signup.
- `UserActivityLogin` with the same object name on subsequent re-auths.

`user_account_history.action_type` is a one-character code: `C` create, `L` login, `F` failed login, `O` logout, `X` lock, `U` unlock, `P` password, `D` delete, `M` profile change, `N` contact change (object name = `email` / `phone`). The `user_action_type` constant domain labels them in CRUD screens.

Combined with the password-login history that was already written by `GetUserByLogin` / `GetUserByEmail`, every authenticated session in the system now leaves an audit-trail entry — answering "when did this user first sign in?" and "when did this social-only user last log in?" without ambiguity.

### Empty contact fields → SQL NULL

`insertUserAccount` converts an empty `email` or `phone` to SQL `NULL` rather than the empty string. The UNIQUE indexes described next treat NULL as distinct, so multiple accounts can legitimately have no email or no phone without colliding. `user_account.user_email` is nullable; phone-OTP and Apple "Hide My Email" flows that have no usable address rely on this.

### Duplicate prevention — UNIQUE indexes on email and phone

`schema/core/user_account.yml` declares two unique indexes:

| Index | Column | What it prevents |
|---|---|---|
| `user_account_email_uq` | `user_email` | Two active accounts with the same canonical email |
| `user_account_phone_uq` | `phone` | Two active accounts with the same E.164 phone |

Combined with the entry-point normalization (`normalizeEmail` lowercases + trims; `normalizePhone` rewrites to E.164), the indexes guarantee at most one active account per contact value. `INSERT` failures are surfaced as typed sentinel errors so callers can route the user to a "sign in instead" flow:

```go
_, err := userSvc.GetOrCreateUserFromSocial(...)
if errors.Is(err, user.ErrDuplicateEmail) { ... }
if errors.Is(err, user.ErrDuplicatePhone) { ... }
```

Soft-deleted accounts (`status='D'`) don't compete for the index — `DeleteAccount` rewrites email to `deleted+<id>@local.invalid` (unique per id) and phone to `NULL` (multiple NULLs allowed). A user can re-register with the same email/phone after deletion.

**Not yet handled:** if two accounts already exist for the same person (one created via email-password, another via phone-OTP) and the user wants to merge them or add the missing contact to an existing account, keel has no built-in flow for that. The UNIQUE indexes prevent *new* duplicates from being created via the standard `GetOrCreateUserFromSocial` / `GetOrCreateUserByPhone` / registration paths, but they do not resolve duplicates that already exist or back a "verified add" flow. That is intentionally deferred until a consumer requires it.

### Social Login Endpoint

| Method | Path | Description |
|--------|------|-------------|
| GET | `/public/login/social` | Issue the single-use nonce the ID token must carry |
| POST | `/public/login/social` | Authenticate via provider ID token (Google or Apple) |
| POST | app-chosen authenticated path | `LinkSocial`: link a provider identity to the signed-in account |

### Enabling providers

A provider is enabled by its client id: `google_client_id` enables Google, `apple_client_id` enables Apple, and a provider without one answers 400 `provider_not_enabled`. The setting is application-wide, not per partner; `application_config_value` can give each node its own id. The Google OAuth code flow (`LoginGoogle`) uses the same id with the `google_client_secret` secret.

Verification lives in `oauth/oidc`: `SocialLoginHandler.Verifier` (an `oidc.SocialVerifier`) checks the ID tokens, and `PublicHandler.GoogleCode` (an `oidc.GoogleCode`) redeems `LoginGoogle`'s code without following redirects. Both are nil by default, which uses Google's and Apple's published endpoints; tests and applications with their own key sets set them.

### Revoking Sign in with Apple

Apple expects an app to revoke the user's Sign in with Apple grant when the account is deleted. Revocation needs an Apple refresh token, which only the authorization code yields, so wire `oidc.AppleGrants`:

```go
sealer, _ := crypto.NewSealer(ctx, secrets, "apple_grant_kek")
apple, err := oidc.NewAppleGrants(ctx, secrets, sealer)
socialHandler.Apple = apple       // Apple sign-in and LinkSocial require "code"
userService.GrantRevoker = apple  // DeleteAccount revokes the stored grant
userService.Journal = journal     // a failed revocation is logged here
```

With `Apple` set, an Apple `POST /public/login/social` or `LinkSocial` must carry the authorization code beside the ID token (`{"provider":"apple","token":…,"code":…}`); a missing code is 400 and a code Apple refuses, or one issued to another Apple account, is 401. The refresh token is sealed and kept in `user_external_identity.provider_grant`; a later sign-in with a code replaces it. `DeleteAccount` revokes it after the deletion commits; a failed revocation does not undo the deletion and is written to `Journal`. Set `RedirectURI` when the code comes from the web flow.

| Flag | Default | Purpose |
|---|---|---|
| `apple_team_id` | `` | Team id that signs the client secret (JWT `iss`) |
| `apple_key_id` | `` | Key id of the Sign in with Apple `.p8` key |
| `apple_key_secret` | `apple_key` | Secret name holding the `.p8` PEM |

### Requiring SSO

`user_account_policy` rows are global when `partner_id` is NULL and otherwise apply to that partner's users; a partner's own row overrides the global one for each policy type, and `UserService.EffectivePolicies(partnerID)` returns them resolved that way. Only platform roles can write policy rows as seeded.

The policy type `SSO_REQUIRED` takes three values:

| Value | Admits |
|---|---|
| 0 | Every sign-in method |
| 1 | Any external identity: Google, Apple or the partner's own identity provider |
| 2 | Only the partner's own identity provider |

A sign-in counts as the partner's own identity provider (`sign_in_method` `T`) when it comes through the partner's active connection (see Tenant Single Sign-On), or when it is a Google Workspace account whose hosted domain the user's partner holds by identity-grade domain evidence; wire `LocalUserService.TenantDomains` to the `domain.Service` to enable the latter. A personal Google or Apple account is `E` and does not satisfy value 2.

`CheckSignInMethod(userID, method)` resolves the user's partner and the policy in one lookup and refuses with 403 `sso_required`; a failed lookup refuses too. keel calls it at password sign-in, at one-time-code sign-in, at Google and Apple sign-in and again when a 2FA step completes. A downstream login handler must call it, and set `session.SignInMethod`, before `SessionTokens`. Each session records its method, and a refresh is refused once the policy no longer admits it, so tightening the policy ends other sessions at their next refresh; a session without a method is admitted only by value 0.

The password rules (`MIN_PASSWORD_*`, `MAX_ATTEMPTS`, `AUTO_UNLOCK_MINUTES`, `PASSWORD_EXPIRE_DAYS`) `SESSION_MAX_HOURS` and `SSO_JIT_CREATE` resolve the same way. A failed policy lookup refuses the operation instead of falling back to the global rules. `GetPasswordPolicy` and `/public/password/policy` report the global rules.

### Registering Social Login Routes

```go
socialHandler := handler.SocialLoginHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
}
srv.Handle(map[string]func(w, r){
    "/public/login/social": socialHandler.LoginSocial,
})
// authenticated mux
srv.Handle(map[string]func(w, r){
    "/api/v1/user/social/link": socialHandler.LinkSocial,
})
```

### Database Tables

| Table | Purpose |
|-------|---------|
| `user_external_identity` | External links keyed by `(issuer, subject)`, with one identity per issuer per account. `provider` is only the adapter/UI label; `provider_grant` is a sealed provider refresh token revoked on account deletion. Phone registrations remain in `user_account.phone`. |
| `user_account.passtext` | Nullable. NULL means "this account authenticates via social/OTP only; password login is disabled." |
