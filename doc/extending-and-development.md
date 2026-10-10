# Extending and Developing Keel

Extension points, repository structure, security expectations, contribution workflow, and development standards.

## Extending Keel

### UserService

Keel provides a full `UserService` implementation with:
- **Password auth** with policy enforcement (complexity, expiry, lockout)
- **JWT** token creation and parsing
- **2FA (TOTP)** setup, verify, disable, backup codes
- **Refresh tokens** with revocation
- **Trusted devices** with 30-day expiry
- **OTP authentication** (phone/email) with rate limiting
- **Social login** (Google, Apple) via `GetOrCreateUserFromSocial` — issuer-and-subject links, linking by Google- or Apple-verified email, atomic account creation, authenticated `LinkSocial`, NULL `passtext` for social-only accounts
- **Phone-first auth** via `GetOrCreateUserByPhone` — E.164 normalization (libphonenumber), `phone` stored in `user_account.phone` directly (no external-identity shim), `passtext=NULL` on OTP registrations
- **Session hygiene** — `SetPassword`, `Setup2FA`, `Disable2FA`, `RevokeTrustedDevice` automatically revoke all active refresh tokens; public `LogoutEverywhere(userID)` for explicit "log out of all devices"
- **Single-device policy** — `SetSingleDevicePolicy(userID, on)` primitive; when on, `CreateRefreshToken` revokes all prior tokens on issue (e.g. drivers must be signed in on one device at a time)
- **Account deletion** — `DeleteAccount(userID, reason)` anonymizes in place, revokes tokens, drops trusted devices, deactivates device tokens, drops external-identity links; App Store / Play Store compliant
- **Consent capture** — optional `port.ConsentService` called from signup flows; PIPEDA / GDPR audit trail in `consent_policy` + `consent_event` tables
- **Push notifications (FCM)** — channel-keyed `port.MessageDispatcher` (FCM and `NoOp` push impls ship; email adapter wraps `MailClient`), `device_token` table, register/revoke endpoints, stale-token auto-deactivation. `port.PushProvider` is now a deprecated alias of `MessageDispatcher`.

`RegistrationService` creates an account and its partner (`business_partner`, `partner_address`, `partner_domain`, `partner_user`, roles, subscription) in one transaction:
- `SendConfirmation(ctx, *PartnerRegistration)` then `Register(ctx, email, code)` — signup by emailed code. The account is active with the email verified (`R`), and the session signed in by one-time code. A registration with no partner field creates only the account. A global `SSO_REQUIRED` policy refuses it with `ErrSSORequired`, and a `userName` containing `@` must equal the email.
- `CreatePartner(ctx, userID, *PartnerSetup, evidence)` — the second step of a two-step signup, for a signed-in user without a partner (`ErrAlreadyMember` otherwise).
- `RegisterWithIdentity(ctx, identity, consent, *PartnerSetup, evidence)` — signup with an external identity the caller verified, account and partner in one transaction through `IdentityAccountCreator` (implemented by `LocalUserService`); the session carries `ExternalSignInMethod`. An identity or email of an existing account returns `ErrAccountExists`. Consent is recorded after commit; its failure returns `ErrConsentNotRecorded` with the other results valid.

Blank optional `PartnerSetup` address fields (city, state, zipcode, country, phone) and an unset `0, 0` coordinate pair are stored as NULL. `country` and `state` are trimmed and upper-cased; a code missing from `country` / `state`, or a state without a country, is a 400 before any write.

The sessions `Register` and `RegisterWithIdentity` return passed `CheckSignInMethod`. Composition fields:

| Field | Effect |
|---|---|
| `Users` | Password and sign-in policy, sessions. Required for signup |
| `Domains`, `RequireDomainProof` | `evidence` from `Domains.Check` is recorded by `RecordTx` in the partner transaction; without it the account's verified email proves the domain (`VE`) when it can. `RequireDomainProof` requires every partner to have a proven domain, and `SendConfirmation` refuses a mailbox off it; without it the domain is optional |
| `Roles` | Granted to the creator; each must be `partner_scoped`. Nil grants `PARTNER_ADMIN` |
| `EmailPolicy` | Screens an emailed-code signup address; `user.BusinessEmail` refuses free mailboxes |
| `OnPartnerTx` | Writes the application's rows in the partner transaction; `PartnerSetup.Extra` carries its fields. Bind the application's queries with `port.TxQueryCatalog` |
| `Checkout`, `CheckoutSuccessURL`, `CheckoutCancelURL` | Opens the checkout of a plan that activates at checkout, priced by the offer's `provider_price_id`, with the metadata `billing.NewProviderSubscriptionEventHandler` reads |

The plan's `activation_mode` decides the subscription: a free offer or `F` plan is active at once, `P` inserts a pending row that checkout activates, and `A` and `T` leave the row to checkout. `PaymentRequired` then sends the client to `PaymentURL`, or to the billing page when no checkout client is set. A checkout failure after the partner exists returns `ErrCheckout` with the other results valid.

`PublicHandler.GetAuthRoutes(apiPrefix)` mounts `POST {apiPrefix}/register/partner` (`CreatePartner`, body `PartnerSetup`). A redirect-based provider signup hands the session to the browser with `PublicHandler.HandoffCode(ctx, session)`: a single-use code, valid for `signin_handoff_ttl` (default five minutes), that `/public/register/exchange` trades for tokens after re-checking the account, the sign-in policy and 2FA.

Use the built-in `LocalUserService` directly:

```go
userSvc, _ := user.NewLocalUserService(ctx, db, jwtSecret, "myapp")
```

Or embed it to add project-specific methods:

```go
type MyUserService struct {
    *user.LocalUserService
    customQS port.QueryService
}
```

### Custom Handlers

Embed `handler.AbstractHandler` to get JWT parsing and a set of common request-handling helpers for free:

```go
type MyDomainHandler struct {
    handler.AbstractHandler
    MyService *MyDomainService
}

func (h *MyDomainHandler) UpdateItem(w http.ResponseWriter, r *http.Request) {
    if !h.RequireMethod(w, r, http.MethodPost) { return }   // 405 if not POST
    id, ok := h.RequireQueryInt64(w, r, "id")
    if !ok { return }                                       // 400 if missing/invalid
    var req UpdateItemReq
    session, ok := h.ReadAuthRequest(w, r, &req)
    if !ok { return }                                       // 401 (no JWT) / 400 (bad body)
    if !h.RequireFields(w, map[string]string{"name": req.Name}) {
        return                                              // 400 lists missing field names
    }
    item, err := h.MyService.Update(r.Context(), session.PartnerId, id, req)
    if err != nil {
        h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
        return
    }
    common.WriteJSON(w, http.StatusOK, item)
}
```

#### AbstractHandler request helpers

All methods are stateless — they only inspect the JWT or request context and write the canonical RFC 7807 envelope via `h.WriteError`. Every handler that embeds `AbstractHandler` inherits them automatically.

| Method | Purpose |
|---|---|
| `ParseSession(r)` | Returns the JWT session, or nil. Read-only — no error envelope. |
| `GetUser(r) / GetPartner(r)` | Convenience accessors; -1 when absent. |
| `RequireSession(w, r) (*Session, bool)` | 401 if no session. Use when you need the full session. |
| `RequireUser(w, r) (int, bool)` | 401 if no user id. |
| `RequirePartner(w, r) (int64, bool)` | 401 if `partner_id <= 0`. |
| `SessionPartner(session) (int64, error)` | Same rule for a `JSONFunc`, which has a session and no writer; the error is a 401 `*APIError`. |
| `ReadRequest(w, r, &req) bool` | `MaxBytesReader(config.Config().MaxRequestSize)` + JSON unmarshal; 400 on failure. Public endpoints. |
| `ReadAuthRequest(w, r, &req) (*Session, bool)` | `RequireSession + ReadRequest` combined. Authenticated endpoints with a JSON body. |
| `RequireMethod(w, r, methods...string) bool` | 405 + `Allow` header if `r.Method` doesn't match any of the allowed methods. One-line guard for HTTP-method-restricted handlers. |
| `RequireQueryInt64(w, r, name string) (int64, bool)` | Reads `?name=<int>` from the URL, parses to int64. 400 on missing or unparseable value. |
| `RequireFields(w, fields map[string]string) bool` | 400 listing any empty (after `TrimSpace`) values. |
| `PartnerFromCtx(r) int64` | Reads `common.PartnerID` from the request context (injected by `APIKeyMiddleware` for `/pubapi/*` traffic). -1 when absent. |
| `HasScope(r, scope) bool` | Checks the API key's `common.Scopes` context value. |
| `RequireScope(w, r, scope) bool` | 403 if scope missing. |
| `WriteError(w, status, title, detail)` | RFC 7807 problem+json envelope writer used by every method above. The single canonical error path — handlers should never call `http.Error`. |

In-repo demos: [handler/rest_handler.go](../handler/rest_handler.go) `Post` uses `ReadRequest`. [handler/payment_handler.go](../handler/payment_handler.go) keeps a bespoke 256 KiB cap for webhook traffic — that's a deliberate exception, not a pattern to copy. [handler/document_handler.go](../handler/document_handler.go) uses `RequireMethod`.

#### Query-result projection

`*model.QueryResult` carries a `.AsMaps()` method that projects rows into `[]map[string]any` keyed by `Columns`. Useful when a handler needs to JSON-encode an ad-hoc query response without defining a typed model:

```go
res, _ := qs.Query(ctx, "list_active_partners")
common.WriteJSON(w, http.StatusOK, res.AsMaps())
```

Returns an empty slice (not nil) when there are no rows, so JSON encoding always emits `[]`.

## Directory Structure

```
keel/
├── cmd/
│   └── schemagen/             # CLI: YAML schema → DDL + seed SQL
├── common/                    # Type helpers, HTTP response envelope, shared HTTP client, flag variables
├── domain/                    # Domain names and domain verification service + verifiers
├── model/                     # Domain-agnostic data shapes (UserSession, TableDefinition, AppError, ...)
├── port/                      # Pluggable component interfaces (messaging, notification, quota,
│                              #   table change logger, web socket hub, ID generator)
├── data/                      # AbstractRepository, AbstractTableService, DatabaseRepository / TxView /
│                              #   QueryService interfaces, file TableLogger, SnowflakeGenerator
├── pgsql/                     # PostgreSQL adapter (pgx/v5): repository, table service,
│                              #   query service, tx-bound query service, tx view
├── schema/                    # YAML schema definitions + seed loader + schemagen model
│   ├── dependency.yml         # Component folders, FK dependencies, and seed dependencies
│   ├── core/                  # Startup config, UI/REST metadata, users, RBAC, and consent
│   ├── worker/                # Worker runtime registry
│   ├── geo/                   # Country, state, and county reference tables
│   ├── tenant_management/     # Business partners, users, addresses, domains
│   ├── oauth_server/          # OAuth clients, codes, refresh tokens
│   ├── api_key_management/    # Public API keys
│   ├── oauth_connect/         # Partner credentials and auth nonces
│   ├── sso/                   # Tenant identity provider connections, role mappings, SCIM provisioning
│   ├── subscription/          # Plans, prices, quotas, subscriptions, usage
│   ├── payment/               # Payment methods and payment webhook log
│   ├── payout/                # Bank information and payout webhook log
│   ├── outbox/                # Transactional outbox
│   ├── billing/               # Invoices, payments, and allocations
│   ├── agency/                # Agency clients, commissions, and payouts
│   ├── seed/                  # One <component>.yml seed file per table group
│   ├── dialect/               # DDL dialects: PostgreSQL, MySQL
│   ├── schema.go              # Schema model + parser + Validate
│   └── seed.go                # Seed-file parser + GenerateSeedSQL (FK-safe topo sort)
├── rest/                      # Metadata-driven REST engine + parent-child relation CRUD
├── handler/                   # AbstractHandler + login / 2FA / OTP / social / payment / push / REST / cache
├── user/                      # UserService interface + LocalUserService + RegistrationService +
│                              #   ConsentService
├── service/                   # APIKeyService + JWT/API-key middleware + HttpBackend + QuotaServiceDb
├── dispatcher/                # MailClient + LocalNotificationService + Email & Twilio dispatchers
├── worker/                    # JobExecutor + AbstractWorker one-call bootstrap
├── secret/                    # Local JSON / GCP Secret Manager / AWS Secrets Manager / Azure Key Vault / Infisical + factory
├── logger/                    # File / GCP Cloud Logging / AWS CloudWatch / Azure Monitor Logs + factory
├── clock/                     # Injectable time: Clock, System, Fake
├── limiter/                   # Fair slots, local and distributed partner×fleet rate limits
├── cache/                     # Redis / Valkey single-node + cluster + bounded memory fallback
├── storage/                   # S3 (AWS + Cloudflare R2) / GCS / Azure Blob
├── messaging/                 # GCP Pub/Sub + AWS SNS+SQS + NATS JetStream + factory
├── payment/                   # Stripe + LemonSqueezy webhook processor, signatures, parsers,
│                              #   SQL webhook log repo, Stripe Checkout client
├── billing/                   # SaaS billing: AbstractBillingService, lifecycle, BillingEngine,
│                              #   installment math, provider webhook→billing handler
└── push/                      # FCM + NoOp port.MessageDispatcher implementations + factory
```

## Role Matrix

```
A = Access    S = Select    I = Insert    U = Update    D = Delete
```

Keel defines 6 shared roles. Projects may add domain-specific roles (e.g., SEO_ADMIN, SEO_OPER).

### Principals — who a grant is evaluated for

Every permission check takes a `model.Principal` — `{Kind, ID, Scope}` — not a user id. `model.UserPrincipal(id)` is the built-in human subject, granted out of `user_permission`. `model.RolePrincipal(roleID)` is the role itself, checked directly against `authorization_role_permission` with the same `low_limit` and `bypass_scope` rules, for asking what a role may do without an assignment table. The zero `Principal` is never authorized.

To authorize non-human subjects (agents, service accounts, workloads), register where their grants live before repository `Init`, and inject the catalog:

```go
grants := data.NewGrantCatalog()
grants.Register("agent", data.GrantSource{
    Table:   "agent_permission",    // must carry role_id, begda, endda
    Subject: "agent_id",
    Filters: []string{"tenant_id"}, // bound from Principal.Scope, in order
})
repo.GrantCatalog = grants          // nil uses data.DefaultGrantCatalog

allowed, ownScope := db.CheckActionPermission(ctx,
    model.Principal{Kind: "agent", ID: agentID, Scope: []any{tenantID}},
    "REPORT", "RUN", "monthly_revenue")
```

To answer many questions for one principal, `db.ActionGrants(ctx, principal)` reads its grants in one query; the returned `model.GrantSet.Allows(object, action, scope)` gives the same answer as `CheckActionPermission`.

keel generates each kind's SQL from its `GrantSource`, so effective dating, the `low_limit` exact-or-`'*'` rule and `bypass_scope` cannot drift between kinds. A scope-arity mismatch fails closed; table and column names are validated as SQL identifiers at registration.

Non-human principals draw on the *same* roles and matrix below, out of their own assignment table. `IsGlobalRole(ctx, userID int)` stays user-specific: it decides row scoping beside the id used as the row filter, not who is acting.

| Type | Object | SUPER | APP_ADMIN | SECURITY_ADMIN | SECURITY_OPER | BUSINESS_ADMIN | PARTNER_ADMIN |
|------|--------|-------|-----------|----------------|---------------|----------------|---------------|
| PAGE | * | A | | | | | |
| TABLE | * | SIUD | | | | | |
| REPORT | * | A | | | | | |
| **Security** | | | | | | | |
| PAGE | authorization_roles | | A | A | A | A | |
| PAGE | authorization_objects | | A | A | A | A | |
| PAGE | user_accounts | | A | A | A | | |
| PAGE | user_account_policies | | A | A | A | A | |
| TABLE | authorization_role | | S | SIUD | S | S | |
| TABLE | authorization_role_permission | | S | SIUD | S | S | |
| TABLE | authorization_object | | SIUD | S | S | S | |
| TABLE | authorization_object_action | | SIUD | S | S | S | |
| TABLE | user_account | | S | SIUD | SIU | | |
| TABLE | user_permission | | S | SIUD | SIUD | | S |
| TABLE | user_account_history | | S | S | S | | |
| TABLE | user_account_policy | | S | SIUD | S | S | |
| TABLE | partner_user | | S | SI | S | | SI |
| **Framework** | | | | | | | |
| PAGE | application_menus | | A | A | A | A | |
| PAGE | constant_headers | | A | A | | A | |
| PAGE | foreign_key_lookups | | A | A | | A | |
| PAGE | rest_api_headers | | A | A | | A | |
| TABLE | application_menu | | SIUD | S | S | S | |
| TABLE | application_menu_item | | SIUD | S | S | S | |
| TABLE | constant_header | | SIUD | S | | S | |
| TABLE | constant_value | | SIUD | S | | S | |
| TABLE | constant_lookup | | SIUD | S | | S | |
| TABLE | foreign_key_lookup | | SIUD | S | | S | |
| TABLE | rest_api_header | | SIUD | S | | S | |
| TABLE | rest_api_child | | SIUD | S | | S | |
| TABLE | service_registry | | S | | | | |
| **Business Partner** | | | | | | | |
| PAGE | partner_registrations | | A | A | A | A | |
| PAGE | api_keys | | A | A | | | |
| TABLE | business_partner | | S | S | S | SIUD | SU |
| TABLE | partner_address | | S | | | | SIUD |
| TABLE | partner_domain | | S | | | | SIUD |
| TABLE | partner_domain_verification | | S | | | | S |
| TABLE | api_key | | S | S | | S | SD |
| **Subscriptions** | | | | | | | |
| PAGE | subscription_plans | | A | | | A | S |
| PAGE | subscription_resources | | A | A | | A | |
| PAGE | subscription_addons | | | | | A | |
| PAGE | partner_quota_usages | | | | | A | |
| TABLE | subscription_plan | | S | | | SIUD | S |
| TABLE | subscription_plan_price | | S | | | SIUD | S |
| TABLE | subscription_quota | | S | | | SIUD | S |
| TABLE | subscription_resource | | SIUD | S | | S | |
| TABLE | subscription_addon | | S | | | SIUD | |
| TABLE | partner_plan_subscription | | S | | | SIUD | S |
| TABLE | partner_addon_subscription | | S | | | SIUD | S |
| TABLE | usage_ledger | | S | | | S | S |
| **Payments** | | | | | | | |
| PAGE | payment_records | | A | | | A | A |
| PAGE | payment_methods | | A | | | A | A |
| PAGE | payment_webhook_logs | | A | | | A | |
| TABLE | payment_record | | S | | | S | S |
| TABLE | payment_method | | S | | | SIUD | SIUD |
| TABLE | payment_webhook_log | | S | | | S | |
| **Geo** | | | | | | | |
| PAGE | countries | | | | | | A |
| TABLE | country | | | | | | S |
| TABLE | state | | | | | | S |
| TABLE | county | | | | | | S |

## Status

Keel is under active development. Public interfaces and transport contracts
are kept stable within their documented compatibility boundaries; internal
implementations may change.

## Security

If you discover a security vulnerability in keel, please **do not open a
public GitHub issue.** Report it privately by emailing the maintainer; you
should expect an acknowledgement within 72 hours and a coordinated disclosure
timeline thereafter. Vulnerabilities in dependencies (pgx, jwt, redis,
firebase, AWS/GCP/Azure SDKs, Stripe webhooks) are tracked the same way.

## Contributing

Contributions are welcome via GitHub pull requests. A few ground rules:

- **Don't break method signatures.** Downstream consumers depend on the
  signatures of every exported function in `port/`, `service/`, `handler/`,
  `data/`, and `worker/`. Additive changes (new methods on a struct, new
  optional struct fields) are fine; renames, parameter reordering, and return
  shape changes are not.
- **Ports are minimal.** New interfaces in `port/` should expose the
  smallest surface that a consumer or implementation needs. Adapters in
  `service/<area>/` may carry richer types internally.
- **Write Go that gofmt is happy with.** Run `go vet ./...` and
  `go test ./...` before submitting. If you add a new adapter, include at
  least one no-op or in-memory test.
- **One logical change per PR,** with its documentation, role matrix, flag table and schema change in the same commit as the code.
- **Doc-comment every exported symbol.** This repo is the public surface for
  several downstream projects; opaque exports cost everyone time.
- **Follow the Development Standards below.** Every contribution — internal
  or external — is expected to honour the patterns the rest of the codebase
  has converged on. Reviewers will reject PRs that bypass them without a
  written rationale.

## Development Standards

Keel is Apache-2.0 licensed and consumed by multiple downstream projects plus the [sail](https://github.com/nauticana/sail)
Angular frontend. The following standards exist so contributions stay
predictable across all of those consumers and so the codebase grows without
turning into a yard sale of one-off patterns.

These are NOT suggestions. A PR that violates them needs to either fix the
violation or include a `Why:` paragraph in the description explaining the
constraint that justified the deviation.

### 1. Object-orientation via composition

Go has no classical inheritance, so "OOP" in keel means **struct embedding +
narrow interfaces**, applied in this fixed order:

1. **Abstraction** — every cross-cutting concern (HTTP handler base, webhook
   provider, payout provider, table service) has an `Abstract<Name>` struct
   that holds the shared state and methods.
   - `handler.AbstractHandler` — session parsing, RFC 7807 envelopes,
     request reading.
   - `handler.AbstractPaymentHandler` — webhook lifecycle + checkout
     redirect-host / price allowlist enforcement.
   - `payment.AbstractProvider` — provider Name / SignatureHeader / Verify
     / Parse plumbing shared by Stripe + LemonSqueezy.
2. **Inheritance** — concrete types embed the abstract by value (not by
   pointer) at the top of the struct declaration. Method promotion gives
   the "extends" feel without runtime cost.

   ```go
   type StripeProvider struct{ AbstractProvider }
   type UserPaymentMethodHandler struct{ AbstractHandler; … }
   ```

   Never re-implement a method the embedded abstract already provides —
   override it only when the concrete genuinely differs (e.g. Stripe's
   `setup_intent` mode in [payment/stripe_client.go](../payment/stripe_client.go)).
3. **Polymorphism** — consumers depend on **interfaces**, never on the
   concrete struct. Interfaces live next to the abstraction
   (`payment.PaymentProvider`, `payout.PayoutProvider`,
   `payment.SignatureVerifier`, `payment.EventParser`,
   `payment.CheckoutClient`, `payment.WebhookRepository`,
   `port.UserService`, etc.). New providers add a file, implement the
   interface, register themselves in the factory — nothing else
   changes. Airwallex, Stripe Connect, and Wise remain isolated provider
   implementations selected by [`payout/factory.go`](../payout/factory.go).

Every concrete type that implements an interface MUST include a
compile-time assertion at the bottom of the file:

```go
var _ payout.PayoutProvider = (*AirwallexProvider)(nil)
```

This catches drift the moment the interface evolves — the build fails
where the contract breaks, not at runtime in a downstream project.

### 2. Don't reinvent the standard library

Reaching for a homegrown utility when `strings`, `strconv`, `path`, `net/url`,
or `net/http` already covers the case is a regression. Some patterns we keep
catching in review:

| Don't write                | Use instead                              |
|----------------------------|------------------------------------------|
| local `upper(s string)` / `toUpperASCII` | `strings.ToUpper(s)`              |
| local `equalFold`          | `strings.EqualFold(a, b)`               |
| manual last-segment split  | `path.Base(urlPath)`                    |
| string-concat URL building | `url.URL{}` / `url.Values.Encode()`     |
| `time.Now().Sub(t).Abs()` reimplemented | `time.Since(t)` / `Sub` then abs |

Exception: helpers that genuinely don't have a stdlib equivalent (e.g.
`common.AsInt64`, `common.PascalCase`) belong in
[common/functions.go](../common/functions.go) and are reused everywhere.

### 3. No magic strings — constants and `constant_header`

Two distinct tools, two distinct purposes. Get them right.

**Code-level constants** for any literal that's referenced from more than
one place or carries semantic meaning (provider names, status codes, event
types, URL prefixes, header names). They live in the package they describe:

```go
// payment/webhook_repository_sql.go
const (
    StatusReceived  = "R"
    StatusProcessed = "P"
    StatusFailed    = "F"
    StatusDuplicate = "D"
    StatusSkipped   = "S"
)

// payout/airwallex.go
const airwallexCode = "AW"
```

If a literal appears in more than one file in a package, hoist it to a
package-level `const` block. If it appears in more than one package, it
belongs in [common/variables.go](../common/variables.go) (configuration) or
the relevant `port/` interface file (protocol-level constant).

**`constant_header` / `constant_value` tables** are the runtime equivalent
for domain enumerations that the **UI** has to render — order status,
payout provider code, payment method type, country code. Sail reads these
through `GetClientCache` and auto-renders dropdowns; the Go side reads them
through `RestService.GetConstantCache`. Always add a `constant_header` row
+ `constant_value` rows + a `constant_lookup` row pointing the column at
the header — never hardcode the dropdown options in TypeScript.

The two complement each other: the `const` block in Go enforces type-safety
at compile time; the `constant_header` row makes the same value editable
through the admin UI without a redeploy. New domain enums add both.

### 4. Flag variables for every deployable knob

Anything an operator might want to change between environments — host,
port, credential location, feature toggle, provider selector, return URL —
goes through `flag` in [common/variables.go](../common/variables.go).

Rules:

- One flag per knob. Don't overload a single flag with multiple meanings.
- Documented default that's safe for local dev. `cors_origin` defaults
  to empty (deny all); `--secret_mode` to `local`; `push_mode` to `noop`.
  Deny-by-default beats permissive defaults that bite you on a fresh
  install.
- Doc-comment **at the variable declaration** explaining what it does,
  what the valid range is, what depends on it, and what the consequence of
  the empty/zero value is. The flag's `Description` argument is short
  user-facing help; the Go doc-comment is the engineering reference.
- Add a corresponding row to the [Flag Variables](data-and-infrastructure.md#flag-variables) table
  so downstream consumers can `Cmd-F` for it.
- Validate combinations at startup, not at first-use. `common.MustRequireTrustedProxyCIDR`
  is the pattern: fail fast in `main`, not on the first signed-in user.

**Flags, never environment variables.** keel does NOT read `os.Getenv` for
configuration anywhere. Every deployable knob is a `flag.*` declaration in
[common/variables.go](../common/variables.go), period. The reason is uniformity:
one override surface (`--flag=value`), one place to grep, one table in this
README that documents the whole set. If you find yourself reaching for
`os.Getenv`, stop and declare a flag instead. A PR that adds an env-var
read will be rejected.

### 5. SQL: parameterised, cached, schema-aware

- **No string-built SQL.** Every query goes through
  `data.QueryService.Query(ctx, queryName, args...)` with a query map
  registered once per package (see
  [payment/webhook_repository_sql.go](../payment/webhook_repository_sql.go) for
  the canonical shape). The placeholder rewriter handles `?` → `$N` per
  driver. It does not coerce argument types: pgx cannot bind a Go integer to
  a text-typed parameter, so a `?::text` placeholder that receives an `int`
  fails at run time — cast in SQL instead (`?::bigint::text`).
- **`TableService.Update` is full-row.** A map that omits a column writes NULL
  to it. To change a subset of columns call
  `TableService.Patch(ctx, partnerID, userID, key, changes)`: only the listed
  columns move, `U` stamps are applied, and naming a key, scope, or
  read-only column is an error.
- **Typed constraint errors.** `pgsql.IsUniqueViolation(err)` /
  `pgsql.IsForeignKeyViolation(err)` detect SQLSTATE 23505 / 23503 through
  the wrap chain; map them to a sentinel in the service, never substring-match
  the message.
- **Cache the QueryService** with `sync.Once` at the struct level
  (see `SQLWebhookRepository`). Re-rewriting the same query map per call
  burns CPU on the hot webhook path.
- **Idempotency via unique indexes**, not application-side checks.
  Concurrent retries from a payment provider WILL race the cheap-path
  existence check; the unique-index insert is the authoritative gate
  (SQLSTATE 23505 → treat as duplicate, see
  [payment/webhook_processor.go](../payment/webhook_processor.go)).
- **`UserSpecific` / `PartnerSpecific` row scoping** is automatic via the
  table flag. A table is `PartnerSpecific` when its `partner_id` column
  references `business_partner` (`PartnerTableName`), directly or through the
  `partner_id` of another `PartnerSpecific` table at any depth, as any column of
  a composite key; so a composite child needs no direct partner key. A table
  that references the partner through another column (`agency_partner_id`,
  `client_partner_id`) is multi-actor and is not scoped: grant its generic
  CRUD to global roles only. Don't re-implement scoping in raw SQL unless the operation
  legitimately crosses actors (e.g. `OnboardingService.ListReusableAccounts`
  spans partners by design).

### 6. HTTP handlers: thin, RFC-compliant, deny-by-default

- Embed `AbstractHandler`. Use `RequireSession`, `RequireMethod`,
  `ReadAuthRequest`, `WriteError`, `WriteJSON` — not their hand-rolled
  equivalents. If you find yourself reading `Authorization` directly,
  stop and use `ParseSession`.
- `WriteError` passes a 4xx `detail` through (validation messages are
  intentionally user-facing). `WriteServiceError` never sends `err.Error()`:
  the client gets the registered message, else the registered sentinel's own text, else the
  `*model.AppError`'s `Message`, else the status text, and `AppError.Code`
  fills `code` when no registration sets one; the full cause (with
  `AppError.Detail`, which is never serialized) is logged at warning with the
  `request_id` and user (`-1` when unavailable). 5xx responses replace `detail` with a generic message
  and surface a `request_id` so the user-visible error correlates to the
  application log.
- **Allowlists default to empty = deny.** `AllowedPriceIDs`,
  `AllowedRedirectHosts`, `AllowedEventTypes`, `TrustedProxyCIDR` — every
  one of these is permissive ONLY when the operator explicitly populates
  it. A zero-value struct should never be exploitable.
- Mount custom table-row actions through `WrapTableAction` (see
  [handler/table_action_middleware.go](../handler/table_action_middleware.go))
  so the authorization gate is consistent with the generic-CRUD path.
  Don't reimplement `CheckActionPermission` per handler.

### 7. The sail (Angular frontend) contract

Sail consumes keel JSON shapes directly. Breaking the wire contract breaks
sail with no compile-time signal, so the following are HARD constraints:

- **PascalCase JSON keys** for every table row and `model/` struct that
  rides the wire (`Id`, `PartnerId`, `Caption`). The data layer's
  `PascalCase()` does the column → field translation; new JSON-tagged
  fields on hand-written types must match.
- **`TableAction.Method`** is the absolute URL path sail POSTs against
  (`/v1/{table}/{action}` or `/v1/{method_name}`). Don't change the path
  scheme without coordinating with sail's table-action dispatcher.
- **`canExecute()` on the sail side** matches `authorityObject` /
  `authorityCheck` from the `TableAction` JSON against the user's
  permission set. Authorisation seeds MUST include the
  `authorization_object` + `authorization_object_action` row for every
  custom action, or sail will show the button greyed out.
- **`ProblemDetail`** (RFC 7807) is the error envelope sail expects.
  Don't return bare strings or custom shapes.
- **`MainMenu` / `Permissions` / `TableDefinitions`** in
  `RestService.GetClientCache` are sail's bootstrap payload. Adding a new
  metadata table for sail to consume = add a slot to `GetClientCache` and
  invalidate the cache (`RestService.InvalidateCache`) after admin tooling
  edits the source table.
- **`PublicHandler.GetPasswordPolicy`** exposes the global password rules
  (`UserService.GetPasswordPolicy().ClientView()`) at a public route, so
  pre-login screens (signup, reset) and in-session change-password all validate
  input before submit. The server stays the authoritative gate.

### 8. Security defaults are non-negotiable

- **Verify signatures BEFORE writing to the DB.** Don't log unsigned
  webhook bodies — an unauthenticated attacker would otherwise fill the
  log table with garbage.
- **Bound every external input.** `MaxBytesReader` for HTTP bodies
  (`config.Config().MaxRequestSize` global cap; `MaxWebhookBodyBytes` tighter cap
  for webhooks); `MaxSigHeaderBytes` for signature headers;
  `stripeMaxResponseBytes` for upstream responses. A missing bound is a
  DoS vector.
- **Use `crypto/rand`** for any token that an attacker shouldn't be
  able to predict. `math/rand` is never appropriate for security
  contexts.
- **`hmac.Equal` and `subtle.ConstantTimeCompare`** for signature
  comparisons — `bytes.Equal` leaks timing.
- **No PII in error responses.** "user not found" is more dangerous
  than it looks: it confirms whether an email is registered. Prefer
  generic "credentials rejected" / "request rejected".

### 9. Testing

- Every adapter / provider gets at least a no-op or in-memory test that
  exercises the public surface — `payment/webhook_test.go`,
  `payment/signature_test.go`, `payment/parser_test.go` are the canonical
  shapes.
- Signature verifiers MUST have a known-good vector test and at least one
  tamper-detection test (flipped byte → reject).
- Webhook processors MUST have an idempotency test (same event id twice →
  one handler invocation).
- Tests live next to the code (`*_test.go` in the same package). No
  separate `tests/` tree.

### 10. Doc comments are the public surface

Every exported symbol (`Capitalised`) carries a doc comment that explains:

- What it does (one line, complete sentence).
- What the non-obvious constraints are — preconditions, idempotency
  guarantees, security implications, why this exists rather than the
  obvious-looking alternative.
- For deprecated APIs, what replaces them and the cutover date.

The doc comments on `payment.WebhookProcessor.Process` and
`handler.AbstractPaymentHandler.CreateCheckout` are good references —
they describe WHY the order of operations matters and what attack each
step defends against, not just WHAT the function does.

### 11. Compatibility

- Public APIs in `port/`, `model/`, `handler/`, `data/`, `worker/`,
  `service/`, `payment/`, `payout/` are **stable across minor releases**.
  Renames, parameter reordering, and return-shape changes require a major
  release.
- Additive changes (new method on a struct, new optional struct field,
  new constant, new interface impl) are minor-version-safe.
- New SQL columns are added NULL-able with a default so old schemas
  continue to read; column removals wait one major release.
- `TODO.md` tracks deferred work with `why deferred / acceptance / effort`
  so cross-version follow-up isn't lost.

### 12. Commit & PR hygiene

- Keep each PR and commit focused on one logical change.
- README + role matrix + flag table + schema changelog update in the
  SAME commit as the code change. A schema row without a README row is a
  bug.

---

These standards apply equally to the keel maintainers and to external
contributors — same review bar, same rationale.

