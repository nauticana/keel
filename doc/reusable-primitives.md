# Reusable Primitives

Small product-neutral building blocks shared by Keel consumers.

## Reusable Primitives (upstreamed from downstream services)

These generic building blocks are available directly from their Keel packages.

### `crypto` — AES-256-GCM seal/open

At-rest encryption for sensitive fields (TOTP seeds, refresh tokens, secret-manager values). Sealed output is tagged `enc:v1:` + base64(nonce‖ciphertext). `IsSealed` identifies the envelope; `Open` returns `(nil, false)` for invalid input.

```go
import "github.com/nauticana/keel/crypto"

kek, _ := crypto.LoadKEK(ctx, secrets, "field_kek")           // 32-byte AES-256 key, hex or base64
sealed, _ := crypto.Seal(kek, []byte(totpSeed))               // store in DB
if plain, ok := crypto.Open(kek, row); ok { use(plain) } else { use([]byte(row)) /* legacy */ }
```

### `handler.JSON` / `handler.JSONPublic` — typed JSON endpoint adapter

Eliminates the method-check / auth / decode / dispatch / error-map / write prologue every JSON handler otherwise repeats. Available as methods on `AbstractHandler`, so any handler that embeds it gets them for free. Return `*handler.APIError` to set a specific status; any other error → 500.

```go
type MyHandler struct{ handler.AbstractHandler; svc *MyService }

mux.Handle("/api/v1/widget", h.JSON("POST", func(ctx context.Context, s *model.UserSession, body json.RawMessage) (any, error) {
    var req CreateWidget
    if err := json.Unmarshal(body, &req); err != nil {
        return nil, handler.NewAPIError(http.StatusBadRequest, "bad request: "+err.Error())
    }
    w, err := h.svc.Create(ctx, s.UserID, req)
    if errors.Is(err, ErrConflict) { return nil, handler.NewAPIError(http.StatusConflict, "exists") }
    return w, err
}))

mux.Handle("/public/lookup", h.JSONPublic("GET", func(ctx context.Context, _ json.RawMessage) (any, error) { ... }))
```

### `crypto.Sealer` — one KEK per purpose

`NewSealer(ctx, secrets, secretName)` loads the KEK once and seals/opens the same `enc:v1:` envelope. `SealBytes` fits byte-column hooks:

```go
taxIDs, err := crypto.NewSealer(ctx, secrets, "tax_id_kek")
payoutHandler.SealTaxID = taxIDs.SealBytes
```

### `common.RequestJSON` — typed outbound JSON calls

Sends a JSON body on the shared client and returns body + headers. A non-2xx response returns both alongside `*common.HTTPStatusError`, which classifies itself (`Unauthorized`, `RateLimited`, `Transient`, `Permanent`); mapping to provider errors and decoding stay with the caller. Bodies over `outbound_max_response_size` return the truncated body with `ErrResponseTooLarge` (joined with the status error on a non-2xx).

```go
body, hdr, err := common.RequestJSON(ctx, http.MethodPost, url, map[string]string{"Authorization": "Bearer " + tok}, payload)
var status *common.HTTPStatusError
if errors.As(err, &status) && status.Unauthorized() { return ErrReauthorize }
```

For a URL a partner or user chose, use `common.RequestJSONWith(ctx, common.PublicHTTPClient(), ...)`. `PublicHTTPClient` dials only public addresses, checked after DNS resolution, and ignores proxies; a refused address is `common.ErrNonPublicAddress`. `common.DialPublicOnly` and `common.IsPublicAddr` are the same check for a client with its own timeouts or redirect policy.

### `common.PlainText` — HTML to text

Visible text of a document or fragment: `script`/`style`/`noscript`/`template`/`title` dropped, entities decoded, whitespace collapsed, a space where a block element separated two words (`<b>wo</b>rd` stays `word`).

### `pgsql/sqlsmoke` — PREPARE every named query

Queries go through the production `pgsql.RewritePlaceholders`, so PostgreSQL validates exactly what runs. Schema order, query groups and the DSN belong to the calling test:

```go
conn, _ := pgx.Connect(ctx, dsn)
if err := sqlsmoke.LoadSchema(ctx, conn, "sql/basis.sql", "sql/app.sql"); err != nil { t.Fatal(err) }
sqlsmoke.Run(t, conn, map[string]map[string]string{"orders": orderQueries}) // one subtest per query
```

### Connecting a partner to a provider

`handler.OAuthConnectHandler` mounts, per provider, `authorize`, `callback`, `complete` and `test` under `/api/oauth/{provider}/`. The flow is bound to the signed-in user and partner who start it:

1. The app calls `GET authorize` with the user's session and sends the browser to the returned consent URL.
2. The provider redirects to `callback`, which checks it and returns the browser to `FrontendReturnURL?connect={provider}&ticket={ticket}`. It creates nothing.
3. The signed-in app posts `{"ticket": "..."}` to `complete`. keel connects only for the user and partner who started the flow: 403 for anyone else, 400 for a spent or expired ticket (`oauth_state_ttl_seconds`).

`client` ships `NewGoogleProvider` (and `NewGBPProvider`), `NewMetaProvider`, `NewShopifyProvider`, `NewTikTokProvider` (TikTok's `client_key` authorize and form exchange; stores the refresh token) and `NewXProvider` (PKCE, `offline.access` always requested); `NewOAuth2Provider` covers any other standard service. Scopes are the caller's. Register their refreshes with `connect.NewRefresher`: Google with `RefreshOAuth2Lib` on `google.Endpoint`, X with `connect.XRefreshSpec` (HTTP Basic, rotating refresh token), TikTok with `connect.TikTokRefreshSpec`.

`Nonce` (the `connect.NonceService`) holds the tickets; without it callbacks fail closed. `connect.CredentialStoreDB` enforces the binding through `client.WithInitiator`; an application's own `client.CredentialStore` must record the initiator at `CreateOAuthState` and compare it at `ConsumeOAuthState` the same way.

### OAuth connections record the scopes they were granted

Every provider's exchange writes what the provider actually returned into `partner_credential.granted_scopes`, and a refresh that reports a scope set updates it — so a feature needing a wider grant than onboarding asked for can tell, before it calls the provider and gets a 403:

```go
missing, err := store.MissingScopes(ctx, partnerID, "gsc", []string{"https://www.googleapis.com/auth/webmasters"})
if len(missing) > 0 {
    // ask this partner to re-consent, for exactly these scopes
    u, _ := provider.AuthURL(ctx, partnerID, map[string]string{client.ParamExtraScopes: client.JoinScopes(missing)})
}
```

`ParamExtraScopes` widens the consent URL without a second provider registration. The merged requested set is kept in OAuth state because RFC 6749 lets a provider omit `scope` when it granted that exact set; `BaseProvider.NoImpliedScopes` (set for Meta, where users decline individual permissions) records nothing instead. `BaseProvider.RequiredScopes` refuses a narrower grant before persistence. `GrantedScopes` returns `connect.ErrNoActiveConnection` when no connection exists.

### `worker.Scheduler` — which tenants are due?

`JobLoop` covers queue-shaped work. `Scheduler` covers the other shape — recurring per-tenant work — so a worker stops re-deriving due-ness from whatever table its task happens to write:

```go
sched := &worker.Scheduler{DB: db}
_ = sched.Schedule(ctx, partnerID, "review_poll", 6*time.Hour)   // enroll; re-intervalling keeps its place

for _, task := range due {           // due, err := sched.Due(ctx, "review_poll", 25)
    if err := poll(ctx, task.PartnerID); err != nil {
        _ = sched.Fail(ctx, task, err)
        continue
    }
    _ = sched.Complete(ctx, task)
}
```

Calendar-aligned work enrolls with a cadence instead of an interval: `sched.ScheduleCalendar(ctx, partnerID, "weekly_report", worker.Weekly(time.Monday, 9*60, loc))` or `worker.Monthly(1, 0, loc)` (a day past the month's end runs on its last day). The slot is local time in a named zone; `Complete` sets the next run to the first slot after completion, so missed slots are not replayed. Re-enrolling with the same cadence keeps the pending slot; a changed cadence moves it. `Due` fails, without handing out, a schedule whose time zone no longer loads.

`RunNow(ctx, partnerID, taskKind)` makes an enrolled tenant due at the store clock for an on-demand run, keeping its interval, cadence and failure backoff; it returns `worker.ErrNotScheduled` for a tenant that is not enrolled.

Due-ness lives in `work_schedule`, so an empty run still counts and failures back off exponentially. Each `ScheduledTask` carries a lease token; `Complete` and `Fail` return `worker.ErrScheduleClaimLost` for a claim that was re-claimed after its lease lapsed, or whose tenant was dropped. The interval and task remain app-owned.

### Notification suppression and dedupe

Honoring unsubscribes, bounces and complaints is a compliance obligation (CAN-SPAM, CASL, the carrier rules for SMS), not app-specific behavior, so the check sits behind `port.NotificationService` rather than at every call site:

```go
notif := dispatcher.NewLocalNotificationService()
notif.Suppressor = &dispatcher.SuppressionService{DB: db}  // table-backed default
notif.Recipients = userService                             // resolves a UserID to its email/phone
notif.Ledger     = ledger                                  // backs NotificationRequest.DedupeKey

err := notif.Send(ctx, port.NotificationRequest{Channel: dispatcher.EmailChannel, UserID: 42, PartnerID: 7, ...})
switch {
case errors.Is(err, port.ErrNotificationSuppressed): // *port.SuppressedError carries the reason
case errors.Is(err, port.ErrNotificationDuplicate):  // an earlier Send already carried this DedupeKey
}
```

A refusal is a typed outcome, never a silent success. The check covers the `email` and `sms` channels only, on the address the dispatcher would use — an explicit `To`, or the contact `Recipients` resolves — so a user-id send cannot bypass the list; other channels (the inbox, push device tokens) have nothing to suppress. A suppression store that is down fails the send rather than reading as "not suppressed". `SuppressionService.Suppress` / `Release` keep `notification_suppression`, scoped to a partner or, with `dispatcher.AllPartners` (stored as a NULL `partner_id`), to the whole fleet, and a fleet-wide entry outranks a tenant one. The table is partner-specific, so generic CRUD shows a tenant only its own entries; contacts are stored lowercased so a differently-cased address cannot slip past its own entry. `DedupeKey` collapses repeats through the idempotency ledger, a failed delivery releases the key so a retry is not mistaken for a duplicate, and a delivery whose completion could not be recorded is marked unknown so it is not sent twice.

### `connect.ReadinessResolver` — can this tenant's data exist?

Evaluates an injected `[]connect.Source{ID, Provider, Collected}` against the tenant's active connections: `NOT_COLLECTED` (no collector ships — connecting an account will not help), `NOT_CONNECTED`, or `READY`. Table names, collectors and user copy stay in the app.

### `content` — edit existing objects on a content platform

`ResourceWriter` reads and updates one logical field of an object addressed by `ResourceRef`; `Writers{"shopify": w}` selects the provider; `ConnectionFieldReader` resolves the partner's connection through `connect.CredentialStoreDB.ResolveAccess`. `ResolveAccess` mints OAuth access tokens under the refresh-sweep lease (one exchange per credential, fleet-wide, so a rotating refresh token is never spent twice), reuses them in-process for `oauth_access_token_cache_ttl`, and returns `connect.ErrRefreshInProgress` when another worker holds the lease past its retry window. Failures are typed: `ErrUnsupportedProvider/Kind/Field`, `ErrResourceNotFound`, `ErrAccessDenied`, `ErrThrottled` (retryable), `ErrRejected`. `ShopifyWriter` owns the Admin GraphQL transport; where each logical field lives is injected:

```go
shopify, err := content.NewShopifyWriter(content.ShopifyFieldMap{
    content.ShopifyProduct: {"body": {Input: "descriptionHtml"}, "seo_title": {SEO: "title"}},
    content.ShopifyPage:    {"seo_title": {Metafield: &content.ShopifyMetafield{Namespace: "global", Key: "title_tag", Type: "single_line_text_field"}}},
    content.ShopifyArticle: {
        "published": {Input: "isPublished", Type: content.ValueBool},
        "tags":      {Input: "tags", Type: content.ValueList},
        "author":    {Input: "author", Type: content.ValueJSON},
        "image":     {Input: "image", Type: content.ValueJSON, Selection: "{altText url}"},
    },
})
```

Values stay strings at the port; an `Input` target's `Type` says how one is decoded before it is sent — `ValueString` (the zero value), `ValueBool`, `ValueList` (a JSON array of strings or comma-separated) or `ValueJSON` (any JSON document, `""` is null). A typed field reads back as JSON text its own decoder accepts, so a read value can be written back unchanged; an object-typed input needs a `Selection` to be readable. A value that does not decode is `ErrInvalidValue` and nothing is sent.

### `content` — create, delete and upload

`ResourceCreator` builds a new object from the same logical fields `UpdateField` writes — including the ones the provider demands at creation, which the field map supplies as ordinary inputs — and returns a `ResourceRef` carrying the provider's own id, so the caller can edit or delete what it just made. `ResourceDeleter` removes one. `MediaUploader` puts a file on the platform's CDN and returns the URL to write into a field; `storage` is the wrong tool there, because it puts bytes in *our* bucket and a CMS field wants the file on the platform's own. An app therefore needs no second HTTP client for the store it is already connected to.

```go
ref := content.ResourceRef{Endpoint: endpoint, Token: token, Kind: content.ShopifyPage}

creator, err := writers.Creator("shopify")                    // ErrUnsupportedOperation if it cannot
page, _, err := creator.Create(ctx, ref, map[string]string{"title": "Sizing", "body": html})

uploader, err := writers.Uploader("shopify")
url, _, err := uploader.Upload(ctx, ref, "hero.png", "image/png", file)   // provider-hosted URL
_, err = shopify.UpdateField(ctx, page, "hero", url)
```

`MediaLister` lists the images a resource owns (`ResourceImage{ID, URL, Alt}`) and `MediaAnnotator` sets the alt text of one of them. `ShopifyWriter` implements both for a product's gallery; `SetImageAlt` confirms the image belongs to the product before `fileUpdate`, which would otherwise accept any file in the shop, and reports a foreign one as `ErrResourceNotFound`. An article's or collection's single featured image is a field — map it as `ValueJSON` with a `Selection`.

A `ShopifyTarget{Redirect: true}` field retires a page, article, product or collection behind a URL redirect. Writing a target creates or retargets the redirect, then unpublishes the object from the storefront; writing `""` republishes it and deletes the redirect. A live object reads as `""`. An already-unpublished object without a redirect is rejected because rollback could not safely restore it. `RedirectLister` lists the store's redirects. The connection needs `read_online_store_navigation` and `write_online_store_navigation`; products and collections also need `write_publications`.

`Writers.Creator` / `.Deleter` / `.Uploader` / `.Lister` / `.Annotator` / `.RedirectLister` select the provider and report `ErrUnsupportedOperation` when its writer does not carry that capability, so no call site type-asserts. `ShopifyWriter` implements all six: create and delete map to each kind's own mutation shape (Shopify puts the id in the input for some kinds and beside it for others), and `Upload` runs the staged-upload / POST / `fileCreate` sequence and waits for the asset to leave `PROCESSING` — a URL that is not servable yet would publish as a broken image. Uploads are capped at `MaxUploadBytes` (default 20 MiB, `ErrMediaTooLarge`) because the staged target is signed for an exact size; `PollAttempts` and `PollInterval` bound the wait, and exhausting them is `ErrThrottled`, not a failure.

### Shopify mandatory compliance webhooks

`handler.ShopifyComplianceHandler` serves `customers/data_request`, `customers/redact` and `shop/redact` on one public route: capped raw body, `X-Shopify-Hmac-Sha256` verified under the app secret named by `SecretName` (401 on mismatch), routed by `X-Shopify-Topic` (unknown topic 404) to a `port.ShopifyComplianceService`. `service.BaseShopifyComplianceService` journals each request (ids only, no contact data) and acknowledges it — complete for an app that stores no Shopify customer data. An app that does embeds it and overrides the topics it holds data for; `connect.CredentialStoreDB.ConnectionsByShopDomain` resolves the shop to its connections in any status, since `shop/redact` arrives after the uninstall.

```go
compliance := &handler.ShopifyComplianceHandler{
    Service:    &service.BaseShopifyComplianceService{Journal: journal},
    Secrets:    secrets,
    SecretName: "shopify_api_secret",
}
mux.HandleFunc("/public/webhook/shopify/compliance", compliance.Handle)
```

### `browser` — headless Chrome

`Launcher` owns what is easy to get wrong around chromedp: a per-launch profile dir removed on cancel, a sweep of profile dirs leaked by killed processes, new-mode headless, a crashpad-safe flag set, and `TMPDIR`/`HOME` for the Chrome subprocess. Settings are fields, wired from the app's own flags — keel adds no config keys for it.

```go
launcher := &browser.Launcher{Headless: true, Journal: journal}

// one page: load, probe, capture
renderer := &browser.DOMRenderer{Launcher: launcher}
res, err := renderer.Render(ctx, browser.RenderRequest{URL: u, Evaluations: map[string]string{"cmp": "!!window.__tcfapi"}})
found := res.Truthy("cmp")

// many pages on one Chrome: the tab context takes any chromedp action
session, err := launcher.Start(ctx)
defer session.Close()
tabCtx, closeTab := session.NewTab(30 * time.Second)
defer closeTab()
```

Depend on `browser.Renderer`, not `*DOMRenderer`, so a pooled implementation can replace it without touching callers. An expression that throws evaluates to `nil`; one that could not run is reported in `RenderResult.EvaluationErrors`.

`CaptureRequests` records what the page asked the network for — a library that loaded is not a beacon that left. Each `NetworkRequest` carries URL, method, Chrome's resource type (`Ping` for `sendBeacon`), status (0 while unanswered) and Chrome's error text for a failed one (`net::ERR_BLOCKED_BY_CLIENT`); redirect hops are separate entries. The list stops at `MaxRequests` (default 1000) and sets `RequestsTruncated`; bodies are never recorded, and a cross-origin iframe's requests run in another renderer and are not seen. `Settle` waits after load before anything is captured, for tags that fire late. Matching URLs to vendors is the caller's job. `Launcher.NewAllocator` is the lower-level entry for code that manages its own chromedp contexts.

### `reference` — CrUX, Knowledge Graph, Wikidata, IndexNow

```go
key := reference.APIKey{Secrets: secrets, SecretName: "google_api_key"}
crux := &reference.CrUXClient{APIKey: key}
rec, err := crux.RecordForURL(ctx, pageURL, reference.CrUXFormFactorPhone) // falls back to the origin aggregate
```

`ErrNoAPIKey` means "not tried" (no secret named, or it is empty); `ErrCrUXNoData` means CrUX publishes nothing for the URL or origin; an unpublished metric is `CrUXNoValue`. `KGClient.FindEntity` and `WikidataClient.FindEntity` return an empty match, not an error, when nothing is found. `WikidataClient.UserAgent` is required by Wikimedia policy. Other failures are `*common.HTTPStatusError`, so `RateLimited()` / `Transient()` classify them.

`IndexNowClient{APIKey, KeyLocation}.Submit(ctx, host, urls)` posts in batches of 10,000 and stops at the first failed batch; 400/403/422/429 map to `ErrIndexNowBadRequest` / `KeyInvalid` / `URLMismatch` / `RateLimited`. The host must serve the key at `/<key>.txt` or `KeyLocation`. `VerifyKeyFile(ctx, host)` reads that file back through `common.PublicHTTPClient` (or `KeyFileClient` when set) and returns `ErrIndexNowKeyNotServed` when it is missing or different, or when the host resolves to an internal address; a transient failure is a plain error, never a verdict about the host.

### `reference.Geocoder` — address ↔ point, and the `geo` columns it fills

`Geocoder` is the provider-independent port (`Geocode`, `Reverse`); `GoogleGeocodeClient` is the shipped implementation, so an app can move to Mapbox or Nominatim without its callers changing. A result carries the point, the provider's normalized components (street, city, county, state, country, postal code) and a `Precision` the caller must be able to reject on — a city centroid silently turns a proximity ranking into noise:

```go
geocoder := &reference.GoogleGeocodeClient{APIKey: key, Region: "us"}
addresses := &geo.AddressService{DB: db, Geocoder: geocoder} // MinPrecision defaults to GEOMETRIC_CENTER
point, err := addresses.EnsureCoordinates(ctx, partnerID, street)
```

`geo.AddressService` fills `partner_address.latitude` / `longitude`, which nothing else in keel writes: a row that already has a point costs no vendor call and is never overwritten, a placement coarser than `MinPrecision` is `geo.ErrPrecisionTooCoarse` and is not stored, and the street line is geocoded together with the row's city/state/zip/country. Nothing found is `reference.ErrNoGeocodeMatch`; a quota refusal — which this API reports inside a 200 body — is `reference.ErrGeocodeQuotaExceeded`. Which addresses are worth geocoding, geo-grid construction and ranking by point stay with the app.

### `common` — URL and parsed-HTML helpers

`WithScheme` (bare host → `https://`), `ResolveURL` (DNS check with a `www.` fallback, `ErrHostUnresolvable`), and over `*html.Node`: `ExtractLinks`, `ExtractTitle` (skips `<svg>` icon titles), `ExtractText` (verbatim), `PlainTextNode` (`PlainText` for a parsed subtree).

### `service.PartnerDomainService` — does this URL belong to the partner?

`Owns(ctx, partnerID, rawURL)` returns the normalized URL when its host is one of the partner's `partner_domain` rows or a subdomain of one (a stored `www.` is ignored, names compare as lowercase punycode), and refuses with `ErrInvalidURL` (not absolute http(s), or carrying credentials), `ErrInvalidPartner`, `ErrNoPartnerDomain`, `ErrURLNotOwned`, or `ErrDomainStore` when no database is wired. Check it before fetching a partner-supplied URL, so `evilexample.com` never passes for `example.com`.

`Names(ctx, partnerID)` returns the partner's domains as normalized names, primary first, for matching many hosts with `domain.CoveredBy(host, name)` after one query. `Primary(ctx, partnerID)` returns the primary domain as stored, or the first domain when none is marked primary. Both return `ErrNoPartnerDomain` when the partner has no usable domain.

### `service.Health` — health check for any mux

`Health(db)` answers 200 `ok` when the database responds to a ping within two seconds and 503 otherwise, without detail. `HttpBackend` mounts it at `/health`; a standalone mux mounts it itself.

### Session partner for multi-partner users

Login, `GetUserById`, token refresh and the phone, email and social lookups put the user's earliest current `partner_user` membership in the session (ordered by `begda`, then `partner_id`; ended memberships are ignored), so the partner does not change between refreshes. `UserService.ListPartners(userID)` returns every current membership in the same order.

A user belongs to at most one partner at a time. PostgreSQL enforces it with the exclusion constraint `partner_user_no_overlap` (needs the `btree_gist` extension), so two memberships of one user can never overlap; an insert that would overlap fails with SQLSTATE 23P01 (`pgsql.IsExclusionViolation`). To move a user, end the membership and create a new row.

### Ending a membership

`UserService.EndMembership(partnerID, userID, reason)` sets `endda` on the open `partner_user` row and, in the same transaction, ends the user's open `user_permission` rows and revokes every refresh and access token; with `LocalUserService.OAuthTokens` set it also revokes the user's authorization-server refresh tokens. Rows are ended, never deleted. `handler.MembershipHandler` mounts `partner_user/end` for the session partner, gated by `PARTNER_USER` `END` (seeded for `PARTNER_ADMIN`).

A `partner_user` or `user_permission` row is read-only once `endda` is set (`data.EndedReadOnlyTables`): generic Update, Patch and Delete skip it, and a later change is a new row. No seeded role may update or delete a `partner_user` row through generic REST, so a membership ends only through the route.

### `common.CallerSession` — who is calling, anywhere a context flows

`CallerSessionFromContext(ctx)` reads what keel's OAuth, API-key and request-id middlewares bound — principal, subject, partner, session user, key, scopes, request id — and fails closed on an unauthenticated context. `WithCallerSession` is the inverse for workers acting on a claimed job, so a background task carries the same identity a request would.

### `common.Period` — effective dating in Go

`Period{From, To}` is the `begda`/`endda` convention: `From` inclusive, `To` exclusive, zero `To` open-ended. `Contains(t)` and `Ordered()` replace the per-project copies of the same three lines.

### `idempotency` — replay-safe mutating operations

`port.IdempotencyLedger` records a key as in flight, completed with a non-nil opaque result, or unknown. `Begin` returns the prior entry so a replay hands back the stored result, a concurrent caller sees the claim, and an unknown outcome blocks retries until reconciled. A granted claim carries a fence that every later write must present. With a `Lease`, an in-flight claim not `Renew`ed within it is taken over under a new fence and the previous holder's ledger writes fail. The fence protects the ledger, not the side effect: a merely slow worker still finishes its external call, so a caller that enables takeover must make that call idempotent under the stable ledger key, arrange for its target to reject superseded fences, or leave the lease at zero and reconcile stuck keys explicitly. `ReclaimUnknown` grants a reconciler a fresh fence on an unknown key, which it then resolves with `Complete`, `Release` or `MarkUnknown`; the key stays unknown to `Begin`, and a later reclaim supersedes the earlier fence. `PgsqlLedger` decides lease expiry on the database's own clock, so skew between worker nodes cannot cause a premature takeover. `MemoryLedger` is for one process.

### `outbox.HTTPDispatcher` — signed webhooks off the outbox

An `outbox.Dispatcher` that POSTs each event to one partner-owned HTTPS endpoint. The application owns event names, payloads and subscription storage; it enqueues **one outbox row per subscriber**, so each destination retries and dead-letters independently, and injects a `WebhookDestinationResolver` that answers with that row's `{PartnerID, URL, SecretRef}`.

```go
dispatcher, err := outbox.NewHTTPDispatcher(outbox.HTTPDispatcherConfig{
    Resolver: subscriptions, // outbox.WebhookDestinationResolver
    Secrets:  secrets,       // secret.SecretProvider; SecretRef is read per delivery, never cached
    Egress:   outbox.EgressPolicy{AllowedHosts: []string{"hooks.partner.example", "*.partner.example"}},
})
w := &outbox.Worker{Dispatcher: dispatcher}
```

Body — ids are strings because they are bigint; `payload` is the event's JSON verbatim (`null` when empty):

```json
{"id":"7","type":"finding.created","aggregateType":"finding","aggregateId":"99","partnerId":"42","payload":{}}
```

| Header | Value |
|---|---|
| `Webhook-Id`, `Idempotency-Key` | the outbox event id — stable across retries; receivers dedupe on it |
| `Webhook-Timestamp` | unix seconds of this attempt |
| `Webhook-Signature` | `v1,` + base64(HMAC-SHA256(key, `id.timestamp.body`)) |

The scheme is [Standard Webhooks](https://www.standardwebhooks.com/) v1, so receivers can use an existing verifier; Go receivers call `outbox.VerifyWebhookSignature`. A secret prefixed `whsec_` is base64-decoded into the key, any other value is used as raw bytes.

| Outcome | Result |
|---|---|
| 2xx | delivered |
| 408, 425, 429, 5xx, transport error or timeout, secret lookup failure | retried with the worker's backoff |
| any other status, a redirect, an egress rejection, invalid payload JSON, an event without a partner, a destination owned by another partner | `outbox.PermanentError` — dead-lettered on the first attempt |

Egress fails closed: HTTPS only, no credentials in the URL, the host must match `AllowedHosts` (exact, `*.suffix`, or `*`), and the *resolved* address is checked at connect time, so a listed name pointing at a loopback, private, link-local or CGNAT address is refused (`AllowPrivateNetworks` lifts that for in-cluster receivers). Redirects are never followed, the proxy environment is ignored, the response body is read up to 64 KiB and discarded, and one attempt is bounded by `Timeout` (10s; keep it below the worker's `LeaseTTL`). Errors stored in `last_error` name the host only, never the URL. Any `Dispatcher` or resolver can return `outbox.Permanent(err)` to skip the remaining retries.

### `clock` — injectable time

Services take a `clock.Clock` instead of calling `time.Now` / `time.After`, so tests advance time rather than wait for it. It covers waiting as well as reading: injecting only `Now` still leaves a service that sleeps for a real second. Production passes `clock.System{}`; tests pass `clock.NewFake(time.Time{})` and call `Advance`.

### `handler.HeaderCarrier` — errors that carry response headers

Any error in the chain implementing `ErrorHeaders() http.Header` has those headers written on the error response, so retry advice survives the status+message mapping.

```go
return nil, handler.NewAPIError(http.StatusTooManyRequests, "rate limited").WithHeader("Retry-After", "30")
```

### `handler.WellKnownHandler` — app-association files

```go
wk := &handler.WellKnownHandler{Documents: map[string][]byte{
    handler.AppleAppSiteAssociationPath: aasaJSON,
    handler.AndroidAssetLinksPath:       assetLinksJSON,
}}
if err := wk.Validate(); err != nil { … } // non-JSON document fails wiring
srv.Handle(wk.GetPublicRoutes())
```

Answers GET/HEAD with `application/json` and a direct 200 — Apple and Android reject a redirect, so mount it on the apex host itself.

### `handler.CSRF` — double-submit-cookie helper

For server-rendered admin pages in downstream services (keel's own JWT API doesn't need this). `Issue` mints a token and sets it in an HttpOnly/Secure/Strict cookie; `Validate` constant-time compares it against the form field. Cookie name / path / TTL are struct fields.

```go
csrf := &handler.CSRF{CookieName: "myapp_csrf", Path: "/", TTL: 2 * time.Hour}
// GET render: tok, _ := csrf.Issue(w); render with hidden <input name="csrf_token" value="{{tok}}">
// POST handler: if !csrf.Validate(r, "csrf_token") { http.Error(w, "forbidden", 403); return }
```

### `handler.AdminSessionStore` — opaque-token in-memory session

Replaces the "cookie value == static admin secret" anti-pattern with a revocable, expiring, server-minted token. Cookies are the caller's concern — the store is just the token→expiry map, so it composes with any handler stack. In-memory: tokens are lost on restart, which is usually the right behavior for an admin/console area.

```go
store := handler.NewAdminSessionStore(2*time.Hour, 10_000)
// login: tok, _ := store.Create(); http.SetCookie(w, ...{Value: tok})
// guard: c, _ := r.Cookie(...); if !store.Valid(c.Value) { http.Error(w, "forbidden", 403); return }
// logout: store.Delete(tok)
```

### `data.ScanRows[T]` — generic `*sql.Rows` scanner

Collapses the `rows.Next` / `rows.Scan` / `rows.Err` boilerplate that recurs once per typed query. Pair it with a single-row scan closure.

```go
type Widget struct{ ID int64; Name string }

rows, err := db.QueryContext(ctx, `SELECT id, name FROM widget WHERE owner = $1`, ownerID)
if err != nil { return nil, err }
widgets, err := data.ScanRows(rows, func(r *sql.Rows) (Widget, error) {
    var w Widget
    return w, r.Scan(&w.ID, &w.Name)
})
```

**For pgx consumers (anything wired through keel/pgsql), use [`pgx.CollectRows[T]`](https://pkg.go.dev/github.com/jackc/pgx/v5#CollectRows) directly** — pgx ships an equivalent helper with the same shape, plus `CollectOneRow`, `AppendRows`, and `ForEachRow` siblings. `data.ScanRows` exists for `database/sql` callers (downstream services with non-pgx stores) where no built-in helper is available.

```go
// pgx-native equivalent — no keel helper needed:
rows, err := pool.Query(ctx, `SELECT id, name FROM widget WHERE owner = $1`, ownerID)
if err != nil { return nil, err }
widgets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Widget, error) {
    var w Widget
    return w, r.Scan(&w.ID, &w.Name)
})
```

For metadata-driven dynamic-schema reads, keep using `QueryService.Query` — the `[][]any` shape is intentional for the REST engine and table-action handlers; replacing it with typed scans would defeat the purpose.
