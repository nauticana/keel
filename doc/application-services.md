# Application Services

Runtime services, guards, notifications, recording, and realtime delivery.

## Quota Service

`port.QuotaService` enforces per-partner subscription limits. `service.QuotaServiceDb` is the standard implementation: it reads caps from `subscription_quota` (joined to the partner's active `partner_plan_subscription`), caches them per partner (1-hour TTL, singleflight-collapsed), and is **fail-closed** — no active plan, or a resource absent from the plan, denies. A cap of `-1` means unlimited.

```go
allowed, err := quota.CheckQuota(ctx, partnerID, "MEDIA", 1) // room for 1 more?
hasAddon, err := quota.CheckAddon(ctx, partnerID, "PRO_LOCATIONS")
remainingQuota, err := quota.GetPartnerQuota(ctx, partnerID int64, "PRO_LOCATIONS", 20)
quota.LogUsage(ctx, partnerID, "API_CALLS", 1, "public-api")
```

### Two resource categories

How a resource's **current usage** is measured depends on whether it has a count query:

| Category | Usage source | Semantics | Examples |
|---|---|---|---|
| **Live-count** | a `COUNT(*)` query keyed by resource id | concurrent — deletes free quota | `MAX_DOMAINS`, `MEDIA`, `LOCATION` |
| **Metered** | `SUM(usage_ledger)` windowed by `period_type` (`D`/`M`/…/`L`) | cumulative — `LogUsage` ticks it up | `API_CALLS`, `AI_CREDITS` |

Keel ships exactly one default live-count query — `MAX_DOMAINS` (over `partner_domain`, a keel table). Everything else defaults to the ledger.

Each `usage_ledger` row records who acted, read from the context: `user_id` (a JWT session, bound by `SSOMiddleware` as `common.UserID`), `api_key_id`, and `oauth_client_id` (the token's `client_id` claim). Each is NULL when absent, as in a worker without `common.WithCallerSession`.

### Wiring

To live-count **your own** tables, inject per-resource SQL via `QuotaServiceDb.Queries` — a map keyed by **resource id**:

```go
quota := &service.QuotaServiceDb{
    Repo: db,
    Queries: map[string]string{
        // Partner-direct table:
        "BUSINESS": "SELECT COUNT(*) FROM business WHERE partner_id = ? AND deleted_at IS NULL",
        // Child table — scope to the partner via its FK chain:
        "MEDIA":    "SELECT COUNT(*) FROM business_media m JOIN business b ON m.business_id = b.id WHERE b.partner_id = ?",
    },
}
```

Your entries are **merged over** keel's defaults (yours win on a key clash), and `MAX_DOMAINS` stays available unless you override it. Then seed `subscription_resource` + `subscription_quota` rows for those ids and you're done — `CheckQuota` routes to your query automatically. No keel change, no fork.

**Contract for an injected count query** — keel binds and reads it positionally:
- Exactly **one** bound parameter: `partnerID` (a single `?`).
- Returns **one row, one column** = the partner's current usage (an integer).
- Must be **partner-scoped** — directly (`WHERE partner_id = ?`) or via a `JOIN` to a table that has `partner_id`. There's no need for a `partner_id` column on the resource table itself; the join keeps it normalized.
- Use bound `?` params only (never string-interpolate) — these are developer-defined SQL, but treat them as you would any prepared statement.

A `COUNT(*)` query yields concurrent "N at a time" limits; a `SUM(usage_ledger)` query yields lifetime/consumption — the query you write decides the semantics. Caps, caching, period windowing, and fail-closed behavior are unchanged regardless.

## MCP Server Layer

The MCP server layer (transports, tool/resource registry, response envelopes, text bundles, field-catalog discovery, conformance assertions) lives in [`github.com/nauticana/scout`](https://github.com/nauticana/scout) — packages `scout/mcp`, `scout/mcp/mcptest`, `scout/domain`, and `scout/contract`. Keep keel's API-key/OAuth middleware, quota, guards, and query services around the scout transport for remote servers; authentication state enters through keel request context, not MCP arguments.

## Admission Limiters

`limiter` is process- and fleet-level admission control; `guard` stays the DB-counted trust check for individual writes. The subject is `model.AdmissionSubject{PartnerID}`; consumers keep domain-specific scheduling classes and telemetry dimensions in their own adapters. The ports are `port.RateLimiter` and `port.ConcurrencyLimiter`.

- `FairSlotLimiter` — a weighted semaphore with one FIFO per partner served round-robin, so no partner monopolizes capacity and a large request cannot starve behind small ones. Cancellation never leaks a slot.
- `LocalRateLimiter` — per-partner and fleet token buckets per named lane; drained buckets are never evicted, so a partner cannot reset its own limit by churning keys.
- `DistributedRateLimiter` — the same lanes as fixed windows shared across replicas. Partner and fleet are charged as **one all-or-nothing** `Admit`, so a fleet refusal never leaves a partner increment behind. Concurrent callers on a hot key coalesce into one charge; a batch that does not fit is charged to the exact boundary, and a window seen full is refused locally until it rolls. Store errors or a `StoreTimeout` degrade to epoch-aligned local windows carrying `FallbackFraction` of each limit, rounded up (fleet-wide overshoot ≤ replicas × rounded local limit), counted as `limiter_store_outages_total`; one probe per `RecoveryProbe` restores shared admission. Both counters of a lane share the `{prefix:lane}` hash tag an atomic charge needs on Redis Cluster.
- `LimitError{Err, Scope, After}` — every rejection; it satisfies `port.RetryAfterError` and `handler.HeaderCarrier`, so `Retry-After` reaches the client through `handler.JSON`.

```go
rl, err := limiter.NewDistributedRateLimiter(cacheSvc.(cache.MultiScopeAdmitter), limiter.DistributedRateLimiterConfig{
    Lanes:               map[string]limiter.WindowLane{"turn": {Partner: {Limit: 600, Window: time.Minute}, Fleet: {Limit: 10000, Window: time.Minute}}},
    KeyPrefix:           "app:rl",
    StoreTimeout:        50 * time.Millisecond,
    FallbackFraction:    0.5,
    FallbackMaxPartners: 4096,
    RecoveryProbe:       time.Second,
})
err = rl.Allow(ctx, "turn", model.AdmissionSubject{PartnerID: session.PartnerID})
```

## Trust Guards (write/queue endpoints)

A retry loop must not flood a worker queue or double-write. Compose `guard` guards into a `GuardChain` and run it before persisting. keel ships the mechanism; the app owns the named SQL and thresholds.

```go
guards := guard.NewGuardChain(
    guard.NewMinAgeGuard("qKeyAge", 7*24*time.Hour),
    guard.NewDuplicateGuard("qDupeJob", 5*time.Minute),         // debounce window
    guard.NewMaxCountGuard("qDailyRate", "daily rate", 100, 24*time.Hour),
)

in := port.GuardInput{PartnerID: pid, DedupKey: dedup, ClientIP: ip, Now: time.Now().UTC()}
if err := guards.Check(ctx, qs, in); err != nil {
    var dup *guard.DuplicateError
    if errors.As(err, &dup) {
        return existingJob(dup.ExistingID), nil   // return the in-flight job, don't re-enqueue
    }
    return nil, err                                // ErrGuardRejected → refuse; map at the transport boundary
}
```

`DuplicateGuard.Check` is a read, so two concurrent callers can both pass. When exactly one write must win, check and write in one transaction that first takes `guard.Lock(ctx, tx, key)`, a transaction-scoped advisory lock (merge `guard.Queries` into the `BeginTx` catalog):

```go
tx, _ := db.BeginTx(ctx, queries) // queries includes guard.Queries
if err := guard.Lock(ctx, tx, fmt.Sprintf("%d:scan", pid)); err != nil { return err }
if err := guards.Check(ctx, tx, in); err != nil { return err }
// insert the job, then tx.Commit
```

`GuardInput.Now` is injected so guards are deterministic in tests. The `port.TrustGuard` contract takes a `port.GuardQuerier` (which `data.QueryService` satisfies) — usable from any REST write handler or MCP tool alike.

## Push Notifications (FCM, APNs)

Keel ships a push-notification subsystem behind `port.MessageDispatcher` (legacy alias `port.PushProvider`). The `device_token` table stores per-user tokens with their platform; FCM covers Android, web and Firebase-integrated iOS builds, and a native APNs provider covers iOS apps that ship without the Firebase SDK and can only offer a raw APNs token. Non-mobile consumers get a NoOp provider by default and are unaffected.

### Wiring

Select the provider via `push_mode` (default `noop`):

| `push_mode` | Provider | Notes |
|---|---|---|
| `noop` / empty | `NoOpPushProvider` | dispatches are discarded |
| `fcm` | `FCMPushProvider` | every active token goes through FCM |
| `apns` | `APNsPushProvider` | every active token goes to APNs over HTTP/2 with token-based auth |
| `fcm,apns` | `PlatformRouter` | rows with `platform = I` go to APNs, all other rows to FCM; `Send` picks APNs for a 64-hex token, FCM otherwise |

```go
// In main.go, after UserService is constructed:
pushProvider, err := push.NewPushProvider(ctx, secrets, userSvc, journal)
if err != nil { ... }

// Register the mobile-facing endpoints on SecurityHandler or a dedicated PushHandler:
pushHandler := &handler.PushHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
}
srv.Handle(pushHandler.GetAuthRoutes())
```

FCM mode resolves credentials via Google's Application Default Credentials. Three working setups, listed best-first:

1. **Workload Identity on GCP** — running on GCE / GKE / Cloud Run with an attached service account that holds `roles/firebasecloudmessaging.admin` (or a custom role with `cloudmessaging.messages.create`). The Firebase SDK pulls a short-lived token from the metadata server; nothing to mount, nothing to rotate. **Recommended.**
2. **Workload Identity Federation on AWS/other** — set `GOOGLE_APPLICATION_CREDENTIALS` to a credential-config JSON that exchanges the local-cloud OIDC token for a GCP access token. No static key on disk.
3. **Static service-account key (legacy)** — set `GOOGLE_APPLICATION_CREDENTIALS` to a downloaded Firebase Admin SDK private-key JSON. Works everywhere but you own the rotation; GCP org policies increasingly force short key lifetimes (~14 days) making this unsustainable. Prefer (1) or (2).

APNs mode authenticates with an Apple auth key (`.p8`). The PEM lives in the secret store under the name in `apns_key_secret`; the ids come from config:

| Config | Default | Meaning |
|---|---|---|
| `apns_key_id` | `` | Key id shown next to the `.p8` in the Apple developer portal |
| `apns_team_id` | `` | Apple developer team id (JWT `iss`) |
| `apns_bundle_id` | `` | App bundle id, sent as `apns-topic` |
| `apns_key_secret` | `apns_key` | Secret name holding the `.p8` PEM |
| `apns_sandbox` | `false` | Use `api.sandbox.push.apple.com` (development builds) |
| `apns_token_ttl` | `3000` | Seconds a minted provider token is reused; Apple rejects tokens older than an hour |

The provider JWT (ES256) is minted once and reused for `apns_token_ttl` seconds. Payloads are `{"aps":{"alert":{"title","body"},"sound":"default"}, …data}`, so the app reads custom keys from `userInfo` at the top level. A `410 Unregistered`, `BadDeviceToken` or `DeviceTokenNotForTopic` response marks the row `is_active=false`; any other non-200 surfaces as the `Dispatch` error without revoking.

### Device-token endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/push/register` | Idempotent upsert. Body: `{ "platform": "I\|A\|W", "token": "<fcm or apns token>", "appVersion": "1.2.3", "deviceModel": "iPhone 15" }`. Called by the mobile SDK after each login + on token-refresh events. In `fcm,apns` mode the `platform` value decides the provider, so an iOS build registering a raw APNs token must send `I`. |
| POST | `/api/push/revoke` | Mark a token inactive. Body: `{ "token": "<token>" }`. Called on explicit logout. |

### Dispatch

Server-side code that decides a push is warranted calls the provider directly:

```go
err := pushProvider.Dispatch(ctx, userID, "Order shipped", "Your order is on the way", map[string]string{
    "order_id": "o-123",
    "type":     "order_shipped",
})
```

Stale tokens (FCM `registration-token-not-registered`, APNs `410 Unregistered` / `BadDeviceToken`) are automatically marked `is_active=false` so subsequent dispatches skip them. `Dispatch` against a user with zero active devices is a silent no-op, not an error.

### device_token table

Columns: `id`, `user_id` (FK → user_account), `platform` (`CHAR(1)` — I=iOS, A=Android, W=Web), `token` (TEXT — FCM or raw APNs token), `app_version`, `device_model`, `is_active`, `created_at`, `updated_at`, `last_seen_at`. Unique index on `(user_id, token)` to keep re-registration idempotent. `DeleteAccount` cascades to deactivate every token for the user.

## Recording Sessions (consent-gated capture)

`recording.Service` orchestrates a capture session over an application context. Keel enforces that every required participant has a current, session-scoped consent before capture is authorized, tracks the session state, bounds capture with a renewable token, and stores media by object reference through `storage.ObjectStorage`. The camera runs on the client or a capture provider; keel never claims capture is happening until the client acknowledges it.

```go
rec := &recording.Service{DB: db, Consents: consentSvc, Storage: recordingsStore, CaptureTTL: 15 * time.Minute, MaxMediaBytes: 100 << 20, AllowedContentType: map[string]bool{"video/mp4": true}}

s, _ := rec.CreateSession(ctx, partnerID, "order:42", user.ConsentTypeVideoSession,
    user.ConsentPolicyRef{Type: "video", Region: "US", Version: "2026-09", Language: "en"}, actorID,
    []recording.Participant{{UserID: 7, Role: "customer"}, {UserID: 9, Role: "provider"}})
_ = rec.Decide(ctx, s.ID, 7, true, user.ConsentRequest{PolicyType: "video", PolicyVersion: "2026-09"})
_ = rec.Decide(ctx, s.ID, 9, true, user.ConsentRequest{PolicyType: "video", PolicyVersion: "2026-09"})
token, expires, err := rec.Start(ctx, s.ID, 9)          // ErrConsentMissing until both decided yes
_ = rec.Acknowledge(ctx, s.ID, actorID, token)            // client confirms capture is running
media, _ := rec.Upload(ctx, s.ID, actorID, token, "clip1.mp4", "video/mp4", body)
_ = rec.Stop(ctx, s.ID, 9)                                // finalizing → ready once media is stored
url, _ := rec.MediaURL(ctx, s.ID, 7, media.ID, 300)       // participants only, ready media only

invite, _, _ := rec.Invite(ctx, s.ID, 9, 10*time.Minute)  // a participant shares a join token (e.g. QR)
_, _ = rec.JoinWithConsent(ctx, invite, 12, "guest", user.ConsentRequest{PolicyType: "video", PolicyVersion: "2026-09"})
_, _ = rec.Reopen(ctx, s.ID, 9)                          // S or D → W; everyone consents again, media kept
```

| State | Meaning |
|---|---|
| `W` awaiting consent | created; participants deciding |
| `A` authorized | every participant consented; capture token issued |
| `R` recording | client acknowledged capture with the token |
| `F` finalizing | stopped; waiting for media |
| `D` ready | no upload pending and at least one object is ready; a failed clip stays failed and can be retried by key |
| `S` stopped | stopped before capture ever ran |
| `X` failed | reserved for application-marked failures |

- Consent is scoped to the session and resolved policy ID: `Decide` records with `ConsentRequest.PolicyID` and `EventRef`. `Start` locks the session while checking every participant.
- The creator need not be a participant (a dispatcher or system job may open a session); only participants may decide, start, stop, upload or read media. Re-creating a context with different consent terms returns `ErrConflict`.
- `Acknowledge`, `Renew`, and `Upload` require both a participant ID and the expiring capture token.
- Uploads require an allowed content type and size limit, use a session-prefixed object key, and may retry a failed media row by the same key.
- `Invite` mints a reusable, expiring join token (hash stored in `recording_invite`); `InviteSession` previews it. `JoinWithConsent` adds the joiner and records its consent under the same session lock, while the session is `W`, `A` or `R`.
- `Reopen` starts a new `attempt`; `EventRef(sessionID, attempt)` scopes consent to it, so earlier decisions no longer authorize `Start`.
- `Service.ObjectKey` overrides the `recording/<sessionID>/<key>` layout (e.g. by `Session.CreatedAt`); it must be deterministic, unique per (session, key) and stay under `recording/`.
- `ListMedia` and `PrivilegedMediaURL` skip the participant check for a caller the application has already authorized.
- `RetentionSweeper{DB, Storage, Retention, Hold}.Sweep` deletes ready objects older than `Retention` and marks them `R` purged; `Hold` exempts a session. `MediaURL` on purged media returns `ErrMediaPurged`.
- Typed errors let downstream handlers map failures without HTTP logic in the service.

The application owns: mapping its aggregate to `context_ref` with its own FK, deriving participants and roles, deciding which contexts are eligible, who may use the privileged media reads, what places a hold, and the client capture and upload implementation. Schema group `recording` (`recording_session`, `recording_participant`, `recording_media`, `recording_invite`) depends on `core` and `tenant_management`.

## Realtime WebSocket Hub

`realtime.Hub` holds the live sockets of one process and implements `port.WebSocketHub`. Keel owns the transport: authentication on the handshake, one registry of sockets per user, a subscribe / unsubscribe protocol over named channels, keepalive pings, and a relay through the cache service so a worker or another pod can deliver to a connected user. Everything on top is the downstream's: channel names, event payloads, who may subscribe to what, and what an inbound application frame means.

### Wiring

```go
hub := &realtime.Hub{
    Cache:   cacheSvc, // optional; enables cross-pod / cross-process delivery
    Journal: journal,
    CanSubscribe: func(ctx context.Context, userID int, channel string) (bool, error) {
        return myAccess.MayWatch(ctx, userID, channel)
    },
    OnMessage: func(ctx context.Context, userID int, msg []byte) error {
        return myInbound.Handle(ctx, userID, msg)
    },
}
if hub.Cache != nil {
    if err := hub.Run(ctx); err != nil { log.Fatal(err) }
}
srv.Handle((&handler.WebSocketHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
    Hub:             hub,
}).GetPublicRoutes()) // GET /public/ws — JWT via Authorization or ?token= (browsers cannot set headers on the handshake)
```

The socket lives under `/public` so the SSO middleware does not gate the handshake; the handler validates the JWT itself. WebSocket upgrades honor the `cors_origin` allowlist (override with `Hub.CheckOrigin`); a missing `Origin` header, as native apps send, is accepted.

`CanSubscribe` is required for channel subscriptions; nil denies them. An empty `cors_origin` permits native clients without `Origin` and enforces same-origin browser handshakes.

### Wire protocol

| Direction | Frame | Meaning |
|---|---|---|
| client → server | `{"op":"subscribe","channel":"order:42"}` | join a channel; answered by `{"op":"subscribed","channel":…}` or `{"op":"error","channel":…,"reason":"forbidden"}` |
| client → server | `{"op":"unsubscribe","channel":"order:42"}` | leave; answered by `{"op":"unsubscribed",…}` |
| client → server | anything else | passed to `OnMessage` unchanged |
| server → client | `{"channel":"order:42","data":{…}}` | a `Broadcast` / `PublishChannel` payload |
| server → client | `{…}` | a `SendToUser` / `PublishUser` payload, delivered raw |

Channel names are opaque strings to keel; choose them per aggregate (`order:42`, `conversation:9`). A socket's subscriptions end with the socket. Frames are capped at 64 KiB; the server pings every 30 s and drops a socket that does not answer within 60 s.

### Delivering

- From the process that holds the hub: `hub.SendToUser(userID, payload)` and `hub.Broadcast(channel, payload)`. With `Cache` set both go through the relay so every pod delivers to its own sockets; without it they reach local sockets only, and `SendToUser` errors when the user is not connected.
- From a worker or any other process: `realtime.PublishUser(ctx, cacheSvc, userID, payload)` and `realtime.PublishChannel(ctx, cacheSvc, channel, payload)`. Relay delivery is fire-and-forget; a user with no live socket is not an error, so keep a REST read path for state a client may have missed.
- As a notification channel: `notif.Register(realtime.NotificationChannel, &realtime.UserDispatcher{Cache: cacheSvc})` delivers `{"op":"notification","type","title","body","data"}` to the recipient's sockets. A channel that implements `port.TypedMessageDispatcher` (this one and `InboxService`) receives `req.Type`.

### What the downstream owns

- Producers: the service that changes an aggregate publishes its event on that aggregate's channel.
- Authorization: `CanSubscribe` decides who may watch a channel.
- Inbound frames: `OnMessage` parses and validates application messages; the authenticated `userID` is the only trusted identity in them.
- Payload schema and event names.

## Notifications & Messaging

Keel exposes a channel-keyed dispatcher abstraction so consumer code can fire `notif.Send({Channel: "email", UserID: 42, Title: ...})` without caring whether email/push/sms is wired up underneath. Email (SMTP/API via `MailClient`), push (FCM), and SMS (Twilio) all ship in keel; custom channels are consumer-supplied implementations of the same interface.

### `port.MessageDispatcher`

Single-channel delivery contract with two entry points. **`Dispatch`** resolves a `userID` to the channel-specific address (via `RecipientResolver`) and sends. **`Send`** delivers to an explicit `to` address — for recipients that aren't users (e.g. a business contact during claim verification). Returning `nil` for an empty/absent address is correct (the channel-level "nobody to notify" no-op); reserve non-nil errors for transport failures.

```go
type MessageDispatcher interface {
    Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error
    Send(ctx context.Context, to string, title, body string, data map[string]string) error
}
```

`Send`'s arguments carry per-channel meaning:

- **Email** — `to` = address, `title` = subject, `body` = text.
- **SMS** — `to` = E.164 or a national number; `data["country"]` = ISO-3166 region used to normalize a national number to E.164 (ignored once `to` starts with `+`); `title` is unused (SMS has no subject).
- **Push** — `to` = device token; `title`/`body` = the notification. Unlike `Dispatch`, `Send` can't auto-revoke a stale token (no userID), so the caller handles delivery errors.

> Note the two same-named methods at different layers: `NotificationService.Send(req)` is the **router** (picks a channel, then calls `Dispatch` or the dispatcher's `Send`); `MessageDispatcher.Send(ctx, to, …)` is a **channel's** explicit-address delivery.

`port.PushProvider` is now a deprecated alias of `MessageDispatcher` (same shape). FCM continues to satisfy both names; new code should depend on `MessageDispatcher`.

### `dispatcher.LocalNotificationService` — registry + router

Default keel implementation of `port.NotificationService`. Holds a channel name → dispatcher map; `Send(req)` routes by `req.Channel`, then delivers via the dispatcher's `Send` when `req.To` is set (explicit recipient) or `Dispatch` otherwise (resolve from `req.UserID`):

```go
notif := dispatcher.NewLocalNotificationService()
notif.Register("email", &dispatcher.EmailDispatcher{Mail: mailClient, Users: userSvc})
notif.Register("push",  fcmProvider)             // FCMPushProvider satisfies MessageDispatcher
notif.Register("sms",   smsDispatcher)           // dispatcher.NewSMSDispatcher (Twilio / Telnyx)

// Resolve the recipient from a userID:
err := notif.Send(ctx, port.NotificationRequest{
    UserID:  42,
    Channel: "email",
    Title:   "Receipt",
    Body:    "Thanks for your order…",
})

// …or deliver to an explicit address (no userID needed):
err = notif.Send(ctx, port.NotificationRequest{
    Channel: "sms",
    To:      "9493946318",
    Data:    map[string]string{"country": "US"}, // → +19493946318
    Body:    "Your verification code is 123456",
})
```

Unknown channel returns a typed error so callers can distinguish "channel not configured" from "dispatcher failed". `Channels()` lists registered channel names — useful for admin/diagnostic surfaces.

### `dispatcher.InboxService` — in-app inbox

Persists messages in `user_notification` and implements `port.NotificationInbox` (`Add`, `List`, `MarkRead`, `MarkAllRead`). Registered as a channel it stores `req.Type` as the consumer-defined `notification_type`:

```go
inbox := &dispatcher.InboxService{DB: db}
notif.Register(dispatcher.InboxChannel, inbox)
inboxHandler := handler.InboxHandler{AbstractHandler: base, Inbox: inbox} // mount GetAuthRoutes()
```

| Route | |
|---|---|
| `GET /notifications?before=<id>&limit=<n>` | `port.InboxPage{messages, unreadCount}`, newest first; `before` pages backwards, `limit` caps at 100 |
| `POST /notifications/mark_read` `{"id": "<id>"}` | 204; 404 for a message the caller does not own |
| `POST /notifications/mark_all_read` | 204 |

### `dispatcher.EmailDispatcher` — MailClient adapter

Wraps the existing `MailClient` so SMTP/API email plugs into the dispatcher registry:

```go
&dispatcher.EmailDispatcher{Mail: mailClient, Users: userSvc}
```

`Users` is a `port.RecipientResolver` (just `EmailFor` and `PhoneFor`) — the keel-shipped `LocalUserService` satisfies it directly, and consumers can wire a thinner address-only resolver (e.g. one backed by a recipient cache) if they don't want dispatcher to import the user package. Returns `nil` (no-op) when the user has no email on file — correct for deleted accounts and social-only signups that never set one.

**Custom headers.** `MailClient.SendEmail(ctx, subject, body, recipients, headers)` takes a `map[string]string` of extra RFC 5322 headers — pass `nil` for none, or e.g. `{"List-Unsubscribe": "<https://…/unsub?token=…>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}` for the Gmail/Yahoo one-click unsubscribe button. SMTP mode injects them into the message; API mode forwards them as a `headers` object in the JSON to the mail backend (which must place them on the outbound message). Names are validated (RFC 5322 field-name syntax; reserved/structural names like `From`/`Subject`/`Content-Type`/`Resent-*` are rejected; values may not contain C0 control bytes or DEL — tab excepted; a `Name: value` line over 998 octets is rejected) — `SendEmail` returns an error rather than silently rewriting a bad header. The `EmailDispatcher`/`LocalNotificationService` path does **not** carry headers — its `data` map is a generic per-dispatcher bag (the SMS adapter reads `data["country"]`), not RFC 5322 headers — so senders that need headers call `MailClient.SendEmail` directly. `SendEmailHTML` does not take a headers argument.

### `dispatcher.NewSMSDispatcher` — provider-agnostic SMS (Twilio / Telnyx / Quo)

Sends SMS through the provider selected by config `sms_provider`. All providers implement `port.MessageDispatcher` behind one factory, so they plug into `LocalNotificationService` on the `"sms"` channel behind one sender id — switching providers is a config + secret change, no code edits:

```go
sms, err := dispatcher.NewSMSDispatcher(ctx, secrets, userSvc, journal)
if err != nil {
    journal.Error("SMS disabled: " + err.Error()) // run cleanly with SMS off
} else {
    notif.Register("sms", sms)
}
```

Configuration:

| Source | Key | Purpose |
|---|---|---|
| Config | `sms_provider` | `twilio` (default), `telnyx` or `quo`; empty disables SMS |
| Config | `sms_service_sid` | Sender: Twilio Messaging Service SID (`MG…`), Telnyx Messaging Profile ID, or Quo phone number id (`PN…`)/E.164 number |
| Secret provider | `sms_auth_token` | Twilio auth token, Telnyx API key (Bearer), **or** Quo API key |
| Secret provider | `sms_account_sid` | Twilio account SID (basic-auth username). Unused by Telnyx and Quo. |

The sender pool (`sms_service_sid`) routes each outbound message to the right sender (CA long code, US 10DLC, UK/EU alphanumeric, …) from the senders/numbers attached in the provider console — adding regional coverage is a console-only change. **Telnyx** is the cost-effective alternative to Twilio and uses the same interface here (Bearer-auth JSON to the Messages v2 API vs Twilio's basic-auth form POST — the difference is entirely inside the provider adapter). **Quo** (formerly OpenPhone) has no sender-pool object — `sms_service_sid` names one sender directly, and the adapter posts one message per recipient to the v1 Messages API with the raw API key as the `Authorization` header (no `Bearer` prefix). Quo also caps `content` at **1600 characters** and rejects anything longer with a 400 — Twilio and Telnyx segment a long body transparently, so check message templates against that limit before switching a deployment to `quo`.

The factory fails fast when the provider is unset/unknown or a required credential/id is missing, so callers `Register` only on success. `Dispatch` resolves `userID` to an E.164 phone via the `RecipientResolver`, returning `nil` when there's no phone on file (the "nobody to notify" no-op); `Send` targets an explicit recipient. Non-2xx and transport failures are wrapped as errors so the worker logs and leaves the notification pending for retry.
