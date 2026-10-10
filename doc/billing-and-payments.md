# Billing and Payments

Billing, payment processing, payouts, and reseller commissions.

## Billing

keel already shipped the payment *substrate* — the Stripe/LemonSqueezy webhook pipeline (`payment.WebhookProcessor`), the checkout client (`payment.StripeCheckoutClient`), the quota engine (`service.QuotaServiceDb`), and the canonical `subscription_*` / `partner_plan_subscription` / `usage_ledger` / `payment_method` tables. Keel also provides the reusable **SaaS billing glue** needed to compose billing from configuration and a thin wiring layer.

| New | What it does | Project supplies |
|---|---|---|
| `billing.AbstractBillingService` (+ `BillingService` interface) | `GetSubscription/CreateSubscription/CancelSubscription/GetPlans/GetInvoices/GetUsage` over the basis tables; `GetPlans` returns each plan with its `Prices[]` (one per offered billing interval); `CreateSubscription` takes the chosen interval; returns the `ErrNoSubscription`/`ErrPlanNotFound`/`ErrPriceNotFound` sentinels so a handler can `errors.Is` → 404/400 | `Queries` overrides, `ResourceNames` |
| `billing.AbstractBillingService` provider-driven write helpers (exposed via the `ProviderBillingStore` interface): `RecordProviderInvoice` (writes the `invoice` row on a provider `invoice.paid` so `GetInvoices` isn't empty — keel otherwise writes invoices only in the SelfScheduledEngine; idempotent on `invoice_number`), `LinkCustomer`/`CustomerToken`/`PartnerByCustomer` (partner ↔ provider-customer mapping in the dedicated `partner_billing_customer` table, for the portal + recurring-invoice attribution), `ListPaymentMethods` (the partner's saved methods for sail's `listPaymentMethods()`) | — (call from your `AbstractWebhookEventHandler` hooks / billing bridges) |
| `billing.SubscriptionLifecycle` (on `AbstractBillingService`) | the subscription verbs over `partner_plan_subscription`: `Activate(…, BillingTerms, …)`/`ChangePlan(…, BillingTerms)`/`CreateSubscription(…, BillingTerms)` take the chosen offer (billing cycle + commitment term) — they read the matching `subscription_plan_price` row and snapshot the price, set `renewal_date` (= term end), `next_charge_date`, and the per-installment `monthly_cost`, `CancelByPartner`/`CancelByProviderSubID` (immediate or at-period-end), `ConvertTrial`, `SetSeats`, `Reactivate`, `SetDunningState` | per-plan `activation_mode` + `trial_days` + the `subscription_plan_price` rows; the metadata keys |
| `payment.PaymentEvent.EventKind` + typed ids/lines | provider-agnostic event kind; `SubscriptionID`, `InvoiceID`, `ChargeID`, `DisputeID`; and canonical `InvoiceLines` with completeness, signed minor amount, currency, service period, and metadata | — |
| `payment.AbstractWebhookEventHandler` | dispatches `EventKind` → nil-safe hooks (`OnCheckoutCompleted/OnInvoicePaid/OnInvoicePaymentFailed/OnSubscriptionUpdated/…`) | the per-kind closures (your domain SQL) |
| `billing.ProviderSubscriptionEventHandler` (a `payment.PaymentEventHandler`) | the **default** provider-driven mapping pre-wired on `AbstractWebhookEventHandler`: `checkout_completed`→`LinkCustomer`+`Activate` (terms from `metadata[BillingCycleKey/TermTypeKey/TermCountKey]`), `invoice_paid`→`RecordProviderInvoice`+`ConvertTrial`, `invoice_payment_failed`→past-due (`X`), `subscription_canceled`→`CancelByProviderSubID` (fallback `CancelByPartner`). Collapses a hand-written `payment_service.go` to wiring | `billing.NewProviderSubscriptionEventHandler(svc, svc, opts)` — partner resolution + metadata keys (`PartnerIDKey`/`PlanIDKey`/`BillingCycleKey`/`TermTypeKey`/`TermCountKey`) |
| `handler.QuotaEnforcer` | HTTP middleware: count new resources in a POST body → `CheckQuota` → **402** + optional post-write `After` hook. `CountOpCodeRows` builds your extractors | `Extractors []ResourceExtractor` |
| `handler.FeatureGate` | entitlement via the `cap<0` flag convention: `FeatureAllowed`, `ListFeatures`, `FilterResponseField` (strip a premium child from a GET) | `Features`, `StripFeature`/`StripRecordKey` |
| `payment.AddonReconciler` + `StripeAddonReconciler` | sync a metered add-on quantity as a subscription item (INERT when `PriceID==""`) | `PriceID`, `DesiredQty`, `SubIDFor` closures |
| `payment.ChargeClient` + `StripeChargeClient` | off-session charge of a vaulted method. `ChargeRequiresAction` = the PaymentIntent has a `next_action` to run; `ChargeAuthenticationRequired` = the off-session confirmation was refused for SCA, so the customer confirms it again on-session with `ChargeResult.PaymentMethodID` + `ClientSecret` (Stripe.js `confirmCardPayment`, stripe-ios `STPPaymentHandler.confirmPayment`); declines and any other PaymentIntent status are `ChargeFailed` with the reason in `Error`; an undecodable provider response is returned as `err`; forwards `ChargeRequest.Metadata` onto the PaymentIntent so the settled charge's webhook can correlate back; `StripeCheckoutClient.PostRaw(ctx, path, form, idemKey)` exposes the 4xx body and threads a caller idempotency key | `ChargeRequest` per call (`AmountMinor`, `IdempotencyKey`, `Metadata`) |
| `worker.AbstractBillingReconciler` | daily backstop pass over active partners (run from a systemd timer, never a CI cron) | `Partners`, `Reconcile` closures |
| `billing.BillingEngine` (+ `ProviderSubscriptionEngine`, `SelfScheduledEngine`) | the recurring-engine strategy: provider runs the cycle **or** we self-schedule (own billing-run → off-session charge → invoice → dunning). `SelfScheduledEngine.BillSubscriptionsFromTable` enables keel's built-in **installment engine**: charges every due `partner_plan_subscription`, computes the per-installment amount from its snapshot terms, advances `next_charge_date`, and rolls to a new term (`auto_renew`) or ends the row at term end | engine choice + the self-scheduled closures (or just the flag for the built-in installment pass) |
| basis: `invoice`/`invoice_line`/`partner_billing_customer`, `subscription_plan_price{plan_id,billing_cycle,term_count,term_type,amount_minor,currency,provider_price_id}` (per-offer prices, nested under `subscription_plan` via `rest_api_child`), `subscription_plan.{activation_mode,trial_days}`, `subscription_addon.{billing_cycle,term_count,term_type}`, `partner_plan_subscription`/`partner_addon_subscription.{billing_cycle,term_count,term_type,amount_minor,renewal_date,next_charge_date,…}` | the missing billing tables/columns | per-env seed of `subscription_plan_price` rows (amount + `provider_price_id`) + `activation_mode` |

What stays the application's: the plan catalog and prices, the resource taxonomy and count SQL, the per-event domain mapping (or only its options with `ProviderSubscriptionEventHandler`), add-on economics, feature names and branding.

`handler.BillingHandler` serves sail's billing paths. Cancel, plan change and the portal need `Subscriptions`, `DB` and a `PARTNER_PLAN_SUBSCRIPTION` grant (`CANCEL`, `CHANGE`, `PORTAL` on `partner_plan_subscription`, seeded for `PARTNER_ADMIN`); the read routes need only a session.

### Provider-driven vs self-scheduled

`ProviderSubscriptionEngine` lets Stripe Billing / LemonSqueezy run the recurring cycle (you only react to webhooks via `AbstractWebhookEventHandler`); it carries the provider's recurring fee but is the least code and handles SCA/dunning/retries for you. `SelfScheduledEngine` runs the cycle itself (a systemd-timer billing-run that charges off-session via `ChargeClient`, writes its own `invoice`, and owns dunning + SCA) — it avoids the recurring fee and is maximally provider-agnostic, but you own the money-critical SCA/dunning/proration logic. **Test self-scheduled exhaustively in provider test mode before enabling**, and keep it behind a per-plan flag (it is inert until its closures are wired).

**Money is integer minor units.** Amounts on the charge path are `int64` minor units, never floats: `InvoiceDraft` lines and the authoritative `invoice.total_minor` column carry the exact value, while `invoice.subtotal`/`total` are a display-only major-unit projection. Conversions go through `common.CurrencyExponent` / `common.ParseMinorUnits` / `common.FormatMinorUnits`, which derive the decimal places from the ISO‑4217 currency — so JPY (0 minor digits) and BHD (3) are correct, not a hardcoded ×100 — and refuse an unknown code instead of assuming two. Stripe's `amount` is already minor units, so `ChargeRequest.AmountMinor` passes straight through.

**Off-session charge idempotency & atomicity.** `SelfScheduledEngine` charges with the invoice id as Stripe's `Idempotency-Key` (threaded via `StripeCheckoutClient.PostRaw(ctx, path, form, idemKey)`), so a charge retried after an ambiguous transport failure resolves to the original PaymentIntent instead of double-charging. Stripe remembers a key for 24h; a dunning retry past that window is treated as new, so the engine still stops once the invoice flips to paid. The `invoice` header + its lines are written in one `TxQueryService` transaction, so a half-written invoice is never charged.

**Off-session charge metadata.** `ChargeRequest.Metadata map[string]string` is forwarded as PaymentIntent `metadata[k]=v`, so the resulting `charge`/`payment_intent` webhook arrives with the same pairs on `PaymentEvent.Metadata` — the outbound counterpart to the inbound metadata already surfaced to webhook handlers. Use it to carry the originating record's ids (e.g. order/booking id, line splits) and correlate the settled charge back without a Stripe round-trip. It is validated against Stripe's limits **before** the network call (≤49 caller keys, key ≤40 chars, value ≤500 chars; the `idempotency_key` key is reserved); a violation returns the typed `payment.ErrInvalidMetadata` (map to a 4xx at the handler boundary) rather than silently truncating.

**Checkout line correlation.** `CheckoutRequest.LineMetadata` is separate from
top-level Session `Metadata`. Stripe subscription checkouts mirror it into
`subscription_data[metadata]` (one-shot payments into
`payment_intent_data[metadata]`, setup mode into
`setup_intent_data[metadata]`). Stripe snapshots subscription metadata onto
subscription invoice lines, so keys such as `business_id` survive from
checkout creation to `PaymentEvent.InvoiceLines[i].Metadata`.

### Subscription lifecycle & activation modes

`SubscriptionLifecycle` (default impl on `AbstractBillingService`) owns the verbs every SaaS re-implements over `partner_plan_subscription`. How a checkout *activates* a sub is the plan's **activation mode** (`subscription_plan.activation_mode`, the `SUBSCRIPTION_ACTIVATION_MODE` dictionary) — a small, **open** enum, so a new policy is a dictionary row, not a schema break:

| Mode | Code | Activation |
|---|---|---|
| create-active | `A` | INSERT a fresh active row (provider already created the sub) — the default; preserves the old `CreateSubscription` behavior |
| activate-pending | `P` | flip a pre-seeded `status='P'` row → `'A'` (register-then-pay flows) |
| trial | `T` | start `status='T'` + `trial_end` (from `subscription_plan.trial_days`); `ConvertTrial` flips `T→A` on the first paid invoice |
| free | `F` | active immediately, no provider sub / charge |

These four are mutually-exclusive **policies**. Orthogonal to them are **modifiers** that overlay any policy, so they are *columns, not enum values*: `seats` (seat-based pricing — pairs with `AddonReconciler`), `trial_end`/start-date (scheduling), the engine choice (`ProviderSubscriptionEngine` vs `SelfScheduledEngine`), and the collection method (charge-now vs send-invoice). Putting `seats` in the mode enum would make "seat-based trial" inexpressible — keep it a modifier.

**Billing is three independent axes — payment cadence, commitment term, and price — not one "interval".** Conflating them is the classic billing bug; keel keeps them separate (`billing.BillingTerms`):

- **`billing_cycle`** (`PERIOD_TYPE`: `W`/`M`/`Q`/`A`) — *how often money is taken*. Drives `next_charge_date`.
- **`term_count` × `term_type`** — *the commitment*. Drives `renewal_date` (= **term end**, when it renews or ends) and the no-refund-on-early-cancel behavior. `term_count` is usually 1; `auto_renew` continues past it.
- **`amount_minor`** — *the price for one `term_type` unit* (e.g. $/year), authoritative integer minor units, never a float. Per-charge = `amount ÷ installments(term_type→billing_cycle)`; contract total = `amount × term_count`.

This expresses every real shape, e.g. **$1000/yr billed monthly** (`billing_cycle=M`, `term=1·A`, `amount=$1000` → twelve $83.33 charges, the last truing up the remainder) or **a 3-year fixed-price contract paid monthly** (`term=3·A`). The offers a plan sells are rows in `subscription_plan_price(plan_id, billing_cycle, term_count, term_type, amount_minor, currency, provider_price_id)` (Stripe Product→Prices), nested under `subscription_plan` via `rest_api_child`; each offer has its own `provider_price_id`. The customer picks one **at checkout** — the terms belong to the *subscription*, not the plan.

- **Activation:** `Activate(…, BillingTerms, …)` / `ChangePlan(…, BillingTerms)` / `CreateSubscription(…, BillingTerms)` read the matching price row (`ErrPriceNotFound` otherwise) and **snapshot** the price onto `partner_plan_subscription`, set `renewal_date = begda + term`, `next_charge_date = begda` (first installment due), `amount_minor`, and the per-installment display `monthly_cost`. All dates are computed in Go and bound — the lifecycle INSERTs carry no dialect-specific `INTERVAL` SQL.
- **Price locks for the term, refreshes on renewal:** the snapshot holds the price steady for the whole committed term, so a long commitment is how you lock a fixed/discount price. At renewal the engine re-reads the current offer and re-snapshots — so a month-to-month sub (1-month term) follows the current price each month, while a 3-year term holds its price for 3 years. If the offer was withdrawn, the term can't renew and the row ends.
- **Cancellation falls out for free:** cancel-at-period-end sets `effective_cancel_date = renewal_date`. A monthly term ends next month; a committed annual/3-yr term keeps billing monthly until the term ends — exactly the discount-commitment rule. `auto_renew` then decides whether a new term begins.
- **Installment engine:** set `SelfScheduledEngine.BillSubscriptionsFromTable = true` and each `RunCycle` charges every due subscription: it computes the installment (exact int64, remainder on the final charge of the term), advances `next_charge_date` by one `billing_cycle`, and at term end either rolls to a new term (`auto_renew`, re-reading the current price) or stops and ends the row. Pure math lives in `BillingTerms`/`InstallmentMinor` (unit-tested); `InstallmentsPerUnit` errors rather than guessing for cycles that don't divide the term unit.
- **Provider-driven path:** `ProviderSubscriptionEventHandler` reads terms from `metadata[BillingCycleKey/TermTypeKey/TermCountKey]` (defaults `billing_cycle`/`term_type`/`term_count`, stamped by the checkout creator from the selected price); a field absent from the metadata falls back to `opts.DefaultTerms` (whose zero value is monthly / 1-month term).
- **Catalog read:** `GetPlans` returns each `Plan` with `Prices []PlanPrice` (cycle, term, `AmountMinor`, major `Amount`, currency, `PriceID`) — the single source of truth for pricing. Build the checkout `AllowedPriceIDs` whitelist from `Prices[].PriceID`.
- **Annual-only products** (e.g. an annually-billed plan) seed a single `A`-term price row per plan and pass `BillingTerms{TermType: PeriodAnnual}` (or, on the provider-driven path, set `opts.DefaultTerms` to the annual offer instead of stamping term metadata); they no longer fork the lifecycle SQL.

`subscription_addon` carries the same `billing_cycle`/`term_count`/`term_type` columns; the built-in installment pass currently covers plan subscriptions (addons via `AddonReconciler` / project closures as before). Multi-currency per term is a future extension (add `currency` to the price PK).

Statuses use the `SUBSCRIPTION_STATUS` dictionary: `A` active · `P` pending payment · `T` trialing · `C` cancelled (voluntary) · `X` expired/past-due (involuntary). `SetDunningState` moves `A↔X`; cancels set `C` (immediate) or `effective_cancel_date` (at-period-end, finalized by `AbstractBillingReconciler`).

*Not* activation modes (handled separately): **metered/usage** (a billing model over an already-active sub), **comp/admin grant** (set `A` via an admin path), and the transitions **change-plan / reactivate / pause** (their own verbs). Further policies — one-time/lifetime, invoice-terms (NET-x), manual/sales-approval — slot into the open dictionary when a project needs them.

> **Note:** `ProviderSubscriptionEventHandler`'s `checkout_completed` always *activates* — it does not detect a plan change, so a re-checkout for a different plan creates a second active row rather than switching. Route upgrades/downgrades through `ChangePlan` (e.g. from `subscription_updated`), not a fresh checkout. Cancels (immediate or at-period-end, by partner or provider-sub-id) act on both active (`A`) and trialing (`T`) subs.

## Payments (Stripe & LemonSqueezy)

Keel ships a provider-agnostic payment layer: HMAC signature verification,
idempotent webhook processing, canonical event parsing, and a Stripe checkout
client. Each consumer project implements a small `PaymentEventHandler`
that maps canonical events into its domain actions.

### Webhook Lifecycle

```
POST /public/webhook/{provider}
  1. Bind/reuse request id; read body (MaxBytesReader, 256 KiB cap)
  2. Peek event id + type via EventParser.PeekEventMeta — reject empty id
  3. Verify signature BEFORE any DB write — bad signatures never touch storage
  4. Idempotency check on (provider, event_id) — duplicates → return without dispatching
  5. Insert correlated log row (unique-index race guard catches concurrent retries)
  6. Parse into canonical PaymentEvent (minor-unit amount, identities, request id, metadata)
  7. Enrich through optional PaymentEventEnricher (Stripe fetches every invoice-line page)
  8. Call project's PaymentEventHandler.OnPaymentEvent(event)
  9. AfterHandler hook (optional, idempotent) — e.g. attach SetupIntent's PaymentMethod
 10. Update log status; when Metrics is wired, record counter + duration with a request-id exemplar
```

The verify-before-log ordering is load-bearing: an attacker pumping invalid-signature requests never reaches the DB, so `payment_webhook_log` cannot be filled with unsigned junk. Step 4 is the cheap-path dedupe; step 5's unique index on `(provider, event_id)` is the authoritative race guard for the TOCTOU window between them.

Statuses are `R` (received/in progress), `P` (processed), `F` (failed and replayable), `S` (skipped by the allowlist), `D` (legacy duplicate), and `L` (dead-lettered, terminal). Status-write failures are returned rather than discarded, so an HTTP 200 can no longer hide a row that failed to reach `P`.

`AbstractPaymentHandler` preserves an upstream `common.RequestID` or creates one before processing. The same id is stored on `payment_webhook_log.request_id`, exposed to the domain handler as `PaymentEvent.RequestID`, included in lifecycle logs, and attached to Prometheus samples as an exemplar. It is deliberately not a metric label: request ids as labels create one time series per request.

### Operator replay and dead-letter

Provider redelivery still atomically reclaims an `F` row. Once the provider's retry window has ended, run an explicit operator sweep:

```go
summary, err := processor.RetryFailed(ctx, domainHandler, payment.WebhookReplayOptions{
    Limit:       50,
    MaxAttempts: 5,
})
```

`RetryFailed` claims one oldest replayable row at a time with `FOR UPDATE SKIP LOCKED`, increments `replay_attempts`, and dispatches its already-verified stored payload. Claims are scoped to the processor's registered providers, so a row for a decommissioned provider stays `F` untouched instead of spending budget or dead-lettering. An id cursor guarantees each row is claimed at most once per sweep, and a claim lease (`last_claimed_at`, database clock, `webhook_claim_lease_seconds` config flag, default 900) spaces attempts on the same row across sweeps — including concurrent ones — so a still-failing row costs one attempt per lease window rather than burning its whole budget at once. It intentionally does not recheck the provider signature: a Stripe signature timestamp has normally expired by then. `PaymentEvent.ReplayMode` is true on this path, so domain code can suppress non-idempotent ancillary behavior if necessary. A final failed attempt moves the row to `L`; an already-failed row beyond a newly lowered attempt budget is terminalized without dispatch. Later provider deliveries and replay sweeps cannot reclaim `L`. The sweep continues past individual event failures and returns both its `WebhookReplaySummary` and a joined error for operator alerting.

The same lease recovers crashed claims: a row stuck in `R` past its lease — the process died between the claim and the terminal status write — is claimable again by both provider redelivery and `RetryFailed`. Configure the lease longer than the slowest dispatch; a handler that legitimately runs longer would have its claim stolen and dispatched twice, which idempotent handlers absorb.

Run this from an authenticated operator action or a separate worker/CLI, never from the public provider endpoint. Domain handlers and `AfterHandler` must remain idempotent because a replay re-enters both.

### Signature replay protection per provider

| Provider | Signed payload | Replay window | What stops replay |
|---|---|---|---|
| **Stripe** | `<unix_ts>.<body>` (HMAC-SHA256) | ±5 min (`Stripe-Signature: t=...,v1=...`) | Bidirectional timestamp window in `StripeSignatureVerifier`. A captured signed pair becomes invalid 5 minutes after Stripe emitted it. |
| **LemonSqueezy** | `<body>` (HMAC-SHA256, no timestamp) | none — see below | **The `(provider, event_id)` unique index on `payment_webhook_log` is the sole replay defence.** |

**LemonSqueezy specifics — read carefully if you integrate a non-LemonSqueezy.com source against this verifier.** LemonSqueezy's webhook signature is HMAC-SHA256 over the raw body alone — no timestamp is in the signed payload, so the signature itself stays valid forever. The only thing preventing an attacker who captured a single legitimate webhook+signature pair from replaying it indefinitely is the idempotency layer:

- [payment/parser_lemosqueezy.go](../payment/parser_lemosqueezy.go) **rejects** payloads whose `data.id` is missing (no synthetic-id fallback).
- [payment/webhook_processor.go](../payment/webhook_processor.go) treats any prior `(provider, event_id)` row — even in status 'R' (in flight) — as a duplicate and never re-dispatches.
- The unique index on `payment_webhook_log(provider, event_id)` is the authoritative race guard at the DB layer.

Operational implications:

1. If you point this verifier at a webhook source that emits non-unique or stable `data.id` values, idempotency collapses and the first signed event will be the only one ever processed. Verify your source emits a fresh id per event.
2. If your `payment_webhook_log` schema lacks the UNIQUE constraint on `(provider, event_id)`, replay protection degrades to a non-atomic "exists check then insert" — a concurrent retry can sneak past. The schema-invariant check (see `SQLWebhookRepository.VerifySchema`) asserts the constraint at boot; run it.
3. LemonSqueezy webhooks are NOT safe to log to a non-deduplicating sink and replay later by hand — the deduplication is the security boundary.

### Core Interfaces

Payment interfaces are defined in [payment/payment_interfaces.go](../payment/payment_interfaces.go); the monitoring boundary is [port/metrics.go](../port/metrics.go):

| Interface | Purpose |
|-----------|---------|
| `PaymentEventHandler` | Implemented by each project — maps `PaymentEvent` → domain action |
| `SignatureVerifier` | Validates a provider's webhook signature |
| `EventParser` | Converts raw provider body → canonical `PaymentEvent` |
| `PaymentProvider` | Bundles name + signature header + verifier + parser |
| `PaymentEventEnricher` | Optional authenticated follow-up that completes a parsed event before dispatch |
| `WebhookRepository` | Persists, claims, and updates log rows (idempotency + audit + replay) — `SQLWebhookRepository` is the default |
| `CheckoutClient` | Outbound checkout / billing-portal API (Stripe impl: `StripeCheckoutClient`) |
| `port.MetricsRecorder` | Records backend-neutral counter/histogram measurements; `metrics.PrometheusRecorder` is the Prometheus adapter |

### Wiring Example

```go
import (
    "github.com/nauticana/keel/handler"
    "github.com/nauticana/keel/payment"
)

stripeClient := payment.NewStripeCheckoutClient(secrets)

repo := payment.NewSQLWebhookRepository(db)
processor := payment.NewWebhookProcessor(
    repo,
    journal,
    payment.NewStripeProvider(secrets),
    payment.NewLemonSqueezyProvider(secrets),
).
    // fail-closed on dashboard misconfiguration. Events not
    // listed here are logged with status='S' and never dispatched.
    // Omit the call to allow every signed event through.
    WithAllowedEventTypes(
        "checkout.session.completed",
        "setup_intent.succeeded",
        "invoice.paid",
        "customer.subscription.deleted",
    )
    // optional follow-up hook for cross-cutting work that must
// run AFTER OnPaymentEvent succeeded — e.g. attaching a freshly-saved
// PaymentMethod to the customer for default-payment-method routing.
// MUST be idempotent — Stripe re-delivers on a 5xx and OnPaymentEvent
// will run again on the retry.
processor.AfterHandler = func(ctx context.Context, e *payment.PaymentEvent) error {
    if e.EventType != "setup_intent.succeeded" || e.SetupIntentID == "" {
        return nil
    }
    // Read the SetupIntent to recover the PaymentMethod, then attach it.
    body, err := stripeClient.Get(ctx, "/setup_intents/"+e.SetupIntentID, nil)
    if err != nil { return err }
    // ... extract pm_xxx from body, then:
    _, err = stripeClient.Post(ctx, "/payment_methods/pm_xxx/attach",
        url.Values{"customer": {e.CustomerID}})
    return err
}

paymentHandler := &handler.AbstractPaymentHandler{
    Processor: processor,
    Handler:   &myDomainHandler{db: db},       // implements port.PaymentEventHandler
    Checkout:  stripeClient,
    Journal:   journal,
}

srv.Handle(map[string]func(http.ResponseWriter, *http.Request){
    "/public/webhook/stripe":       paymentHandler.HandleStripeWebhook,
    "/public/webhook/lemonsqueezy": paymentHandler.HandleLemonSqueezyWebhook,
    "/api/billing/checkout":        paymentHandler.CreateCheckout,
})
```

`Processor.Metrics` is optional. A deployment with an existing Prometheus
runtime can construct `metrics.NewPrometheusRecorder(ownedRegisterer)` and
inject it. Keel does not create a registry, expose a `/metrics` route, or choose
a scrape topology; deployments without that monitoring design leave the field
nil. Correlated lifecycle logs and replay/dead-letter behavior are independent
of metrics wiring.

### Project-Specific Handler

`OnPaymentEvent` receives a typed `*PaymentEvent`; branch on typed fields
instead of unmarshalling `RawPayload`. Stripe invoice events carry
pagination-complete `InvoiceLines` before dispatch. Check
`InvoiceLinesComplete` before treating an empty slice as authoritative. Each
line carries `AmountMinor`, `Currency`, `ServiceFrom`, `ServiceTo`, and
`Metadata`. Refund/dispute consumers correlate through `ChargeID` and
`DisputeID`. The JWT-gated checkout path also injects `user_id` into top-level
metadata automatically. `RequestID` correlates domain logs to the webhook log
and metrics exemplar; `ReplayMode` identifies an operator replay.

```go
func (h *myDomainHandler) OnPaymentEvent(ctx context.Context, e *payment.PaymentEvent) error {
    userID := e.Metadata["user_id"] // auto-injected by CreateCheckout for JWT-gated callers
    switch e.EventType {
    case "checkout.session.completed":
        if e.Mode == "setup" {
            // PaymentMethod-capture flow; the SetupIntent fires its own event.
            return nil
        }
        return h.activateSubscription(ctx, userID, e.Metadata["plan"], e.MinorUnits)
    case "setup_intent.succeeded":
        // e.SetupIntentID and e.CustomerID are pre-extracted.
        return h.recordPaymentMethod(ctx, userID, e.SetupIntentID, e.CustomerID)
    case "invoice.paid":
        return h.recordRenewal(ctx, e)
    case "customer.subscription.deleted":
        return h.cancelSubscription(ctx, userID)
    }
    return nil
}
```

### Outbound Stripe API calls — `StripeCheckoutClient.Get` / `Post`

Webhook handlers and after-hooks often need to read or mutate Stripe resources synchronously (e.g. expand a SetupIntent to get the attached PaymentMethod, or attach a PaymentMethod to a Customer). Use the same `StripeCheckoutClient` you already constructed for `CreateCheckoutSession` — it carries the secret, retry budget, and 1 MiB response cap.

```go
// Read: GET /v1/setup_intents/{id}?expand[]=payment_method
body, err := client.Get(ctx, "/setup_intents/"+id, url.Values{
    "expand[]": {"payment_method"},
})

// Write: POST /v1/payment_methods/{id}/attach
form := url.Values{"customer": {"cus_abc"}}
body, err := client.Post(ctx, "/payment_methods/pm_xyz/attach", form)
```

`Get` does NOT send the `Idempotency-Key` header (Stripe rejects it on read endpoints); `Post` does. Both apply the shared 5xx/429 retry with exponential backoff.

### Secrets

| Secret name | Used by | Purpose |
|-------------|---------|---------|
| `stripe_secret_key` | `StripeCheckoutClient` | Basic-auth to `api.stripe.com` |
| `stripe_webhook_secret` | `StripeSignatureVerifier` | HMAC key for Stripe webhook validation |
| `lemonsqueezy_webhook_secret` | `LemonSqueezySignatureVerifier` | HMAC key for LS webhook validation |

### Database Tables

| Table | Purpose |
|-------|---------|
| `payment_webhook_log` | Raw inbound webhooks — idempotency key on `(provider, event_id)`, request correlation, replay attempts, and terminal dead-letter state |
| `payment_method` | Partner-owned provider customer tokens (`stripe cus_...`) |
| `payment_record` | Completed / failed / refunded transactions — `amount_minor` is authoritative; provider-scoped unique payment id; optional indexed `(provider, provider_charge_id)` for refund/dispute correlation; `invoice_id` FK |
| `invoice_line_payment` | Durable payment (`P`) / refund (`R`) allocation to invoice lines in minor units; `provider_ref` uniquely keys refund sources |

### Checkout modes

`POST /api/billing/checkout` accepts three Stripe modes via the `mode` field:

| Mode | `priceId` required | Use case |
|------|--------------------|----------|
| `subscription` (default) | yes — must be in `AllowedPriceIDs` | Recurring billing — subscriptions, seats |
| `payment` | yes — must be in `AllowedPriceIDs` | One-off charge |
| `setup` | **must be empty** | Capture a payment method without charging (SetupIntent flow). `line_items` are omitted from the Stripe request; a non-empty `priceId` here is rejected because Stripe ignores it anyway. |

Setup mode returns the same `{ "checkoutUrl": "..." }` shape; Stripe persists a SetupIntent on the resulting session that consumers can read from `setup_intent.succeeded` webhooks. The handler enforces the `mode` allowlist (one of the three values above) before reaching the port — unknown modes fail with 400, not a downstream Stripe 502.

**`AllowedRedirectHosts` matching:** an entry without a colon matches the URL's hostname port-insensitively, so listing `"app.example"` accepts both `https://app.example/` and `https://app.example:8443/`. An entry containing a colon (e.g. `"app.example:8443"`) stays port-strict.

### Refunds — `payment.RefundClient`

`StripeChargeClient.CreateRefund` refunds part or all of a captured payment:

```go
res, err := chargeClient.CreateRefund(ctx, payment.RefundRequest{
    PaymentID: "pi_…", AmountMinor: 500, Currency: "USD",
    IdempotencyKey: "refund-<your request id>", Reason: "requested_by_customer",
})
// res.RefundID, res.Status (pending | succeeded | failed), res.AmountMinor, res.Currency
```

The idempotency key is required so a retried request cannot refund twice. The payment's currency is read from the provider before the refund is posted. If the provider reports a different amount than requested, the result is returned together with `ErrRefundAmountMismatch`: the refund exists and must be reconciled, not retried. A currency that does not match the payment's is rejected before any ledger effect. Whether a refund is owed, who approves it, and who bears it are application decisions; persist the authorized request before calling the provider and reconcile the outcome by refund id.

**Sign rule for inbound refund events.** Refund amounts are negative. `charge.refunded` sets `RefundCumulative=true` and carries the cumulative total; `charge.refund.updated` carries one refund delta and its `RefundID`. Consumers must deduplicate by provider identity and must not negate the amount again.

### Native payment sheet intents

Mobile apps that confirm on-device need a client secret rather than a hosted checkout URL. `payment.IntentClient` (implemented by `StripeCheckoutClient`) creates the Stripe customer when none is given, mints the customer-scoped ephemeral key the mobile SDK requires, and returns the intent's client secret:

```go
type IntentClient interface {
    CreateSetupIntent(ctx, IntentRequest) (*IntentResult, error)   // save a card, usage=off_session
    CreatePaymentIntent(ctx, IntentRequest) (*IntentResult, error) // Amount (minor units) + Currency
}
// IntentResult{IntentID, ClientSecret, CustomerID, EphemeralKey}
```

Set `AbstractPaymentHandler.Intents` and mount `CreateSetupIntent`, by convention at `POST /api/billing/setup-intent`. It is always JWT-gated, takes no body, derives the email and `metadata[user_id]` from the authenticated session, and answers `{setupIntentId, clientSecret, customerId, ephemeralKey}` with `Cache-Control: no-store`. It never accepts a caller-supplied provider customer ID: wire `payment.UserCustomerService{DB, Provider: payment.ProviderStripe}` into the `CustomerID` and `LinkCustomer` hooks — the first intent's customer is stored in `user_billing_customer` and reused; with `CustomerID` unset every call creates a new provider customer. `UserPaymentMethodService.RecordFromSetupIntent` stores `currency` as NULL unless one is passed: a SetupIntent carries none, so charge in the order's currency, not the card's. Payment intents carry an amount, so there is no HTTP route for them: the service that knows the price calls `CreatePaymentIntent` and hands the client secret to the app only when Stripe reports `requires_action` (3DS). `StripeCheckoutClient.APIVersion` pins the `Stripe-Version` header used to create ephemeral keys; other Stripe calls retain the account's configured API version.

**Removing a saved method.** `UserPaymentMethodService.Remove(ctx, userID, id)` detaches the method at the provider through `Detacher` (`payment.PaymentMethodDetacher`, implemented by `StripeChargeClient`; a `seti_…` token is resolved to its PaymentMethod, and an already-detached or missing method is success), then deletes the row; a failed detach keeps it. `UserPaymentMethodHandler` serves it as the `remove` table action (`POST …/user_payment_method/remove`, `{id}`, 404 for a method the user does not own). Generic REST DELETE on `user_payment_method` is not granted, so a client cannot skip the detach. Removing the default leaves none; the charge path takes the newest method. A restricted Stripe key needs **Payment Methods: write**.

### What each project still owns

- **Event → domain action mapping** — your `OnPaymentEvent` switch.
- **Plan ↔ Price ID table** — hardcode, flag, or DB; keel's checkout takes any `price_xxx`.
- **Accounting / journaling** — keel is provider-neutral; per-project until a pattern clearly repeats.
- **Success / cancel URLs** — computed from each project's `ConfirmBaseURL`.

## Payout (Airwallex / Stripe Connect / Wise)

`keel/payout` is the out-bound counterpart to `keel/payment`. It abstracts the third-party providers that hold bank routing details and disburse payouts to partner users (marketplace sellers, contractors, creators, gig-economy workers — keel is domain-neutral). The application never sees raw IBAN / SWIFT / ABA / institution numbers; only the provider's account handle.

### Provider feature matrix

| Provider | Code | Onboarding | Webhook | Instant payout | Status lookup | Notes |
|---|---|:--:|:--:|:--:|:--:|---|
| Airwallex      | `AW` | ✅ via beneficiary | ✅ | ✅ | ✅ | Payout destination is a **Beneficiary**: app collects details with Airwallex's embedded component, then `OnboardingService.RegisterBeneficiary` creates it and persists the id. Hosted-KYC `StartOnboarding` is connected-account KYC only — `acct_…` ids are rejected at dispatch. Rail/reason via `airwallex_transfer_method`/`airwallex_transfer_reason` flags. |
| Stripe Connect | `SC` | ✅ | ✅ | ✅ two-leg | ✅ | Express accounts via `/v1/account_links`. Disbursement = platform transfer + connected-account **instant payout**; `ErrInstantPayoutUnavailable` on ineligible destinations. |
| Wise           | `WI` | ✅ | ✅ | ✅ | ✅ | Email-recipient model — no hosted KYC; transfer is created **and balance-funded** (see below). |

The payout SQL surface is **PostgreSQL-only** — call `OnboardingService.VerifySchema` and `SQLWebhookLog.VerifySchema` once at boot; they fail fast on MySQL (or a missing unique index) before any money moves.

### `PayoutProvider` interface

```go
type PayoutProvider interface {
    Code() string
    StartOnboarding(ctx, StartOnboardingInput) (*PayoutOnboardingSession, error)
    VerifyAndParseWebhook(headers, rawBody) (*PayoutWebhookEvent, error)
    RequestInstantPayout(ctx, InstantPayoutInput) (*InstantPayoutResult, error)
    GetPayoutStatus(ctx, providerPayoutID) (*InstantPayoutResult, error)
}
```

`RequestInstantPayout` takes integer minor units (`599` = $5.99 USD); each provider converts to its native wire representation with exact integer math — Wise and Airwallex send ordinary currency decimals (`5.99`), Stripe sends minor units unchanged. `GetPayoutStatus` is the reconciliation path when a transfer webhook was missed; provider idempotency-key retention is finite, so look up before reissuing an old key.

Events are normalized into a small taxonomy — account lifecycle (`account.created` / `activated` / `updated` / `rejected`), transfer lifecycle (`transfer.paid` / `failed` / `returned` / `reversed`), and `ignored` for verified events with nothing to apply — the service layer never reads provider-native event names. Webhook signature verification is per-provider HMAC; failures surface as the typed error and the handler replies 401 to trigger provider retry with backoff. `OnboardingService` dedupes events durably on the provider's raw event id via the basis `payout_webhook_log` table (`payout.SQLWebhookLog`) and dispatches transfer events to the application's `TransferEventSink`.

### `user_bank_info` table (basis)

Ships with basis.sql. **Versioned**: surrogate `id` PK, at most one **active** row per `(user_id, partner_id)` (`status='A'`, partial unique index; MySQL degrades to service-enforced). Identity-bearing changes (provider, account, tax id, holder, country, currency, address) close the active row via `OnboardingService.SupersedeBankInfo` (`status='S'`, `superseded_at`) and insert a fresh one — destination history is never overwritten; onboarding lifecycle fields mutate the active row in place. A `(id, partner_id)` unique index lets downstream tables pin an exact destination version with a declared composite FK. Multi-partner users get one active row per partner, with the option to **share one `provider_account_id` across rows** via `OnboardingService.LinkReusableAccount` (no provider call — the account already cleared KYC on the provider's side; the link copies the source row's real activation state, never manufactures it).

Columns: `country_code`, `currency`, `account_holder_name`, `billing_address`, `tax_id_type`, `tax_id_encrypted` (secret display mode — never ordinary CRUD input), `provider`, `provider_account_id`, `provider_agreement`, `provider_onboarded_at`, `status`, `superseded_at`. PartnerSpecific auto-filter applies via the `partner_id` FK.

### Downstream wiring

```go
provider, err := payout.NewProvider(*kcommon.PayoutProvider, apiKey, webhookSecret, journal)
providers := payout.NewStaticProviderResolver(provider) // or NewSQLProviderResolver(db, providers...) per partner
instructions := payout.NewInstructionService(payout.NewSQLInstructionStore(db), providers, appAllocator, journal)
svc := &payout.OnboardingService{
    DB:                  db,
    Providers:           providers,
    OnboardingReturnURL: *kcommon.PayoutReturnURL,
    WebhookCallbackURL:  *kcommon.PayoutWebhookURL,
    WebhookLog:          payout.NewSQLWebhookLog(db), // durable event-id dedup — required in production
    TransferSink:        instructions,                // payout.InstructionService, or your own TransferEventSink
    Journal:             journal,
}
h := &handler.PayoutHandler{
    AbstractHandler: handler.AbstractHandler{UserService: userSvc},
    PayoutService:   svc,
}
mux.Handle(h.Routes(kcommon.RestPrefix + "/v1"))
```

`partner_payout_provider` maps a partner to its provider code; webhooks select the provider by the code in the route. `InstructionService` records each payout in `payout_instruction`, dispatches it through one or more `payout_instruction_leg` attempts outside any transaction, and applies transfer events once per `(provider, event_id)` in `payout_instruction_event`, bounding reversals by the leg amount. The app's `payout.Allocator` posts and releases the amount against its earnings in the same transactions. `ReconcileInFlight(ctx, before, limit, partnerIDs)` polls stuck legs (empty `partnerIDs` = all). `handler.PayoutInstructionActionHandler{DB, Instructions}` serves `cancel`, `execute` (retry new/failed), and audited `resolve` (manual review) actions behind separate permissions, scoped to the caller's partner unless it holds a global role.

Routes registered:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/payout/onboard/start` | session | Mint hosted-KYC link |
| POST | `/api/v1/payout/reusable`      | session | List user's other-partner accounts |
| POST | `/api/v1/payout/reusable/link` | session | Reuse an account on the current partner |
| POST | `/api/v1/payout/status`        | session | "Onboarding complete?" boolean |
| POST | `/api/v1/payout/bank/replace`  | session | Atomic bank-info version replacement (wire `SealTaxID` on the handler) |
| POST | `/api/v1/payout/beneficiary/register` | session | Create provider Beneficiary from app-collected details, link as destination |
| POST | `/api/v1/webhook/payout/{AW\|SC\|WI}` | signature | Provider webhook intake |

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `payout_provider` | `AW` | Provider code for a single-provider deployment (`AW` / `SC` / `WI`); per-partner codes live in `partner_payout_provider` |
| `payout_return_url` | (empty) | Deep-link the provider redirects to after hosted KYC |
| `payout_webhook_url` | (empty) | Public host the provider posts webhooks to |
| `airwallex_api_base` | `https://api-demo.airwallex.com` | Airwallex REST API base — flip to `https://api.airwallex.com` for production |
| `wise_api_base` | `https://api.sandbox.transferwise.tech` | Wise Platform REST API base — flip to `https://api.wise.com` for production |
| `wise_profile_id` | (empty) | Wise platform profile id (numeric). **Required** when `payout_provider=WI` |

### Wise specifics — recipient model + balance funding

Wise's Platform API does not have a hosted KYC flow for platform-paid recipients. Bank details flow through the platform's own UI, then the platform creates the recipient via API. To stay within `user_bank_info`'s schema (no IBAN/sort_code/BIC columns), the keel implementation uses **`type=email` recipients** — Wise sends the recipient an email claim link and they enter their own bank details on Wise's side. `StartOnboarding` returns an empty `URL` and a numeric recipient id in `ExternalAccountID`; sail's frontend should render "linked, awaiting recipient email confirmation" when `URL` is empty.

`RequestInstantPayout` creates the Wise transfer via `POST /v3/profiles/{profile}/quotes` + `POST /v1/transfers`, then **funds it from the profile's Wise balance** (`POST /v3/profiles/{profile}/transfers/{id}/payments`, `type=BALANCE`) — creation alone was never disbursement. A funding rejection is a loud error; the idempotency key stays valid, so a retry re-creates nothing and re-attempts funding. Profiles with Strong Customer Authentication enabled reject the balance payment with an approval challenge — resolve SCA at the profile level before shipping Wise-backed payouts. Track transfer state through `transfers#state-change` webhooks (normalized to `transfer.*` events) or `GetPayoutStatus` polling.

### Secrets

| Secret | Required | Source |
|---|---|---|
| `payout_provider_key` | yes (when payouts enabled) | Provider dashboard — API key / bearer token |
| `payout_webhook_secret` | yes (when payouts enabled) | Airwallex / Stripe: HMAC signing key. Wise: the PEM **public** key Wise publishes for RSA-SHA256 webhook signatures |

### What the application owns

`OnboardingService` deliberately stops at the bank-info table. The calling application is responsible for:

- **Fee / minimum / cooldown** policy on `RequestInstantPayout`. Keel runs the transfer; the application gates whether it should.
- **Payout ledger + state machine** — generic payout callers record the returned `ProviderPayoutID` against their domain table and consume `transfer.*` events via a `TransferEventSink`. Agency commission payouts can use `agency.BaseAgencyPayoutService` instead. A payout is paid only on provider-confirmed completion, never on creation.
- **Reconciliation cadence** — polling `GetPayoutStatus` for payouts stuck in a non-terminal state past a threshold. (Event dedup itself is keel's job now — `payout_webhook_log` — not an application cache.)

## Agency / reseller commission

`keel/agency` is the shared agency-channel layer over `billing` provenance and
`payout` providers. Basis now owns `agency_profile`,
`agency_client_invitation`, `agency_client_delegation`,
`agency_client_billing`, `agency_client_rate`, `agency_commission`,
`agency_payout_profile`, `agency_payout`, and `agency_payout_line`. Apps add only
FK-backed extension tables when their managed entity is narrower than a
`business_partner` (for example, a business below the client partner). Basis
does not impose a partner-wide active-delegation uniqueness constraint: the
direct-partner base service serializes on the partner row and permits one,
while a narrower app enforces uniqueness on its extension entity so separate
businesses owned by one client can use different agencies.

A client controls what its agency may do through roles on the delegation
(`agency_delegation_role`), each an `agency_delegation_role` code (seeded
`view`, `operate`, `publish`; products add `constant_value` rows) with an
optional `expires_at`. Acceptance creates a delegation with no roles, which
grants no access. `SetDelegationRoles`, callable by the client partner only and
gated by `AGENCY_DELEGATION/SET_ROLE` (granted to `PARTNER_ADMIN`), replaces the
whole set in one transaction; an empty set removes access without revoking.
Every grant, expiry change and removal appends an `agency_delegation_event` row
(`G`, `E`, `R`). Revoking a delegation expires its open roles at the database
clock in the same transaction and keeps the rows. Authorization code depends on
`port.AgencyDelegationResolver`: `ActiveFor` lists an approved, unsuspended
agency's active delegations holding at least one unexpired role, and `HasRole`
returns nil or `ErrDelegationNoAccess`.

`agency.TenantResolver` answers which partners a caller may act in, for
surfaces where one identity spans tenants (an API, an MCP server).
`Authorized(ctx, model.TenantCaller)` lists the user's current own partners,
then the clients delegated to any of them when the user holds
`AGENCY/MANAGE_CLIENTS`, or the one partner an API key is bound to; an inactive
user or a malformed caller is `ErrTenantCaller`. A delegated `model.Tenant`
carries its `Level`: the highest of the injected `Levels` (lowest first) the
delegation holds; roles not listed grant nothing. A client the user also belongs
to stays own; one several agencies share resolves at the highest level. `Resolve` picks a requested tenant, the only one for `0`,
or returns `TenantChoiceError` (`ErrTenantRequired`); a tenant outside the set
is `ErrTenantNotFound`, never forbidden. `DelegationPrincipal(level)` is the
role principal (`LevelRoles`) a delegated caller is authorized as instead of
its own roles, and `Delegable(scope)` is false for the `NeverDelegated` grant
scopes. `CacheTTL` bounds how long a revocation keeps resolving;
`AuthorizedFresh` bypasses it before an irreversible action.

The agency commission, provenance, and payout runtime is PostgreSQL-only. The
MySQL artifact includes the tables for schema portability, but it does not
provide a runnable implementation of the transaction/query semantics.

The commercial model is deliberately small:

- Every accepted client starts in referral (`R`) billing. Referral charges the
  client normally and creates commission for the agency.
- `agency_profile.wholesale_allowed` is permission to switch an individual
  client to wholesale (`W`); it does not force every client wholesale.
- Commission is percentage-only. `BaseFrozenRateResolver` freezes one
  `agency_client_rate.commission_rate_bp` at the client's first eligible earning:
  agency override first, otherwise the `default_commission_rate_bp` application
  config flag. Later default changes do not rewrite that client; each ledger row
  snapshots `applied_rate_bp`.
- There is no `agency_commission_rule`, tier/fixed-rate schedule, or
  `btree_gist` dependency. PostgreSQL prevents two open billing rows with a
  partial unique index; historical intervals are maintained by the atomic
  close-then-insert service flow.
- Amounts remain integer minor units and balances/payouts remain separated by
  currency. `commission_hold_days` controls held-to-payable promotion and
  `agency_payout_min_minor` controls monthly selection. Display projections use
  `NUMERIC(20,4)` so currencies with three minor-unit digits are not rounded.

`billing.ProvenanceRecorder` writes `payment_record`, `invoice_line`, and
`invoice_line_payment` atomically, validates canonical provider lines fail
closed, and invokes an injected recognition hook in the same transaction.
`PaymentEvent.PaymentID` is the provider payment transaction key (separate from
the invoice and webhook-event ids). Signed credit/proration lines remain on the
invoice; captured money is apportioned across positive service lines, and a
line whose share rounds to zero receives no allocation or commission.
`billing.ProvenanceReverser` performs source-idempotent, balance-capped refund
allocation and invokes an injected reversal hook. `agency.BaseCommissionRecognizer`
and `agency.BaseCommissionReverser` are the standard hooks. The monthly
`BaseAgencyPayoutService` reserves payable ledger rows in a short transaction,
dispatches outside that transaction, resumes retryable work with the same
provider idempotency key, releases provider-confirmed terminal failures, and
uses manual-review state for partial or otherwise unknown provider outcomes.
Payable reversals net immediately against the next payout even when the refund
arrives after the monthly earning cutoff. A balance at or above the payout
minimum with no active destination for its provider/currency is returned as an
operations-visible cycle error instead of remaining silent.

Agency enrollment grants the `AGENCY` role while approval is pending so the
app can render profile and read-only status/history views. Client, billing,
invitation-cancellation, and payout-destination mutations also enforce an
active, non-suspended profile in the service. Payout-profile `GET` requires
`AGENCY/VIEW_EARNINGS`; `POST` separately requires `AGENCY/MANAGE_PAYOUT`.
The generic `agency_profile` admin API intentionally has no nested commission
ledger children; ledger/history views use their dedicated endpoints.

Status codes are column-scoped. Commission `entry_type` uses `E` earning / `R`
reversal; commission `status` uses `H` held, `P` payable, `R` reserved, `D`
disbursed, `O` offset or settled reversal. Payout `status` uses `C` created,
`P` provider-pending, `D` disbursed, `F` failed, `M` manual review, `R`
returned, and `V` reversed.

The HTTP surface is supplied by `handler.AgencyHandler`:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/agency/enroll` | Create a pending `agency_profile` |
| GET | `/api/v1/agency/profile` | Read agency approval/wholesale state |
| GET/POST | `/api/v1/agency/clients` | List or stage invitations |
| POST | `/api/v1/agency/clients/invite` | Mint/reuse an invitation token |
| POST | `/api/v1/agency/clients/cancel` | Withdraw an invitation |
| GET | `/public/agency/invite` | Read public invitation summary |
| POST | `/api/v1/agency/invite/accept` | Accept and create referral delegation |
| GET/POST | `/api/v1/agency/payout-profile` | Read/select a fully onboarded payout destination |
| GET | `/api/v1/agency/earnings` | Read currency-separated balances and history |
| POST | `/api/v1/agency/delegation/roles` | Client replaces the agency's role set and per-role expiries |

Wire `AgencyHandler.Routes(restPrefix+"/v1", "/public")`, install the returned
handlers, and wire `payout.OnboardingService.TransferSink` to the agency payout service.
The consuming app still decides which invoice lines are commission-eligible and
supplies that attribution when invoking the provenance recorder. Routes and
brand copy remain app-owned on the frontend.

When invitation acceptance fails because the authenticated user has no business
partner yet, the RFC 7807 response includes `code: "agency_no_partner"`.
Clients branch on this stable code; `detail` remains human-readable copy and may
change. Other registered errors continue to omit `code` unless explicitly
registered with `handler.RegisterErrorCode`, or with `handler.RegisterErrorMessage`
when the sentinel's own text is not client wording.

