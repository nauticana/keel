# keel — deferred work

Tracking known issues and contribution opportunities. Items are grouped by tier; within a tier the order roughly matches priority. Severity tags: **HIGH** = security or data-integrity; **MED** = ergonomics or hardening; **LOW** = polish. Status tags: ✅ done, 🚧 in progress, ⏳ open, ⛔ won't do.

This file consolidates the prior v0.6 deferral notes plus the downstream-consumer review that previously lived in `TODO_FROM_SEO.md`.

---

## Status overview

| ID | Title | Tier | Severity | Status |
|---|---|---|---|---|
| A1 | `user_account` row-scope for non-SUPER roles | A | HIGH | ✅ done |
| A2 | Migration note for `EventParser.PeekEventMeta` | A | LOW | ✅ done |
| A3 | Drop unused `io.Reader` param in `StripeCheckoutClient.request` | A | LOW | ✅ done |
| A4 | LemonSqueezy no-timestamp note in README §Webhook | A | LOW | ✅ done |
| B1 | `payout/` package tests | B | MED | ✅ done |
| B2 | `pgsql/` package tests | B | MED | ✅ done (bundled with A1) |
| B3 | Commit generated DDL + `make verify-schema` | B | MED | ✅ done |
| B4 | `VerifySchema` invariant check on `SQLWebhookRepository` | B | MED | ✅ done |
| B5a | Picker scope: "unassigned users" view for partner_user FK | B | MED | ⏳ open — alternative to B5b |
| B5b | Invite-by-email handler (cleaner UX) | B | MED | ⏳ open — alternative to B5a |
| B6 | Document Wise SCA funding gap | B | MED | ✅ done |
| C1 | `port.MetricsRecorder` + Prometheus + correlation-id propagation | C | MED | ⏳ open — driven by demand |
| C2 | Distributed lock on `CacheService` for OTP issuance race | C | MED | ⏳ open — driven by demand |
| C3 | Paddle payment provider (ed25519) | C | MED | ⏳ open — driven by demand |
| C4 | Subscription mutation API on `CheckoutClient` | C | MED | ⏳ open — driven by demand |
| C5 | `CreateRefund` + `SubmitDisputeEvidence` | C | MED | ⏳ open — driven by demand |
| C6 | Webhook replay / dead-letter | C | MED | ⏳ open — driven by demand |
| C7 | Tax + coupon on `CheckoutRequest` | C | MED | ⏳ open — driven by demand |
| C8 | IP allowlist on webhook endpoints (defence-in-depth) | C | MED | ⏳ open — driven by demand |
| C9 | Fuzz tests on Stripe signature verification | C | LOW | ⏳ open |
| C10 | Property-based parser tests (`rapid`) | C | LOW | ⏳ open |
| — | Body cap inside `WebhookProcessor` | — | — | ⛔ won't do — see Won't do section |
| — | Log encoder errors on 5xx in `WriteError` | — | — | ⛔ won't do |
| — | Write-amplification DoS via webhook log | — | — | ⛔ won't do — closed in v0.5.0 |
| — | Multiple `AfterHandler` hooks slice | — | — | ⛔ won't do — Standards §1 |
| — | Full typed event-name enum across every provider event | — | — | ⛔ won't do — maintenance lag |
| — | `CONTRIBUTING.md` walkthrough | — | — | ⛔ won't do — Development Standards covers it |
| — | Per-package READMEs | — | — | ⛔ won't do — Standards §10 (doc-comments are the surface) |
| — | Rename `CheckoutClient` → `PaymentClient` | — | — | ⛔ won't do — major-version territory |

**Quick read.** All Tier A done. Tier B: ✅ five done, ⏳ one open (B5 — pick one of two alternatives). Tier C: ⏳ all ten open, defer until a downstream consumer asks.

---

## Tier B (open items only)

### B5. Pick one — picker scope OR invite-by-email [MED] ⏳

These are alternatives. Both close the "PARTNER_ADMIN sees all users globally on the picker" hole that A1 doesn't address (A1 stops API enumeration; the picker is the ADD path).

**B5a. Picker scope: "unassigned users only" for `partner_user → user_account` FK** ⏳

- New DB view `unassigned_user_account` shipped via `schema/security/`.
- `foreign_key_lookup` table gains a `source_table VARCHAR(60) NULLABLE` column.
- Seed row: `[user_partners, S, "*", unassigned_user_account]`.
- [data/abstract_repository.go](data/abstract_repository.go)`:loadFkLookupStyles` reads the new column.
- [model/foreign_key.go](model/foreign_key.go)`:ForeignKey` gains `SourceTable string` field exposed via JSON to sail.
- The sail frontend picker queries `/api/v1/<source_table>/list` when `SourceTable` is set.
- Parser-level test verifying a `PARTNER_ADMIN`'s picker query returns the unassigned set only.

Effort: ~40 lines Go + ~30 lines schema + ~10 lines seed. **Depends on A1 (done).**

**B5b. Custom invite-by-email handler (cleaner UX, replaces B5a)** ⏳

- New endpoint: `POST /api/partner-user/invite { email }`.
- If `user_account` exists for that email AND no active partner_user row: creates the partner_user (atomic).
- If `user_account` exists but is already assigned to another partner: 409 Conflict, no email leak.
- If `user_account` does not exist: triggers `RegistrationService.SendConfirmation` with a partner-bound payload so confirmation auto-creates the partner_user link.
- All three branches return the same 200 response shape — no enumeration via timing or response code.
- Permission: `PARTNER_ADMIN` PAGE ACCESS to `partner_user_invite`.

Effort: ~80 lines handler + tests.

---

## Tier C — feature surface (driven by downstream demand) ⏳

Real value but no concrete consumer asking yet. Defer until a downstream project requests one of these.

| ID | Title | Effort |
|---|---|---|
| C1 | `port.MetricsRecorder` interface + Prometheus impl + correlation-id propagation through webhook lifecycle | 1–2 days |
| C2 | Distributed lock on `port.CacheService` (`Lock(ctx, key, ttl)`) to close the multi-instance OTP race | 4–6 hr |
| C3 | Paddle payment provider (ed25519 signatures) — stress-tests the `SignatureVerifier` abstraction | 2–3 days |
| C4 | Subscription mutation API on `CheckoutClient` (`UpdateSubscription`, `Cancel/Pause/Resume`) | 1 day |
| C5 | Refund + dispute creation API — `CreateRefund` + `SubmitDisputeEvidence` (additive methods only; rename to `PaymentClient` is v1.0) | 4–6 hr |
| C6 | Webhook replay / dead-letter — `WebhookProcessor.RetryFailed` + `ReplayMode` flag on `PaymentEvent` | 1 day |
| C7 | Tax + coupon on `CheckoutRequest` — `CouponID`, `AutomaticTax`, `CustomerTaxID` | 1 day |
| C8 | IP allowlist on webhook endpoints — defence-in-depth + CPU savings (not the DoS fix originally claimed; that was closed in v0.5.0) | 3–4 hr |
| C9 | Fuzz tests on Stripe signature verification | 1 hr |
| C10 | Property-based parser tests (`rapid`) | 2 hr |

---

## Won't do (with rationale) ⛔

These items appeared in the prior reviews but conflict with Development Standards or are based on outdated / incorrect premises. Recorded here so they don't get re-raised.

| Item | Reason |
|---|---|
| Body cap inside `WebhookProcessor` | Already enforced upstream at `payment_handler.go:72` via `http.MaxBytesReader(w, r.Body, MaxWebhookBodyBytes)`. Bytes reaching `Process()` are bounded. Adding a second cap inside the processor is redundant for handler callers and only helps the documented-unusual path of calling `Process()` directly. |
| Log JSON encoder errors on 5xx in `WriteError` | `ProblemDetail` is a fixed-shape struct with only `string`/`int` fields; `json.Marshal` cannot fail. The Encoder write failure mode is "client disconnected mid-response" — not actionable. |
| Write-amplification DoS via webhook log | The premise (log row written before signature verification) was true in pre-v0.5 keel. The v0.5.0 refactor moved verify before log; bad signatures never touch the DB. See the doc-comment on `WebhookProcessor.Process` step 2. |
| Multiple `AfterHandler` hooks (slice + ordering) | Development Standards §1: "Ports are minimal." Downstream composition of N hooks is a 3-line wrapper. Adding API surface for what callers can do explicitly conflicts with the minimal-interface rule. Revisit if a concrete consumer asks. |
| Full typed event-type enum (every Stripe / LemonSqueezy event name) | Stripe alone has 100+ event types. A keel-side enum becomes a maintenance lag — every new provider event needs a keel update before downstreams can `case payment.EventChargeRefunded:`. The provider-name + checkout-mode constants shipped earlier are the right scope. |
| `CONTRIBUTING.md` walkthrough | Development Standards §1–§12 in README cover contribution conventions. Duplicating into `CONTRIBUTING.md` invites drift. |
| Per-package READMEs | Development Standards §10: "Doc comments are the public surface." Per-package READMEs drift from code; package-level Go doc-comments don't. Improve doc-comments where they're thin instead. |
| Rename `CheckoutClient` → `PaymentClient` | Development Standards §11: renames go in major version bumps, not minor. v1.0 territory if ever. |

---

## Done in current cycle ✅

Closed by recent work. Each row links to the artifact that made the change.

| ID | Title | Where |
|---|---|---|
| A1 | `user_account` row-scope for non-SUPER roles | `model.TableDefinition.PartnerUserScoped` + `data.GlobalRoleIDs` + `data.QCheckGlobalRole` + `IsGlobalRole` helper; injected subquery in [pgsql/table_service.go](pgsql/table_service.go) `Get` / `Delete`; auto-set on `user_account` in `AbstractRepository.Init` |
| A2 | Migration note for `EventParser.PeekEventMeta` interface gain | [README.md](README.md) — new section before the v0.5.9 migration guide |
| A3 | Dropped unused `io.Reader` param in `StripeCheckoutClient.request` | [payment/stripe_client.go](payment/stripe_client.go) |
| A4 | LemonSqueezy no-timestamp-window note + corrected Webhook Lifecycle | [README.md](README.md) — Payments → Webhook Lifecycle + Signature replay protection table |
| B1 | `payout/` package tests — 15 tests | [payout/payout_test.go](payout/payout_test.go) — HMAC helper, three providers' StartOnboarding / RequestInstantPayout / VerifyAndParseWebhook, factory dispatch |
| B2 | `pgsql/` package tests — 6 tests | [pgsql/table_service_test.go](pgsql/table_service_test.go) — row-scope injection + bypass + by-key path + Delete defence-in-depth + QCheckGlobalRole shape |
| B3 | Committed DDL + `make verify-schema` CI gate | [schema/basis_pgsql.sql](schema/basis_pgsql.sql), [schema/basis_mysql.sql](schema/basis_mysql.sql), [Makefile](Makefile) — `gen-pgsql` / `gen-mysql` / `gen-schema` / `verify-schema` |
| B4 | `SQLWebhookRepository.VerifySchema` invariant check | [payment/webhook_repository_sql.go](payment/webhook_repository_sql.go) — boot-time `pg_indexes` assertion |
| B6 | Wise SCA funding gap documented + Payout provider matrix corrected | [README.md](README.md) — Payout section + flags table |
| — | Bug fix: multi-line table comments produced syntax-broken SQL | `commentBlock` helper in [schema/dialect/dialect.go](schema/dialect/dialect.go); used by [pgsql.go](schema/dialect/pgsql.go) + [mysql.go](schema/dialect/mysql.go); DDL regenerated |
| — | Repo cleanup: deleted `dialect/*.go.bak`; added `*.bak`/`*~`/`*.swp`/`bin/` to [.gitignore](.gitignore); deleted `TODO_FROM_SEO.md` | |

## Already shipped (prior cycles)

| Item | Where |
|---|---|
| Payment provider name constants (`ProviderStripe` / `ProviderLemonSqueezy`) | [payment/payment_interfaces.go](payment/payment_interfaces.go) |
| Checkout mode constants (`ModeSubscription` / `ModePayment` / `ModeSetup`) | [payment/payment_interfaces.go](payment/payment_interfaces.go) |
| Payout provider code constants (`ProviderCodeAirwallex` / `ProviderCodeStripeConnect` / `ProviderCodeWise`) | [payout/payout_interfaces.go](payout/payout_interfaces.go) |
| `EventParser.PeekEventMeta` — polymorphic peek replacing the provider-name switch | [payment/payment_interfaces.go](payment/payment_interfaces.go) + [payment/webhook_processor.go](payment/webhook_processor.go) |
| `payout.AbstractProvider` — embedded base for the three payout providers | [payout/payout_interfaces.go](payout/payout_interfaces.go) |
| `OnboardingService` `sync.Once` query-service cache | [payout/onboarding_service.go](payout/onboarding_service.go) |
| Stripe Connect full wiring — `StartOnboarding` + `RequestInstantPayout` | [payout/stripe_connect.go](payout/stripe_connect.go) |
| Wise full wiring (email-type recipient) — `StartOnboarding` + `RequestInstantPayout` (funding deferred — see B6) | [payout/wise.go](payout/wise.go) |
| Typed `airwallexAPIError` / `stripeAPIError` / `wiseAPIError` replacing substring error matching | [payout/](payout/) |
| `--airwallex_api_base` / `--wise_api_base` / `--wise_profile_id` flags | [common/variables.go](common/variables.go) |
| Stdlib-reinvention cleanup (`toUpperASCII`, `upper`, `equalFold`, `extractProviderCode`, `userServiceFromAbstract`) | various |
| Development Standards §1–§12 | [README.md](README.md) |
