# keel — deferred work

Tracking known issues and contribution opportunities. Items are grouped by tier; within a tier the order roughly matches priority. Severity tags: **HIGH** = security or data-integrity; **MED** = ergonomics or hardening; **LOW** = polish. Status tags: ✅ done, 🚧 in progress, ⏳ open, ⛔ won't do.

This file consolidates the v0.6 deferral notes plus the downstream-consumer review that previously lived in `TODO_FROM_SEO.md`. Last reconciled against the tree at **v1.2.40** (2026-07-29). Shipped feature work is not tracked here — `migration_guide.json` is the changelog and `CODE_REVIEW_*.md` holds review findings; this file tracks only what is still deferred.

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
| B5a | Picker scope: "unassigned users" view for partner_user FK | B | LOW | ⏳ open — alternative to B5b, **re-scoped** |
| B5b | Invite-by-email handler (cleaner UX) | B | MED | ⏳ open — alternative to B5a, **preferred** |
| B6 | Document Wise SCA funding gap | B | MED | ✅ done |
| C1 | `port.MetricsRecorder` + Prometheus; correlation-id through the webhook lifecycle | C | **HIGH** | ⏳ open — **re-ranked**, amplifies C6: money-path failures are currently unobservable |
| C2 | Distributed lock on `CacheService` for OTP issuance race | C | MED | ⏳ open — driven by demand |
| C3 | Paddle payment provider (ed25519) | C | MED | ⏳ open — driven by demand |
| C4 | Subscription mutation API | C | MED | ✅ done — shipped on `billing.SubscriptionLifecycle`, not `CheckoutClient` |
| C5 | `CreateRefund` + `SubmitDisputeEvidence` | C | MED | ⏳ open — premise strengthened by v1.2.39/40 |
| C6 | Operator-initiated webhook replay + dead-letter | C | **HIGH** | ⏳ open — **re-ranked**, ledger-integrity risk once the agency layer carries volume |
| C7 | Tax + coupon on `CheckoutRequest` | C | MED | ⏳ open — driven by demand |
| C8 | IP allowlist on webhook endpoints (defence-in-depth) | C | MED | ⏳ open — driven by demand |
| C9 | Fuzz tests on Stripe signature verification | C | LOW | ✅ done |
| C10 | Property-based parser tests (`rapid`) | C | LOW | ⏳ open — lower value now, fuzz targets cover adjacent ground |
| C11 | Subscription pause / resume | C | LOW | ⏳ open — residual of C4 |
| D1 | Reconcile fail-open vs fail-closed on `SecurityHandler.Cache == nil` | D | MED | ⏳ open |
| — | Body cap inside `WebhookProcessor` | — | — | ⛔ won't do — see Won't do section |
| — | Log encoder errors on 5xx in `WriteError` | — | — | ⛔ won't do |
| — | Write-amplification DoS via webhook log | — | — | ⛔ won't do — closed in v0.5.0 |
| — | Multiple `AfterHandler` hooks slice | — | — | ⛔ won't do — Standards §1 |
| — | Full typed event-name enum across every provider event | — | — | ⛔ won't do — maintenance lag |
| — | `CONTRIBUTING.md` walkthrough | — | — | ⛔ won't do — Development Standards covers it |
| — | Per-package READMEs | — | — | ⛔ won't do — Standards §10 (doc-comments are the surface) |
| — | Rename `CheckoutClient` → `PaymentClient` | — | — | ⛔ won't do — major-version territory |

**Quick read.** All Tier A done. Tier B: ✅ five done, ⏳ one open (B5 — pick one of two alternatives; B5b preferred). Tier C: ✅ two done (C4, C9), ⏳ nine open — **C6 and C1 are the two to close before the agency/commission layer carries production volume**; the rest wait for a downstream consumer to ask. Tier D: ⏳ one open.

**Severity note.** No open item is a brute-force or data-exposure hole: password login, OTP verify, TOTP verify, and backup-code verify all bound attempts through a persisted counter that locks the account, so they are unaffected by cache backend or replica count. C2's per-process counters multiply only the secondary layers. The genuine production exposure is on the money path — C6 (a webhook stranded past the provider's retry window yields no `payment_record`, therefore no commission, permanently and silently) and C1 (nothing surfaces that it happened).

---

## Tier B (open items only)

### B5. Pick one — picker scope OR invite-by-email ⏳

These are alternatives, and **the original rationale no longer holds**. This entry used to read "both close the *PARTNER_ADMIN sees all users globally on the picker* hole that A1 doesn't address (A1 stops API enumeration; the picker is the ADD path)."

A1 set `PartnerUserScoped` on `user_account` ([data/abstract_repository.go](data/abstract_repository.go)`:275`), and `Get` injects `id IN (SELECT user_id FROM partner_user WHERE partner_id = …)` for every non-global role. The picker reads that same scoped list endpoint, so the enumeration hole is closed — and the problem inverted: a `PARTNER_ADMIN` now sees **only already-assigned** users, so the ADD picker cannot surface anyone to add. What is left is a functional gap, not a security hole. Severity drops accordingly, and the inversion favours B5b, which needs no unassigned-users view at all.

Before acting, confirm the picker really does read `/api/v1/user_account/list`. The `foreign_key_lookup.lookup_style` metadata implies it, but the fetch is sail-side and cannot be verified from this repo.

**B5a. Picker scope: "unassigned users only" for `partner_user → user_account` FK** [LOW] ⏳

Plan below is still accurate: the `user_partners` FK exists ([schema/security/09_partner_user.yml](schema/security/09_partner_user.yml)) and `foreign_key_lookup` carries no row for it.

- New DB view `unassigned_user_account` shipped via `schema/security/`.
- `foreign_key_lookup` table gains a `source_table VARCHAR(60) NULLABLE` column.
- Seed row: `[user_partners, S, "*", unassigned_user_account]`.
- [data/abstract_repository.go](data/abstract_repository.go)`:loadFkLookupStyles` reads the new column.
- [model/foreign_key.go](model/foreign_key.go)`:ForeignKey` gains `SourceTable string` field exposed via JSON to sail.
- The sail frontend picker queries `/api/v1/<source_table>/list` when `SourceTable` is set.
- Parser-level test verifying a `PARTNER_ADMIN`'s picker query returns the unassigned set only.

Effort: ~40 lines Go + ~30 lines schema + ~10 lines seed. **Depends on A1 (done).**

**B5b. Custom invite-by-email handler (cleaner UX, replaces B5a — preferred)** [MED] ⏳

The agency layer shipped a working precedent to mirror rather than reinvent: `agency_client_invitation` + `AgencyHandler.InviteClient` / `AcceptInvite` already implement token-minting, TTL expiry, and a uniform response across the exists / already-assigned / unknown branches.

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
| C1 | `port.MetricsRecorder` interface + Prometheus impl, and correlation-id propagation through the **webhook lifecycle**. The HTTP-boundary half already shipped (`common.RequestID` context key, `ProblemDetail.RequestID`, 5xx log correlation in `writeError`) — only metrics and the webhook path remain | 1 day |
| C2 | Distributed lock on `cache.CacheService` (`Lock(ctx, key, ttl)`) to close the multi-instance OTP race | 4–6 hr |
| C3 | Paddle payment provider (ed25519 signatures) — stress-tests the `SignatureVerifier` abstraction | 2–3 days |
| C5 | Refund + dispute creation API — `CreateRefund` + `SubmitDisputeEvidence` on `ChargeClient` (additive only; a rename to `PaymentClient` is v2.0 territory). v1.2.39/40 added inbound refund/dispute **provenance** (`billing.BaseProvenanceReverser`, typed `ChargeID`/`DisputeID`), so keel now reconciles refunds it cannot itself create — the asymmetry is the argument for closing this | 4–6 hr |
| C6 | **Operator-initiated** webhook replay + dead-letter. Retry-on-provider-redelivery already shipped via `WebhookRepository.ReclaimFailed` (KR-002), so a failed delivery is no longer permanently stranded; what remains is an explicit replay sweep and a dead-letter terminal state. The `outbox` package's dead-letter handling is the model to follow | 4–6 hr |
| C7 | Tax + coupon on `CheckoutRequest` — `CouponID`, `AutomaticTax`, `CustomerTaxID` | 1 day |
| C8 | IP allowlist on webhook endpoints — defence-in-depth + CPU savings (not the DoS fix originally claimed; that was closed in v0.5.0) | 3–4 hr |
| C10 | Property-based parser tests (`rapid`). Lower value since C9: `payment/parser_test.go` and `signature_test.go` carry four fuzz targets covering adjacent ground | 2 hr |
| C11 | Subscription pause / resume — the only mutation C4 listed that `billing.SubscriptionLifecycle` does not cover | 3–4 hr |

---

## Tier D — security-control failure modes ⏳

Not feature surface: cases where a control's behavior on misconfiguration or backend failure is the open question.

### D1. Reconcile fail-open vs fail-closed on an unwired cache [MED] ⏳

`SecurityHandler.rateLimitVerify2FA` returns "allow" when `Cache == nil` ([handler/security_handler.go](handler/security_handler.go)). That is deliberate and documented — it keeps pre-cache deployments working — and the blast radius is bounded, because `LocalUserService.Verify2FA` / `VerifyBackupCode` lock the account at `MaxAttempts` through a persisted counter that no cache outage can touch.

It nonetheless runs against the convention the rest of the codebase follows: `AbstractTableService.IsGlobalRole` fails **closed** specifically so "a misconfigured deployment applies the stricter scope rather than silently granting". Two security helpers, opposite defaults, no stated rule for choosing.

Options: (a) require `Cache` at wiring time and fail startup, turning a silent config gap into a boot error; (b) keep allow-on-nil but document the convention explicitly, naming the DB lockout as the control that makes it safe; (c) add a `RequireRateLimiter bool` so a deployment can opt into strict mode. (a) is the cleanest but is a breaking wiring change for downstreams that never set `Cache`.

Note the distinction already drawn in code, which any resolution should preserve: `Cache == nil` means "the layer was never wired" (a deployment choice), while a cache **error** means "wired but broken" (an incident). The send path treats the error as fatal because dispatch has no backstop; verify treats it as allow-and-log because it does.

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
| Rename `CheckoutClient` → `PaymentClient` | Development Standards §11: renames go in major version bumps, not minor. v1.0 has shipped, so this is **v2.0** territory if ever. |

---

## Done in v1.0 – v1.2 ✅

Tracked items closed after the v0.6 cycle. Feature work is not listed — see `migration_guide.json`.

| ID | Title | Where |
|---|---|---|
| C4 | Subscription mutation API — shipped on `billing.SubscriptionLifecycle` rather than `CheckoutClient`: `Activate`, `ChangePlan` (+ `ChangePlanTx` for a caller-owned tx), `Reactivate`, `ConvertTrial`, `SetSeats`, `CancelByPartner` (immediate or period-end), `CancelByProviderSubID`, `SetDunningState`. Pause/Resume remain open as C11 | [billing/subscription_lifecycle.go](billing/subscription_lifecycle.go), [billing/abstract_billing_service.go](billing/abstract_billing_service.go) |
| C9 | Fuzz tests on signature verification — `FuzzStripeSignatureHeader`, `FuzzLemonSqueezyVerifier`, plus `FuzzStripeParser` / `FuzzLemonSqueezyParser` | [payment/signature_test.go](payment/signature_test.go), [payment/parser_test.go](payment/parser_test.go) |
| — | Rate limiters no longer discard cache errors. `rateLimitOTP` fails **closed** with a 503 + journal entry: dispatch is the one limited path with no persisted-counter backstop, so a swallowed error silently uncapped SMS/email spend. `rateLimitVerify2FA` still allows on error but logs it, because the account lockout in `Verify2FA` / `VerifyBackupCode` remains the real bound and failing closed there would turn a cache hiccup into a 2FA login outage | [handler/otp_handler.go](handler/otp_handler.go), [handler/security_handler.go](handler/security_handler.go), [handler/rate_limit_failure_test.go](handler/rate_limit_failure_test.go) |
| KR-001…KR-005 | v1.0.9 review round — generic-CRUD scope coercion, webhook retry-after-failure, exact-or-`*` permission-match contract, test-helper row shape, OTP TTL binding. Review write-up was `CODE_REVIEW_20260613.md`, removed during v1.2.40 staging — recover with `git show 3dd2aa9` | [pgsql/table_service.go](pgsql/table_service.go), [payment/webhook_repository_sql.go](payment/webhook_repository_sql.go), [data/abstract_repository.go](data/abstract_repository.go), [user/user_service_local.go](user/user_service_local.go) |
| KR-006 | REST list pagination pushed into SQL via the optional `port.PagedTableService` capability, with a primary-key tie-break on both the capability and fallback paths. Documented under v1.2.40 in [migration_guide.json](migration_guide.json) | [pgsql/table_service.go](pgsql/table_service.go), [port/table_service.go](port/table_service.go), [rest/relation_api.go](rest/relation_api.go) |

## Done in the v0.5 – v0.6 cycle ✅

Each row links to the artifact that made the change.

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
