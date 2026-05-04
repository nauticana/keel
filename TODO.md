# keel — deferred work

Tracking known issues and deferred work that did not ship in v0.5.x. Each entry has the **why deferred**, the **acceptance criteria** for the fix, and a rough **effort estimate** so they can be picked up in priority order.

---

## v0.6 — security / data layer

### 1. Row-level scope on `user_account` for non-SUPER roles

**Problem.** `PARTNER_ADMIN` and other partner-tier roles hold `TABLE SELECT user_account` so the `partner_users` list can display joined names/emails via the FK display lookup. The same permission lets the role hit `/api/v1/user_account/list` directly and enumerate every user in the system (PII: name, email, phone, social provider). The menu surface for global user_accounts has been closed (no PAGE access for `PARTNER_ADMIN`), but the API endpoint remains callable with a JWT.

**Why deferred.** Closing this requires a server-side row-scope filter — a small Go change in `pgsql/table_service.go` Get/List that's table-and-role aware. Held back to keep v0.5.2 a pure schema-seed change with no risk to the data layer.

**Acceptance.**
- When a non-SUPER role calls `/api/v1/user_account/list` (or `/{id}`), the SQL injects `id IN (SELECT user_id FROM partner_user WHERE partner_id = $sessionPartnerID)` automatically.
- `partner_users` list display still resolves user names correctly (because each user_id IS in the caller's partner_user set).
- SUPER and BUSINESS_ADMIN bypass the filter (they manage cross-partner data legitimately).
- New test: `pgsql/table_service_test.go` — verify a `PARTNER_ADMIN` cannot read a `user_account` belonging to a different partner; same call as `SUPER` returns the row.

**Effort.** ~30 lines + test fixtures. Localized to `pgsql/table_service.go:Get`.

**Files.**
- [pgsql/table_service.go:177-200](pgsql/table_service.go) — Get scoping injection
- [pgsql/table_service.go:391-410](pgsql/table_service.go) — Delete (defense-in-depth)
- [user/user_service.go](user/user_service.go) — may need to expose the role check helper

---

### 2. Picker scope: "unassigned users only" for the partner_user → user_account FK

**Problem.** When a `PARTNER_ADMIN` clicks "add partner_user" and the picker (FK lookup style `S` for `user_partners`) opens, today it queries `/api/v1/user_account/list` — exposing every user globally, including users already assigned to OTHER partners. This is a UX leak even after #1 lands (because the picker's purpose is "find a user not yet on my team").

**Why deferred.** Requires either (a) a new `foreign_key_lookup.source_table` override column + Go support for it, plus a DB view `unassigned_user_account` that filters out users with active partner_user rows; or (b) a custom invite-by-email handler that bypasses the picker entirely. Both are larger than v0.5.2's scope.

**Acceptance.**
- New DB view `unassigned_user_account` shipped via `schema/security/`.
- `foreign_key_lookup` table gains a `source_table VARCHAR(60) NULLABLE` column.
- Seed row: `[user_partners, S, "*", unassigned_user_account]`.
- `data/abstract_repository.go:loadFkLookupStyles` reads the new column.
- `model/foreign_key.go:ForeignKey` gains `SourceTable string` field exposed via JSON to the UI.
- The frontend picker queries `/api/v1/<source_table>/list` when `SourceTable` is set.
- New test: parser-level — verify a `PARTNER_ADMIN`'s picker query against `unassigned_user_account` returns 0 rows when all users are already assigned, and exactly the orphans otherwise.

**Effort.** ~40 lines Go + ~30 lines schema + ~10 lines seed.

**Depends on #1** because the partner_users LIST display still needs to resolve names through `user_account`; #1 gates the read but allows the in-partner rows. The picker is the ADD path.

---

### 3. Custom invite-by-email handler (alternative to #2)

**Problem.** Even with the unassigned-users picker (#2), a `PARTNER_ADMIN` can still enumerate user_accounts that exist but haven't been claimed by any partner — reduced surface but not zero. An invite-by-email flow is the right UX: PARTNER_ADMIN types an email; the server either creates the partner_user link (if user_account exists) or sends a registration invite (if not).

**Why deferred.** Net-new handler work, larger than v0.5.2's scope. Keeping #2 as the leaner deliverable; #3 can come later or replace #2 entirely.

**Acceptance.**
- New endpoint: `POST /api/partner-user/invite { email }`.
- If `user_account` exists for that email AND no active partner_user row: creates the partner_user (atomic).
- If `user_account` exists but is already assigned to another partner: 409 Conflict, no email leak.
- If `user_account` does not exist: triggers `RegistrationService.SendConfirmation` with a partner-bound payload so confirmation auto-creates the partner_user link.
- All three branches return the same 200 response shape — no enumeration via timing or response code.
- Permission: `PARTNER_ADMIN` PAGE ACCESS to `partner_user_invite`.

**Effort.** ~80 lines handler + tests.

---

## Known issue (v0.5.2)

### Global `/api/v1/user_account/list` is reachable by `PARTNER_ADMIN` via direct API call

This is the rationale-narrative for #1 above, restated as a release-notes-grade caveat for downstream consumers.

**Today's behavior.** The security-menu reorg in v0.5.2 closed the menu surface — `PARTNER_ADMIN` no longer has `PAGE ACCESS user_accounts`, so the keel-shipped UI does not navigate there. However, `TABLE SELECT user_account` remains held by `PARTNER_ADMIN` because the `partner_users` list display lookup uses it to resolve user names and emails. A `PARTNER_ADMIN` who knows the API can still hit `/api/v1/user_account/list` with a JWT and receive every user_account row in the system.

**Mitigation in v0.5.2.** None. Recommend downstream consumers either (a) wait for v0.6 #1 above, (b) gate the `user_account` REST endpoint behind a custom row-scope middleware locally, or (c) restrict the API at the load-balancer level (allow only paths under `/api/v1/partner_user/*` for non-SUPER tokens).

**Rollback path.** None needed — the v0.5.2 change is purely seed data; no code paths shifted.
