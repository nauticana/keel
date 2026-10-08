# Tenant single sign-on and domain verification — sail work

Handover to the sail maintainers. keel owns the data model, the HTTP contracts and every security decision listed here; sail renders them. Nothing in this list needs a schema or endpoint that keel does not already define. The backend is documented in keel's README under Tenant Single Sign-On, Directory Provisioning (SCIM) and Domain Verification.

keel version: the next release after v1.2.99 (`v1.2.100` in the migration guide, not yet tagged). sail must not depend on it before it is published.

## Constraints

- **Opt-in.** Every new entry point is hidden unless the application turns it on. Applications that only use password, OTP, Google or Apple sign-in must see no change.
- **Top-level navigation, never XHR.** `/public/sso/start`, `/public/sso/launch` and `/public/sso/callback` set or read an `HttpOnly` cookie on the API host. Open them with `window.location.assign`, never with `HttpClient`. This applies to OpenID Connect and SAML connections alike.
- **No tokens in URLs.** A sign-in comes back with a single-use `code`, which is exchanged through the existing `BaseAuthService.exchangeHandoff`.
- **Codes from keel, not from sail.** The status, protocol and client-authentication codes come from backend metadata (`constant_value`). sail does not hardcode their captions.
- **No styling.** As usual, sail ships no CSS or SCSS.

## Backend contract

### Browser routes (public)

| Route | Use |
|---|---|
| `GET /public/sso/start?email=<address>` | Sends the browser to the identity provider of the organization that owns the address's domain |
| `GET /public/sso/launch?code=<code>` | Opens a test sign-in; the URL comes from the `test` action |
| `GET/POST /public/sso/callback` | The identity provider's redirect target; sail never calls it |

Every outcome sends the browser to the application's **return URL**, which the application configures in keel (`SSOHandler.FrontendReturnURL`). The return URL gets exactly one of:

| Query | Meaning | sail action |
|---|---|---|
| `code=<handoff>` | Sign-in succeeded | `exchangeHandoff(code)`, then the normal post-login path. `twoFactorRequired` is always `false`, because the organization's identity provider owns MFA. |
| `error=<code>` | Sign-in refused | Show the message for the code (table below) and offer the other sign-in methods |
| `test=passed` | An administrator's test sign-in passed | Return to the identity provider screen and show success |
| `test=failed&error=<code>` | The test failed | Return to the identity provider screen and show the message |

| Error code | Message intent |
|---|---|
| `sso_unavailable` | No single sign-on for this address; use another method. Do not reveal whether the domain is known. |
| `sso_failed` | The sign-in could not be completed; try again |
| `mfa_required` | The organization requires multi-factor authentication at its identity provider |
| `sso_email_not_allowed` | The account is outside the organization's verified domains |
| `sso_no_account` | No account yet; ask the organization's administrator |
| `sso_other_partner` | The account belongs to another organization |
| `sso_required` | The organization requires single sign-on for this account |
| `account_unavailable` | The account is locked or expired |
| `identity_linked` | The account is already linked to a different identity from this provider |
| `sso_test_mismatch` | Test only: the identity provider signed in someone other than the administrator |
| `domain_not_proven` | Test only: the identity provider did not prove the organization's domain |
| `server_error` | Unexpected failure |

### Connection administration (authenticated table actions)

Table `partner_identity_provider`, with generic REST children `partner_idp_oidc` (settings) and `partner_idp_role_mapping` (role mappings), menu item `partner_identity_providers`. Seeded grants: `PARTNER_ADMIN` reads all three tables, inserts and deletes role mappings, and runs every action. `APP_ADMIN` reads the tables and can only disable.

| Action | Kind | Body | Answer |
|---|---|---|---|
| `configure` | P | JSON, or multipart when `private_key` or `idp_metadata` is a file. Common: `id` (empty for new), `protocol` (`O` default, `S` SAML), `caption`, `subject_claim`, `email_claim`, `require_mfa`. OpenID Connect: `issuer`, `client_id`, `client_auth` (`P`, `B`, `J`), `client_secret` or `private_key`, or `operator_client` instead; `scopes`. SAML: `idp_metadata` (XML file), whose `entityID` becomes the issuer | `{id}` |
| `test` | R | `{id}` | `{url}`; Sail's redirect-action handling must follow it as a top-level navigation |
| `activate` | P | `{id}` | `{id, status}` |
| `disable` | P | `{id}` | `{id, status}` |

Action errors are RFC 7807 problems with these codes:
- `identity_provider_not_found` (404)
- `invalid_identity_provider` (400)
- `identity_provider_active` (409)
- `identity_provider_not_tested` (409)
- `identity_domain_required` (409)
- `sso_test_mismatch` (403)

### Provisioning tokens (authenticated table actions)

Table `partner_scim_token`, menu item `partner_scim_tokens`, with generic REST tables `partner_scim_user`, `partner_scim_group` and `partner_scim_group_member` (read-only for the partner, written by the directory).

| Action | Kind | Body | Answer |
|---|---|---|---|
| `generate` | V | `{caption, expires_days?}` | `{id, token, scimBaseUrl}`, shown once by the existing reveal dialog |
| `revoke` | P | `{id}` | `{id, revoked}` |

`too_many_provisioning_tokens` (409): the partner already holds `scim_max_active_tokens` active tokens (default 5).

The SAML service provider metadata the identity provider administrator needs is at `GET /public/sso/saml/metadata` when the application mounts it.

### Domain verification (already shipped by keel)

These table actions are on `partner_domain` (`PARTNER_DOMAIN VERIFY / CANCEL`):

| Action | Request | Response |
|---|---|---|
| `challenge` | `{domainUrl, method, recipient?}` | `{challenge}`. For `DT` it carries `recordName` and `recordValue`; for `HF`, `fileUrl` and `fileBody`. For `EC` the code is mailed and never returned. |
| `confirm` | `{domainUrl, method, code?}` | `{verification}` |
| `unverify` | `{domainUrl, method?}` | `{cancelled}` |

`partner_domain_verification` is readable through generic REST as a child of `partner_domain`.

## Work items

| ID | Item | Acceptance |
|---|---|---|
| SL1 | **Organization sign-in entry.** A `<sail-sso-login>` component (email field and "Continue with your organization" button) that navigates to `RestURL.ssoStartURL` (new key, default `/public/sso/start`) with the email. `LoginComponent` gains an opt-in input that shows it; the default is off. A single control uses `type="button"` with click and Enter handling, not a bare `<form (ngSubmit)>`. | Navigation is `window.location.assign` to the API host. The email is URL-encoded. Nothing renders unless enabled. Unit test for the URL. |
| SL2 | **Return page.** A `<sail-sso-return>` routed component for the return URL. It reads `code`, `error` and `test` once, then removes them from the address bar (`history.replaceState`). A code uses the existing handoff exchange and login completion. An error shows the mapped message. A test outcome navigates to a configurable route with the outcome. | The code is exchanged exactly once, even on reload. An unknown error code shows the `server_error` message. Tests cover each query shape. |
| SL3 | **Error messages.** One message map for the codes above, overridable by the application for wording and translation. | Every code in this file has an entry. |
| SL4 | **Secret parameter kind.** `ActionParamsDialog` supports a `secret` (or `password`) `data_type`: a masked input, never echoed back or logged. keel will switch `client_secret` to that type once sail supports it. | Masked input. The value is posted like `string`. |
| SL5 | **Code-list choices for action parameters.** `protocol` and `client_auth` must offer the `identity_protocol` (`O`, `S`) and `oidc_client_auth` (`P`, `B`, `J`) values with captions from metadata. Extend `table_action_parameter` choices to code lists if `lookup_table` cannot express them, and coordinate the metadata shape with keel before building. | Choices come from backend metadata. No literals in sail. |
| SL6 | **Identity provider screen.** The generic table list and detail for `partner_identity_provider` already work through metadata. Verify the following, and record any gap as a follow-up rather than building a bespoke screen. | Works end to end against a keel test environment. |
| SL7 | **Domain verification for DNS and HTTP file.** Extend `<sail-domain-verification>`, or add a sibling, so a partner administrator can run `DT` (show `recordName` and `recordValue` with copy buttons, then Confirm) and `HF` (show `fileUrl` and `fileBody`). Today it handles the send-code and confirm steps only. Keep the `DOMAIN_VERIFIER` port; add the challenge payload to it rather than calling keel paths from the component. | An administrator can prove a domain by `DT` without leaving the application. |
| SL9 | **Protocol-aware configure dialog.** Show the OpenID Connect fields or the SAML `idp_metadata` upload according to `protocol`, so an administrator never sees fields the other protocol ignores. Offer a link to `/public/sso/saml/metadata` for SAML. | A SAML connection can be configured with only caption and metadata file. |
| SL10 | **Provisioning screens.** Generic table screens for `partner_scim_token` (generate, revoke), `partner_scim_user` and `partner_scim_group` with members. After `generate`, the reveal dialog shows the token and `scimBaseUrl` with copy buttons and a note that the token is not shown again. | A partner administrator can hand the token and base URL to the directory administrator. |
| SL8 | **Documentation.** README sections for SL1, SL2 and SL7, covering the opt-in, the routes the application must add, the keel settings they pair with (`PublicBaseURL`, `FrontendReturnURL`), and the migration-guide entry. | README matches the shipped components. |

SL6 checklist:
- the `status`, `tested_at` and `status_changed_at` columns render read-only;
- `credential_sealed` stays hidden;
- the `configure` dialog posts multipart when a key file is chosen;
- `test` follows the returned URL;
- role mappings can be added and removed as children.

## Out of scope for sail

- **Per-vendor setup wizards** (Entra ID, Okta, Google Workspace). These belong to applications, built on SL6, SL9 and SL10.
