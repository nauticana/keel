# Identity and Access

Domain verification, tenant single sign-on, directory provisioning, and consent.

## Domain Verification

`domain.Service` records how a partner proved one of its `partner_domain` rows. keel records evidence; it does not decide what is good enough. Each consumer passes the methods it honors to `Current`, `Domains` or `Holders`.

| Code | Method | Proves | Re-checked |
|------|--------|--------|------------|
| `EC` | Email code | A mailbox on the domain: a code sent to an address sharing its registrable domain | No |
| `VE` | Verified email | A mailbox on the domain: the acting user's verified email | No |
| `GH` | Google hosted domain | Membership in the Google organization: the verified ID token's `hd` claim | No |
| `GM` | Google mail server | A Google mailbox: a Google sign-in whose mail domain receives mail at Google | No |
| `HF` | HTTP file | Control of the host's content: the token at `https://<domain>/.well-known/<label>.txt` | Yes |
| `DT` | DNS TXT record | Control of DNS: `<label>=<token>` in a TXT record of the domain | Yes |
| `GS` | Google Search Console | The Google account owns the DNS-verified domain property; not exclusive | With a grant |
| `GB` | Google Business Profile | The user manages a verified listing naming the domain as its website; self-asserted | With a grant |
| `GW` | Google Workspace admin | The user administers the Google organization that verified the domain | With a grant |
| `ME` | Microsoft Entra admin | The user holds a domain administrator role in the Entra tenant that verified the domain | With a grant |

The `HF` check fetches over HTTPS through a public-address client within `default_outbound_timeout`, follows at most `outbound_max_redirects` redirects and only between the domain and its `www` host, and reads at most 1 KiB, since the file holds one token.

Provider grants: `GW` needs `admin.directory.domain.readonly` and matches verified domains and domain aliases; `ME` needs `Domain.Read.All` plus a directory read permission that exposes role template ids; `GS` needs `siteverification`. A listing longer than the page limit, or role details the grant cannot read, is an error, not a verdict.

`domain.IdentityMethods()` returns the methods (`DT`, `GW`, `ME`) strong enough to route sign-in to a tenant. They are exclusive: recording one fails with `ErrDomainHeld` while another partner holds current identity evidence, and `IdentityHolder(domain)` returns the single holder or `ErrNotHeld`. Other methods are non-exclusive. Public suffixes, IP literals and free mailbox providers (`IsPublicDomain`) cannot be verified.

`domain.CoveredBy(name, parent)` is the normalized-name match every verifier uses: equal, or a subdomain on a label boundary.

Each verification is a `partner_domain_verification` row keyed `(partner_id, domain_url, verified_at)`. Proving a method that is already current refreshes that row; after a lapse or cancellation a new row is appended, so history is kept. A row is current while `lapsed_at` and `cancelled_at` are NULL.

```go
domains := &domain.Service{
    DB: db,
    Verifiers: []domain.DomainVerifier{
        &domain.DNSTXTVerifier{}, &domain.HTTPFileVerifier{}, domain.EmailCodeVerifier{},
        domain.VerifiedEmailVerifier{}, &domain.GoogleWorkspaceVerifier{}, &domain.MicrosoftEntraVerifier{},
    },
}

// Challenge methods (EC, DT, HF): issue, publish or deliver, confirm.
ch, err := domains.Challenge(ctx, partnerID, userID, domainURL, domain.MethodDNSTXT, "")
// publish ch.RecordValue as a TXT record on ch.RecordName, then:
v, err := domains.Confirm(ctx, partnerID, userID, domainURL, domain.MethodDNSTXT, "")

// Other methods on an existing domain; identity fields come from a verified
// session or token, AccessToken from the acting user's provider grant.
v, err = domains.Verify(ctx, partnerID, userID, domainURL, domain.MethodGoogleWorkspace,
    domain.DomainProof{AccessToken: token})
```

A signup that proves the domain before the partner exists checks first and records inside the transaction that creates the partner, its `partner_domain` row and the membership:

```go
if err := domain.MailboxOnDomain(email, domainURL); err != nil { ... } // before sending a code
ev, err := domains.Check(ctx, domainURL, domain.MethodVerifiedEmail,
    domain.DomainProof{Email: email, EmailVerified: true})
tx, err := db.BeginTx(ctx, common.MergeMaps(myQueries, domain.TxQueries()))
// insert business_partner, partner_domain, partner_user ...
_, err = domains.RecordTx(ctx, tx, partnerID, userID, domainURL, ev)
```

Challenges store only the SHA-256 of the token or code, expire after `domain_challenge_ttl` (`domain_code_ttl` for `EC`), allow `domain_challenge_attempts` confirmations and are not reissued within `domain_challenge_cooldown`. `domain_verification_label` names the TXT prefix and file.

A worker calls `Recheck(ctx, limit)` to re-verify `DT`, `HF` and, when `Service.AccessToken` supplies a current grant, the provider methods once evidence is older than `domain_recheck_interval`. A negative verdict marks the row failing and lapses it after `domain_recheck_grace`, then runs `Service.OnLapsed`; a check that cannot complete records `last_error` without a verdict.

Identity evidence must also keep passing: `IdentityHolder` and the exclusivity rule count it only while its last passed check (`last_held_at`) is younger than `domain_identity_max_age` (default 7 days). Evidence that only errors, such as a demoted administrator's, therefore stops routing and stops blocking other partners without lapsing; a passing check revives it, and another partner's verification supersedes it. Run `Recheck` on a schedule, or identity evidence expires.

`HTTPFileVerifier` fetches over HTTPS only, follows redirects only between the domain and its `www` host, reads at most 1 KiB and never dials a private, loopback or link-local address. Provider HTTP failures are not proof verdicts because statuses such as 403 can also mean missing scopes, quota exhaustion or a disabled API.

`handler.DomainVerificationHandler` mounts `partner_domain/challenge`, `partner_domain/confirm` and `partner_domain/unverify`, gated by `PARTNER_DOMAIN` `VERIFY` and `CANCEL` on `partner_domain` (seeded for `PARTNER_ADMIN`). Set `SendCode` to deliver `EC` codes; the code is never returned to the client. Evidence is read through the generic `partner_domain` → `partner_domain_verification` REST child.

A downstream method uses its own two-character code in `domain_verification_method` and its own `domain.DomainVerifier`.

## Tenant Single Sign-On

A partner (tenant) can sign its people in through its own identity provider: Microsoft Entra ID, Okta, Google Workspace, SAP Identity Authentication, Ping, AD FS or any other OpenID Connect or SAML 2.0 provider. Package `sso` holds the service and `handler.SSOHandler` the routes. Single sign-on is opt-in twice: the application mounts the routes, and a partner activates a connection. Applications that do neither see no change; password, one-time-code, Google and Apple sign-in work exactly as before.

### Schema

Schema group `sso` (depends on `core` and `tenant_management`):

| Table | Holds |
|---|---|
| `partner_identity_provider` | The connection: protocol, status, issuer, subject and email claims, MFA requirement, last test |
| `partner_idp_oidc` | OpenID Connect settings: client id, client authentication, scopes, and either an operator secret name or a sealed partner credential |
| `partner_idp_saml` | SAML settings: the identity provider's metadata document |
| `partner_idp_role_mapping` | A claim value mapped to a role |
| `partner_idp_role_grant` | The role assignments a mapping made |

The schema enforces three rules:
- a partner has at most one active connection;
- only a tested connection can be active;
- a mapping can name only a `partner_scoped` role, through a composite foreign key on `authorization_role(id, partner_scoped)`, so generic REST insertion of a mapping can never grant a platform role.

Codes come from `constant_value`: `identity_protocol` (`O` OpenID Connect, `S` SAML 2.0), `identity_provider_status` (`D` draft, `A` active, `X` disabled), `oidc_client_auth` (`P` client secret post, `B` client secret basic, `J` private key JWT). Linked identities stay in `user_external_identity`, keyed by issuer and subject. Policy stays in `user_account_policy`:
- `SSO_REQUIRED` is described under Requiring SSO.
- `SSO_JIT_CREATE` (global default 0) lets a first sign-in create the account when set to 1.

### Wiring

```go
oidcProvider := &oidc.Provider{DB: db, Secrets: secrets, Sealer: credentialSealer}
samlProvider := &saml.Provider{DB: db, EntityID: "https://api.example/public/sso/saml"} // optional
ssoService := &sso.Service{
    DB: db, Users: userSvc, Domains: domainSvc, Nonces: nonces, Sealer: credentialSealer,
    Providers: map[string]port.IdentityProvider{oidc.ProtocolOIDC: oidcProvider, saml.Protocol: samlProvider},
    // Optional: the operator's own app registrations a partner may pick.
    OperatorClients: map[string]sso.OperatorClient{"entra": {ClientID: id, ClientAuth: sso.ClientSecretPost,
        SecretName: "entra_client_secret", IssuerPrefix: "https://login.microsoftonline.com/"}},
}
ssoHandler := &handler.SSOHandler{AbstractHandler: abstract, DB: db, SSO: ssoService, Handoff: nonces,
    PublicBaseURL: "https://api.example", FrontendReturnURL: "https://app.example/sso/return",
    ServiceProviderMetadata: samlProvider} // optional
srv.Handle(ssoHandler.PublicRoutes())                                // public mux
srv.Handle(ssoHandler.Routes(common.RestPrefix + common.APIVersion)) // authenticated mux
```

- `Users` must also implement `user.TenantAccountCreator`, which `LocalUserService` does.
- `Nonces` is the same `connect.NonceService` as `PublicHandler.Handoff`.
- `credentialSealer` is a `crypto.Sealer` for partner-supplied client credentials.
- Register `PublicBaseURL + "/public/sso/callback"` at each identity provider: as the redirect URI for OpenID Connect, and as the assertion consumer service for SAML. For SAML, the service provider entity id is `saml.Provider.EntityID`, and `/public/sso/saml/metadata` serves keel's metadata.
- An application without SAML does not import `sso/saml`, so it never links XML signature code.

### Sign-in

1. `GET /public/sso/start?email=` finds the partner that holds the email's domain, or its nearest parent domain, by identity-grade evidence (`domain.IdentityHolder`, see Domain Verification), and that partner's active connection.
2. It stores the pending sign-in in `auth_nonce` and binds it to the browser with an `HttpOnly`, `Secure` cookie on `/public/sso`. The cookie is `SameSite=None` so it also rides a SAML response's cross-site POST; the binding rests on the cookie's secret value, which only this browser holds. The browser is then redirected to the identity provider.
3. The callback (`GET` or `POST /public/sso/callback`) consumes the pending sign-in once and completes the protocol.
4. It then requires:
   - the connection's exact issuer;
   - an MFA method when the connection requires MFA;
   - an email whose domain the same partner holds; for Google, also a hosted domain (`hd`) it holds.

   An identity provider can therefore only vouch for its own organization's addresses. An `email` claim that the issuer does not verify, such as Entra ID's, cannot reach another tenant's account or a guest's.
5. It signs in, in this order:
   - the account linked to the identity's issuer and subject;
   - or the partner's own account with that email, which it then links;
   - or, only under `SSO_JIT_CREATE = 1`, a new account, or an account without a partner made a member.

   An account of another partner is refused.
6. Mapped roles are synchronized in the same transaction:
   - a claim the issuer truncated grants nothing;
   - a role the mapping granted ends when its claim disappears;
   - a role assignment made any other way is never touched.

   A user the directory provisions (Directory Provisioning) takes its roles from its groups instead.
7. The session uses sign-in method `T`. The browser returns to `FrontendReturnURL?code=`, and the application trades the code at `/public/register/exchange`. The exchange skips keel's second factor for these sessions, because the identity provider owns MFA.

Refusals return `FrontendReturnURL?error=`, one code each:

| Code | Cause |
|---|---|
| `sso_unavailable` | No partner holds the domain with an active connection |
| `sso_failed` | The callback or the identity provider's answer was invalid |
| `mfa_required` | The connection requires MFA and the identity provider did not report it |
| `sso_email_not_allowed` | The email or hosted domain is outside the partner's verified domains |
| `sso_no_account` | No account, and the partner does not create one |
| `sso_other_partner` | The account belongs to another partner |
| `sso_required` | The partner requires its own identity provider for this account |
| `account_unavailable` | The account is locked or expired |
| `identity_linked` | The account already has a different identity from this issuer |
| `domain_not_proven` | Test only: the identity provider's grant did not prove the domain |
| `sso_test_mismatch` | Test only: someone other than the administrator signed in |
| `server_error` | Anything else; the cause goes to the journal |

### Settings

| Flag | Default | Governs |
|---|---|---|
| `oauth_state_ttl_seconds` | 600 | How long a started sign-in may take to come back, and the binding cookie's lifetime |
| `signin_handoff_ttl` | 300 s | Validity of the sign-in handoff code and the test-launch code |
| `sso_max_document_size` | 1 MiB | Largest callback body, SAML response or SAML metadata |
| `sso_metadata_max_stale` | 86400 s | How long cached OpenID Connect discovery serves while the issuer is unreachable |
| `sso_connection_cache_size` | 1024 | Connections whose parsed settings each node caches |
| `social_jwks_cache_ttl` | 3600 s | Refresh interval of OpenID Connect discovery and keys |
| `outbound_max_response_size`, `default_outbound_timeout` | 16 MiB, 30 s | Token endpoint responses and identity provider requests |
| `max_request_size` | 16 MiB | The `configure` body, including uploaded keys and metadata |

### Administration

Table actions on `partner_identity_provider`. They are granted to `PARTNER_ADMIN`; `APP_ADMIN` may only disable.

| Action | What it does |
|---|---|
| `configure` | Creates a draft or edits a connection. Takes JSON, or multipart when `private_key` or `idp_metadata` is an uploaded file. Partner credentials are sealed. An active connection may only rotate its credential and edit its claims; changing its issuer or client needs a disable first, and a changed issuer or client voids the last test. |
| `test` | Kind `R`: returns a launch URL for a sign-in by the calling administrator, who must be asserted with their own email. It records nothing but the test, except that Entra ID and Google connections also ask for the grant that records `ME` or `GW` domain evidence in the same round trip. |
| `activate` | Needs a passed test and a held identity domain. A connection it replaces is disabled, its mapped roles end, and its sessions are revoked; provisioned users' groups are mapped through the new connection. |
| `disable` | Stops routing at once and ends the connection's mapped roles. Disabling the active connection also signs out every session it signed in. |

Role mappings (`partner_idp_role_mapping`) are ordinary generic REST children of the connection.

### OpenID Connect connections

`configure` takes `issuer`, `client_id`, `client_auth`, and `client_secret` or `private_key`, or an `operator_client` preset instead. It also takes `subject_claim`, `email_claim`, `scopes` (default `openid email profile`) and `require_mfa`.

- **Discovery.** It is read from `<issuer>/.well-known/openid-configuration`. Its issuer must equal the connection's exactly, so a multi-tenant authority whose issuer is a `{tenantid}` template is refused.
- **Flow.** Every sign-in uses the authorization code with PKCE (S256), a nonce and a state.
- **ID token.** It must carry:
  - the issuer;
  - the client as audience, and `azp` when there are several audiences;
  - an unexpired `exp`;
  - the nonce;
  - a signature by an algorithm both keel and the issuer accept (RSA, RSA-PSS or ECDSA; never `none` or symmetric).
- **Token endpoint.** Requests to it never follow a redirect. Discovery, keys and token requests go through `common.PublicHTTPClient`, because a tenant administrator chooses the issuer.
- **Client authentication.**
  - A client secret is sent by post or basic authentication.
  - `private_key_jwt` sends a one-minute assertion with a unique `jti`, naming the certificate by `x5t` and `x5t#S256`. The private key is uploaded as a PEM bundle with its certificate and sealed.
  - A method the issuer does not list in `token_endpoint_auth_methods_supported` is refused.
- **Operator presets.** `OperatorClients` lets the operator offer its own app registration, such as one multi-tenant Entra ID registration each customer administrator consents to. Its secret stays in the secret provider and is used only with issuers under the preset's `IssuerPrefix`, so a partner can never send it to an issuer of its choosing.
- **MFA.** `require_mfa` needs `mfa` in the token's `amr`.
- **Truncated claims.** Entra ID's `_claim_names` / `hasgroups` mark the groups claim as truncated (overage).

**Microsoft Entra ID.**
- Use the directory's own issuer, `https://login.microsoftonline.com/<tenant-id>/v2.0`. The shared `common`, `organizations` and `consumers` authorities, and the consumer directory, are refused.
- The subject claim defaults to `oid`, which survives an app-registration change.
- Map app roles (`roles`) rather than groups when a user may have more than the token's group limit.
- A certificate key may live in Azure Key Vault through the `azure` secret provider when the operator registers it as a preset.

**Google Workspace.** Use issuer `https://accounts.google.com`. The hosted domain must be held by the partner, so a personal Google account never signs in to a tenant.

**Okta, SAP Identity Authentication, Ping, AD FS 2016+.** Use the organization's issuer URL. With SAP Identity Authentication in front of Entra ID, configure the issuer the browser meets.

### SAML connections

`configure` with `protocol` `S` takes `idp_metadata`, the identity provider's metadata XML. Its `entityID` becomes the issuer, and it needs a single sign-on service and a signing certificate. `subject_claim` defaults to `NameID`; any other value names an attribute. The email comes from `email_claim`, then the usual email attributes (`mail`, `emailaddress` and their URIs), then a NameID that is an address.

- Requests use the HTTP-Redirect binding. Responses must arrive by HTTP-POST at the callback, which is checked as their destination.
- Responses must answer the request this browser started, be signed by a certificate in the metadata, name keel's entity id as their audience, and be within their validity window (180 seconds of clock skew).
- Identity-provider-initiated sign-in is refused.
- A multi-factor authentication context, or Entra ID's `multipleauthn` method claim, counts as MFA.
- Entra ID's `groups.link` attribute marks its groups claim as truncated.
- Encrypted assertions and signed requests need `saml.Provider.Key` and `Certificate`.
- Response parsing uses `github.com/crewjam/saml`, isolated in package `sso/saml`.

### OpenID Connect client

`oidc.Client` signs users in with one OpenID Provider. It needs no partner model, so an application with a single fixed identity provider, such as an appliance console, can use it directly:

```go
signer, cert, err := oidc.ParseClientKey(pemBundle) // private key, optionally its certificate
client := &oidc.Client{
    Issuer:       "https://login.microsoftonline.com/<tenant-id>/v2.0",
    DiscoveryURL: "https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration",
    ClientID:     clientID,
    Credential:   oidc.ClientCredential{Method: oidc.AuthPrivateKey, Key: signer, Certificate: cert},
    SubjectClaim: "oid",
}
redirect, err := client.Begin(ctx, port.IdentityBegin{State: state, RedirectURI: callbackURL})
// store redirect.Pending server-side under state, send the browser to redirect.URL
assertion, err := client.Complete(ctx, port.IdentityCallback{RedirectURI: callbackURL, Params: r.URL.Query(), Pending: stored})
```

Errors:
- an OAuth error answer is `*oidc.TokenError`;
- an error returned to the redirect URI is `*oidc.CallbackError`;
- a failed check is `oidc.ErrInvalidResponse`;
- unusable settings are `oidc.ErrBadConfiguration`.

`IdentityAssertion.Claims` holds the multi-valued non-protocol claims. `AccessToken` is returned only when `Begin` asked for extra scopes.

`port.IdentityProvider` (`Begin`, `Complete`) is the seam between the sign-in service and a protocol, so an application can add a provider keel does not ship.

## Directory Provisioning (SCIM)

A partner's directory (Entra ID, Okta, Google or any SCIM 2.0 client) creates, updates, deactivates and deletes users and groups at `PublicBaseURL + "/public/scim/v2"`. `sso.Provisioning` holds the service and `handler.SCIMHandler` the routes.

```go
provisioning := &sso.Provisioning{DB: db, Users: userSvc, Domains: domainSvc}
scimHandler := &handler.SCIMHandler{AbstractHandler: abstract, DB: db, Provisioning: provisioning, PublicBaseURL: "https://api.example"}
srv.Handle(scimHandler.PublicRoutes())                                // /public/scim/v2/...
srv.Handle(scimHandler.Routes(common.RestPrefix + common.APIVersion)) // token actions
```

### Tokens

A partner administrator issues a token with the `generate` table action on `partner_scim_token`. It is kind `V`: the token and the SCIM base URL are shown once. Only the token's SHA-256 is stored. Rules:
- a partner holds at most `scim_max_active_tokens` active tokens (default 5);
- a token may expire after up to `scim_token_max_days` days (default 3650);
- `revoke` ends a token at once.

The directory sends the token as `Authorization: Bearer scim_...`, and it selects the partner for every request.

### Endpoints

- `/Users` and `/Users/{id}`: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`.
- `/Groups` and `/Groups/{id}`: the same methods.
- `/ServiceProviderConfig`, `/ResourceTypes`, `/ResourceTypes/{id}`, `/Schemas` and `/Schemas/{id}`: public.
- `/Me`: 501.

A 201 carries `Location`; a 401 carries `WWW-Authenticate: Bearer`.

Request limits:
- Lists take `startIndex` and `count`. A `startIndex` below 1 is 1, a negative `count` is 0, and `count=0` returns only `totalResults`. An omitted `count` is `default_list_page_size`; any count is capped at `max_list_page_size`.
- Filters compare `id`, `userName` and `externalId` for users, and `id`, `displayName` and `externalId` for groups, with `eq`, `ne`, `co`, `sw`, `ew` and `pr`, joined by `and`, `or`, `not (...)` and parentheses. Attribute names may carry the schema URN. `userName` and `displayName` compare without case. Anything else, including filters on members, is `invalidFilter`.
- `attributes` and `excludedAttributes` shape every returned resource; `id` and `schemas` are always returned. Groups, listed or read, carry their members unless `excludedAttributes=members` or an `attributes` list without `members` leaves them out.
- Bodies are capped at `max_request_size`, a PATCH at `scim_max_patch_operations` operations (default 1,000), and a group at `scim_max_group_members` members (default 10,000).

Errors use the SCIM error schema:

| Status | `scimType` | Cause |
|---|---|---|
| 401 | | Token missing, unknown, revoked or expired |
| 404 | | Resource not found in the token's partner |
| 409 | `uniqueness` | Taken key or email, or an account of another partner |
| 400 | `invalidFilter` | Unsupported filter |
| 400 | `invalidPath` | A patch path the User or Group schema does not define |
| 400 | `noTarget` | A remove without a path |
| 400 | `mutability` | Add or replace on `members[value eq "..."]` |
| 400 | `invalidValue` | Missing or malformed attribute, an email outside the partner's verified domains, or too many operations or members |
| 413 | | Body over `max_request_size` |
| 500 | | Anything else; the cause goes only to the journal |

### Users

- **What keel keeps.** `userName` (compared without case), `externalId`, `name.givenName`, `name.familyName`, the primary email (else the first, else a `userName` that is an address) and `active`. Other attributes the User schema or the enterprise extension defines, such as phone numbers and addresses, are accepted and ignored.
- **Email domain.** The email must lie in a domain the partner holds by identity-grade evidence.
- **Creating.** A new email creates an account verified by the tenant (`email_verification_method` `T`) and, when active, a membership. An existing account with that email is adopted when it belongs to this partner or to none; an account of another partner is a conflict.
- **Deactivating and reactivating.** `active` false ends the membership, its roles and its sessions at once (`UserService.EndMembership`). True again makes the account a member again.
- **Deleting.** `DELETE` stops provisioning and ends the membership; the account remains, as for any former member.
- **PATCH.** Accepts:
  - operations in any case (`Replace`, `add`);
  - booleans as JSON or as the strings `"True"` and `"False"`;
  - path-less value objects;
  - dotted paths (`name.givenName`);
  - `emails[type eq "work"]` and `emails[type eq "work"].value`, which touch only that type; a new type is a secondary address and leaves the stored email alone.

### Groups and roles

- **Group keys.** A group keeps `displayName`, unique per partner without case, `externalId` and members. PATCH accepts member add, replace and remove by value list, remove by `members[value eq "id"]`, and path-less value objects.
- **Role mapping.** Group membership feeds the role mapping of the partner's active identity provider connection: a mapping matches when its `claim_value` equals a group's display name or external id, whatever its `claim_name`.
- **Role changes.** A provisioned user's mapped roles change whenever its groups change, and sign-in leaves them alone, so a token without the groups claim never removes a directory role.
- **No active connection.** Without one, the directory assigns no roles.
- **Mapping edits.** A changed mapping reaches a provisioned user at its next group change or connection activation, and a signed-in user at its next sign-in.
- **Inactive users.** An inactive user gets none.

## Consent Capture (PIPEDA / GDPR)

Keel exposes an optional `port.ConsentService` that signup flows (social login, phone OTP) call after account creation. Any consumer that needs regulator-visible consent audit trails can register one at `LocalUserService` construction.

### Consent DB tables

| Table | Purpose |
|-------|---------|
| `consent_policy` | Versioned policy text registry. Unique on `(policy_type, region, version, language)`. |
| `consent_event` | One row per (user × consent_type × policy version) decision. Stores `email_hash` / `phone_hash` fallbacks when the row predates (or isn't tied to) user_account creation — the `phone_hash` links an SMS/10DLC opt-in to its number — plus `client_ip` / `client_user_agent` for the audit trail. `ConsentService.Withdraw` records opt-outs (STOP); `History(subject)` returns the full opt-in/opt-out trail for a user/email/phone (carrier + DSAR export). |

### Wiring

```go
consentSvc, _ := user.NewLocalConsentService(ctx, db, journal)
userSvc, _ := user.NewLocalUserService(ctx, db, jwtSecret, "myapp")
userSvc.ConsentService = consentSvc  // optional; leave nil to skip consent recording
```

Social-login and OTP request bodies accept optional `policyType`, `policyVersion`, `policyRegion`, `policyLanguage`, `region`, and `consents: {<type>: <bool>}` fields. On a new-user signup they're recorded. On re-auth they're ignored. When no `ConsentService` is registered the handlers accept the fields but skip the recording — consumers that don't need consent audit trails are unaffected.

If the user is created but the subsequent consent insert fails, handlers return **HTTP 425 Failed Dependency** with the session context so clients can retry the consent write rather than recreate the account.

### HTTP surface (`ConsentHandler`)

Signup-time recording bundles every consent in the call under one policy version. To record a *single* consent under its own policy after login (e.g. terms acceptance separate from the SMS opt-in), or to let a user export their trail, mount `ConsentHandler`:

```go
consentHandler := handler.ConsentHandler{AbstractHandler: base, Consent: consentSvc}
// merge consentHandler.GetAuthRoutes() into your authenticated route table
```

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/user/consent` | Record one decision. Body `{consentType, consented, policyType, policyVersion, policyRegion?, policyLanguage?, region?, eventRef?}`. Identity (user/email/phone) + IP/UA are taken from the session/request — never the body. `consented=false` is a first-class opt-out. **424** if the referenced `consent_policy` row isn't seeded. |
| GET | `/api/user/consent` | Export the session user's audit trail (`{items:[…]}`, newest first). |

Nil-safe: with `Consent` unset both routes return **503**.

### Canonical consent type labels (port constants)

- `port.ConsentTypePrivacyPolicy`, `port.ConsentTypeTerms`, `port.ConsentTypeCrossBorder`, `port.ConsentTypeVideoOptIn`, `port.ConsentTypeVideoSession`, `port.ConsentTypeMarketing`

Consumers may record additional custom types just by passing their own string — keel does not enforce the label set.

### Session-scoped consent — `LatestConsentFor`

`LatestConsent` answers per user and consent type. Session-sensitive checks record with `ConsentRequest.PolicyID` + `EventRef` (resolve the id once with `ResolvePolicyID`) and read back with `LatestConsentFor(ctx, userID, consentType, eventRef, policyID)`, so another session or policy version cannot authorize the action.

### Spoof-safe client IP — `bcommon.TrustedClientIP(r)`

The `client_ip` column on `consent_event` is part of the regulator-visible audit trail; it must reflect the real caller, not whatever an attacker types into `X-Forwarded-For`. `common.TrustedClientIP(r *http.Request) string` honors `X-Forwarded-For` / `X-Real-IP` **only** when the inbound socket address falls inside `trusted_proxy_cidr`. With an empty CIDR config the helper returns `RemoteAddr`'s host part — a fail-closed default. `common.RemoteHost(remoteAddr)` is the bare host-part strip, for callers that only need the socket peer.

Use this helper anywhere a downstream consumer would otherwise reach for `r.RemoteAddr` or read forwarding headers directly:

```go
import "github.com/nauticana/keel/common"

func (h *MyHandler) Register(w http.ResponseWriter, r *http.Request) {
    consent := &port.SignupConsent{
        ClientIP:        common.TrustedClientIP(r), // gated; safe behind a trusted proxy
        ClientUserAgent: r.UserAgent(),
        // …
    }
}
```

Keel's own consent-capturing handlers (`SocialLoginHandler.LoginSocial`, the OTP flows, the Google login activity-history insert) all use this helper internally, so they're safe by default. Consumers writing their own handlers should call it explicitly rather than re-implementing the gate — the obvious-looking `r.Header.Get("X-Forwarded-For")` shortcut accepts spoofed values whenever the deployment isn't behind a CIDR-restricted proxy.

**Production startup check.** The empty-config default is library-friendly but operationally dangerous: every audit row would attribute traffic to the load balancer's peer IP and the spoof-gated `TrustedClientIP` would never promote XFF. Production binaries should call:

```go
flag.Parse()
common.MustRequireTrustedProxyCIDR() // log.Fatalf if trusted_proxy_cidr is empty / all-invalid
```

(Or the error-returning variant `common.RequireTrustedProxyCIDR()` if you prefer to handle the failure yourself.) This converts the silently-broken-attribution failure mode into a deploy-time crash. The validator parses the CIDR list with the same logic the runtime uses — a config that splits to zero valid nets fails too, since that's behaviorally identical to "empty" at request time. Skip the helper for unit tests, localhost-only deployments, or consumers that genuinely do not record client IPs.
