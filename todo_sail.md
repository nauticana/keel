# Sail adoption of keel v1.2.101

## S1 — Connect flow: complete the callback ticket (breaking)

keel binds a provider connection to the user who started it (RFC 6749 §10.12). The provider callback no longer creates the connection or redirects with `?<provider>=success`.

**New flow**

1. `GET /api/oauth/{provider}/authorize` is unchanged; it needs a signed-in user as well as a partner.
2. The provider redirects to `/api/oauth/{provider}/callback`. keel validates it, stores a single-use ticket, and redirects the browser to `FrontendReturnURL?connect={provider}&ticket={ticket}`.
3. The signed-in app posts the ticket with its bearer token:

   `POST /api/oauth/{provider}/complete` with body `{"ticket": "..."}`

   | Status | Meaning |
   |---|---|
   | 200 `{"status":"ok","provider":"..."}` | Connected |
   | 400 | Missing, expired (`oauth_state_ttl_seconds`) or already used ticket, or a ticket for another provider |
   | 403 | The flow was started by another user or partner, or the caller lacks the connection-management grant |
   | 500 | Provider exchange failed |

**Sail changes**

- `OAuthConnectionService`: add `completeOAuth(provider, ticket): Observable<{status, provider}>` posting to `/api/oauth/{provider}/complete`.
- `OAuthConnectionPanel.ngOnInit`: replace the `?<provider>=success` detection with `connect` + `ticket`:
  - ignore a `connect` value that is not a configured provider;
  - strip `connect` and `ticket` from the URL before the call (`history.replaceState`, hash preserved), so a reload never re-posts a spent ticket;
  - call `completeOAuth`, then keep the existing reload-and-confirm behavior (`pendingSuccess`, `connected` output);
  - show a distinct message for 403 ("started by another user, start again") and for 400 ("expired, start again").
- The page at `FrontendReturnURL` must require sign-in before the panel runs; the call needs the bearer token of the user who started the flow.
- No change to provider redirect URIs, `startOAuth`, `testConnection`, `saveApiKey`, `list` or `disconnect`.

**Blocked downstream work**: every application using the connection panel, once it upgrades keel to v1.2.101.
