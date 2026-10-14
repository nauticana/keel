# keel v1.2.118 adoption notes for sail

Two changes in keel v1.2.118 touch sail. Neither is required for sail to keep working.

## 1. Timestamps are now RFC 3339

String timestamp fields in hand-built keel DTOs are RFC 3339 UTC, for example `2026-11-12T00:00:00Z`. They used to be Go's default `time.Time` layout, `2026-11-12 00:00:00 +0000 UTC`, which Angular's `date` pipe rejects. Affected fields: `trialEnd`, `begda`, `endda` and `scheduledAt` on `GET /api/billing/subscription`, and the created and last-seen fields on device tokens and trusted devices. Generic REST rows were already RFC 3339.

- `<sail-trial-banner>` and any other place that guards against an unparsable date can drop the guard once the deployment runs keel v1.2.118 or later. Keep it if sail must support older keel servers.
- Unset stays the empty string, so `=== ''` checks keep working.
- Render these values through the `date` pipe with no timezone argument. The string is an absolute instant and the pipe shows it in the browser's zone. Do not shift it by hand.

## 2. Send the browser time zone on every API call

keel reads an optional `X-Time-Zone` request header carrying the browser's IANA zone name. It uses the zone only for output a person reads that keel renders server-side (emails, notifications, exports). It is request state: keel does not store it and it is not in any token. Without the header keel renders in UTC.

Change in `src/service/auth.interceptor.ts`, where the `Authorization` header is already set for keel API URLs:

```ts
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

if (isKeelApiUrl(req.url)) {
  req = req.clone({ setHeaders: { 'X-Time-Zone': TIME_ZONE } });
}
```

- Set it on every keel API request, authenticated or not, so public flows such as registration emails also get the zone. Keep the existing rule that only keel URLs receive sail headers.
- Read the zone once per page load, as above. It follows the device setting, so a user who travels gets the new zone on the next load.
- keel's CORS middleware already allows the header; no server configuration is needed.
- Values keel accepts: an IANA name of at most 64 characters, such as `Europe/Istanbul` or `UTC`. keel ignores anything else and logs it, so send the browser value unmodified.
- No sail test needs to assert keel behaviour. One unit test on the interceptor should check the header is present on a keel URL and absent on a non-keel URL.

Delete this file once both items are done.
