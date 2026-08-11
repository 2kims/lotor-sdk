# @lotor.dev/sdk

The ESM-only Node.js/TypeScript client for Lotor's LWP/1 data-plane protocol.
It supports warm pipelined connections, TLS and mTLS, verified runtime ownership,
reconnect, watch events, and the complete v0 data-plane operation set. The
package has no runtime dependencies and requires Node.js 22.14 or newer.

## Run the example

1. Start a compatible development `lotord` on `127.0.0.1:7420`.
2. From a checkout of this repository, run:
   ```bash
   pnpm install
   pnpm example
   ```

Expected output (abridged):
```
✓ authed as tenant=tenant:demo plan=free scope=rw
— ACCESS.CHECK —
  user:42 view doc:99    {"allow":true,"reason":"allowed","ttl":0}
  user:42 view doc:1     {"allow":false,"reason":"no_grant","ttl":0}
  org:acme has feat:sso  {"allow":true,"reason":"allowed","ttl":0}
— METER.CONSUME —
  consume ai_assets +1   {"accepted":true,"remaining":99,...}
  retry +5 (same key)    {... same used/logSeq — not double-counted}
— a simulated API request (authorize + meter inline) —
  ✓ user:42 → doc:99: 200  (ai_assets remaining=...)
  ✗ user:42 → doc:1: 403 (no_grant)
```

## Org members + per-member feature gating & metering
`pnpm org` (`examples/org.ts`) shows the B2B2C shape: an owner invites members, each is entitled to some
features (x/y/z), and each member's usage of each feature is gated and metered **independently**:
```
invited user:alice with features [x, y];  user:bob with [x]
members of org:acme: ... alice, bob           # ACCESS.EXPAND
alice feat x: 200,200,200 then 429 quota_exceeded   # per-member quota (3)
alice feat y: 200 (entitled);  feat z: 403 not_entitled
bob   feat x: 200             # his own counter — alice's exhaustion doesn't affect him
```
Built from: `accessGrant` (membership + entitlement tuples) · `accessCheck` (gate) ·
`meterConsume(scope=member, "feat_x")` (per-member counter) · `accessExpand` (list members). The
invitation lifecycle and organization roles are normally orchestrated by the control plane; this
example models the accepted result. Since `ACCESS.CHECK` is direct-tuple today, each member's feature
access is granted explicitly rather than inherited via org→plan.

## Role-based per-member features (`pnpm roles`)
Different members of one org get **different** feature subsets via their **role** — resolved by ReBAC,
not per-member grants. A role `grants` features; a member is `assignee` of a role:
```
roles: editor grants [x, y]; viewer grants [x]
alice → editor;  bob → viewer
alice: feature x 200, feature y 200
bob:   feature x 200, feature y 403 not_entitled   # viewer's role doesn't grant y
```
In production the control plane's `manage` domain (orgs/roles/invitations, `POST /v1/orgs/…`) emits
these tuples into the bundle; `examples/roles.ts` writes them directly to show the resolution.

## Prepaid wallet (credits + auto-reload)
`pnpm wallet` (`examples/wallet.ts`) shows the prepaid-credit shape: a wallet is a *balance* you draw
down (`WALLET.DEBIT`), unlike a meter (a counter up to a cap). The demo seeds `org:acme/credits=50`;
the example spends it down, hits `insufficient_funds`, then reloads (`WALLET.CREDIT`) and continues:
```
starting balance        50
debit 20 (#1)           {"accepted":true,"reason":"debited","balance":30}
debit 20 (#3)           {"accepted":false,"reason":"insufficient_funds","balance":10}
credit +100             {"accepted":true,"reason":"credited","balance":110}
retry same top-up       {"accepted":true,...,"balance":110}   # idempotent — no double-credit
```
```ts
const r = await lotor.walletDebit("org:acme", "credits", 20, idemKey);
if (!r.accepted) { /* insufficient_funds — reload or reject */ }
const bal = await lotor.walletBalance("org:acme", "credits");
await lotor.walletCredit("org:acme", "credits", 100, topupId); // idempotent (top-up id)
```
In production the reload is **automatic**: `lotor-control` polls the balance over LWP and, when it
drops below the configured threshold (`billing.wallets`), charges the customer and issues the
`WALLET.CREDIT` — the top-up id keys both the charge and the credit for exactly-once.

### Overage (auto-buy past a quota)
`pnpm overage` (`examples/overage.ts`) shows the **atomic overage rule**: a meter with an overage
policy auto-buys blocks from a wallet when a `meterConsume` would exceed its quota — the debit, the
allowance bump, and the consume are **one** durable record. The demo seeds `api_calls` (max 2, 5-unit
blocks @ 10 credits):
```
consume #2   {"accepted":true,"reason":"consumed","used":2,"max":2}
consume #3   {"accepted":true,"reason":"overage_granted","used":3,"max":7,"blocksPurchased":1,"walletBalance":40}
consume #6   {"accepted":true,"reason":"consumed","used":6,"max":7}   # within the extended allowance
```
```ts
const r = await lotor.meterConsume("org:acme", "api_calls", 1, idemKey);
if (r.reason === "overage_granted") { /* bought r.blocksPurchased block(s); wallet now r.walletBalance */ }
if (!r.accepted) { /* insufficient_funds — wallet couldn't buy the next block */ }
```

## One-time purchase addon (durable, carries across cycles)
`pnpm addon` (`examples/addon.ts`) shows the **one-time addon**: a pool of *meter units* bought once
that **persists across billing cycles** (not reset on roll), drawn down past the recurring quota
*before* any wallet overage. Two funding modes — control-issued (paid via Stripe upstream) or
credit-funded (debit a prepaid wallet, shown here):
```ts
// buy 10 units of api_calls with 15 credits (idempotent by key — no double-charge/grant)
// Use one stable idempotencyKey per intended purchase; reuse it on retries of that
// same purchase, and never reuse it with different addon parameters.
const purchaseKey = "purchase-2026-06-26-org-acme-api-calls-001";
const g = await lotor.allowanceGrant("org:acme", "api_calls", 10, { wallet: "credits", cost: 15, idempotencyKey: purchaseKey });
const { remaining } = await lotor.allowanceBalance("org:acme", "api_calls");
const r = await lotor.meterConsume("org:acme", "api_calls", 1);
if (r.reason === "addon_granted") { /* drew r.grantDrawn from the pool; r.grantRemaining left */ }
```
```
granted 10 units (cost 15)   {"accepted":true,"unitsTotal":10,"walletBalance":35}
consume #3                   {"reason":"addon_granted","grantDrawn":1,"grantRemaining":9}
```
For control-issued grants (the Stripe path), the control plane's `POST /v1/addons` accepts missing
`idempotency_key` only during a temporary compatibility window. Treat `idempotency_key` as required:
send a stable key per intended purchase and reuse that exact key on retries. A missing key is legacy
best-effort behavior, is not retry-safe, emits deprecation signaling during the compatibility window,
and will be rejected by the final enforcement release. Reusing a key with different parameters fails
closed with an idempotency parameter mismatch. Draw precedence: recurring quota → one-time addon →
wallet overage.

## Wallet low-balance events (`wallet_low`)
Subscribe to a wallet and get pushed an event the instant a debit crosses below its per-account
threshold (edge-triggered; re-armed when a credit recovers it). `pnpm wallet` shows it live:
```ts
await lotor.onWalletLow("org:acme", "credits", ({ balance, threshold }) => {
  console.log(`⚡ low: ${balance} < ${threshold}`); // top up, warn the user, …
});
```
```
debit 20 (#1)   {"balance":30}
⚡ wallet_low — balance 10 < threshold 20      # the debit that crossed below 20
```
The threshold is **per account** (`scope`), configured control-side (`billing.wallets`) and pushed in
the bundle. In production the **control plane** subscribes to the same event (over the Go SDK) to drive
event-driven auto-reload — the app doesn't have to.

## AUTH.VERIFY (validate an end-user JWT)
`LOTOR_END_USER_CREDENTIAL=... pnpm verify` runs `examples/authverify.ts` and
asks the runtime to verify a short-lived JWT against its configured public
JWKS. The example never contains an issuer signing key.
```
— AUTH.VERIFY (cred_type=1 JWT) —
  configured token   {"valid":true,"subject":"user:42","org":"org:example",...,"reason":"valid"}
  tampered token     {"valid":false,...,"reason":"bad_signature"}
```
```ts
const v = await lotor.authVerify(1, jwt);   // 1=JWT, 2=sealed cookie
if (v.valid) console.log(v.subject, v.org); // who the credential is for
```

## WATCH (live change events)
`pnpm watch` runs `examples/watch.ts`: subscribe to selectors and receive server-pushed `EVENT` frames
in real time (e.g. to invalidate a local decision cache the instant a tuple changes). It watches a
subject, `GRANT`s a tuple touching it, and receives the `grant_changed` event:
```
watching "access:user:99" (id=1)
  ⚡ EVENT {"type":"grant_changed","target":"user:99","detail":{},"logSeq":1}
✓ received "grant_changed" for target=user:99
```
```ts
const id = await lotor.watch(["access:user:42", "config"], (ev) => {
  console.log(ev.type, ev.target, ev.logSeq); // grant_changed | config_changed | revoked
});
// ... later
await lotor.unwatch(id);
```
Each EVENT frame carries its subscription's watch id, so a client with several `watch()` calls on
different selectors routes each event to exactly the right handler (no cross-delivery).

## TLS
The data plane serves server-TLS when `lotord` is given a cert+key; the client verifies it against a
CA. `pnpm tls` demonstrates it:
```bash
LOTOR_TLS_CA=/path/to/development-ca.crt pnpm tls
```
```ts
import { readFileSync } from "node:fs";
const lotor = await LotorClient.connect({
  host: "localhost", port: 7420,           // host must match the cert SAN
  tls: { ca: readFileSync("ca.crt") },     // or tls: true for system roots
});
```
`tls: true` uses defaults (system roots); the object form sets `ca` / `servername` /
`rejectUnauthorized` (default `true`) / `cert`+`key` (mTLS). Reconnect works over TLS too.

## Auto-reconnect
On by default. If the connection drops, the client transparently re-dials (exponential backoff),
replays `HELLO` + `AUTH`, and re-establishes every `WATCH` subscription — calls made during the outage
queue until it's back. `pnpm reconnect` demonstrates it (kill & restart `lotord` while it runs):
```
ping 2: ok (...)
… disconnected — reconnecting
✓ reconnected (re-authed + re-watched)
ping 3: ok (...)        # the queued ping resumed once the connection recovered
```
```ts
const lotor = await LotorClient.connect({
  host, port,
  reconnect: true,                 // default
  onDisconnect: () => metrics.inc("lotor.disconnect"),
  onReconnect:  () => log.info("lotor reconnected"),
});
```
In-flight requests at the moment of a drop are rejected (caller may retry); subsequent calls block
until the connection is restored, then proceed. Set `reconnect: false` to opt out.

## Use it in code
```ts
import { LotorClient } from "@lotor.dev/sdk";

const lotor = await LotorClient.connect({ host: "127.0.0.1", port: 7420 });
await lotor.auth(process.env.LOTOR_API_KEY!);

const { allow } = await lotor.accessCheck("user:42", "view", "doc:99");
if (allow) {
  const usage = await lotor.meterConsume("org:acme", "ai_assets", 1, idempotencyKey);
  if (!usage.accepted) throw new Error(usage.reason); // quota/rate
}
```

## Compatibility and security

`0.1.x` speaks LWP protocol version 1 and ownership assertion version 1. The
public API is pre-1.0; breaking changes may occur in a minor release and are
called out in the changelog. CommonJS is not supported.

Keep Lotor API keys, end-user credentials, TLS client keys, and customer data
in backend processes. Reuse stable idempotency keys only for retries of the
same mutation. Report vulnerabilities through the repository's private
security advisory form.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
