// Example: a Node backend using Lotor on its request path. One warm LWP connection does authorization
// (ACCESS.CHECK) and metering (METER.CONSUME) inline — no fan-out to separate auth/billing services.
//
// Run a standalone lotord (demo data) first:
//   cd instance && cargo run -p lotord            # serves LWP on :7420 with built-in demo data
// then:
//   cd lotor-sdk-ts && pnpm install && pnpm example
//
// Env: LOTORD_HOST (127.0.0.1), LOTORD_PORT (7420), LOTOR_API_KEY (demo-key).

import { LotorClient, LotorError } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

function log(label: string, value: unknown) {
  console.log(`  ${label.padEnd(22)} ${JSON.stringify(value)}`);
}

async function main() {
  console.log(`→ connecting to lotord at ${host}:${port}`);
  const lotor = await LotorClient.connect({ host, port });

  const who = await lotor.auth(apiKey);
  console.log(`✓ authed as tenant=${who.tenant} plan=${who.plan} scope=${who.scope}`);

  console.log("\n— ACCESS.CHECK (entitlement + RBAC, one tuple model) —");
  log("user:42 view doc:99", await lotor.accessCheck("user:42", "view", "doc:99")); // allow
  log("user:42 view doc:1", await lotor.accessCheck("user:42", "view", "doc:1"));   // deny
  log("org:acme has feat:sso", await lotor.accessCheck("org:acme", "has", "feat:sso")); // entitlement

  console.log("\n— METER.CONSUME (durable, idempotent usage) —");
  for (let i = 0; i < 3; i++) {
    log(`consume ai_assets +1`, await lotor.meterConsume("org:acme", "ai_assets", 1));
  }
  // idempotent retry: same key counts once, replays the same result
  const key = "req-" + Date.now();
  const first = await lotor.meterConsume("org:acme", "ai_assets", 5, key);
  const retry = await lotor.meterConsume("org:acme", "ai_assets", 5, key);
  log("consume +5 (key)", first);
  log("retry +5 (same key)", retry); // identical used/logSeq — not double-counted
  log("meter.get ai_assets", await lotor.meterGet("org:acme", "ai_assets"));

  console.log("\n— a simulated API request (authorize + meter inline) —");
  await handleApiRequest(lotor, "user:42", "doc:99");
  await handleApiRequest(lotor, "user:42", "doc:1");

  log("ping (server time ms)", await lotor.ping());
  await lotor.quit();
  console.log("\n✓ done");
}

// What a real handler looks like: gate on access, meter the work, all over the warm connection.
async function handleApiRequest(lotor: LotorClient, user: string, doc: string) {
  const decision = await lotor.accessCheck(user, "view", doc);
  if (!decision.allow) {
    console.log(`  ✗ ${user} → ${doc}: 403 (${decision.reason})`);
    return;
  }
  const usage = await lotor.meterConsume("org:acme", "ai_assets", 1);
  if (!usage.accepted) {
    console.log(`  ✗ ${user} → ${doc}: 429 (${usage.reason})`);
    return;
  }
  console.log(`  ✓ ${user} → ${doc}: 200  (ai_assets remaining=${usage.remaining})`);
}

main().catch((e) => {
  if (e instanceof LotorError) console.error(`LWP error ${e.code}: ${e.message}`);
  else console.error(e);
  process.exit(1);
});
