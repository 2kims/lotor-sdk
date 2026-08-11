// Example: one-time purchase addon — a durable unit balance that carries across billing cycles.
//
// Unlike overage (pay-per-spill from a money wallet, resets each cycle), a one-time addon is a pool
// of *meter units* you bought once; it persists until used up or it expires, and a consume past the
// recurring quota draws it down before any wallet overage. Two ways to buy:
//   1. control-issued (paid via Stripe upstream) — always include a stable idempotency key
//   2. credit-funded (debit a prepaid wallet)     — allowanceGrant(..., {wallet, cost})  ← shown here
//
//   cd instance && cargo run -p lotord            # serves LWP on :7420 with demo data
//   cd lotor-sdk-ts && pnpm install && pnpm addon
//
// Env: LOTORD_HOST (127.0.0.1), LOTORD_PORT (7420), LOTOR_API_KEY (demo-key).

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

function log(label: string, value: unknown) {
  console.log(`  ${label.padEnd(30)} ${JSON.stringify(value)}`);
}

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);

  const SCOPE = "org:acme", METER = "api_calls"; // demo meter: max 2, then overage
  const purchaseKey = "purchase-2026-06-26-org-acme-api-calls-001";
  console.log("\n— buy a one-time addon with prepaid credits (scenario 2) —");
  log("credits before", await lotor.walletBalance(SCOPE, "credits")); // 50
  const g = await lotor.allowanceGrant(SCOPE, METER, 10, { wallet: "credits", cost: 15, idempotencyKey: purchaseKey });
  log("granted 10 units (cost 15)", g); // unitsTotal 10, walletBalance 35
  // idempotent — retry the same purchase with the same key. Do not reuse this key with different params.
  log("retry same purchase", await lotor.allowanceGrant(SCOPE, METER, 10, { wallet: "credits", cost: 15, idempotencyKey: purchaseKey }));
  log("addon balance", await lotor.allowanceBalance(SCOPE, METER));

  console.log("\n— consume: recurring quota first, then the durable addon pool —");
  for (let i = 1; i <= 5; i++) {
    const r = await lotor.meterConsume(SCOPE, METER, 1, `c-${i}`);
    log(`consume #${i}`, r); // #1,#2 'consumed' (base 2); #3+ 'addon_granted' drawing the pool
  }
  log("addon remaining", await lotor.allowanceBalance(SCOPE, METER));
  console.log("  (the addon balance carries to the next billing cycle — it is not reset on roll)");

  await lotor.quit();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
