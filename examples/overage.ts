// Example: the atomic overage rule — a meter that auto-buys from a wallet past its quota.
//
// The demo seeds meter `api_calls` with max=2 and an overage rule {wallet: credits, block: 5,
// price: 10, max_blocks: 10}, plus org:acme/credits=50. The first 2 calls are included; the 3rd
// exceeds the quota, so instead of rejecting, the consume atomically buys one 5-unit block from the
// wallet (10 credits) and proceeds — one durable record across the counter + wallet. When the wallet
// can't cover the next block, the consume finally rejects with insufficient_funds.
//
//   cd instance && cargo run -p lotord            # serves LWP on :7420 with demo data
//   cd lotor-sdk-ts && pnpm install && pnpm overage
//
// Env: LOTORD_HOST (127.0.0.1), LOTORD_PORT (7420), LOTOR_API_KEY (demo-key).

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

function log(label: string, value: unknown) {
  console.log(`  ${label.padEnd(26)} ${JSON.stringify(value)}`);
}

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);

  const SCOPE = "org:acme", METER = "api_calls";
  console.log(`\n— metered "${METER}" (max 2, then overage from wallet "credits") —`);
  log("wallet credits", await lotor.walletBalance(SCOPE, "credits")); // 50

  for (let i = 1; i <= 6; i++) {
    const r = await lotor.meterConsume(SCOPE, METER, 1, `call-${i}`);
    log(`consume #${i}`, r);
    if (!r.accepted) break; // insufficient_funds — wallet can't buy another block
  }

  console.log("\n— within quota: 'consumed'; past quota: 'overage_granted' (wallet debited 10/block) —");
  log("final wallet credits", await lotor.walletBalance(SCOPE, "credits"));
  log("api_calls", await lotor.meterGet(SCOPE, METER)); // used + extended max

  await lotor.quit();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
