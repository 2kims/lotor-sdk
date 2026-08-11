// Example: prepaid credit wallet — draw down on usage, hit "insufficient", and reload.
//
// A wallet is a *balance* you draw down (WALLET.DEBIT), unlike a meter (a counter that counts up to a
// cap). The demo seeds org:acme "credits" = 50. Here we spend it down to empty, see a debit rejected,
// then simulate the control plane's auto-reload (a WALLET.CREDIT after a charge) and continue. In
// production the reload is automatic: lotor-control polls the balance over LWP and, when it falls
// below the configured threshold, charges the customer (Stripe) and issues the WALLET.CREDIT.
//
//   cd instance && cargo run -p lotord            # serves LWP on :7420 with demo data
//   cd lotor-sdk-ts && pnpm install && pnpm wallet
//
// Env: LOTORD_HOST (127.0.0.1), LOTORD_PORT (7420), LOTOR_API_KEY (demo-key).

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

function log(label: string, value: unknown) {
  console.log(`  ${label.padEnd(28)} ${JSON.stringify(value)}`);
}

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);

  const SCOPE = "org:acme", WALLET = "credits";
  // event-driven low-balance alert (fires when a debit crosses below the per-account threshold, 20)
  await lotor.onWalletLow(SCOPE, WALLET, (e) => {
    console.log(`  ⚡ wallet_low — balance ${e.balance} < threshold ${e.threshold}`);
  });

  console.log(`\n— prepaid wallet ${SCOPE}/${WALLET} —`);
  log("starting balance", await lotor.walletBalance(SCOPE, WALLET)); // 50 (demo)

  // Spend in chunks of 20 until the balance can't cover the next debit.
  let n = 0;
  for (;;) {
    const r = await lotor.walletDebit(SCOPE, WALLET, 20, `spend-${n++}`);
    log(`debit 20 (#${n})`, r);
    if (!r.accepted) break; // insufficient_funds
  }

  console.log("\n— auto-reload (what lotor-control does: charge, then WALLET.CREDIT) —");
  log("balance before reload", await lotor.walletBalance(SCOPE, WALLET));
  const topupId = "top-demo-1";
  const credited = await lotor.walletCredit(SCOPE, WALLET, 100, topupId); // idempotency = top-up id
  log("credit +100", credited);
  // a retried reload (same top-up id) must not double-credit
  const retry = await lotor.walletCredit(SCOPE, WALLET, 100, topupId);
  log("retry same top-up", retry); // identical balance — idempotent

  console.log("\n— the previously-rejected spend now fits —");
  log("debit 20 (after reload)", await lotor.walletDebit(SCOPE, WALLET, 20, "spend-after"));

  await new Promise((r) => setTimeout(r, 200)); // let the wallet_low event flush
  await lotor.quit();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
