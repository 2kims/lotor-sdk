// Example: auto-reconnect. The client survives a lotord restart — re-dialing, replaying HELLO+AUTH,
// and re-establishing WATCH subscriptions automatically. Calls made during the outage queue until the
// connection is back.
//
//   cd instance && cargo run -p lotord
//   cd lotor-sdk-ts && pnpm reconnect
// ...then kill and restart lotord while this runs; the pings recover on their own.

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const lotor = await LotorClient.connect({
    host, port,
    onDisconnect: () => console.log("  … disconnected — reconnecting"),
    onReconnect: () => console.log("  ✓ reconnected (re-authed + re-watched)"),
  });
  await lotor.auth(apiKey);
  await lotor.watch(["access:user:99"], (ev) => console.log(`  ⚡ ${ev.type} ${ev.target}`));
  console.log("connected; pinging every 1s for 12s — kill & restart lotord to see recovery\n");

  for (let i = 0; i < 12; i++) {
    try {
      const t = await lotor.ping(); // queues during an outage, resolves once reconnected
      console.log(`  ping ${i}: ok (server time ${t})`);
    } catch (e) {
      console.log(`  ping ${i}: failed (${(e as Error).message})`);
    }
    await sleep(1000);
  }
  await lotor.quit();
  console.log("\n✓ done");
}

main().catch((e) => { console.error(e); process.exit(1); });
