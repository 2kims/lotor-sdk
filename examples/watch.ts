// Example: WATCH streaming. Subscribe to change selectors and receive server-pushed EVENT frames in
// real time — e.g. to invalidate a local decision cache the moment an access tuple changes.
//
//   cd instance && cargo run -p lotord        # standalone
//   cd lotor-sdk-ts && pnpm install && pnpm watch
//
// Here we watch a subject, then GRANT a tuple touching it and receive the `grant_changed` event.

import { LotorClient, type LotorEvent } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";

const timeout = <T>(ms: number, msg: string) =>
  new Promise<T>((_, rej) => setTimeout(() => rej(new Error(msg)), ms));

async function main() {
  const lotor = await LotorClient.connect({ host, port });
  await lotor.auth(apiKey);
  console.log("✓ connected\n");

  // a promise that resolves on the first matching event
  let onEvent!: (ev: LotorEvent) => void;
  const firstEvent = new Promise<LotorEvent>((resolve) => { onEvent = resolve; });

  const watchId = await lotor.watch(["access:user:99"], (ev) => {
    console.log("  ⚡ EVENT", JSON.stringify(ev));
    onEvent(ev);
  });
  console.log(`watching "access:user:99" (id=${watchId})`);

  // trigger a change that publishes to our selector
  const grant = await lotor.accessGrant("user:99", "view", "doc:42");
  console.log(`granted user:99 view doc:42 (logSeq=${grant.logSeq})`);

  // wait for the pushed event
  const ev = await Promise.race([firstEvent, timeout<LotorEvent>(2000, "no event within 2s")]);
  console.log(`\n✓ received "${ev.type}" for target=${ev.target} (logSeq=${ev.logSeq})`);

  await lotor.unwatch(watchId);
  await lotor.quit();
  console.log("✓ done");
}

main().catch((e) => { console.error(e); process.exit(1); });
