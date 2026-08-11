// Example: connect over TLS. Configure a compatible development runtime with a
// server certificate whose SAN includes localhost, then provide its CA:
//
//   LOTOR_TLS_CA=/path/to/development-ca.crt pnpm tls
//
// Connect to the SAN host (localhost). Set LOTOR_TLS_INSECURE=1 to skip verification (dev only).

import { readFileSync } from "node:fs";
import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "localhost"; // must match the cert SAN
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";
const caPath = process.env.LOTOR_TLS_CA; // PEM CA that signed the server cert
const insecure = process.env.LOTOR_TLS_INSECURE === "1";

async function main() {
  const lotor = await LotorClient.connect({
    host, port,
    tls: {
      ca: caPath ? readFileSync(caPath) : undefined,
      rejectUnauthorized: !insecure,
      servername: "localhost",
    },
  });
  const who = await lotor.auth(apiKey);
  console.log(`✓ connected over TLS, authed as ${who.tenant}`);
  console.log("  access:", await lotor.accessCheck("user:42", "view", "doc:99"));
  console.log("  meter :", await lotor.meterConsume("org:acme", "ai_assets", 1));
  await lotor.quit();
  console.log("✓ done (encrypted)");
}

main().catch((e) => { console.error(e); process.exit(1); });
