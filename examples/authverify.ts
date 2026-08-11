// Example: ask a compatible Lotor runtime to verify an end-user JWT. Obtain a
// short-lived development credential from the issuer configured for that
// runtime; never embed a signing key in an application or SDK example.

import { LotorClient } from "../src/index.js";

const host = process.env.LOTORD_HOST ?? "127.0.0.1";
const port = Number(process.env.LOTORD_PORT ?? 7420);
const apiKey = process.env.LOTOR_API_KEY ?? "demo-key";
const credential = process.env.LOTOR_END_USER_CREDENTIAL;

function log(label: string, value: unknown) {
  console.log(`  ${label.padEnd(26)} ${JSON.stringify(value)}`);
}

async function main() {
  if (!credential) {
    throw new Error("LOTOR_END_USER_CREDENTIAL is required");
  }

  const lotor = await LotorClient.connect({ host, port });
  const who = await lotor.auth(apiKey);
  console.log(`✓ connected, authed as ${who.tenant}\n`);

  console.log("— AUTH.VERIFY (cred_type=1 JWT) —");
  log("configured token", await lotor.authVerify(1, credential));

  // A modified signature must never validate.
  const tampered = credential.slice(0, -2) + (credential.endsWith("AA") ? "BB" : "AA");
  log("tampered token", await lotor.authVerify(1, tampered));

  await lotor.quit();
  console.log("\n✓ done");
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
