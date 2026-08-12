#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary = mkdtempSync(join(tmpdir(), "lotor-node-sdk-package-"));

function run(command, args, cwd = temporary) {
  execFileSync(command, args, { cwd, stdio: "inherit" });
}

try {
  const packed = JSON.parse(execFileSync(
    "npm",
    ["pack", "--json", "--pack-destination", temporary],
    { cwd: root, encoding: "utf8" },
  ));
  assert.equal(packed.length, 1);
  const artifact = packed[0];
  assert.deepEqual(artifact.files.map(({ path }) => path).sort(), [
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "dist/client.d.ts",
    "dist/client.js",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/ownership.d.ts",
    "dist/ownership.js",
    "dist/wire.d.ts",
    "dist/wire.js",
    "package.json",
  ]);

  const tarball = join(temporary, artifact.filename);
  const consumer = join(temporary, "consumer");
  mkdirSync(join(consumer, "src"), { recursive: true });
  writeFileSync(join(consumer, "package.json"), `${JSON.stringify({
    name: "lotor-node-sdk-clean-consumer",
    private: true,
    type: "module",
    dependencies: { "@lotor.dev/sdk": `file:${tarball}` },
    devDependencies: {
      "@types/node": "22.20.0",
      typescript: "5.9.3",
    },
  }, null, 2)}\n`);
  writeFileSync(join(consumer, "tsconfig.json"), `${JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      noEmit: true,
      types: ["node"],
    },
    include: ["src"],
  }, null, 2)}\n`);
  writeFileSync(join(consumer, "src/consumer.ts"), `
import {
  LotorClient,
  OwnershipResolver,
  ownershipAddress,
  type ClientOptions,
  type Ownership,
} from "@lotor.dev/sdk";

const options: ClientOptions = { host: "localhost", port: 7420, reconnect: false };
const clientType: typeof LotorClient = LotorClient;
const resolver = new OwnershipResolver({
  controlUrl: "https://control.example.test",
  apiKey: "test_api_key",
  scope: {
    tenantId: "tenant_public",
    applicationId: "application_public",
    environmentId: "environment_public",
  },
  publicKey: Buffer.alloc(32),
});
const ownership: Ownership = {
  tenant_id: "tenant_public",
  application_id: "application_public",
  environment_id: "environment_public",
  endpoint: "lwps://runtime.example.test:7420",
  owner_instance_id: "runtime_public",
  ownership_epoch: 1,
  issued_at: 1,
  expires_at: 2,
  version: 1,
  key_id: "public_key",
  signature: "test_signature",
};
void options;
void clientType;
void resolver;
void ownershipAddress(ownership);
`);
  writeFileSync(join(consumer, "runtime.mjs"), `
import assert from "node:assert/strict";
import * as sdk from "@lotor.dev/sdk";

assert.equal(typeof sdk.LotorClient, "function");
assert.equal(typeof sdk.OwnershipResolver, "function");
assert.equal(typeof sdk.ownershipAddress, "function");
assert.equal("wire" in sdk, false);
assert.deepEqual(sdk.ownershipAddress({ endpoint: "lwps://runtime.example.test:7420" }), {
  host: "runtime.example.test",
  port: 7420,
  tls: true,
});
process.stdout.write("packed Node SDK runtime surface passed\\n");
`);

  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], consumer);
  run(join(consumer, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.json"], consumer);
  run(process.execPath, ["runtime.mjs"], consumer);

  const packedManifest = JSON.parse(readFileSync(join(consumer, "node_modules", "@lotor.dev", "sdk", "package.json"), "utf8"));
  const sourceManifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.equal(packedManifest.name, "@lotor.dev/sdk");
  assert.equal(packedManifest.version, sourceManifest.version);
  assert.equal(packedManifest.license, "Apache-2.0");
  assert.equal(packedManifest.private, process.env.LOTOR_PUBLIC_RELEASE === "1" ? undefined : true);
  if (process.env.LOTOR_PUBLIC_RELEASE === "1") {
    assert.equal(readFileSync(join(consumer, "node_modules", "@lotor.dev", "sdk", "README.md")).length, 0);
  }
  process.stdout.write(`clean packed consumer passed for ${packedManifest.name}@${packedManifest.version}\n`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
