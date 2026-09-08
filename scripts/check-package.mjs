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
    "dist/control.d.ts",
    "dist/control.js",
    "dist/gateway-assertion.d.ts",
    "dist/gateway-assertion.js",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/ownership.d.ts",
    "dist/ownership.js",
    "dist/resource-crypto.d.ts",
    "dist/resource-crypto.js",
    "dist/resource.d.ts",
    "dist/resource.js",
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
  GatewayAssertionVerifier,
  LotorClient,
  LotorControlClient,
  LotorResourceClient,
  OwnershipResolver,
  ownershipAddress,
  type ClientOptions,
  type Ownership,
  type AccountResourceList,
  type AccountInvitationList,
  type AccountInvitationMutation,
  type ResourcePayloadManifest,
  type ResourcePayloadAccessLease,
  type ResourceCredentialExchange,
  type ResourceExecutionAuthorization,
  type ResourceLinkSendResult,
  type ResourceCollaboratorList,
  type ResourceSearchList,
  type OrganizationE2EEPolicy,
  type ResourceCollaborationPolicyMutation,
} from "@lotor.dev/sdk";

export async function workloadExchange(client: LotorResourceClient): Promise<ResourceCredentialExchange> {
  return client.exchangeCredential({ audience: "https://provider.example.test", method: "POST", path: "/proxy", bodySha256: "a".repeat(64), querySha256: "b".repeat(64) });
}

export async function workloadExecute(client: LotorResourceClient): Promise<ResourceExecutionAuthorization> {
  const plan = await client.preflightExecution("integration:provider", { method: "POST", path: "/proxy", contentType: "application/json", requestBodyDigest: "a".repeat(64), requestBodySize: 2 });
  return client.commitExecution(plan.resource, plan);
}

export async function userGraph(client: LotorControlClient, token: string) {
  const user = client.forUser(token);
  const directory: AccountResourceList = await user.accountResources({ parent: "project:one", types: ["vault"], limit: 10 });
  const inbox: AccountInvitationList = await user.accountInvitations({ limit: 10 });
  const accepted: AccountInvitationMutation = await user.acceptAccountInvitation("invite");
  const manifest: ResourcePayloadManifest = await user.resourcePayload("vault:one", "config");
  const lease: ResourcePayloadAccessLease = await user.accessResourcePayload("vault:one", "config", manifest.payloadVersion);
  const bytes: Buffer = await user.downloadResourcePayload(lease);
  const linked: ResourceLinkSendResult = await user.sendResourceLinks("vault:one", { changes: [{ action: "grant", relation: "member", subject: "user:bob" }] });
  const collaborators: ResourceCollaboratorList = await user.resourceCollaborators("vault:one", { view: "effective" });
  const resources: ResourceSearchList = await user.searchResources({ filters: { collaborator: { subjects: ["user:bob"] } } });
  const e2ee: OrganizationE2EEPolicy = await user.organizationE2EEPolicy("organization:one");
  const guestPolicy: ResourceCollaborationPolicyMutation = await user.setResourceCollaborationPolicy("vault:one", { guests: { allowed: false } });
  return { directory, inbox, accepted, manifest, bytes, linked, collaborators, resources, e2ee, guestPolicy };
}

const options: ClientOptions = { host: "localhost", port: 7420, reconnect: false };
const clientType: typeof LotorClient = LotorClient;
const controlClientType: typeof LotorControlClient = LotorControlClient;
const verifierType: typeof GatewayAssertionVerifier = GatewayAssertionVerifier;
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
void controlClientType;
void verifierType;
void resolver;
void ownershipAddress(ownership);
`);
  writeFileSync(join(consumer, "runtime.mjs"), `
import assert from "node:assert/strict";
import * as sdk from "@lotor.dev/sdk";

assert.equal(typeof sdk.LotorClient, "function");
assert.equal(typeof sdk.LotorControlClient, "function");
assert.equal(typeof sdk.LotorResourceClient, "function");
assert.equal(typeof sdk.LotorResourceClient.prototype.exchangeCredential, "function");
assert.equal(typeof sdk.LotorResourceClient.prototype.preflightExecution, "function");
assert.equal(typeof sdk.LotorResourceClient.prototype.commitExecution, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.preflightResourceLinks, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.commitResourceLinks, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.resourceCollaborators, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.searchResources, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.organizationE2EEPolicy, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.configureOrganizationE2EE, "function");
assert.equal(typeof sdk.LotorControlClient.prototype.setResourceCollaborationPolicy, "function");
assert.equal(typeof sdk.protectProviderRequest, "function");
assert.equal(typeof sdk.openProviderResponse, "function");
assert.equal(typeof sdk.GatewayAssertionVerifier, "function");
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
