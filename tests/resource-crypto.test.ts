import assert from "node:assert/strict";
import test from "node:test";
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { protectProviderRequest, openProviderResponse, type ResourceExecutionPreflight, type ResourceExecutionAuthorization } from "../src/index.js";

const key = Buffer.alloc(32, 7);
const body = Buffer.from("secret request");
const aad = Buffer.from("command-bound-associated-data");
const plan: ResourceExecutionPreflight = {
  token: "capability", requestFingerprint: "b".repeat(64), method: "POST", path: "/chat", contentType: "application/json",
  requestBodyDigest: createHash("sha256").update(body).digest("hex"), requestBodySize: body.length,
  resource: "integration:slack", resourceRevision: 2, lifecycleGeneration: 1, catalogSnapshotId: "snapshot", catalogEntryId: "entry",
  catalogEntryRevision: "revision", policyRevision: "policy", payloadSlot: "provider_credential", payloadVersion: 1,
  payloadRepresentation: "encrypted-envelope-v1", credentialVersion: 1, executionMode: "managed", expiresAt: 123,
  keyResource: "organization:acme", keyVersion: 1, responsePolicyRef: "encrypt_all", requestAAD: aad.toString("base64url"),
};

function response(): ResourceExecutionAuthorization {
  const responseAAD = Buffer.from(`lotor-provider-response-v1\0${createHash("sha256").update(aad).digest("hex")}\0${200}`);
  const nonce = Buffer.alloc(12, 1);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(responseAAD);
  const plaintext = JSON.stringify({ status: 200, headers: { "Content-Type": "application/json" }, body: body.toString("base64url") });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { status: "completed", requestFingerprint: plan.requestFingerprint, resource: plan.resource, catalogEntryId: plan.catalogEntryId,
    payloadSlot: plan.payloadSlot, payloadVersion: plan.payloadVersion, payloadRepresentation: plan.payloadRepresentation,
    executionMode: plan.executionMode, expiresAt: plan.expiresAt, providerStatus: 200,
    protectedResponse: Buffer.from(JSON.stringify({ nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), aad_hash: createHash("sha256").update(responseAAD).digest("hex") })).toString("base64url") };
}

test("provider request encryption uses the Go envelope contract and fresh nonces", () => {
  const protectedRequest = protectProviderRequest(key, plan, { body, headers: { Accept: "application/json" } });
  assert.notEqual(protectedRequest, protectProviderRequest(key, plan, { body }));
  const envelope = JSON.parse(Buffer.from(protectedRequest, "base64url").toString());
  assert.equal(envelope.aad_hash, createHash("sha256").update(aad).digest("hex"));
  const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(-16));
  const plaintext = JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString());
  assert.equal(plaintext.body, body.toString("base64url"));
  assert.deepEqual(plaintext.headers, { Accept: "application/json", "Content-Type": "application/json" });
});

test("provider request encryption rejects changed body, raw mode, unsafe headers and invalid keys", () => {
  assert.throws(() => protectProviderRequest(key, plan, { body: Buffer.from("different") }));
  assert.throws(() => protectProviderRequest(key, { ...plan, payloadRepresentation: "raw" }, { body }));
  assert.throws(() => protectProviderRequest(Buffer.alloc(16), plan, { body }));
  assert.throws(() => protectProviderRequest(key, { ...plan, requestAAD: "%%%" }, { body }));
  const unsafeHeaders: Array<Record<string, string>> = [{ Authorization: "secret" }, { Accept: "bad\r\nheader" }, { Accept: "a".repeat(8193) }];
  for (const headers of unsafeHeaders) {
    assert.throws(() => protectProviderRequest(key, plan, { body, headers }));
  }
  assert.throws(() => protectProviderRequest(key, plan, { body: Buffer.alloc((1 << 20) + 1) }));
});

test("provider response authenticates status and complete execution binding", () => {
  const authorization = response();
  assert.deepEqual(openProviderResponse(key, plan, authorization), { status: 200, headers: { "Content-Type": "application/json" }, body });
  for (const change of [{ resource: "integration:other" }, { expiresAt: 999 }, { requestFingerprint: "c".repeat(64) }, { providerStatus: 201 }, { payloadVersion: 2 }]) {
    assert.throws(() => openProviderResponse(key, plan, { ...authorization, ...change }));
  }
  assert.throws(() => openProviderResponse(Buffer.alloc(32, 8), plan, authorization));
  const envelope = JSON.parse(Buffer.from(authorization.protectedResponse!, "base64url").toString());
  const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
  ciphertext[0] ^= 1;
  envelope.ciphertext = ciphertext.toString("base64url");
  assert.throws(() => openProviderResponse(key, plan, { ...authorization, protectedResponse: Buffer.from(JSON.stringify(envelope)).toString("base64url") }));
});
