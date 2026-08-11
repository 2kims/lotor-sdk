import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  OwnershipResolver, verifyOwnership, type Ownership, type OwnershipScope,
} from "../src/ownership.js";

test("ownership verification rejects tampering and redirect loops", () => {
  const keys = generateKeyPairSync("ed25519");
  const der = keys.publicKey.export({ format: "der", type: "spki" });
  const publicKey = der.subarray(der.length - 32);
  const scope: OwnershipScope = {
    tenantId: "tnt", applicationId: "app", environmentId: "env",
  };
  const nowMs = 1_800_000_000_000;
  const keyId = createHash("sha256").update(publicKey).digest().subarray(0, 8).toString("hex");
  const assertion = (
    owner: string, epoch: number, endpoint: string,
  ): Ownership => {
    const value: Ownership = {
      tenant_id: "tnt", application_id: "app", environment_id: "env",
      endpoint, owner_instance_id: owner, ownership_epoch: epoch,
      issued_at: nowMs * 1000, expires_at: nowMs * 1000 + 30_000_000,
      version: 1, key_id: keyId, signature: "",
    };
    const payload = [
      value.version, value.tenant_id, value.application_id, value.environment_id,
      value.endpoint, value.owner_instance_id, value.ownership_epoch, value.issued_at,
      value.expires_at, value.key_id,
    ].join("\0");
    value.signature = sign(null, Buffer.from(payload), keys.privateKey).toString("base64url");
    return value;
  };
  const prior = assertion("old", 4, "lwp://old.internal:7420");
  const moved = assertion("new", 5, "lwp://new.internal:7420");
  verifyOwnership(prior, scope, publicKey, nowMs * 1000);
  const resolver = new OwnershipResolver({
    controlUrl: "https://control.test", apiKey: "key", scope, publicKey, now: () => nowMs,
  });
  assert.equal(resolver.acceptMoved(JSON.stringify(moved), prior).ownership_epoch, 5);
  assert.throws(() => resolver.acceptMoved(JSON.stringify(moved), moved), /did not advance/);
  const tampered = { ...moved, endpoint: "lwp://attacker.internal:7420" };
  assert.throws(() => resolver.acceptMoved(JSON.stringify(tampered), prior), /verification failed/);
});
