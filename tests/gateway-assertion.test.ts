import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import {
  GatewayAssertionError,
  GatewayAssertionVerifier,
  gatewayAssertionMiddleware,
  type GatewayAssertionAuthority,
  type GatewayAssertionClaims,
  type GatewayAssertionRequest,
} from "../src/gateway-assertion.js";

interface GoldenFixture {
  public_key_spki_pem: string;
  public_key_raw_base64url: string;
  assertion: string;
  claims: GatewayAssertionClaims;
  request: {
    method: string;
    path: string;
    raw_query: string;
    body_base64url: string;
    idempotency_key: string;
  };
  now: number;
}

const fixture = JSON.parse(readFileSync(
  new URL("./testdata/gateway_assertion_v1.json", import.meta.url), "utf8",
)) as GoldenFixture;

function authority(claims = fixture.claims): GatewayAssertionAuthority {
  return {
    issuer: claims.iss, audience: claims.aud, tenantId: claims.tenant_id,
    applicationId: claims.application_id, environmentId: claims.environment_id,
    bindingId: claims.binding_id, routeId: claims.route_id, routePin: claims.route_pin,
    gatewayPlacementId: claims.gateway_placement_id, gatewayOwnershipEpoch: claims.gateway_ownership_epoch,
    runtimePlacementId: claims.runtime_placement_id, runtimeOwnershipEpoch: claims.runtime_ownership_epoch,
    operation: claims.operation, configurationVersion: claims.configuration_version,
    bindingActivationEpoch: claims.binding_activation_epoch,
  };
}

function request(): GatewayAssertionRequest {
  return {
    method: fixture.request.method, path: fixture.request.path, rawQuery: fixture.request.raw_query,
    body: Buffer.from(fixture.request.body_base64url, "base64url"),
    idempotencyKey: fixture.request.idempotency_key,
  };
}

function verifier(overrides: Partial<ConstructorParameters<typeof GatewayAssertionVerifier>[0]> = {}) {
  return new GatewayAssertionVerifier({
    keys: { [fixture.claims.kid]: Buffer.from(fixture.public_key_raw_base64url, "base64url") },
    authority: authority(), now: () => new Date(fixture.now * 1000), ...overrides,
  });
}

test("verifies the cross-language golden assertion", async () => {
  const claims = await verifier().verify(fixture.assertion, request());
  assert.equal(claims.request_id, "request-golden-1");
  await assert.rejects(
    verifier().verify(fixture.assertion, { ...request(), body: Buffer.from("tampered") }),
    (error) => error instanceof GatewayAssertionError && error.code === "rejected",
  );
  await assert.rejects(
    verifier({ authority: { ...authority(), bindingActivationEpoch: 8 } }).verify(fixture.assertion, request()),
    /gateway assertion rejected/u,
  );
});

test("fails closed when one-time replay storage is unavailable", async () => {
  const [, encodedBody] = fixture.assertion.split(".");
  const claims = JSON.parse(Buffer.from(encodedBody!, "base64url").toString("utf8")) as GatewayAssertionClaims;
  claims.replay_eligible = false;
  delete claims.idempotency_key_sha256;
  const body = Buffer.from(JSON.stringify(claims));
  const seed = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1));
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der", type: "pkcs8",
  });
  const changed = `v1.${body.toString("base64url")}.${sign(null, body, privateKey).toString("base64url")}`;
  await assert.rejects(
    verifier().verify(changed, { ...request(), idempotencyKey: undefined }),
    (error) => error instanceof GatewayAssertionError && error.code === "replay_unavailable",
  );

  let consumed = false;
  const replayVerifier = verifier({ replay: { consume: () => !consumed && (consumed = true) } });
  await replayVerifier.verify(changed, { ...request(), idempotencyKey: undefined });
  await assert.rejects(replayVerifier.verify(changed, { ...request(), idempotencyKey: undefined }), /rejected/u);
  assert.equal(consumed, true);
});

test("middleware requires an independent origin boundary and strips the assertion", async (t) => {
  let called = false;
  const handler = gatewayAssertionMiddleware({
    verifier: verifier(), maxBodyBytes: 1024,
    authenticateOrigin: (incoming) => incoming.headers["x-private-origin"] === "verified",
  }, (_incoming, response, context) => {
    called = true;
    assert.equal(_incoming.headers["x-lotor-assertion"], undefined);
    assert.equal(context.claims.request_id, "request-golden-1");
    assert.equal(context.body.toString(), "opaque-encrypted-payload");
    response.writeHead(204).end();
  });
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  t.after(() => server.close());
  const address = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${address.port}${fixture.request.path}?${fixture.request.raw_query}`;
  const headers = {
    "X-Lotor-Assertion": fixture.assertion,
    "Idempotency-Key": fixture.request.idempotency_key,
  };
  let response = await fetch(url, { method: "POST", headers, body: "opaque-encrypted-payload" });
  assert.equal(response.status, 401);
  assert.equal(called, false);
  response = await fetch(url, {
    method: "POST", headers: { ...headers, "X-Private-Origin": "verified" }, body: "opaque-encrypted-payload",
  });
  assert.equal(response.status, 204);
  assert.equal(called, true);
});
