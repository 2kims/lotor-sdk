import assert from "node:assert/strict";
import test from "node:test";
import { LotorResourceClient, LotorControlError } from "../src/index.js";

const options = { baseUrl: "https://api.lotor.test", clientId: "app", publishableKey: "pk_test", resourceCredential: "lrc_test" };
const input = { method: "POST", path: "/chat", contentType: "application/json", requestBodyDigest: "a".repeat(64), requestBodySize: 2 };
const preflight = { method: "POST", path: "/chat", content_type: "application/json", request_body_digest: input.requestBodyDigest, request_body_size: 2,
  request_fingerprint: "b".repeat(64), resource: "integration:slack", resource_revision: 2, lifecycle_generation: 1,
  catalog_snapshot_id: "snapshot", catalog_entry_id: "entry", catalog_entry_revision: "revision", policy_revision: "policy",
  payload_slot: "provider_credential", payload_version: 1, payload_representation: "raw", credential_version: 1, execution_mode: "raw", expires_at: 123 };
const authorization = { status: "authorized", request_fingerprint: preflight.request_fingerprint, resource: preflight.resource,
  catalog_entry_id: "entry", payload_slot: "provider_credential", payload_version: 1, payload_representation: "raw", execution_mode: "raw", expires_at: 123 };

test("execution preflight and commit preserve one capability and workload authority", async () => {
  let calls = 0;
  const client = new LotorResourceClient({ ...options, fetch: async (url, init) => {
    calls++;
    const headers = new Headers(init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer lrc_test");
    assert.equal(headers.get("X-Lotor-Secret-Key"), null);
    assert.equal(init?.credentials, "omit");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.method, "POST");
    if (calls === 1) {
      assert.equal(headers.get("Lotor-Execution-Token"), null);
      assert.ok(String(url).endsWith("/resources/integration%3Aslack/executions/preflight"));
      assert.deepEqual(JSON.parse(String(init?.body)), { method: "POST", path: "/chat", content_type: "application/json", request_body_digest: input.requestBodyDigest, request_body_size: 2 });
      return Response.json(preflight, { headers: { "Lotor-Execution-Token": "one-capability" } });
    }
    assert.ok(String(url).endsWith("/executions/commit"));
    assert.equal(headers.get("Lotor-Execution-Token"), "one-capability");
    assert.deepEqual(JSON.parse(String(init?.body)), { request_fingerprint: preflight.request_fingerprint });
    return Response.json(authorization);
  } });
  const plan = await client.preflightExecution(preflight.resource, input);
  assert.equal(plan.credentialVersion, 1);
  assert.equal(plan.catalogSnapshotId, "snapshot");
  assert.equal((await client.commitExecution(preflight.resource, plan)).status, "authorized");
  assert.equal(calls, 2);
});

test("execution rejects missing tokens, malformed replies and changed command bindings", async () => {
  for (const change of [{ resource: "integration:other" }, { request_body_digest: "c".repeat(64) }, { request_body_size: -1 }, { payload_version: 0 }, { execution_mode: "unknown" }, { catalog_snapshot_id: undefined }]) {
    const client = new LotorResourceClient({ ...options, fetch: async () => Response.json({ ...preflight, ...change }, { headers: { "Lotor-Execution-Token": "capability" } }) });
    await assert.rejects(client.preflightExecution(preflight.resource, input));
  }
  const missing = new LotorResourceClient({ ...options, fetch: async () => Response.json(preflight) });
  await assert.rejects(missing.preflightExecution(preflight.resource, input));
  for (const change of [{ resource: "integration:other" }, { request_fingerprint: "c".repeat(64) }, { expires_at: 999 }, { catalog_entry_id: "other" }, { status: "completed" }]) {
    let calls = 0;
    const client = new LotorResourceClient({ ...options, fetch: async () => ++calls === 1
      ? Response.json(preflight, { headers: { "Lotor-Execution-Token": "capability" } })
      : Response.json({ ...authorization, ...change }) });
    const plan = await client.preflightExecution(preflight.resource, input);
    await assert.rejects(client.commitExecution("integration:other", plan));
    assert.equal(calls, 1);
    await assert.rejects(client.commitExecution(preflight.resource, plan));
    assert.equal(calls, 2);
  }
});

test("encrypted execution retains key context and requires protected request and response", async () => {
  for (const mode of ["managed", "customer_box"]) {
    let calls = 0;
    const client = new LotorResourceClient({ ...options, fetch: async (_url, init) => {
      calls++;
      if (calls === 1) return Response.json({ ...preflight, payload_representation: "encrypted-envelope-v1", execution_mode: mode,
        key_resource: "organization:acme", key_version: 2, response_policy_ref: "encrypt_all", request_aad: "YWJj" }, { headers: { "Lotor-Execution-Token": "capability" } });
      assert.deepEqual(JSON.parse(String(init?.body)), { request_fingerprint: preflight.request_fingerprint, protected_request: "protected-request", response_policy_ref: "encrypt_all" });
      return Response.json({ ...authorization, status: "completed", payload_representation: "encrypted-envelope-v1", execution_mode: mode, provider_status: 200, protected_response: "protected-response" });
    } });
    const plan = await client.preflightExecution(preflight.resource, input);
    assert.equal(plan.keyResource, "organization:acme");
    assert.equal(plan.requestAAD, "YWJj");
    await assert.rejects(client.commitExecution(preflight.resource, plan));
    assert.equal(calls, 1);
    const response = await client.commitExecution(preflight.resource, plan, { protectedRequest: "protected-request", responsePolicyRef: "encrypt_all" });
    assert.equal(response.providerStatus, 200);
    assert.equal(response.protectedResponse, "protected-response");
  }
});

test("execution denials are single attempts and raw requests reject encryption fields", async () => {
  for (const status of [401, 403, 409, 503]) {
    let calls = 0;
    let denied = false;
    const client = new LotorResourceClient({ ...options, fetch: async () => {
      calls++;
      return denied ? Response.json({ code: "denied" }, { status }) : Response.json(preflight, { headers: { "Lotor-Execution-Token": "capability" } });
    } });
    const plan = await client.preflightExecution(preflight.resource, input);
    await assert.rejects(client.commitExecution(preflight.resource, plan, { protectedRequest: "unexpected" }));
    assert.equal(calls, 1);
    denied = true;
    for (const operation of [() => client.preflightExecution(preflight.resource, input), () => client.commitExecution(preflight.resource, plan)]) {
      const before: number = calls;
      await assert.rejects(operation(), error => error instanceof LotorControlError && error.status === status);
      assert.equal(calls, before + 1);
    }
  }
});
