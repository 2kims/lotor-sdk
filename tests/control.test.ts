import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import { LotorControlClient } from "../src/index.js";

const operation = { id: "op_1", kind: "resource_move", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "a".repeat(64), created_at: 1, updated_at: 1 };

test("SCIM directory setup preserves delegated authority, retries and pagination", async () => {
  const directory = { id: "res_directory", resource: "directory:acme", organization: "organization:acme", credential_resource: "api_key:scim", status: "disabled", revision: 1, base_url: "https://api.lotor.test/scim/v2/directories/res_directory" };
  const calls: { url: string; init: RequestInit }[] = [];
  let response: unknown = directory, status = 200;
  const app = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init = {}) => {
    calls.push({ url: String(url), init });
    assert.equal(new Headers(init.headers).get("Authorization"), "Bearer alice");
    assert.equal(new Headers(init.headers).get("X-Lotor-Secret-Key"), "secret");
    return Response.json(response, { status });
  } });
  const input = { directoryResource: "directory:acme", credentialResource: "api_key:scim", expectedResourceRevision: 1, expectedLifecycleGeneration: 2 };
  await assert.rejects(app.createSCIMDirectory("organization:acme", input, "setup-once"), /forUser/);
  await assert.rejects(app.scimDirectory("organization:acme", "res_directory"), /forUser/);
  await assert.rejects(app.updateSCIMDirectory("organization:acme", "res_directory", { enabled: true, expectedRevision: 1 }, "enable-once"), /forUser/);
  await assert.rejects(app.scimDirectories("organization:acme"), /forUser/);
  assert.equal(calls.length, 0);
  const user = app.forUser("alice");
  const created = await user.createSCIMDirectory("organization:acme", input, "setup-once");
  assert.equal(created.status, "disabled");
  assert.ok(calls[0].url.endsWith("/resources/organization%3Aacme/scim-directories"));
  assert.equal(new Headers(calls[0].init.headers).get("Idempotency-Key"), "setup-once");
  assert.deepEqual(JSON.parse(String(calls[0].init.body)), { directory_resource: "directory:acme", credential_resource: "api_key:scim", expected_resource_revision: 1, expected_lifecycle_generation: 2 });
  assert.deepEqual(await user.scimDirectory("organization:acme", "res_directory"), created);
  response = { ...directory, status: "active", revision: 2 };
  assert.equal((await user.updateSCIMDirectory("organization:acme", "res_directory", { enabled: true, expectedRevision: 1 }, "enable-once")).status, "active");
  assert.equal(calls[2].init.method, "PUT");
  assert.equal(new Headers(calls[2].init.headers).get("Idempotency-Key"), "enable-once");
  assert.deepEqual(JSON.parse(String(calls[2].init.body)), { enabled: true, expected_revision: 1 });
  response = { directories: [directory], next_cursor: "next" };
  assert.deepEqual(await user.scimDirectories("organization:acme", { cursor: "one+two", limit: 1 }), { directories: [created], nextCursor: "next" });
  assert.ok(calls[3].url.endsWith("?cursor=one%2Btwo&limit=1"));
  const before = calls.length;
  await assert.rejects(user.scimDirectories("organization:acme", { limit: 101 }));
  await assert.rejects(user.createSCIMDirectory("organization:acme", { ...input, expectedResourceRevision: 0 }, "setup-once"));
  await assert.rejects(user.updateSCIMDirectory("organization:acme", "res_directory", { enabled: true, expectedRevision: 0 }, "enable-once"));
  await assert.rejects(user.updateSCIMDirectory("organization:acme", "../other", { enabled: true, expectedRevision: 1 }, "enable-once"));
  assert.equal(calls.length, before);
  for (response of [{ ...directory, id: "other" }, { ...directory, secret: "private" }, { ...directory, status: "unknown" }, { ...directory, revision: 0 }]) await assert.rejects(user.scimDirectory("organization:acme", "res_directory"));
  status = 403; response = { error: "private" };
  const beforeDenied = calls.length;
  await assert.rejects(user.scimDirectories("organization:acme"));
  assert.equal(calls.length, beforeDenied + 1);
});

test("organization box lifecycle requires delegated authority and preserves secret-free discovery", async () => {
  let calls = 0, denied = false;
  let status: unknown = { binding_id: "efb_acme", status: "pending", bootstrap_expires_at: 123, challenge: { status: "not_started" } };
  let challenge: unknown = { status: "pending", expires_at: 123 };
  const app = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init = {}) => {
    calls++;
    assert.equal(new Headers(init.headers).get("Authorization"), "Bearer alice");
    assert.equal(new Headers(init.headers).get("X-Lotor-Secret-Key"), "secret");
    assert.ok(String(url).includes("/resources/organization%3Aacme/e2ee/function-bindings"));
    if (denied) return Response.json({}, { status: 403 });
    if (String(url).endsWith("/challenge")) { assert.equal(init.method, "POST"); return Response.json(challenge, { status: 202 }); }
    if (init.method === "POST") return Response.json({ binding_id: "efb_acme", status: "pending", bootstrap_token: "e2ee_bootstrap_once" }, { status: 201 });
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json(String(url).endsWith("/efb_acme") ? status : [status]);
  } });
  await assert.rejects(app.createOrganizationFunctionBinding("organization:acme"), /forUser/);
  await assert.rejects(app.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"), /forUser/);
  assert.equal(calls, 0);
  const client = app.forUser("alice");
  assert.equal((await client.createOrganizationFunctionBinding("organization:acme")).bindingId, "efb_acme");
  assert.deepEqual(await client.organizationFunctionBindings("organization:acme"), [{ bindingId: "efb_acme", status: "pending", bootstrapExpiresAt: 123, challenge: { status: "not_started" } }]);
  assert.deepEqual(await client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"), { status: "pending", expiresAt: 123 });
  for (challenge of [{ status: "ready" }, { status: "pending" }, { status: "unknown" }, { status: "pending", expires_at: 123, connector_token: "secret" }]) {
    await assert.rejects(client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"));
  }
  assert.equal((await client.organizationFunctionBinding("organization:acme", "efb_acme")).status, "pending");
  await client.revokeOrganizationFunctionBinding("organization:acme", "efb_acme");
  status = { binding_id: "efb_other", status: "active" };
  await assert.rejects(client.organizationFunctionBinding("organization:acme", "efb_acme"));
  status = { binding_id: "efb_acme", status: "pending", connector_token: "secret" };
  await assert.rejects(client.organizationFunctionBindings("organization:acme"));
  denied = true;
  const before = calls;
  await assert.rejects(client.createOrganizationFunctionBinding("organization:acme"));
  assert.equal(calls, before + 1);
  await assert.rejects(client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"));
  assert.equal(calls, before + 2);
});

test("payload rewrap preserves key fences and deletion stays distinct from completion", async () => {
  const input = { payloadVersion: 1, expectedWrapRevision: 0, keyBindingRef: "organization:acme", previousKeyVersion: 1, keyVersion: 2, resourceRevision: 3, lifecycleGeneration: 1 };
  let body: Record<string, unknown> = {};
  let calls = 0;
  let denied = false;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init) => {
    calls++;
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer alice");
    if (denied) return Response.json({}, { status: 403 });
    if (String(url).endsWith("/rewraps")) {
      body = JSON.parse(String(init?.body));
      return Response.json({ resource: "vault:one", slot: "config", payload_version: 1, wrap_revision: 1, previous_key_version: 1, key_version: 2, resource_revision: 3, lifecycle_generation: 1, key_binding_ref: input.keyBindingRef, wrapped_payload_key: "wrapped", aad_hash: "hash", rewrapper_subject: "alice", rewrapper_key_id: "key" });
    }
    assert.equal(init?.method, "DELETE");
    assert.equal(new Headers(init?.headers).get("Idempotency-Key"), "delete-once");
    return Response.json({ resource: "vault:one", slot: "config", payload_version: 1, state: "deleting", idempotent: false });
  } }).forUser("alice");
  assert.equal((await client.rewrapResourcePayload("vault:one", "config", input)).keyVersion, 2);
  assert.equal(body.wrapped_payload_key, undefined);
  assert.equal(body.expected_wrap_revision, 0);
  await client.rewrapResourcePayload("vault:one", "config", { ...input, wrappedPayloadKey: "browser-wrap", rewrapperSubject: "alice", rewrapperKeyId: "key", rewrapReceipt: "receipt" });
  assert.equal(body.rewrap_receipt, "receipt");
  assert.equal((await client.deleteResourcePayload("vault:one", "config", "delete-once")).state, "deleting");
  const beforeDenied = calls;
  denied = true;
  await assert.rejects(client.rewrapResourcePayload("vault:one", "config", input));
  await assert.rejects(client.deleteResourcePayload("vault:one", "config", "delete-once"));
  assert.equal(calls, beforeDenied + 2);
});

test("payload writes carry the upload capability only to commit and preserve custody fields", async () => {
  const upload = { resource: "vault:one", slot: "config", payload_version: 1, expected_payload_version: 0, upload_url: "https://objects.test/upload", upload_method: "PUT", required_headers: { "Content-Type": "application/octet-stream" }, expires_at: 99 };
  const input = { schemaId: "avault.config.v1", representation: "raw" as const, expectedPayloadVersion: 0, objectDigest: "a".repeat(64), objectSize: 3, resourceRevision: 1, lifecycleGeneration: 1 };
  let token: string | undefined = "upload-capability";
  let calls = 0;
  let lastBody: Record<string, unknown> = {};
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init) => {
    calls++;
    const headers = new Headers(init?.headers);
    if (String(url) === upload.upload_url) {
      assert.equal(init?.method, "PUT");
      assert.equal(init?.credentials, "omit");
      assert.equal(init?.redirect, "error");
      assert.deepEqual([...headers.entries()], [["content-type", "application/octet-stream"]]);
      return new Response(null, { status: 200 });
    }
    assert.equal(headers.get("Authorization"), "Bearer alice");
    lastBody = JSON.parse(String(init?.body));
    if (String(url).endsWith("/uploads")) {
      assert.equal(headers.get("Lotor-Payload-Token"), null);
      return Response.json(upload, { headers: token ? { "Lotor-Payload-Token": token } : {} });
    }
    assert.ok(String(url).endsWith("/commits"));
    assert.equal(headers.get("Lotor-Payload-Token"), "upload-capability");
    assert.deepEqual(lastBody, { expected_payload_version: 0 });
    return Response.json({ resource: "vault:one", slot: "config", schema_id: input.schemaId, representation: "raw", payload_version: 1, object_digest: input.objectDigest, object_size: 3, resource_revision: 1, lifecycle_generation: 1, state: "committed", committed_at: 1 });
  } }).forUser("alice");
  const intent = await client.createResourcePayloadUpload("vault:one", "config", input);
  assert.equal(intent.token, token);
  assert.equal(lastBody.expected_payload_version, 0);
  assert.equal(lastBody.encryption_suite, undefined);
  await client.uploadResourcePayloadObject(intent, new Uint8Array([1, 2, 3]));
  assert.equal((await client.commitResourcePayload("vault:one", "config", intent)).state, "committed");
  await client.createResourcePayloadUpload("vault:one", "config", { ...input, representation: "encrypted-envelope-v1", encryptionSuite: "AES-256-GCM", keyBindingRef: "organization:acme", keyVersion: 1, wrappedPayloadKey: "wrapped", aadHash: "hash", encryptorSubject: "alice", encryptorKeyId: "key", encryptionReceipt: "receipt" });
  assert.equal(lastBody.encryption_receipt, "receipt");
  assert.equal(lastBody.key_binding_ref, "organization:acme");
  token = undefined;
  await assert.rejects(client.createResourcePayloadUpload("vault:one", "config", input), /token/);
  const beforeInvalid = calls;
  await assert.rejects(client.commitResourcePayload("vault:other", "config", intent));
  await assert.rejects(client.createResourcePayloadUpload("vault:one", "config", { ...input, expectedPayloadVersion: -1 }));
  for (const name of ["Authorization", "Cookie", "X-Lotor-Secret-Key", "Lotor-Payload-Token"]) await assert.rejects(client.uploadResourcePayloadObject({ ...intent, requiredHeaders: { [name]: "secret" } }, new Uint8Array([1])));
  assert.equal(calls, beforeInvalid);
});

test("payload downloads verify bytes without forwarding Control credentials", async () => {
  const bytes = Buffer.from("stored ciphertext");
  const lease = { resource: "vault:one", slot: "config", payloadVersion: 1, representation: "raw" as const, objectDigest: createHash("sha256").update(bytes).digest("hex"), objectSize: bytes.length, downloadUrl: "https://objects.test/signed?cap=example", downloadMethod: "GET" as const, expiresAt: 9999999999, audience: "alice", resourceRevision: 1, lifecycleGeneration: 1 };
  let calls = 0;
  let body = bytes;
  let status = 200;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init) => {
    calls++;
    assert.equal(String(url), lease.downloadUrl);
    assert.equal(init?.method, "GET");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.credentials, "omit");
    assert.deepEqual([...new Headers(init?.headers).entries()], []);
    return new Response(body, { status });
  } }).forUser("alice");
  assert.deepEqual(await client.downloadResourcePayload(lease), bytes);
  await assert.rejects(client.downloadResourcePayload({ ...lease, objectDigest: "0".repeat(64) }), /digest/);
  body = Buffer.from("short");
  await assert.rejects(client.downloadResourcePayload(lease), /size/);
  body = Buffer.alloc(bytes.length + 1);
  await assert.rejects(client.downloadResourcePayload(lease), /size/);
  status = 403;
  await assert.rejects(client.downloadResourcePayload(lease), /403/);
  const beforeInvalid = calls;
  for (const downloadUrl of ["http://objects.test/plain", "file:///etc/passwd", "https://user:pass@objects.test/file", "https://objects.test/file#fragment"]) await assert.rejects(client.downloadResourcePayload({ ...lease, downloadUrl }));
  for (const objectSize of [-1, 1.5, 64 * 1024 * 1024 + 1]) await assert.rejects(client.downloadResourcePayload({ ...lease, objectSize }));
  await assert.rejects(client.downloadResourcePayload({ ...lease, objectDigest: "invalid" }));
  await assert.rejects(client.downloadResourcePayload(lease, { signal: AbortSignal.abort() }));
  assert.equal(calls, beforeInvalid);
});

test("oversized payload streams are cancelled before collecting the full response", async () => {
  let cancelled = false;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(2)); },
    cancel() { cancelled = true; },
  })) });
  await assert.rejects(client.downloadResourcePayload({ resource: "vault:one", slot: "config", payloadVersion: 1, representation: "raw", objectDigest: "0".repeat(64), objectSize: 1, downloadUrl: "https://objects.test/signed", downloadMethod: "GET", expiresAt: 9999999999, audience: "alice", resourceRevision: 1, lifecycleGeneration: 1 }), /size/);
  assert.equal(cancelled, true);
});

test("payload reads preserve delegated authority and validate manifests and leases", async () => {
  const common = { resource: "vault:one", slot: "config", payload_version: 2, representation: "raw", object_digest: "a".repeat(64), object_size: 12, resource_revision: 3, lifecycle_generation: 1 };
  const manifest = { ...common, schema_id: "avault.config.v1", state: "committed", committed_at: 1 };
  const lease = { ...common, download_url: "https://objects.test/signed", download_method: "GET", expires_at: 9, audience: "alice" };
  let response: unknown = manifest;
  let calls = 0;
  let last: RequestInit | undefined;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (url, init) => {
    calls++;
    last = init;
    assert.ok(String(url).includes("/resources/vault%3Aone/payloads/config"));
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer alice");
    return response === null ? Response.json({}, { status: 403 }) : Response.json(response);
  } }).forUser("alice");
  assert.equal((await client.resourcePayload("vault:one", "config")).representation, "raw");
  response = { ...manifest, representation: "encrypted-envelope-v1", encryption_suite: "AES-256-GCM", key_binding_ref: "organization:acme", key_version: 1, wrapped_payload_key: "wrapped", aad_hash: "hash", encryptor_subject: "alice", encryptor_key_id: "key" };
  assert.equal((await client.resourcePayload("vault:one", "config")).representation, "encrypted-envelope-v1");
  for (const invalid of [{ ...manifest, state: "ready" }, { ...manifest, object_size: "12" }, { ...manifest, representation: "unknown" }, { ...manifest, representation: "encrypted-envelope-v1" }]) {
    response = invalid;
    await assert.rejects(client.resourcePayload("vault:one", "config"));
  }
  response = lease;
  assert.equal((await client.accessResourcePayload("vault:one", "config", 2)).payloadVersion, 2);
  assert.equal(last?.method, "POST");
  assert.deepEqual(JSON.parse(String(last?.body)), { payload_version: 2 });
  await client.accessResourcePayload("vault:one", "config");
  assert.deepEqual(JSON.parse(String(last?.body)), {});
  response = { ...lease, download_method: "POST" };
  await assert.rejects(client.accessResourcePayload("vault:one", "config"));
  const beforeInvalid = calls;
  await assert.rejects(client.accessResourcePayload("vault:one", "config", -1));
  await assert.rejects(client.resourcePayload("vault:one", ""));
  assert.equal(calls, beforeInvalid);
  response = null;
  await assert.rejects(client.resourcePayload("vault:one", "config"));
  assert.equal(calls, beforeInvalid + 1);
});

test("durable operations reject malformed state and preserve terminal results", async () => {
  let response: unknown = operation;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => Response.json(response) }).forUser("member");
  for (const status of ["pending", "running", "succeeded", "failed", "cancelled"]) {
    response = { ...operation, status };
    const result = await client.operation("op_1");
    assert.equal(result.status, status);
    assert.equal(result.targetId, "vault:one");
  }
  for (const invalid of [
    { ...operation, target_id: undefined }, { ...operation, id: null },
    { ...operation, status: "ready" }, { ...operation, kind: "unknown" },
    { ...operation, target_kind: "account" }, { ...operation, request_hash: null },
    { ...operation, created_at: "1" }, { ...operation, updated_at: -1 },
    { ...operation, error_code: 5 },
  ]) {
    response = invalid;
    await assert.rejects(client.operation("op_1"));
  }
});

test("portal sessions use delegated organization authority without fallback", async () => {
  let calls = 0;
  const user = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (input, init) => {
    calls++;
    assert.ok(String(input).endsWith("/billing/portal-sessions"));
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer alice");
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(String(init?.body)), { organization_id: "org_acme", return_url: "https://avault.test/settings" });
    return calls === 1 ? Response.json({ id: "portal", url: "https://billing.stripe.com/session/test" }) : Response.json({}, { status: 403 });
  } }).forUser("alice");
  const input = { organizationId: "org_acme", returnUrl: "https://avault.test/settings" };
  assert.equal((await user.createPortalSession(input)).id, "portal");
  await assert.rejects(user.createPortalSession(input));
  await assert.rejects(user.createPortalSession({ ...input, returnUrl: "javascript:alert(1)" }));
  assert.equal(calls, 2);
});

test("portal return URLs support local development but reject remote HTTP and credentials", async () => {
  let calls = 0;
  const user = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => {
    calls++;
    return Response.json({ id: "portal", url: "https://billing.stripe.com/session/test" });
  } }).forUser("alice");
  for (const returnUrl of ["http://localhost:3300/settings", "http://127.0.0.1:3300/settings", "http://[::1]:3300/settings"]) await user.createPortalSession({ organizationId: "org_acme", returnUrl });
  for (const returnUrl of ["http://avault.test/settings", "https://user:pass@avault.test/settings", "https://avault.test/settings?token=secret", "https://avault.test/settings#fragment"]) await assert.rejects(user.createPortalSession({ organizationId: "org_acme", returnUrl }));
  assert.equal(calls, 3);
});

test("member directories retain filters, canonical references and delegated authority", async () => {
  const ref = { id: "one", resource: "vault:one", type: "vault", name: "One" };
  const group = { id: "team", resource: "group:team", type: "group", name: "Team", subject_relation: "member" };
  const wire = { ...ref, parent: { ...ref, resource: "project:a/b" }, relations: ["member"], access_state: "pending_encryption", access: { direct: false, paths: [{ type: "group", relation: "member", via: [group] }] } };
  let requests = 0;
  const controller = new AbortController();
  const app = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (input, init) => {
    requests++;
    const url = new URL(String(input));
    assert.equal(url.pathname, "/v1/public/applications/app/me/resources");
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer alice");
    assert.equal(init?.signal, controller.signal);
    assert.equal(url.searchParams.get("parent"), "project:a/b");
    assert.equal(url.searchParams.get("cursor"), "opaque+cursor");
    assert.equal(url.searchParams.get("limit"), "2");
    assert.deepEqual(url.searchParams.getAll("type"), ["vault", "api_key"]);
    assert.deepEqual(url.searchParams.getAll("access_state"), ["active", "pending_encryption"]);
    return requests === 1 ? Response.json({ resources: [wire], next_cursor: null }) : Response.json({}, { status: 403 });
  } });
  const user = app.forUser("alice");
  const options = { parent: "project:a/b", cursor: "opaque+cursor", limit: 2, types: ["vault", "api_key"], accessStates: ["active", "pending_encryption"] as Array<"active" | "pending_encryption">, signal: controller.signal };
  const page = await user.accountResources(options);
  assert.equal(page.nextCursor, null);
  assert.equal(page.resources[0]?.resource, "vault:one");
  assert.equal(page.resources[0]?.parent?.resource, "project:a/b");
  assert.equal(page.resources[0]?.accessState, "pending_encryption");
  assert.equal(page.resources[0]?.access.paths[0]?.via[0]?.subjectRelation, "member");
  await assert.rejects(user.accountResources(options));
  for (const invalid of [{ limit: 0 }, { limit: 101 }, { limit: NaN }, { types: [""] }, { parent: "x".repeat(513) }, { cursor: "x".repeat(2049) }]) await assert.rejects(user.accountResources(invalid));
  controller.abort();
  await assert.rejects(user.accountResources(options));
  assert.equal(requests, 2);
});

test("member directories preserve empty pages and reject malformed projections", async () => {
  const valid = { id: "one", resource: "vault:one", type: "vault", name: "", relations: ["member"], access_state: "active", access: { direct: true, paths: [] } };
  let response: unknown = { resources: [], next_cursor: "next" };
  const user = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async input => {
    assert.equal(new URL(String(input)).search, "");
    return Response.json(response);
  } }).forUser("alice");
  assert.deepEqual(await user.accountResources(), { resources: [], nextCursor: "next" });
  response = { resources: [valid], next_cursor: null };
  assert.equal((await user.accountResources()).resources[0]?.parent, undefined);
  for (const malformed of [{ resources: [] }, { resources: [], next_cursor: 5 },
    ...[{ ...valid, resource: undefined }, { ...valid, access_state: "disabled" }, { ...valid, access: { direct: "true", paths: [] } }, { ...valid, parent: { id: "parent" } }].map(item => ({ resources: [item], next_cursor: null }))]) {
    response = malformed;
    await assert.rejects(user.accountResources());
  }
});

test("generic catalog administration preserves kinds and serializes the inline document", async () => {
  const bodies: Record<string, unknown>[] = [];
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      assert.equal(new Headers(init?.headers).get("X-Lotor-Secret-Key"), "secret");
      assert.equal(new Headers(init?.headers).get("Idempotency-Key"), bodies.length === 1 ? "create" : "import");
      return Response.json(String(input).endsWith("/catalogs") ? { id: "cat", namespace: "policies", catalog_type: "generic", visibility: "application_private", status: "active", created_at: 1 } : { ...operation, kind: "catalog_import" });
    },
  });
  assert.equal((await client.createCatalog({ namespace: "policies", catalogType: "generic", visibility: "application_private" }, "create")).catalogType, "generic");
  assert.equal((await client.importDefinitions("cat", [{ semanticKey: "rule", entryKind: "policy.rule", definition: { allowed: true } }], "import")).kind, "catalog_import");
  assert.equal(bodies[1]?.format, "definitions_v1");
  assert.deepEqual(JSON.parse(String(bodies[1]?.source_document)), { entries: [{ semantic_key: "rule", entry_kind: "policy.rule", definition: { allowed: true } }] });
});

test("delegated discovery retains published snapshot and opaque pagination", async () => {
  const urls: URL[] = [];
  const app = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init) => {
      assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer user");
      const url = new URL(String(input)); urls.push(url);
      if (url.pathname.endsWith("/entries")) return Response.json({ items: [], next_cursor: null, snapshot_id: "snap" });
      return Response.json({ items: [{ id: "cat", namespace: "rules", catalog_type: "generic", visibility: "application_private", discoverable: true, status: "active", published_snapshot_id: "snap", created_at: 1 }], next_cursor: null });
    },
  });
  const user = app.forUser("user");
  assert.equal((await user.availableCatalogs({ limit: 10 })).items[0]?.discoverable, true);
  assert.equal((await user.availableCatalogEntries("cat", { cursor: "opaque+cursor" })).snapshotId, "snap");
  assert.ok(urls[0]?.pathname.endsWith("/me/catalogs"));
  assert.equal(urls[1]?.searchParams.get("cursor"), "opaque+cursor");
});

test("resource reads reject malformed identity and readiness fields", async () => {
  const valid = { id: "row", resource: "vault:one", resource_type: "vault", display_name: "", status: "active", revision: 2, lifecycle_generation: 1,
    encryption: { required: false, status: "not_required" },
  };
  let response: unknown = valid;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => Response.json(response) });
  assert.equal((await client.resource("vault:one")).displayName, "");
  for (const invalid of [
    { ...valid, resource: undefined }, { ...valid, id: null },
    { ...valid, revision: "2" }, { ...valid, lifecycle_generation: -1 },
    { ...valid, status: "unknown" }, { ...valid, principal_subject: 5 },
    { ...valid, encryption: { required: "false", status: "ready" } },
    { ...valid, encryption: { required: false, status: "unknown" } },
    { ...valid, encryption: { required: true, status: "ready", key_scope: "account" } },
    { ...valid, catalog_binding: { resource: "vault:one", snapshot_id: "snap", snapshot_digest: "digest", entry_kinds: ["api.operation"], resource_revision: 2 } },
  ]) {
    response = invalid;
    await assert.rejects(client.resource("vault:one"));
  }
});

test("resource reads preserve principal identity, effective keys and binding references", async () => {
  const wire = { id: "row", resource: "service_account:worker", principal_subject: "resource_principal:global", resource_type: "service_account", display_name: "Worker", status: "active", revision: 2, lifecycle_generation: 1,
    encryption: { required: true, status: "ready", key_scope: "organization", effective_key_resource: "organization:acme", key_resource: "organization:acme", key_version: 3 },
    catalog_binding: { resource: "service_account:worker", catalog_id: "cat", snapshot_id: "snap", snapshot_digest: "digest", entry_kinds: ["api.operation"], resource_revision: 2 },
  };
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => Response.json(wire) });
  const resource = await client.resource(wire.resource);
  assert.equal(resource.principalSubject, "resource_principal:global");
  assert.notEqual(resource.principalSubject, resource.resource);
  assert.equal(resource.encryption.keyResource, "organization:acme");
  assert.equal(resource.encryption.keyVersion, 3);
  assert.equal(resource.catalogBinding?.resource, resource.resource);
  const plain = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => Response.json({ ...wire, principal_subject: undefined, catalog_binding: undefined, encryption: { required: false, status: "not_required" } }) });
  const unencrypted = await plain.resource("vault:one");
  assert.equal(unencrypted.principalSubject, undefined);
  assert.equal(unencrypted.encryption.keyVersion, undefined);
  assert.equal(unencrypted.catalogBinding, undefined);
});

test("resource credentials preserve delegated authority and expose presentations only on issue/rotate", async () => {
  const metadata = { id: "cred/one", resource: "vault:one", issued_to: "service_account:worker", status: "active", display_hint: "ending1234", version: 1, created_at: 100, expires_at: 200, revoke_at: null };
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init = {}) => {
      requests.push({ url: String(input), init });
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), "Bearer user-session");
      assert.equal(headers.get("X-Lotor-Secret-Key"), "secret");
      const item = { ...metadata, credential: "one-time-presentation" };
      return Response.json(init.method === undefined ? { items: [item] } : item);
    },
  }).forUser("user-session");
  const issued = await client.issueResourceCredential("vault:one", { issuedTo: "service_account:worker", expiresAt: 200 }, "issue-1");
  assert.equal(issued.credential, "one-time-presentation");
  assert.equal(issued.issuedTo, "service_account:worker");
  const listed = await client.resourceCredentials("vault:one");
  assert.equal("credential" in listed[0]!, false);
  assert.equal(listed[0]?.expiresAt, 200);
  assert.equal("revokeAt" in listed[0]!, false);
  assert.equal((await client.rotateResourceCredential("vault:one", "cred/one", { revokePreviousAt: 150 }, "rotate-1")).credential, issued.credential);
  assert.equal("credential" in await client.revokeResourceCredential("vault:one", "cred/one", "revoke-1"), false);
  assert.deepEqual(requests.map(r => r.init.method ?? "GET"), ["POST", "GET", "POST", "DELETE"]);
  assert.ok(requests[2]?.url.endsWith("/resources/vault%3Aone/credentials/cred%2Fone/rotate"));
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { issued_to: "service_account:worker", expires_at: 200 });
  assert.deepEqual(JSON.parse(String(requests[2]?.init.body)), { revoke_previous_at: 150 });
  assert.deepEqual(requests.map(r => new Headers(r.init.headers).get("Idempotency-Key")), ["issue-1", null, "rotate-1", "revoke-1"]);
  for (const invalid of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(client.issueResourceCredential("vault:one", { issuedTo: "user:one", expiresAt: invalid }, "bad"));
    await assert.rejects(client.rotateResourceCredential("vault:one", "id", { revokePreviousAt: invalid }, "bad"));
  }
  await assert.rejects(client.revokeResourceCredential("vault:one", "", "bad"));
  await assert.rejects(client.issueResourceCredential("vault:one", { issuedTo: "" }, "bad"));
  assert.equal(requests.length, 4);
});

test("credential denial is not retried and malformed successful replies are rejected", async () => {
  let calls = 0;
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async () => { calls++; return Response.json({}, { status: calls === 1 ? 403 : 200 }); },
  }).forUser("user-session");
  await assert.rejects(client.issueResourceCredential("vault:one", { issuedTo: "user:one" }, "issue"), { status: 403 });
  assert.equal(calls, 1);
  await assert.rejects(client.issueResourceCredential("vault:one", { issuedTo: "user:one" }, "issue"), /invalid credential/);
  assert.equal(calls, 2);
});

test("user-scoped Control client remains isolated and never retries as the application", async () => {
  const authorizations: Array<string | null> = [];
  const application = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "avault_sandbox", secretKey: "test-secret",
    fetch: async (_input, init) => {
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("X-Lotor-Secret-Key"), "test-secret");
      authorizations.push(headers.get("Authorization"));
      return Response.json({ error: "denied" }, { status: 403 });
    },
  });
  const user = application.forUser("user-session");
  for (const client of [user, application, user]) await assert.rejects(client.resource("vault:one"));
  assert.deepEqual(authorizations, ["Bearer user-session", null, "Bearer user-session"]);
  for (const token of ["", " ", "a\nb", "a\rb"]) assert.throws(() => application.forUser(token));
});

test("Control client reads typed catalog entries through an explicit resource binding", async () => {
  const entry = { id: "entry_1", catalog_id: "cat_1", semantic_key: "send", entry_kind: "api.operation", revision_id: "rev_1", revision_digest: "digest", definition: { method: "POST" } };
  const requests: URL[] = [];
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init) => {
      const url = new URL(String(input)); requests.push(url);
      assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer user-session");
      assert.equal(url.searchParams.get("resource"), "vault:one");
      return Response.json(url.pathname.endsWith("/entries/entry_1") ? entry : { items: [entry], next_cursor: "next" });
    },
  }).forUser("user-session");
  const page = await client.resourceCatalogEntries("vault:one", "cat_1", { cursor: "opaque+cursor", limit: 2 });
  assert.equal(page.items[0]?.revisionId, "rev_1");
  assert.equal(page.nextCursor, "next");
  assert.equal(requests[0]?.searchParams.get("cursor"), "opaque+cursor");
  assert.equal(requests[0]?.searchParams.get("limit"), "2");
  assert.equal((await client.resourceCatalogEntry("vault:one", "cat_1", "entry_1")).semanticKey, "send");
  await assert.rejects(client.resourceCatalogEntry("", "cat_1", "entry_1"));
  await assert.rejects(client.resourceCatalogEntries("vault:one", "cat_1", { limit: 101 }));
  assert.equal(requests.length, 2);
});

test("Control client authenticates with only the application secret and preserves lifecycle signatures", async () => {
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const client = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "avault_sandbox", secretKey: "ls_sbx_secret",
    fetch: async (input, init = {}) => {
      requests.push({ url: String(input), init });
      return new Response(JSON.stringify(operation), { status: 202, headers: { "Content-Type": "application/json" } });
    },
  });
  const result = await client.moveResource("vault:one", { parent: "project:two", expectedRevision: 4, expectedLifecycleGeneration: 8 }, "move-1");
  assert.equal(result.id, "op_1");
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/avault_sandbox/resources/vault%3Aone/move");
  const headers = new Headers(requests[0]?.init.headers);
  assert.equal(headers.get("X-Lotor-Secret-Key"), "ls_sbx_secret");
  assert.equal(headers.get("Authorization"), null);
  assert.equal(headers.get("Idempotency-Key"), "move-1");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { expected_revision: 4, expected_lifecycle_generation: 8, parent: "project:two" });
});

test("Control client waits for durable operations with bounds and cancellation", async () => {
  let reads = 0;
  const signals: Array<AbortSignal | null | undefined> = [];
  const client = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "avault_sandbox", secretKey: "test-secret",
    fetch: async (_input, init) => {
      signals.push(init?.signal);
      const status = ++reads === 1 ? "running" : "failed";
      return Response.json({ ...operation, status, error_code: status === "failed" ? "resource_conflict" : undefined });
    },
  });
  const controller = new AbortController();
  const result = await client.waitForOperation("op_1", { signal: controller.signal, intervalMs: 0 });
  assert.equal(result.status, "failed");
  assert.equal(result.errorCode, "resource_conflict");
  assert.deepEqual(signals, [controller.signal, controller.signal]);

  await assert.rejects(client.waitForOperation("op_1", { maxAttempts: 0 }), /maxAttempts/);
  await assert.rejects(client.waitForOperation("op_1", { intervalMs: 60_001 }), /intervalMs/);
  assert.equal(reads, 2);

  let pendingReads = 0;
  const pending = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "avault_sandbox", secretKey: "test-secret",
    fetch: async () => { pendingReads++; return Response.json({ ...operation, status: "pending" }); },
  });
  await assert.rejects(pending.waitForOperation("op_1", { maxAttempts: 2, intervalMs: 0 }), /maxAttempts/);
  assert.equal(pendingReads, 2);

  const delayedAbort = new AbortController();
  const delayed = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "avault_sandbox", secretKey: "test-secret",
    fetch: async () => {
      setTimeout(() => delayedAbort.abort(new Error("stop delay")), 0);
      return Response.json({ ...operation, status: "running" });
    },
  });
  await assert.rejects(delayed.waitForOperation("op_1", { signal: delayedAbort.signal, intervalMs: 60_000 }), /stop delay/);

  const cancelled = new AbortController();
  cancelled.abort(new Error("cancelled"));
  await assert.rejects(client.waitForOperation("op_1", { signal: cancelled.signal }), /cancelled/);
  assert.equal(reads, 2);
});

test("Control client exposes resource type, Catalog, and binding contracts", async () => {
  const requests: string[] = [];
  const client = new LotorControlClient({
    baseUrl: "http://127.0.0.1:8080", clientId: "avault_sandbox", secretKey: "ls_sbx_secret",
    fetch: async (input) => {
      const url = String(input);
      requests.push(url);
      if (url.includes("/resource-types/")) return Response.json({ resource_type: "vault", kind: "container", allowed_parent_types: ["project"], lifecycle: "application", direct_links: true, relations: ["owner"], key_behavior: "configurable", catalog_entry_kinds: ["api.operation"], payload: { storage: "none", slots: [] } });
      return Response.json({ ...operation, kind: "catalog_binding" }, { status: 202 });
    },
  });
  const definition = await client.putResourceType("vault", { resourceType: "vault", kind: "container", allowedParentTypes: ["project"], lifecycle: "application", directLinks: true, relations: ["owner"], keyBehavior: "configurable", catalogEntryKinds: ["api.operation"], payload: { storage: "none", slots: [] } });
  assert.equal(definition.resourceType, "vault");
  assert.equal((await client.bindResourceCatalog("vault:one", { catalogId: "cat_1", snapshotId: "snap_1", entryKinds: ["api.operation"], expectedRevision: 1, expectedLifecycleGeneration: 2 }, "bind-1")).kind, "catalog_binding");
  assert.ok(requests.some(url => url.endsWith("/resource-types/vault")));
  assert.ok(requests.some(url => url.endsWith("/resources/vault%3Aone/catalog-binding")));
});
test("delegated invitation inbox preserves canonical resources and pending encryption", async () => {
  const requests: URL[] = [];
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init) => {
      const url = new URL(String(input)); requests.push(url);
      assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer invitee");
      if (url.pathname.endsWith("/invitations")) {
        assert.equal(url.searchParams.get("cursor"), "opaque+cursor");
        assert.equal(url.searchParams.get("limit"), "2");
        return Response.json({ invitations: [{ id: "invite/one", resource: { id: "one", resource: "vault:one", type: "vault", name: "Vault" }, relation: "member", status: "pending_acceptance", expires_at: 123, encryption_required: true }], next_cursor: null });
      }
      assert.equal(init?.method, "POST");
      assert.equal(init?.body, undefined);
      assert.ok(url.pathname.includes("/invitations/invite%2Fone/"));
      if (requests.length === 4) return Response.json({ error: "denied" }, { status: 403 });
      return Response.json({ id: "invite/one", status: url.pathname.endsWith("/accept") ? "pending_encryption" : "declined" });
    },
  }).forUser("invitee");
  const page = await client.accountInvitations({ cursor: "opaque+cursor", limit: 2 });
  assert.equal(page.invitations[0]?.resource.resource, "vault:one");
  assert.equal(page.invitations[0]?.encryptionRequired, true);
  assert.equal(page.nextCursor, null);
  assert.equal((await client.acceptAccountInvitation("invite/one")).status, "pending_encryption");
  assert.equal((await client.declineAccountInvitation("invite/one")).status, "declined");
  await assert.rejects(client.acceptAccountInvitation("invite/one"), { status: 403 });
  assert.equal(requests.length, 4);
  await assert.rejects(client.acceptAccountInvitation(""));
  await assert.rejects(client.accountInvitations({ limit: 101 }));
  await assert.rejects(client.accountInvitations({ cursor: "x".repeat(2049) }));
  assert.equal(requests.length, 4);
});

test("invitation inbox rejects malformed projections and honors cancellation", async () => {
  let calls = 0;
  let response: unknown = { invitations: [], next_cursor: null };
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async () => { calls++; return Response.json(response); },
  }).forUser("invitee");
  assert.deepEqual(await client.accountInvitations(), { invitations: [], nextCursor: null });
  await assert.rejects(client.accountInvitations({ signal: AbortSignal.abort() }));
  assert.equal(calls, 1);
  const invitation = { id: "invite", resource: { id: "one", resource: "vault:one", type: "vault", name: "" }, relation: "member", status: "pending_approval", expires_at: 123, encryption_required: false };
  response = { invitations: [invitation], next_cursor: "next" };
  assert.equal((await client.accountInvitations()).invitations[0]?.status, "pending_approval");
  for (const invalid of [{ ...invitation, status: "active" }, { ...invitation, encryption_required: "false" }, { ...invitation, expires_at: -1 }, { ...invitation, resource: { id: "one", type: "vault", name: "" } }]) {
    response = { invitations: [invalid], next_cursor: null };
    await assert.rejects(client.accountInvitations());
  }
  response = { id: "invite", status: "ready" };
  await assert.rejects(client.acceptAccountInvitation("invite"));
});

const linkResult = (status: "ready" | "active" = "ready", committable = true) => ({
  resource: "vault:one", status, expires_at: 123, idempotent: false, committable,
  revisions: { customer: "1", graph: "2", policy: "3", identity: "4", billing: "5", seat: "6", key: "7" },
  outcomes: [{ resource: "vault:one", subject: "user:bob", relation: "member", state: status === "active" ? "active" : "pending_encryption", allowed: true }],
  capacity: { scope: "per_organization", before: 1, after: 2, claim: 1, release: 0 },
  billing: { current_quantity: 1, next_cycle_quantity: 2, increase: 1, next_cycle_reduction: 0 },
  invitation_actions: [], key_requirements: [],
  impact: { impacted_resources: ["vault:one"], retained_resources: [], rekey_resources: [] },
});

test("Control client exposes the complete generic resource collaboration workflow", async () => {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  let deniedPreflight = false;
  const app = new LotorControlClient({
    baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret",
    fetch: async (input, init = {}) => {
      const url = new URL(String(input)); calls.push({ url, init });
      assert.equal(new Headers(init.headers).get("X-Lotor-Secret-Key"), "secret");
      assert.equal(new Headers(init.headers).get("Authorization"), "Bearer alice");
      if (url.pathname.endsWith("/link-candidates/search")) return Response.json({ candidates: [{ kind: "user", display_name: "Bob", subject: "user:bob", email: "bob@example.test", link_state: "available", selectable: true }], next_cursor: null });
      if (url.pathname.endsWith("/links/preflight")) return Response.json(linkResult("ready", !deniedPreflight), { headers: { "Lotor-Link-Token": "link-token" } });
      if (url.pathname.endsWith("/links/commit")) {
        assert.equal(new Headers(init.headers).get("Lotor-Link-Token"), "link-token");
        return Response.json(linkResult("active"));
      }
      if (url.pathname.endsWith("/links/link%2Fone")) return Response.json({ id: "link/one", resource: "vault:one", status: "revoked", rekey_required: true, rekey_subjects: ["user:bob"], idempotent: false });
      if (url.pathname.endsWith("/collaborators")) return Response.json({ resource: "vault:one", collaborators: [{ kind: "user", id: "user:bob", display_name: "Bob", relations: ["member"], status: "active", access: { direct: true, paths: [{ type: "direct", relation: "member", link_id: "link/one", via: [] }] } }], next_cursor: "next" });
      if (url.pathname.endsWith("/resources/search")) return Response.json({ resources: [{ resource: "vault:one", resource_type: "vault", display_name: "Vault", status: "active", parent: { resource: "project:one", resource_type: "project", display_name: "Project" }, collaborator_matches: [] }], next_cursor: null });
      return Response.json({ error: "not found" }, { status: 404 });
    },
  });
  await assert.rejects(app.searchResources(), /forUser/);
  assert.equal(calls.length, 0);
  const client = app.forUser("alice");

  const candidates = await client.searchResourceLinkCandidates("vault:one", { query: "bob", relation: "member", kinds: ["user"], limit: 2, cursor: "candidate+cursor" });
  assert.equal(candidates.candidates[0]?.subject, "user:bob");
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { query: "bob", relation: "member", kinds: ["user"], limit: 2, cursor: "candidate+cursor" });

  const changes = [{ action: "grant" as const, relation: "member", subject: "user:bob", provisioning: "existing_only" as const, delivery: "none" as const }];
  const preflight = await client.preflightResourceLinks("vault:one", changes);
  assert.equal(preflight.token, "link-token");
  assert.equal(preflight.result.committable, true);
  assert.deepEqual(JSON.parse(String(calls[1]?.init.body)), { changes: [{ action: "grant", relation: "member", subject: "user:bob", provisioning: "existing_only", delivery: "none" }] });
  const envelope = { manifestItemId: "item", encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM" as const, ciphertext: "ciphertext", aadHash: "hash", issuer: "user:owner", issuerKeyId: "key", signature: "signature" };
  assert.equal((await client.commitResourceLinks("vault:one", preflight, [envelope])).status, "active");
  assert.deepEqual(JSON.parse(String(calls[2]?.init.body)), { envelopes: [{ manifest_item_id: "item", encryption_suite: envelope.encryptionSuite, ciphertext: "ciphertext", aad_hash: "hash", issuer: "user:owner", issuer_key_id: "key", signature: "signature" }] });
  assert.equal((await client.sendResourceLinks("vault:one", { changes })).committed.status, "active");

  assert.equal((await client.unlinkResource("vault:one", "link/one", "unlink-once")).rekeyRequired, true);
  assert.equal(new Headers(calls.at(-1)?.init.headers).get("Idempotency-Key"), "unlink-once");
  const collaborators = await client.resourceCollaborators("vault:one", { view: "effective", kind: "user", kinds: ["invitation"], statuses: ["active"], relations: ["member"], direct: true, cursor: "page+one", limit: 10 });
  assert.equal(collaborators.collaborators[0]?.access?.paths[0]?.linkId, "link/one");
  const collaboratorQuery = calls.at(-1)!.url.searchParams;
  assert.deepEqual(collaboratorQuery.getAll("kind"), ["user", "invitation"]);
  assert.deepEqual(collaboratorQuery.getAll("status"), ["active"]);
  assert.equal(collaboratorQuery.get("cursor"), "page+one");
  const resources = await client.searchResources({ filters: { resource: { types: ["vault"], parent: "project:one" }, collaborator: { subjects: ["user:bob"], view: "effective", direct: true } }, include: ["parent", "collaborator_matches"], sort: { field: "display_name", direction: "asc" }, page: { limit: 20, cursor: "next+page" } });
  assert.equal(resources.resources[0]?.parent?.resource, "project:one");
  assert.deepEqual(JSON.parse(String(calls.at(-1)?.init.body)).page, { limit: 20, cursor: "next+page" });

  deniedPreflight = true;
  const beforeDenied = calls.length;
  await assert.rejects(client.sendResourceLinks("vault:one", { changes }), { status: 409, code: "link_denied" });
  assert.equal(calls.length, beforeDenied + 1);
});

test("resource collaboration methods reject invalid input and malformed authority responses", async () => {
  let calls = 0;
  let response: unknown = linkResult();
  let headers: Record<string, string> = { "Lotor-Link-Token": "link-token" };
  const client = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async () => { calls++; return Response.json(response, { headers }); } }).forUser("alice");
  await assert.rejects(client.searchResourceLinkCandidates("vault:one", { query: "", relation: "member" }));
  await assert.rejects(client.searchResourceLinkCandidates("vault:one", { query: "bob", relation: "member", limit: 101 }));
  await assert.rejects(client.preflightResourceLinks("vault:one", []));
  await assert.rejects(client.resourceCollaborators("vault:one", { limit: 0 }));
  await assert.rejects(client.searchResources({ page: { limit: 101 } }));
  await assert.rejects(client.commitResourceLinks("vault:one", { result: linkResult() } as never));
  assert.equal(calls, 0);
  headers = {};
  await assert.rejects(client.preflightResourceLinks("vault:one", [{ action: "revoke", linkId: "link" }]), /token/);
  response = { ...linkResult(), status: "unexpected" };
  headers = { "Lotor-Link-Token": "link-token" };
  await assert.rejects(client.preflightResourceLinks("vault:one", [{ action: "revoke", linkId: "link" }]));
  response = { resource: "vault:one", collaborators: [{ kind: "robot", id: "one", relations: [], status: "active" }], next_cursor: null };
  await assert.rejects(client.resourceCollaborators("vault:one"));
  response = { resources: [], next_cursor: 42 };
  await assert.rejects(client.searchResources());
});

test("delegated resource policies preserve E2EE custody and guest restrictions", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let denied = false;
  let malformed = false;
  const app = new LotorControlClient({ baseUrl: "https://api.lotor.test", clientId: "app", secretKey: "secret", fetch: async (input, init = {}) => {
    calls.push({ url: String(input), init });
    assert.equal(new Headers(init.headers).get("Authorization"), "Bearer alice");
    if (denied) return Response.json({}, { status: 403 });
    if (String(input).endsWith("/collaboration-policy")) return Response.json(malformed ? { resource: "vault:one", revision: 0 } : { resource: "vault:one", revision: 2 });
    return Response.json(malformed ? { organization: "organization:acme", status: "unknown", revision: 1 } : { organization: "organization:acme", required_account_custody: "enterprise_box", resource_key_executor: "customer_box", automation_executor: "customer_box", function_binding_id: "efb_acme", resource_key_policy: "organization_default", status: "ready", revision: 3 });
  } });
  await assert.rejects(app.organizationE2EEPolicy("organization:acme"), /forUser/);
  await assert.rejects(app.setResourceCollaborationPolicy("vault:one", { guests: { allowed: false } }), /forUser/);
  assert.equal(calls.length, 0);
  const client = app.forUser("alice");
  assert.equal((await client.organizationE2EEPolicy("organization:acme")).functionBindingId, "efb_acme");
  const configured = await client.configureOrganizationE2EE("organization:acme", { requiredAccountCustody: "enterprise_box", resourceKeyExecutor: "customer_box", automationExecutor: "customer_box", functionBindingId: "efb_acme", resourceKeyPolicy: "organization_default" });
  assert.equal(configured.status, "ready");
  assert.deepEqual(JSON.parse(String(calls[1]?.init.body)), { required_account_custody: "enterprise_box", resource_key_executor: "customer_box", automation_executor: "customer_box", function_binding_id: "efb_acme", resource_key_policy: "organization_default" });
  assert.equal((await client.setResourceCollaborationPolicy("vault:one", { guests: { allowed: true, allowedDomains: ["example.com"] } })).revision, 2);
  assert.deepEqual(JSON.parse(String(calls[2]?.init.body)), { guests: { allowed: true, allowed_domains: ["example.com"] } });
  const beforeInvalid = calls.length;
  await assert.rejects(client.configureOrganizationE2EE("organization:acme", { requiredAccountCustody: "invalid" as never, resourceKeyExecutor: "managed", automationExecutor: "managed", resourceKeyPolicy: "organization_only" }));
  await assert.rejects(client.setResourceCollaborationPolicy("vault:one", { guests: {} }));
  assert.equal(calls.length, beforeInvalid);
  malformed = true;
  await assert.rejects(client.organizationE2EEPolicy("organization:acme"));
  await assert.rejects(client.setResourceCollaborationPolicy("vault:one", { guests: { allowed: false } }));
  denied = true; malformed = false;
  const beforeDenied = calls.length;
  await assert.rejects(client.organizationE2EEPolicy("organization:acme"), { status: 403 });
  assert.equal(calls.length, beforeDenied + 1);
});
