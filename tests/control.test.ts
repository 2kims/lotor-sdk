import assert from "node:assert/strict";
import test from "node:test";

import { LotorControlClient } from "../src/index.js";

const operation = { id: "op_1", kind: "resource_move", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "a".repeat(64), created_at: 1, updated_at: 1 };

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
