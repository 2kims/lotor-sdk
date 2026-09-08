import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import { LotorResourceClient, LotorControlError } from "../src/index.js";

const input = { audience: "https://avault.test", method: "POST", path: "/proxy/slack", bodySha256: "a".repeat(64), querySha256: "b".repeat(64), expiresIn: 10 };
const result = { assertion: "signed-assertion".repeat(3), token_type: "X-Lotor-Assertion", subject: "service_account:bot", api_key_resource: "api_key:one", client_id: "app", application_id: "application", environment_id: "sandbox", environment_mode: "sandbox", expires_at: 123, credential_version: 1 };
const options = { baseUrl: "https://api.lotor.test", clientId: "app", publishableKey: "pk_test", resourceCredential: "lrc_test" };

test("workload exchange uses only publishable key and resource credential", async () => {
  let calls = 0;
  const client = new LotorResourceClient({ ...options, fetch: async (url, init) => {
    calls++;
    assert.equal(String(url), "https://api.lotor.test/v1/public/applications/app/credential-exchanges");
    const headers = new Headers(init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer lrc_test");
    assert.equal(headers.get("X-Lotor-Publishable-Key"), "pk_test");
    assert.equal(headers.get("X-Lotor-Secret-Key"), null);
    assert.equal(headers.get("Cookie"), null);
    assert.equal(init?.credentials, "omit");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(String(init?.body)), { audience: input.audience, method: input.method, path: input.path, body_sha256: input.bodySha256, query_sha256: input.querySha256, expires_in: 10 });
    return Response.json(result);
  } });
  const exchange = await client.exchangeCredential(input);
  assert.equal(exchange.assertion, result.assertion);
  assert.equal(exchange.environmentMode, "sandbox");
  assert.equal(exchange.apiKeyResource, "api_key:one");
  assert.equal(exchange.credentialVersion, 1);
  assert.equal(calls, 1);
});

test("workload denial is typed and never retried as application authority", async () => {
  for (const status of [401, 403, 409, 503]) {
    let calls = 0;
    const client = new LotorResourceClient({ ...options, fetch: async () => {
      calls++;
      return Response.json({ code: "denied", error: "request denied" }, { status });
    } });
    await assert.rejects(client.exchangeCredential(input), error => error instanceof LotorControlError && error.status === status && error.code === "denied");
    assert.equal(calls, 1);
  }
});

test("workload client rejects unsafe configuration and invalid request bounds", async () => {
  for (const baseUrl of ["http://remote.test", "https://user:password@api.test", "https://api.test/path", "https://api.test?query=x", "https://api.test/#fragment"]) {
    assert.throws(() => new LotorResourceClient({ ...options, baseUrl }));
  }
  for (const field of ["clientId", "publishableKey", "resourceCredential"] as const) {
    assert.throws(() => new LotorResourceClient({ ...options, [field]: "" }));
    assert.throws(() => new LotorResourceClient({ ...options, [field]: "bad\r\nvalue" }));
  }
  let calls = 0;
  const client = new LotorResourceClient({ ...options, fetch: async () => { calls++; return Response.json(result); } });
  for (const change of [{ bodySha256: "bad" }, { querySha256: "A".repeat(64) }, { expiresIn: 31 }, { expiresIn: 0 }, { expiresIn: 1.5 }]) {
    await assert.rejects(client.exchangeCredential({ ...input, ...change }));
  }
  assert.equal(calls, 0);
});

test("workload exchange rejects malformed successful responses", async () => {
  for (const body of [null, [], {}, { ...result, environment_mode: "unknown" }, { ...result, credential_version: 1.5 }, { ...result, assertion: "" }]) {
    const client = new LotorResourceClient({ ...options, fetch: async () => Response.json(body) });
    await assert.rejects(client.exchangeCredential(input));
  }
  const client = new LotorResourceClient({ ...options, fetch: async () => new Response("<html>not JSON</html>") });
  await assert.rejects(client.exchangeCredential(input));
});

test("workload exchange bounds the response body and forwards cancellation", async () => {
  const controller = new AbortController();
  const client = new LotorResourceClient({ ...options, fetch: async (_url, init) => {
    assert.equal(init?.signal, controller.signal);
    return new Response("x".repeat(65537));
  } });
  await assert.rejects(client.exchangeCredential(input, { signal: controller.signal }), /exceeds limit/);
});

test("workload exchange uses real HTTP and does not follow credential-bearing redirects", async () => {
  let redirects = false;
  let leaked = 0;
  const server = createServer(async (request, response) => {
    if (request.url === "/redirect-target") {
      leaked++;
      response.end();
      return;
    }
    assert.equal(request.headers.authorization, "Bearer lrc_test");
    assert.equal(request.headers["x-lotor-publishable-key"], "pk_test");
    assert.equal(request.headers["x-lotor-secret-key"], undefined);
    assert.equal(request.headers.cookie, undefined);
    if (redirects) {
      response.writeHead(307, { Location: "/redirect-target" });
      response.end();
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(body.idempotency_key_sha256, "c".repeat(64));
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify(result));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const client = new LotorResourceClient({ ...options, baseUrl: `http://127.0.0.1:${address.port}` });
    assert.equal((await client.exchangeCredential({ ...input, idempotencyKeySha256: "c".repeat(64) })).tokenType, "X-Lotor-Assertion");
    redirects = true;
    await assert.rejects(client.exchangeCredential(input));
    assert.equal(leaked, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
