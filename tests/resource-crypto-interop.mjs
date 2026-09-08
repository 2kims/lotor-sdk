import { protectProviderRequest, openProviderResponse } from "../dist/index.js";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const fixture = JSON.parse(Buffer.concat(chunks).toString());
const camel = value => Object.fromEntries(Object.entries(value).map(([name, field]) => [name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()), field]));
const plan = { ...camel(fixture.preflight), requestAAD: fixture.preflight.request_aad };
const key = Buffer.from(fixture.key, "base64");
const body = Buffer.from(fixture.body, "base64");
const opened = openProviderResponse(key, plan, camel(fixture.authorization));
process.stdout.write(JSON.stringify({
  protected_request: protectProviderRequest(key, plan, { body, headers: { Accept: "application/json" } }),
  opened_body: opened.body.toString("base64url"), opened_status: opened.status,
}));
