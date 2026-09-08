import { LotorControlError } from "./control.js";

export interface LotorResourceClientOptions {
  baseUrl: string;
  clientId: string;
  publishableKey: string;
  resourceCredential: string;
  fetch?: typeof globalThis.fetch;
}

export interface ResourceCredentialExchangeInput {
  audience: string;
  method: string;
  path: string;
  bodySha256: string;
  querySha256: string;
  idempotencyKeySha256?: string;
  expiresIn?: number;
}

export interface ResourceCredentialExchange {
  assertion: string;
  tokenType: "X-Lotor-Assertion";
  subject: string;
  apiKeyResource: string;
  clientId: string;
  applicationId: string;
  environmentId: string;
  environmentMode: "sandbox" | "production";
  expiresAt: number;
  credentialVersion: number;
}

export interface ResourceExecutionRequest {
  method: string; path: string; contentType: string; requestBodyDigest: string; requestBodySize: number;
}

interface ExecutionBinding {
  requestFingerprint: string; resource: string; catalogEntryId: string; payloadSlot: "provider_credential";
  payloadVersion: number; payloadRepresentation: "raw" | "encrypted-envelope-v1";
  executionMode: "raw" | "managed" | "customer_box"; expiresAt: number;
}

export interface ResourceExecutionPreflight extends ExecutionBinding, ResourceExecutionRequest {
  token: string; resourceRevision: number; lifecycleGeneration: number; catalogSnapshotId: string;
  catalogEntryRevision: string; policyRevision: string; credentialVersion: number;
  keyResource?: string; keyVersion?: number; responsePolicyRef?: "encrypt_all"; requestAAD?: string;
}

export interface ResourceExecutionCommitInput {
  protectedRequest?: string; responsePolicyRef?: "encrypt_all";
}

export interface ResourceExecutionAuthorization extends ExecutionBinding {
  status: "authorized" | "completed"; providerStatus?: number; protectedResponse?: string;
}

/** A workload credential client, not an application-secret or user-session client. */
export class LotorResourceClient {
  private readonly applicationUrl: string;
  private readonly publishableKey: string;
  private readonly resourceCredential: string;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: LotorResourceClientOptions) {
    const url = new URL(options.baseUrl);
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("baseUrl must contain only an origin");
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) throw new Error("baseUrl must use HTTPS outside loopback development");
    this.applicationUrl = `${url.origin}/v1/public/applications/${encodeURIComponent(string(options.clientId, "clientId", 512))}`;
    this.publishableKey = string(options.publishableKey, "publishableKey", 8192);
    this.resourceCredential = string(options.resourceCredential, "resourceCredential", 8192);
    this.fetcher = options.fetch ?? globalThis.fetch;
    if (!this.fetcher) throw new Error("fetch is required");
  }

  async exchangeCredential(input: ResourceCredentialExchangeInput, options: { signal?: AbortSignal } = {}): Promise<ResourceCredentialExchange> {
    const audience = string(input.audience, "audience", 512);
    new URL(audience);
    if (!["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"].includes(input.method)) throw new Error("invalid method");
    const path = string(input.path, "path", 8192);
    if (!path.startsWith("/")) throw new Error("path must start with /");
    const body = {
      audience, method: input.method, path,
      body_sha256: digest(input.bodySha256), query_sha256: digest(input.querySha256),
      ...(input.idempotencyKeySha256 === undefined ? {} : { idempotency_key_sha256: digest(input.idempotencyKeySha256) }),
      ...(input.expiresIn === undefined ? {} : { expires_in: integer(input.expiresIn, "expiresIn", 1, 30) }),
    };
    const { raw } = await this.request("/credential-exchanges", body, options);
    if (raw.token_type !== "X-Lotor-Assertion" || (raw.environment_mode !== "sandbox" && raw.environment_mode !== "production")) throw new Error("invalid credential exchange response");
    const assertion = string(raw.assertion, "assertion", 8192);
    if (assertion.length < 32) throw new Error("invalid assertion");
    return {
      assertion, tokenType: raw.token_type, environmentMode: raw.environment_mode,
      subject: string(raw.subject, "subject", 512), apiKeyResource: string(raw.api_key_resource, "apiKeyResource", 512),
      clientId: string(raw.client_id, "clientId", 512), applicationId: string(raw.application_id, "applicationId", 512),
      environmentId: string(raw.environment_id, "environmentId", 512), expiresAt: integer(raw.expires_at, "expiresAt", 0),
      credentialVersion: integer(raw.credential_version, "credentialVersion", 1),
    };
  }

  async preflightExecution(resource: string, input: ResourceExecutionRequest, options: { signal?: AbortSignal } = {}): Promise<ResourceExecutionPreflight> {
    const { raw, headers } = await this.request(executionPath(resource, "preflight"), {
      method: method(input.method), path: requestPath(input.path), content_type: string(input.contentType, "contentType", 256),
      request_body_digest: digest(input.requestBodyDigest), request_body_size: integer(input.requestBodySize, "requestBodySize", 0),
    }, options);
    const plan: ResourceExecutionPreflight = {
      ...executionBinding(raw), token: string(headers.get("Lotor-Execution-Token"), "execution token", 4096),
      method: method(raw.method), path: requestPath(raw.path), contentType: string(raw.content_type, "contentType", 256),
      requestBodyDigest: digest(string(raw.request_body_digest, "requestBodyDigest", 64)), requestBodySize: integer(raw.request_body_size, "requestBodySize", 0),
      resourceRevision: integer(raw.resource_revision, "resourceRevision", 1), lifecycleGeneration: integer(raw.lifecycle_generation, "lifecycleGeneration", 1),
      catalogSnapshotId: string(raw.catalog_snapshot_id, "catalogSnapshotId", 512), catalogEntryRevision: string(raw.catalog_entry_revision, "catalogEntryRevision", 512),
      policyRevision: string(raw.policy_revision, "policyRevision", 512), credentialVersion: integer(raw.credential_version, "credentialVersion", 1),
    };
    if (plan.resource !== resource || plan.method !== input.method || plan.path !== input.path || plan.contentType !== input.contentType ||
      plan.requestBodyDigest !== input.requestBodyDigest || plan.requestBodySize !== input.requestBodySize) throw new Error("preflight does not match execution request");
    if (plan.payloadRepresentation === "encrypted-envelope-v1") {
      if (raw.response_policy_ref !== "encrypt_all") throw new Error("invalid encrypted response policy");
      plan.keyResource = string(raw.key_resource, "keyResource", 512);
      plan.keyVersion = integer(raw.key_version, "keyVersion", 1);
      plan.responsePolicyRef = raw.response_policy_ref;
      plan.requestAAD = string(raw.request_aad, "requestAAD", 16384);
    } else if ([raw.key_resource, raw.key_version, raw.response_policy_ref, raw.request_aad].some(value => value !== undefined)) {
      throw new Error("raw preflight contains encryption context");
    }
    return plan;
  }

  async commitExecution(resource: string, preflight: ResourceExecutionPreflight, input: ResourceExecutionCommitInput = {}, options: { signal?: AbortSignal } = {}): Promise<ResourceExecutionAuthorization> {
    if (preflight.resource !== resource) throw new Error("execution resource does not match preflight");
    const body: Record<string, unknown> = { request_fingerprint: digest(preflight.requestFingerprint) };
    if (preflight.payloadRepresentation === "encrypted-envelope-v1") {
      if (input.responsePolicyRef !== "encrypt_all") throw new Error("encrypted execution requires encrypt_all response policy");
      body.protected_request = string(input.protectedRequest, "protectedRequest", 3 * 1024 * 1024);
      body.response_policy_ref = input.responsePolicyRef;
    } else if (input.protectedRequest !== undefined || input.responsePolicyRef !== undefined) {
      throw new Error("raw execution forbids encryption fields");
    }
    const { raw } = await this.request(executionPath(resource, "commit"), body, options,
      { "Lotor-Execution-Token": string(preflight.token, "execution token", 4096) }, 4 * 1024 * 1024);
    const binding = executionBinding(raw);
    for (const key of Object.keys(binding) as Array<keyof ExecutionBinding>) {
      if (binding[key] !== preflight[key]) throw new Error("execution response does not match preflight");
    }
    if (binding.payloadRepresentation === "raw") {
      if (raw.status !== "authorized" || raw.protected_response !== undefined || raw.provider_status !== undefined) throw new Error("invalid raw execution response");
      return { ...binding, status: "authorized" };
    }
    if (raw.status !== "completed") throw new Error("encrypted execution did not complete");
    return { ...binding, status: "completed", providerStatus: integer(raw.provider_status, "providerStatus", 100, 599),
      protectedResponse: string(raw.protected_response, "protectedResponse", 3 * 1024 * 1024) };
  }

  private async request(path: string, body: unknown, options: { signal?: AbortSignal }, extraHeaders: Record<string, string> = {}, maximum = 64 * 1024): Promise<{ raw: Record<string, unknown>; headers: Headers }> {
    const response = await this.fetcher(`${this.applicationUrl}${path}`, {
      method: "POST", redirect: "error", credentials: "omit", signal: options.signal,
      headers: { Accept: "application/json", "Content-Type": "application/json", Authorization: `Bearer ${this.resourceCredential}`, "X-Lotor-Publishable-Key": this.publishableKey, ...extraHeaders },
      body: JSON.stringify(body),
    });
    const raw = await readJSON(response, maximum);
    if (!response.ok) throw new LotorControlError(response.status, typeof raw.code === "string" ? raw.code : "request_failed", typeof raw.error === "string" ? raw.error : `Lotor request failed with status ${response.status}`);
    return { raw, headers: response.headers };
  }
}

function executionPath(resource: string, operation: string): string {
  return `/resources/${encodeURIComponent(string(resource, "resource", 512))}/executions/${operation}`;
}
function method(value: unknown): string {
  if (typeof value !== "string" || !["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"].includes(value)) throw new Error("invalid execution method");
  return value;
}
function requestPath(value: unknown): string {
  const path = string(value, "path", 4096);
  if (!path.startsWith("/")) throw new Error("path must start with /");
  return path;
}
function executionBinding(raw: Record<string, unknown>): ExecutionBinding {
  if (raw.payload_slot !== "provider_credential" ||
    (raw.payload_representation !== "raw" && raw.payload_representation !== "encrypted-envelope-v1") ||
    !["raw", "managed", "customer_box"].includes(String(raw.execution_mode)) ||
    (raw.execution_mode === "raw") !== (raw.payload_representation === "raw")) throw new Error("invalid execution representation or mode");
  return {
    requestFingerprint: digest(string(raw.request_fingerprint, "requestFingerprint", 64)), resource: string(raw.resource, "resource", 512),
    catalogEntryId: string(raw.catalog_entry_id, "catalogEntryId", 512), payloadSlot: raw.payload_slot,
    payloadVersion: integer(raw.payload_version, "payloadVersion", 1), payloadRepresentation: raw.payload_representation,
    executionMode: raw.execution_mode as ExecutionBinding["executionMode"], expiresAt: integer(raw.expires_at, "expiresAt", 0),
  };
}

function string(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\r\n]/.test(value)) throw new Error(`invalid ${name}`);
  return value;
}
function integer(value: unknown, name: string, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`invalid ${name}`);
  return value;
}
function digest(value: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("invalid SHA256 digest");
  return value;
}
async function readJSON(response: Response, maximum: number): Promise<Record<string, unknown>> {
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maximum) {
          await reader.cancel();
          throw new Error("Lotor response exceeds limit");
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
  }
  let value: unknown;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch {
    if (!response.ok) return {};
    throw new Error("invalid Lotor JSON response");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    if (!response.ok) return {};
    throw new Error("invalid Lotor JSON response");
  }
  return value as Record<string, unknown>;
}
