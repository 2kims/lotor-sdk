import { createHash, createPublicKey, verify } from "node:crypto";

export interface OwnershipScope {
  tenantId: string;
  applicationId: string;
  environmentId: string;
}

export interface Ownership {
  tenant_id: string;
  application_id: string;
  environment_id: string;
  endpoint: string;
  owner_instance_id: string;
  ownership_epoch: number;
  issued_at: number;
  expires_at: number;
  version: number;
  key_id: string;
  signature: string;
}

export interface OwnershipDiscoveryOptions {
  controlUrl: string;
  apiKey: string;
  scope: OwnershipScope;
  /** Raw 32-byte Ed25519 public key pinned from deployment configuration. */
  publicKey: Buffer;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Resolves and verifies exact-scope ownership, caching only inside the signed validity window. */
export class OwnershipResolver {
  private cached?: Ownership;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly now: () => number;

  constructor(private readonly options: OwnershipDiscoveryOptions) {
    const control = new URL(options.controlUrl);
    if (!["http:", "https:"].includes(control.protocol) || !options.apiKey ||
        !options.scope.tenantId || !options.scope.applicationId || !options.scope.environmentId ||
        options.publicKey.length !== 32) {
      throw new Error("invalid ownership discovery options");
    }
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
  }

  invalidate(): void {
    this.cached = undefined;
  }

  /** Verify a MOVED payload and accept it only when it strictly advances the current assertion. */
  acceptMoved(raw: string, prior: Ownership): Ownership {
    if (Buffer.byteLength(raw) > 64 * 1024) throw new Error("MOVED assertion is too large");
    const moved = JSON.parse(raw) as Ownership;
    verifyOwnership(moved, this.options.scope, this.options.publicKey, this.now() * 1000);
    if (moved.ownership_epoch <= prior.ownership_epoch || moved.endpoint === prior.endpoint) {
      throw new Error("MOVED assertion did not advance ownership");
    }
    this.cached = moved;
    return moved;
  }

  async resolve(): Promise<Ownership> {
    const nowUs = this.now() * 1000;
    if (this.cached && nowUs + 5_000_000 < this.cached.expires_at) return this.cached;
    const url = new URL("/v1/runtime/ownership", this.options.controlUrl);
    url.searchParams.set("tenant_id", this.options.scope.tenantId);
    url.searchParams.set("application_id", this.options.scope.applicationId);
    url.searchParams.set("environment_id", this.options.scope.environmentId);
    const response = await this.fetcher(url, {
      headers: { authorization: `Bearer ${this.options.apiKey}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`ownership discovery returned HTTP ${response.status}`);
    const raw = await boundedResponse(response, 64 * 1024);
    const value = JSON.parse(raw) as Ownership;
    verifyOwnership(value, this.options.scope, this.options.publicKey, nowUs);
    this.cached = value;
    return value;
  }
}

async function boundedResponse(response: Response, limit: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      throw new Error("ownership response is too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks, length).toString("utf8");
}

export function ownershipAddress(value: Ownership): { host: string; port: number; tls: boolean } {
  const endpoint = new URL(value.endpoint);
  if (!["lwp:", "lwps:"].includes(endpoint.protocol) || endpoint.username || endpoint.password ||
      endpoint.pathname !== "" || endpoint.search || endpoint.hash || !endpoint.hostname || !endpoint.port) {
    throw new Error("invalid ownership endpoint");
  }
  const port = Number(endpoint.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error("invalid ownership endpoint port");
  }
  return { host: endpoint.hostname, port, tls: endpoint.protocol === "lwps:" };
}

export function verifyOwnership(
  value: Ownership, scope: OwnershipScope, publicKey: Buffer, nowUs = Date.now() * 1000,
): void {
  if (value.version !== 1 || !Number.isSafeInteger(value.ownership_epoch) || value.ownership_epoch < 1 ||
      !value.owner_instance_id || value.tenant_id !== scope.tenantId ||
      value.application_id !== scope.applicationId || value.environment_id !== scope.environmentId) {
    throw new Error("ownership assertion does not match the requested scope");
  }
  if (value.issued_at > nowUs + 60_000_000 || value.expires_at <= nowUs ||
      value.expires_at - value.issued_at > 60_000_000) {
    throw new Error("ownership assertion is expired or outside its validity window");
  }
  ownershipAddress(value);
  const keyId = createHash("sha256").update(publicKey).digest().subarray(0, 8).toString("hex");
  if (value.key_id !== keyId) throw new Error("ownership signing key mismatch");
  const signature = Buffer.from(value.signature, "base64url");
  if (signature.length !== 64) throw new Error("invalid ownership signature");
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: "der", type: "spki",
  });
  if (!verify(null, ownershipPayload(value), key, signature)) {
    throw new Error("ownership signature verification failed");
  }
}

function ownershipPayload(value: Ownership): Buffer {
  return Buffer.from([
    value.version, value.tenant_id, value.application_id, value.environment_id,
    value.endpoint, value.owner_instance_id, value.ownership_epoch, value.issued_at,
    value.expires_at, value.key_id,
  ].join("\0"));
}
