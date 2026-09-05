import {
  createHash, createPublicKey, timingSafeEqual, verify,
  type KeyObject,
} from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

export const GATEWAY_ASSERTION_HEADER = "x-lotor-assertion";

export class GatewayAssertionError extends Error {
  readonly code: "rejected" | "replay_unavailable";

  constructor(code: "rejected" | "replay_unavailable", cause?: unknown) {
    super(code === "rejected" ? "gateway assertion rejected" : "gateway assertion replay check unavailable", { cause });
    this.name = "GatewayAssertionError";
    this.code = code;
  }
}

export interface GatewayAssertionClaims {
  iss: string;
  kid: string;
  aud: string;
  sub?: string;
  sid_hash?: string;
  tenant_id: string;
  application_id: string;
  environment_id: string;
  binding_id: string;
  route_id: string;
  route_pin: string;
  gateway_placement_id: string;
  gateway_ownership_epoch: number;
  runtime_placement_id: string;
  runtime_ownership_epoch: number;
  operation?: string;
  method: string;
  path: string;
  request_id: string;
  body_sha256: string;
  query_sha256: string;
  idempotency_key_sha256?: string;
  iat: number;
  exp: number;
  configuration_version: number;
  binding_activation_epoch: number;
  replay_eligible: boolean;
}

export interface GatewayAssertionAuthority {
  issuer: string;
  audience: string;
  tenantId: string;
  applicationId: string;
  environmentId: string;
  bindingId: string;
  routeId: string;
  routePin: string;
  gatewayPlacementId: string;
  gatewayOwnershipEpoch: number;
  runtimePlacementId: string;
  runtimeOwnershipEpoch: number;
  operation?: string;
  configurationVersion: number;
  bindingActivationEpoch: number;
}

export interface GatewayAssertionRequest {
  method: string;
  path: string;
  rawQuery?: string;
  idempotencyKey?: string;
  body?: Uint8Array;
}

export interface GatewayAssertionReplayStore {
  consume(requestId: string, expiresAt: Date): boolean | Promise<boolean>;
}

export interface GatewayAssertionVerifierOptions {
  keys: Readonly<Record<string, KeyObject | string | Uint8Array>>;
  authority: GatewayAssertionAuthority;
  replay?: GatewayAssertionReplayStore;
  now?: () => Date;
  clockSkewMs?: number;
}

export class GatewayAssertionVerifier {
  readonly #keys: ReadonlyMap<string, KeyObject>;
  readonly #authority: GatewayAssertionAuthority;
  readonly #replay?: GatewayAssertionReplayStore;
  readonly #now: () => Date;
  readonly #clockSkewMs: number;

  constructor(options: GatewayAssertionVerifierOptions) {
    if (!validAuthority(options.authority) || options.clockSkewMs !== undefined &&
      (!Number.isSafeInteger(options.clockSkewMs) || options.clockSkewMs < 0 || options.clockSkewMs > 30_000)) {
      throw rejected();
    }
    const keys = new Map<string, KeyObject>();
    for (const [keyId, value] of Object.entries(options.keys)) {
      if (!token(keyId, 160)) throw rejected();
      try {
        const key = value instanceof Uint8Array
          ? createPublicKey({
            key: value.byteLength === 32
              ? Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(value)])
              : Buffer.from(value),
            format: "der", type: "spki",
          })
          : createPublicKey(value);
        if (key.asymmetricKeyType !== "ed25519") throw rejected();
        keys.set(keyId, key);
      } catch (error) {
        if (error instanceof GatewayAssertionError) throw error;
        throw rejected(error);
      }
    }
    if (keys.size === 0) throw rejected();
    this.#keys = keys;
    this.#authority = { ...options.authority };
    this.#replay = options.replay;
    this.#now = options.now ?? (() => new Date());
    this.#clockSkewMs = options.clockSkewMs ?? 0;
  }

  async verify(assertion: string, request: GatewayAssertionRequest): Promise<GatewayAssertionClaims> {
    if (!validRequest(request)) throw rejected();
    const parts = assertion.split(".");
    if (parts.length !== 3 || parts[0] !== "v1") throw rejected();
    let body: Buffer;
    let signature: Buffer;
    let value: unknown;
    try {
      body = Buffer.from(parts[1]!, "base64url");
      signature = Buffer.from(parts[2]!, "base64url");
      value = JSON.parse(body.toString("utf8"));
    } catch (error) {
      throw rejected(error);
    }
    if (body.length === 0 || body.length > 16 << 10 || signature.length !== 64 ||
      body.toString("base64url") !== parts[1] || signature.toString("base64url") !== parts[2] ||
      JSON.stringify(value) !== body.toString("utf8") || !validClaimsShape(value)) throw rejected();
    const claims = value;
    const key = this.#keys.get(claims.kid);
    if (!key || !verify(null, body, key, signature) || !this.#validClaims(claims, request)) throw rejected();
    if (!claims.replay_eligible) {
      if (!this.#replay) throw replayUnavailable();
      let first: boolean;
      try {
        first = await this.#replay.consume(claims.request_id, new Date(claims.exp * 1000));
      } catch (error) {
        throw replayUnavailable(error);
      }
      if (!first) throw rejected();
    }
    return claims;
  }

  #validClaims(claims: GatewayAssertionClaims, request: GatewayAssertionRequest): boolean {
    const expected = this.#authority;
    if (claims.iss !== expected.issuer || claims.aud !== expected.audience ||
      claims.tenant_id !== expected.tenantId || claims.application_id !== expected.applicationId ||
      claims.environment_id !== expected.environmentId || claims.binding_id !== expected.bindingId ||
      claims.route_id !== expected.routeId || claims.route_pin !== expected.routePin ||
      claims.gateway_placement_id !== expected.gatewayPlacementId ||
      claims.gateway_ownership_epoch !== expected.gatewayOwnershipEpoch ||
      claims.runtime_placement_id !== expected.runtimePlacementId ||
      claims.runtime_ownership_epoch !== expected.runtimeOwnershipEpoch ||
      (claims.operation ?? "") !== (expected.operation ?? "") ||
      claims.configuration_version !== expected.configurationVersion ||
      claims.binding_activation_epoch !== expected.bindingActivationEpoch) return false;
    const nowSeconds = this.#now().getTime() / 1000;
    if (claims.iat < 1 || claims.exp <= claims.iat || claims.exp - claims.iat > 30 ||
      claims.iat > nowSeconds + this.#clockSkewMs / 1000 || claims.exp <= nowSeconds - this.#clockSkewMs / 1000) return false;
    if (claims.method !== request.method || claims.path !== request.path ||
      !equalText(claims.body_sha256, sha256(request.body ?? new Uint8Array())) ||
      !equalText(claims.query_sha256, sha256(Buffer.from(request.rawQuery ?? "")))) return false;
    const idempotencyHash = request.idempotencyKey ? sha256(Buffer.from(request.idempotencyKey)) : "";
    if (!equalText(claims.idempotency_key_sha256 ?? "", idempotencyHash)) return false;
    const safe = request.method === "GET" || request.method === "HEAD" || request.method === "OPTIONS";
    return (!safe || claims.replay_eligible) && (safe || !claims.replay_eligible || idempotencyHash !== "");
  }
}

export interface GatewayAssertionMiddlewareContext {
  claims: GatewayAssertionClaims;
  body: Buffer;
}

export type GatewayAssertionNext = (
  request: IncomingMessage,
  response: ServerResponse,
  context: GatewayAssertionMiddlewareContext,
) => void | Promise<void>;

export interface GatewayAssertionMiddlewareOptions {
  verifier: GatewayAssertionVerifier;
  authenticateOrigin: (request: IncomingMessage) => boolean | Promise<boolean>;
  maxBodyBytes: number;
}

export function gatewayAssertionMiddleware(
  options: GatewayAssertionMiddlewareOptions,
  next: GatewayAssertionNext,
): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  if (!(options.verifier instanceof GatewayAssertionVerifier) || typeof options.authenticateOrigin !== "function" ||
    typeof next !== "function" || !Number.isSafeInteger(options.maxBodyBytes) ||
    options.maxBodyBytes < 0 || options.maxBodyBytes > 1 << 30) throw rejected();
  return async (request, response) => {
    try {
      if (!await options.authenticateOrigin(request)) return gatewayHTTPError(response, 401);
      const assertion = singleHeader(request.headers[GATEWAY_ASSERTION_HEADER]);
      const idempotencyKey = optionalSingleHeader(request.headers["idempotency-key"]);
      if (!assertion || idempotencyKey === null) return gatewayHTTPError(response, 401);
      const chunks: Buffer[] = [];
      let length = 0;
      for await (const chunk of request) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += buffer.length;
        if (length > options.maxBodyBytes) return gatewayHTTPError(response, 413);
        chunks.push(buffer);
      }
      const body = Buffer.concat(chunks);
      const url = new URL(request.url ?? "/", "http://lotor.invalid");
      const claims = await options.verifier.verify(assertion, {
        method: request.method ?? "", path: url.pathname, rawQuery: url.search.slice(1),
        idempotencyKey: idempotencyKey ?? undefined, body,
      });
      delete request.headers[GATEWAY_ASSERTION_HEADER];
      await next(request, response, { claims, body });
    } catch (error) {
      gatewayHTTPError(response, error instanceof GatewayAssertionError && error.code === "replay_unavailable" ? 503 : 401);
    }
  };
}

const requiredClaimKeys = [
  "iss", "kid", "aud", "tenant_id", "application_id", "environment_id", "binding_id", "route_id",
  "route_pin", "gateway_placement_id", "gateway_ownership_epoch", "runtime_placement_id",
  "runtime_ownership_epoch", "method", "path", "request_id", "body_sha256", "query_sha256", "iat", "exp",
  "configuration_version", "binding_activation_epoch", "replay_eligible",
] as const;
const optionalClaimKeys = ["sub", "sid_hash", "operation", "idempotency_key_sha256"] as const;

function validClaimsShape(value: unknown): value is GatewayAssertionClaims {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const claims = value as Record<string, unknown>;
  const allowed = new Set<string>([...requiredClaimKeys, ...optionalClaimKeys]);
  if (Object.keys(claims).some((key) => !allowed.has(key)) || requiredClaimKeys.some((key) => !(key in claims))) return false;
  const strings = ["iss", "kid", "aud", "tenant_id", "application_id", "environment_id", "binding_id", "route_id",
    "route_pin", "gateway_placement_id", "runtime_placement_id", "method", "path", "request_id", "body_sha256",
    "query_sha256"];
  if (strings.some((key) => typeof claims[key] !== "string")) return false;
  for (const key of optionalClaimKeys) if (key in claims && typeof claims[key] !== "string") return false;
  const integers = ["gateway_ownership_epoch", "runtime_ownership_epoch", "iat", "exp", "configuration_version",
    "binding_activation_epoch"];
  if (integers.some((key) => !Number.isSafeInteger(claims[key]))) return false;
  return typeof claims.replay_eligible === "boolean" && token(claims.iss as string, 320) &&
    token(claims.kid as string, 160) && token(claims.aud as string, 512) &&
    token(claims.request_id as string, 300) && hash(claims.route_pin as string) &&
    hash(claims.body_sha256 as string) && hash(claims.query_sha256 as string) &&
    (!("idempotency_key_sha256" in claims) || hash(claims.idempotency_key_sha256 as string)) &&
    ((claims.sub === undefined && claims.sid_hash === undefined) ||
      (token(claims.sub as string, 512) && hash(claims.sid_hash as string)));
}

function validAuthority(authority: GatewayAssertionAuthority): boolean {
  return !!authority && token(authority.issuer, 320) && token(authority.audience, 512) &&
    token(authority.tenantId, 300) && token(authority.applicationId, 300) && token(authority.environmentId, 300) &&
    token(authority.bindingId, 200) && token(authority.routeId, 160) && hash(authority.routePin) &&
    token(authority.gatewayPlacementId, 200) && token(authority.runtimePlacementId, 200) &&
    positive(authority.gatewayOwnershipEpoch) && positive(authority.runtimeOwnershipEpoch) &&
    positive(authority.configurationVersion) && positive(authority.bindingActivationEpoch) &&
    (authority.operation === undefined || token(authority.operation, 256));
}

function validRequest(request: GatewayAssertionRequest): boolean {
  const idempotency = request.idempotencyKey ?? "";
  return !!request && /^[A-Z!#$%&'*+.^_`|~-]{1,32}$/u.test(request.method) &&
    token(request.path, 8 << 10) && request.path.startsWith("/") && !/[\\\0\r\n]/u.test(request.path) &&
    (request.rawQuery?.length ?? 0) <= 8 << 10 && !/[\0\r\n]/u.test(request.rawQuery ?? "") &&
    idempotency.length <= 512 && idempotency.trim() === idempotency && !/[\0\r\n]/u.test(idempotency);
}

function token(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && value.trim() === value &&
    !/[\0\r\n]/u.test(value);
}

function hash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

function positive(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function equalText(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function optionalSingleHeader(value: string | string[] | undefined): string | null | undefined {
  return value === undefined ? undefined : typeof value === "string" ? value : null;
}

function rejected(cause?: unknown): GatewayAssertionError {
  return new GatewayAssertionError("rejected", cause);
}

function replayUnavailable(cause?: unknown): GatewayAssertionError {
  return new GatewayAssertionError("replay_unavailable", cause);
}

function gatewayHTTPError(response: ServerResponse, status: number): void {
  if (response.headersSent || response.writableEnded) return;
  response.writeHead(status, { "cache-control": "no-store", "content-type": "application/json" });
  response.end('{"error":"gateway request rejected"}\n');
}
