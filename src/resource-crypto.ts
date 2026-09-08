import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { ResourceExecutionPreflight, ResourceExecutionAuthorization } from "./resource.js";

export interface ProviderPlainRequest { headers?: Record<string, string>; body: Uint8Array }
export interface ProviderProtectedResponse { headers: Record<string, string>; body: Buffer; status: number }

/** Encrypt locally under the caller-held resource key and exact preflight AAD. */
export function protectProviderRequest(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, input: ProviderPlainRequest): string {
  checkKey(resourceKey);
  const aad = requestAAD(preflight);
  if (input.body.byteLength > 1 << 20) throw new Error("provider request body exceeds 1 MiB");
  if (input.body.byteLength !== preflight.requestBodySize || hash(input.body) !== preflight.requestBodyDigest) throw new Error("provider request body does not match execution preflight");
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    checkHeaderValue(value);
    if (!["accept", "content-type"].includes(name.toLowerCase())) throw new Error("unsupported provider request header");
    if (name.toLowerCase() === "accept") headers.Accept = value;
  }
  checkHeaderValue(preflight.contentType);
  headers["Content-Type"] = preflight.contentType;
  const plaintext = Buffer.from(JSON.stringify({ headers, body: Buffer.from(input.body).toString("base64url") }));
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", resourceKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const wire = Buffer.from(JSON.stringify({ nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), aad_hash: hash(aad) })).toString("base64url");
  if (wire.length > 3 << 20) throw new Error("protected provider payload exceeds 3 MiB");
  return wire;
}

/** Authenticate and decrypt the complete response bound to this execution. */
export function openProviderResponse(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, authorization: ResourceExecutionAuthorization): ProviderProtectedResponse {
  checkKey(resourceKey);
  const aad = requestAAD(preflight);
  if (authorization.status !== "completed" || !Number.isInteger(authorization.providerStatus) || authorization.providerStatus! < 100 || authorization.providerStatus! > 599) throw new Error("execution did not return a protected provider response");
  for (const field of ["requestFingerprint", "resource", "catalogEntryId", "payloadSlot", "payloadVersion", "payloadRepresentation", "executionMode", "expiresAt"] as const) {
    if (authorization[field] !== preflight[field]) throw new Error("execution response does not match preflight");
  }
  const responseAAD = Buffer.from(`lotor-provider-response-v1\0${hash(aad)}\0${authorization.providerStatus}`);
  const envelope = object(JSON.parse(decode(authorization.protectedResponse, 3 << 20).toString("utf8")));
  const nonce = decode(envelope.nonce, 16);
  const ciphertext = decode(envelope.ciphertext, 3 << 20);
  if (nonce.length !== 12 || ciphertext.length < 16 || envelope.aad_hash !== hash(responseAAD)) throw new Error("invalid protected provider response");
  const decipher = createDecipheriv("aes-256-gcm", resourceKey, nonce);
  decipher.setAAD(responseAAD);
  decipher.setAuthTag(ciphertext.subarray(-16));
  const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  const result = object(JSON.parse(plaintext.toString("utf8")));
  if (result.status !== authorization.providerStatus) throw new Error("invalid protected provider response status");
  const body = decode(result.body, Math.ceil((1 << 20) * 4 / 3), true);
  if (body.length > 1 << 20) throw new Error("provider response body exceeds 1 MiB");
  const headers = object(result.headers ?? {});
  for (const value of Object.values(headers)) checkHeaderValue(value);
  return { body, status: result.status as number, headers: headers as Record<string, string> };
}

function requestAAD(preflight: ResourceExecutionPreflight): Buffer {
  if (preflight.payloadRepresentation !== "encrypted-envelope-v1" || preflight.responsePolicyRef !== "encrypt_all" ||
    !["managed", "customer_box"].includes(preflight.executionMode)) throw new Error("execution preflight is not encrypted");
  return decode(preflight.requestAAD, 16384);
}
function checkKey(key: Uint8Array): void {
  if (key.byteLength !== 32) throw new Error("resource key must be 32 bytes");
}
function checkHeaderValue(value: unknown): asserts value is string {
  if (typeof value !== "string" || Buffer.byteLength(value) > 8192 || /[\r\n]/.test(value)) throw new Error("invalid provider header value");
}
function hash(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid protected provider JSON");
  return value as Record<string, unknown>;
}
function decode(value: unknown, maximum: number, allowEmpty = false): Buffer {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.length === 0) || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("invalid protected provider base64url");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw new Error("noncanonical protected provider base64url");
  return bytes;
}
