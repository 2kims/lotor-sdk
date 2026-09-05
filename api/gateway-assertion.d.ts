import { type KeyObject } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
export declare const GATEWAY_ASSERTION_HEADER = "x-lotor-assertion";
export declare class GatewayAssertionError extends Error {
    readonly code: "rejected" | "replay_unavailable";
    constructor(code: "rejected" | "replay_unavailable", cause?: unknown);
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
export declare class GatewayAssertionVerifier {
    #private;
    constructor(options: GatewayAssertionVerifierOptions);
    verify(assertion: string, request: GatewayAssertionRequest): Promise<GatewayAssertionClaims>;
}
export interface GatewayAssertionMiddlewareContext {
    claims: GatewayAssertionClaims;
    body: Buffer;
}
export type GatewayAssertionNext = (request: IncomingMessage, response: ServerResponse, context: GatewayAssertionMiddlewareContext) => void | Promise<void>;
export interface GatewayAssertionMiddlewareOptions {
    verifier: GatewayAssertionVerifier;
    authenticateOrigin: (request: IncomingMessage) => boolean | Promise<boolean>;
    maxBodyBytes: number;
}
export declare function gatewayAssertionMiddleware(options: GatewayAssertionMiddlewareOptions, next: GatewayAssertionNext): (request: IncomingMessage, response: ServerResponse) => Promise<void>;
