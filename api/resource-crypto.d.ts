import type { ResourceExecutionPreflight, ResourceExecutionAuthorization } from "./resource.js";
export interface ProviderPlainRequest {
    headers?: Record<string, string>;
    body: Uint8Array;
}
export interface ProviderProtectedResponse {
    headers: Record<string, string>;
    body: Buffer;
    status: number;
}
/** Encrypt locally under the caller-held resource key and exact preflight AAD. */
export declare function protectProviderRequest(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, input: ProviderPlainRequest): string;
/** Authenticate and decrypt the complete response bound to this execution. */
export declare function openProviderResponse(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, authorization: ResourceExecutionAuthorization): ProviderProtectedResponse;
