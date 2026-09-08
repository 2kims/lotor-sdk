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
    method: string;
    path: string;
    contentType: string;
    requestBodyDigest: string;
    requestBodySize: number;
}
interface ExecutionBinding {
    requestFingerprint: string;
    resource: string;
    catalogEntryId: string;
    payloadSlot: "provider_credential";
    payloadVersion: number;
    payloadRepresentation: "raw" | "encrypted-envelope-v1";
    executionMode: "raw" | "managed" | "customer_box";
    expiresAt: number;
}
export interface ResourceExecutionPreflight extends ExecutionBinding, ResourceExecutionRequest {
    token: string;
    resourceRevision: number;
    lifecycleGeneration: number;
    catalogSnapshotId: string;
    catalogEntryRevision: string;
    policyRevision: string;
    credentialVersion: number;
    keyResource?: string;
    keyVersion?: number;
    responsePolicyRef?: "encrypt_all";
    requestAAD?: string;
}
export interface ResourceExecutionCommitInput {
    protectedRequest?: string;
    responsePolicyRef?: "encrypt_all";
}
export interface ResourceExecutionAuthorization extends ExecutionBinding {
    status: "authorized" | "completed";
    providerStatus?: number;
    protectedResponse?: string;
}
/** A workload credential client, not an application-secret or user-session client. */
export declare class LotorResourceClient {
    private readonly applicationUrl;
    private readonly publishableKey;
    private readonly resourceCredential;
    private readonly fetcher;
    constructor(options: LotorResourceClientOptions);
    exchangeCredential(input: ResourceCredentialExchangeInput, options?: {
        signal?: AbortSignal;
    }): Promise<ResourceCredentialExchange>;
    preflightExecution(resource: string, input: ResourceExecutionRequest, options?: {
        signal?: AbortSignal;
    }): Promise<ResourceExecutionPreflight>;
    commitExecution(resource: string, preflight: ResourceExecutionPreflight, input?: ResourceExecutionCommitInput, options?: {
        signal?: AbortSignal;
    }): Promise<ResourceExecutionAuthorization>;
    private request;
}
export {};
