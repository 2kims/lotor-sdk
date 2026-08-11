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
/** Resolves and verifies exact-scope ownership, caching only inside the signed validity window. */
export declare class OwnershipResolver {
    private readonly options;
    private cached?;
    private readonly fetcher;
    private readonly now;
    constructor(options: OwnershipDiscoveryOptions);
    invalidate(): void;
    /** Verify a MOVED payload and accept it only when it strictly advances the current assertion. */
    acceptMoved(raw: string, prior: Ownership): Ownership;
    resolve(): Promise<Ownership>;
}
export declare function ownershipAddress(value: Ownership): {
    host: string;
    port: number;
    tls: boolean;
};
export declare function verifyOwnership(value: Ownership, scope: OwnershipScope, publicKey: Buffer, nowUs?: number): void;
