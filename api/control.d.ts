export interface LotorControlClientOptions {
    baseUrl: string;
    clientId: string;
    secretKey: string;
    fetch?: typeof globalThis.fetch;
}
export interface SCIMDirectory {
    id: string;
    resource: string;
    organization: string;
    credentialResource: string;
    status: "disabled" | "active";
    revision: number;
    baseUrl: string;
}
export interface SCIMDirectoryCreateInput {
    directoryResource: string;
    credentialResource: string;
    expectedResourceRevision: number;
    expectedLifecycleGeneration: number;
}
export interface SCIMDirectoryUpdateInput {
    enabled: boolean;
    expectedRevision: number;
}
export interface SCIMDirectoryList {
    directories: SCIMDirectory[];
    nextCursor: string | null;
}
export interface ResourceTypeDefinition {
    resourceType: string;
    kind: "container" | "content";
    allowedParentTypes: string[];
    lifecycle: "application";
    directLinks: boolean;
    relations: string[];
    inheritedRelations?: string[];
    mayActAsPrincipal?: boolean;
    mayActAsSubjectSet?: boolean;
    keyBehavior: "none" | "inherited" | "own" | "configurable";
    catalogEntryKinds?: string[];
    payload: {
        storage: "none" | "lotor" | "provider";
        slots: Array<{
            name: string;
            schemaIds: string[];
            maximumObjectSize: number;
            required: boolean;
        }>;
    };
}
export interface ResourceRegistration {
    resourceType: string;
    displayName?: string;
    parent?: string;
    keyScope?: "organization" | "resource";
}
export interface ResourceCatalogBinding {
    resource: string;
    catalogId: string;
    snapshotId: string;
    snapshotDigest: string;
    entryKinds: string[];
    resourceRevision: number;
}
export interface Resource {
    id: string;
    principalSubject?: string;
    resource: string;
    resourceType: string;
    displayName: string;
    parent?: string;
    status: "pending_encryption" | "pending_payload" | "pending_encryption_payload" | "active" | "disabled" | "deleting" | "failed" | "deleted";
    revision: number;
    lifecycleGeneration: number;
    encryption: {
        required: boolean;
        status: "not_required" | "provisioning" | "ready" | "failed";
        keyScope?: "organization" | "resource";
        effectiveKeyResource?: string;
        keyResource?: string;
        keyVersion?: number;
    };
    catalogBinding?: ResourceCatalogBinding;
}
export interface DurableOperation {
    id: string;
    kind: "resource_create" | "resource_move" | "resource_disable" | "resource_restore" | "resource_delete" | "catalog_import" | "catalog_publish" | "catalog_binding";
    status: "pending" | "running" | "succeeded" | "failed" | "cancelled";
    targetKind: "resource" | "catalog" | "catalog_snapshot";
    targetId: string;
    requestHash: string;
    errorCode?: string;
    createdAt: number;
    updatedAt: number;
}
export interface OperationWaitOptions {
    signal?: AbortSignal;
    maxAttempts?: number;
    intervalMs?: number;
}
export interface Catalog {
    discoverable?: boolean;
    id: string;
    namespace: string;
    catalogType: "api" | "generic";
    visibility: "application_private" | "organization_private";
    organization?: string;
    status: "active" | "disabled";
    publishedSnapshotId?: string;
    createdAt: number;
}
export interface CatalogSnapshot {
    id: string;
    catalogId: string;
    sourceDigest: string;
    importerVersion: string;
    digest: string;
    status: "candidate" | "published";
    entryCount: number;
    publishedAt?: number;
    createdAt: number;
}
export interface CatalogEntry {
    id: string;
    catalogId: string;
    semanticKey: string;
    entryKind: string;
    revisionId: string;
    revisionDigest: string;
    definition: Record<string, unknown>;
}
export interface ResourceLifecycleFence {
    expectedRevision: number;
    expectedLifecycleGeneration: number;
}
export interface GenericCatalogDefinition {
    semanticKey: string;
    entryKind: string;
    definition: Record<string, unknown>;
}
export interface ResourceCredentialMetadata {
    id: string;
    resource: string;
    issuedTo: string;
    status: string;
    displayHint: string;
    version: number;
    createdAt: number;
    expiresAt?: number;
    revokeAt?: number;
    revokedAt?: number;
    lastUsedAt?: number;
}
export interface IssuedResourceCredential extends ResourceCredentialMetadata {
    credential: string;
}
export interface ResourceCredentialIssueInput {
    issuedTo: string;
    expiresAt?: number;
}
export interface ResourceCredentialRotateInput {
    revokePreviousAt: number;
    expiresAt?: number;
}
export type ResourceCollaboratorKind = "user" | "group" | "service_account" | "invitation";
export type ResourceLinkCandidateKind = Exclude<ResourceCollaboratorKind, "invitation">;
export interface ResourceLinkChange {
    action: "grant" | "revoke";
    linkId?: string;
    collaborator?: string;
    relation?: string;
    subject?: string;
    email?: string;
    subjectResource?: string;
    subjectRelation?: string;
    provisioning?: "existing_only" | "create_if_missing";
    delivery?: "email" | "in_app" | "external" | "none" | "notification_only";
    cascade?: boolean;
}
export interface ResourceLinkCandidateSearchInput {
    query: string;
    relation: string;
    kinds?: ResourceLinkCandidateKind[];
    limit?: number;
    cursor?: string;
}
export interface ResourceLinkCandidate {
    kind: ResourceLinkCandidateKind;
    displayName: string;
    subject?: string;
    resource?: string;
    subjectRelation?: "member";
    email?: string;
    linkState: "available" | "linked" | "pending_invitation";
    selectable: boolean;
    reason?: string;
}
export interface ResourceLinkCandidateSearchResult {
    candidates: ResourceLinkCandidate[];
    nextCursor: string | null;
}
export interface ResourceLinkOutcome {
    linkId?: string;
    resource: string;
    subject: string;
    relation: string;
    state: "active" | "pending_acceptance" | "pending_encryption" | "revoked" | "denied";
    allowed: boolean;
    reason?: string;
}
export interface ResourceLinkKeyRequirement {
    manifestItemId: string;
    grantId: string;
    resource: string;
    relation: string;
    keyResource: string;
    keyVersion: string;
    recipientSubject: string;
    recipientKeyId: string;
    encryptionAlgorithm: "X25519";
    publicKey: Uint8Array;
    invitationId?: string;
    activation?: "active_access" | "pending_invitation";
}
export interface ResourceLinkEnvelopeSubmission {
    manifestItemId: string;
    encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
    ciphertext: string;
    aadHash: string;
    issuer: string;
    issuerKeyId: string;
    signature: string;
}
export interface ResourceLinkResult {
    resource: string;
    status: "ready" | "committing" | "pending_acceptance" | "pending_encryption" | "active" | "failed" | "expired";
    failureReason?: string;
    expiresAt: number;
    idempotent: boolean;
    committable: boolean;
    revisions: {
        customer: string;
        graph: string;
        policy: string;
        identity: string;
        billing: string;
        seat: string;
        key: string;
    };
    outcomes: ResourceLinkOutcome[];
    capacity: {
        scope: "per_organization" | "per_account";
        before: number;
        after: number;
        claim: number;
        release: number;
    };
    billing: {
        currentQuantity: number;
        nextCycleQuantity: number;
        increase: number;
        nextCycleReduction: number;
    };
    invitationActions: Array<{
        invitationId: string;
        action: "preserve" | "claim" | "activate" | "supersede" | "cancel";
        reason?: string;
    }>;
    keyRequirements: ResourceLinkKeyRequirement[];
    impact: {
        impactedResources: string[];
        retainedResources: string[];
        rekeyResources: string[];
    };
}
export interface ResourceLinkPreflight {
    result: ResourceLinkResult;
    token: string;
}
export interface ResourceLinkSendInput {
    changes: ResourceLinkChange[];
}
export interface ResourceLinkSendResult {
    preflight: ResourceLinkPreflight;
    committed: ResourceLinkResult;
}
export interface UnlinkResult {
    id: string;
    resource: string;
    status: "revoked";
    rekeyRequired: boolean;
    rekeySubjects: string[];
    idempotent: boolean;
}
export interface CollaboratorPath {
    type: "direct" | "group";
    relation: string;
    linkId?: string;
    group?: string;
    subjectRelation?: string;
    via: Array<{
        resource: string;
        subjectRelation: string;
    }>;
}
export interface ResourceCollaborator {
    kind: ResourceCollaboratorKind;
    id: string;
    linkId?: string;
    resource?: string;
    displayName?: string;
    email?: string;
    relations: string[];
    status: string;
    subjectRelation?: string;
    memberCount?: number;
    access?: {
        direct: boolean;
        paths: CollaboratorPath[];
    };
    recipient?: {
        type: "user" | "email" | "group";
        subject?: string;
        display?: string;
    };
    expiresAt?: number;
}
export interface ResourceCollaboratorList {
    resource: string;
    collaborators: ResourceCollaborator[];
    nextCursor: string | null;
}
export interface ResourceCollaboratorListOptions {
    view?: "direct" | "effective";
    search?: string;
    email?: string;
    subject?: string;
    resourceSubject?: string;
    viaGroup?: string;
    direct?: boolean;
    kind?: ResourceCollaboratorKind;
    kinds?: ResourceCollaboratorKind[];
    status?: string;
    statuses?: string[];
    relations?: string[];
    cursor?: string;
    limit?: number;
}
export interface ResourceSearchResourceFilters {
    search?: string;
    resources?: string[];
    types?: string[];
    parent?: string;
    statuses?: string[];
}
export interface ResourceSearchCollaboratorFilters {
    search?: string;
    email?: string;
    subjects?: string[];
    kinds?: ResourceCollaboratorKind[];
    relations?: string[];
    statuses?: string[];
    view?: "direct" | "effective";
    viaGroups?: string[];
    resourceSubject?: string;
    direct?: boolean;
}
export interface ResourceSearchInput {
    filters?: {
        resource?: ResourceSearchResourceFilters;
        collaborator?: ResourceSearchCollaboratorFilters;
    };
    include?: Array<"parent" | "collaborator_matches">;
    sort?: {
        field?: "display_name" | "resource_type" | "resource";
        direction?: "asc" | "desc";
    };
    page?: {
        limit?: number;
        cursor?: string;
    };
}
export interface ResourceSearchParent {
    resource: string;
    resourceType: string;
    displayName: string;
}
export interface ResourceSearchResult {
    resource: string;
    resourceType: string;
    displayName: string;
    status: string;
    parent?: ResourceSearchParent;
    collaboratorMatches?: ResourceCollaborator[];
}
export interface ResourceSearchList {
    resources: ResourceSearchResult[];
    nextCursor: string | null;
}
export interface OrganizationE2EEPolicyInput {
    requiredAccountCustody: "browser_passphrase" | "temporary_box_then_browser" | "enterprise_box";
    resourceKeyExecutor: "managed" | "customer_box" | "browser";
    automationExecutor: "managed" | "customer_box" | "none";
    functionBindingId?: string;
    resourceKeyPolicy: "organization_only" | "organization_default" | "resource_only";
}
export interface OrganizationE2EEPolicy extends OrganizationE2EEPolicyInput {
    organization: string;
    status: "pending" | "ready" | "unavailable";
    revision: number;
}
export interface ResourceCollaborationPolicyOverride {
    guests: {
        allowed?: boolean;
        allowedDomains?: string[];
    };
}
export interface ResourceCollaborationPolicyMutation {
    resource: string;
    revision: number;
}
export declare class LotorControlError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string);
}
export declare class LotorControlClient {
    private readonly baseUrl;
    private readonly clientId;
    private readonly secretKey;
    private userToken?;
    private readonly fetcher;
    constructor(options: LotorControlClientOptions);
    /** Separate user-scoped client; never elevates or retries as the application. */
    forUser(accessToken: string): LotorControlClient;
    createPortalSession(input: {
        organizationId: string;
        returnUrl: string;
    }): Promise<{
        id: string;
        url: string;
    }>;
    private scimDirectoryPath;
    createSCIMDirectory(organization: string, input: SCIMDirectoryCreateInput, idempotencyKey: string): Promise<SCIMDirectory>;
    scimDirectory(organization: string, directoryId: string): Promise<SCIMDirectory>;
    updateSCIMDirectory(organization: string, directoryId: string, input: SCIMDirectoryUpdateInput, idempotencyKey: string): Promise<SCIMDirectory>;
    scimDirectories(organization: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<SCIMDirectoryList>;
    private organizationBindingPath;
    createOrganizationFunctionBinding(organization: string): Promise<OrganizationFunctionBindingBootstrap>;
    organizationFunctionBindings(organization: string): Promise<OrganizationFunctionBindingStatus[]>;
    organizationFunctionBinding(organization: string, bindingId: string): Promise<OrganizationFunctionBindingStatus>;
    revokeOrganizationFunctionBinding(organization: string, bindingId: string): Promise<void>;
    startOrganizationFunctionBindingChallenge(organization: string, bindingId: string): Promise<OrganizationFunctionBindingChallengeStatus>;
    accountResources(options?: AccountResourceListOptions): Promise<AccountResourceList>;
    accountInvitations(options?: AccountInvitationListOptions): Promise<AccountInvitationList>;
    acceptAccountInvitation(id: string): Promise<AccountInvitationMutation>;
    declineAccountInvitation(id: string): Promise<AccountInvitationMutation>;
    private mutateAccountInvitation;
    rewrapResourcePayload(resource: string, slot: string, input: ResourcePayloadRewrapInput): Promise<ResourcePayloadRewrapResult>;
    deleteResourcePayload(resource: string, slot: string, idempotencyKey: string): Promise<ResourcePayloadMutation>;
    createResourcePayloadUpload(resource: string, slot: string, input: ResourcePayloadUploadInput): Promise<ResourcePayloadUploadIntent>;
    commitResourcePayload(resource: string, slot: string, intent: ResourcePayloadUploadIntent): Promise<ResourcePayloadManifest>;
    /** Sends only storage-required headers. Custom fetch implementations must not inject credentials. */
    uploadResourcePayloadObject(intent: ResourcePayloadUploadIntent, bytes: Uint8Array, options?: {
        signal?: AbortSignal;
    }): Promise<void>;
    /** Verifies at most 64 MiB without decrypting. Custom fetch implementations must
     * not inject credentials; the SDK sends none to the signed storage URL. */
    downloadResourcePayload(lease: ResourcePayloadAccessLease, options?: {
        signal?: AbortSignal;
    }): Promise<Buffer>;
    /** Reads metadata only; does not download or decrypt the object. */
    resourcePayload(resource: string, slot: string): Promise<ResourcePayloadManifest>;
    /** Obtains a version-bound lease under this client's application or user authority. */
    accessResourcePayload(resource: string, slot: string, payloadVersion?: number): Promise<ResourcePayloadAccessLease>;
    resource(resource: string): Promise<Resource>;
    putResource(resource: string, input: ResourceRegistration): Promise<Resource>;
    createSystemResource(input: {
        resourceType: "group" | "service_account";
        displayName: string;
        parent: string;
        keyScope?: "organization" | "resource";
    }, idempotencyKey: string): Promise<DurableOperation>;
    moveResource(resource: string, input: ResourceLifecycleFence & {
        parent: string;
    }, idempotencyKey: string): Promise<DurableOperation>;
    disableResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation>;
    restoreResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation>;
    deleteResource(resource: string, input: ResourceLifecycleFence & {
        subtree: boolean;
    }, idempotencyKey: string): Promise<DurableOperation>;
    operation(operationId: string, options?: {
        signal?: AbortSignal;
    }): Promise<DurableOperation>;
    waitForOperation(operationId: string, options?: OperationWaitOptions): Promise<DurableOperation>;
    issueResourceCredential(resource: string, input: ResourceCredentialIssueInput, idempotencyKey: string): Promise<IssuedResourceCredential>;
    resourceCredentials(resource: string): Promise<ResourceCredentialMetadata[]>;
    rotateResourceCredential(resource: string, credentialId: string, input: ResourceCredentialRotateInput, idempotencyKey: string): Promise<IssuedResourceCredential>;
    revokeResourceCredential(resource: string, credentialId: string, idempotencyKey: string): Promise<ResourceCredentialMetadata>;
    putResourceType(resourceType: string, definition: ResourceTypeDefinition): Promise<ResourceTypeDefinition>;
    createCatalog(input: {
        namespace: string;
        catalogType: "api" | "generic";
        visibility: "application_private" | "organization_private";
        organization?: string;
        discoverable?: boolean;
    }, idempotencyKey: string): Promise<Catalog>;
    availableCatalogs(options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: Catalog[];
        nextCursor?: string;
    }>;
    availableCatalogEntries(catalogId: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: CatalogEntry[];
        snapshotId: string;
        nextCursor?: string;
    }>;
    catalogs(options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: Catalog[];
        nextCursor?: string;
    }>;
    catalog(catalogId: string): Promise<Catalog>;
    importOpenAPI(catalogId: string, input: {
        format: "openapi_3_0" | "openapi_3_1";
        sourceDocument: string;
    }, idempotencyKey: string): Promise<DurableOperation>;
    importDefinitions(catalogId: string, entries: GenericCatalogDefinition[], idempotencyKey: string): Promise<DurableOperation>;
    catalogSnapshots(catalogId: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: CatalogSnapshot[];
        nextCursor?: string;
    }>;
    publishCatalogSnapshot(catalogId: string, snapshotId: string, idempotencyKey: string): Promise<DurableOperation>;
    resourceCatalogEntries(resource: string, catalogId: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: CatalogEntry[];
        nextCursor?: string;
    }>;
    resourceCatalogEntry(resource: string, catalogId: string, entryId: string): Promise<CatalogEntry>;
    catalogEntries(catalogId: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<{
        items: CatalogEntry[];
        nextCursor?: string;
    }>;
    catalogEntry(catalogId: string, entryId: string): Promise<CatalogEntry>;
    bindResourceCatalog(resource: string, input: ResourceLifecycleFence & {
        catalogId: string;
        snapshotId: string;
        entryKinds: string[];
    }, idempotencyKey: string): Promise<DurableOperation>;
    searchResourceLinkCandidates(resource: string, input: ResourceLinkCandidateSearchInput): Promise<ResourceLinkCandidateSearchResult>;
    preflightResourceLinks(resource: string, changes: ResourceLinkChange[]): Promise<ResourceLinkPreflight>;
    commitResourceLinks(resource: string, preflight: ResourceLinkPreflight, envelopes?: ResourceLinkEnvelopeSubmission[]): Promise<ResourceLinkResult>;
    sendResourceLinks(resource: string, input: ResourceLinkSendInput): Promise<ResourceLinkSendResult>;
    unlinkResource(resource: string, linkId: string, idempotencyKey?: string): Promise<UnlinkResult>;
    resourceCollaborators(resource: string, options?: ResourceCollaboratorListOptions): Promise<ResourceCollaboratorList>;
    searchResources(input?: ResourceSearchInput): Promise<ResourceSearchList>;
    organizationE2EEPolicy(organization: string): Promise<OrganizationE2EEPolicy>;
    configureOrganizationE2EE(organization: string, input: OrganizationE2EEPolicyInput): Promise<OrganizationE2EEPolicy>;
    setResourceCollaborationPolicy(resource: string, input: ResourceCollaborationPolicyOverride): Promise<ResourceCollaborationPolicyMutation>;
    private lifecycle;
    private requireResourceGraphUser;
    private request;
    private requestWithMetadata;
}
export interface OrganizationFunctionBindingBootstrap {
    bindingId: string;
    status: "pending";
    bootstrapToken: string;
}
export interface OrganizationFunctionBindingStatus {
    challenge: OrganizationFunctionBindingChallengeStatus;
    bindingId: string;
    status: "pending" | "expired" | "active" | "revoked";
    /** Unix microseconds. */
    bootstrapExpiresAt?: number;
    /** Unix microseconds. */
    lastSeenAt?: number;
    boxSubject?: string;
    signingKeyId?: string;
}
export interface OrganizationFunctionBindingChallengeStatus {
    status: "not_started" | "pending" | "ready" | "expired" | "failed" | "unavailable";
    /** Unix microseconds; deadline for completing a pending challenge. */
    expiresAt?: number;
    /** Unix microseconds. */
    challengedAt?: number;
}
export interface AccountResourceReference {
    id: string;
    resource: string;
    type: string;
    name: string;
}
export interface AccountInvitation {
    id: string;
    resource: AccountResourceReference;
    relation: string;
    status: "pending_acceptance" | "pending_approval";
    expiresAt: number;
    encryptionRequired: boolean;
}
export interface AccountInvitationList {
    invitations: AccountInvitation[];
    nextCursor: string | null;
}
export interface AccountInvitationListOptions {
    cursor?: string;
    limit?: number;
    signal?: AbortSignal;
}
export interface AccountInvitationMutation {
    id: string;
    status: "active" | "pending_encryption" | "declined";
}
export interface AccountResourcePathStep extends AccountResourceReference {
    subjectRelation: string;
}
export interface AccountResourceAccessPath {
    type: "direct" | "group";
    relation: string;
    via: AccountResourcePathStep[];
}
export interface AccountResource extends AccountResourceReference {
    parent?: AccountResourceReference;
    relations: string[];
    accessState: "active" | "pending_encryption";
    access: {
        direct: boolean;
        paths: AccountResourceAccessPath[];
    };
}
export interface AccountResourceList {
    resources: AccountResource[];
    nextCursor: string | null;
}
export interface AccountResourceListOptions {
    parent?: string;
    types?: string[];
    accessStates?: Array<"active" | "pending_encryption">;
    cursor?: string;
    limit?: number;
    signal?: AbortSignal;
}
export interface ResourcePayloadRewrapInput {
    payloadVersion: number;
    expectedWrapRevision: number;
    keyBindingRef: string;
    previousKeyVersion: number;
    keyVersion: number;
    resourceRevision: number;
    lifecycleGeneration: number;
    /** Browser custody attestation; omitted for box execution. */
    wrappedPayloadKey?: string;
    rewrapperSubject?: string;
    rewrapperKeyId?: string;
    rewrapReceipt?: string;
}
export interface ResourcePayloadRewrapResult {
    resource: string;
    slot: string;
    payloadVersion: number;
    wrapRevision: number;
    previousKeyVersion: number;
    keyVersion: number;
    resourceRevision: number;
    lifecycleGeneration: number;
    keyBindingRef: string;
    wrappedPayloadKey: string;
    aadHash: string;
    rewrapperSubject: string;
    rewrapperKeyId: string;
}
export interface ResourcePayloadMutation {
    resource: string;
    slot: string;
    payloadVersion: number;
    state: "deleting" | "deleted";
    idempotent: boolean;
}
export type ResourcePayloadUploadInput = {
    schemaId: string;
    expectedPayloadVersion: number;
    objectDigest: string;
    objectSize: number;
    resourceRevision: number;
    lifecycleGeneration: number;
} & ({
    representation: "raw";
} | {
    representation: "encrypted-envelope-v1";
    encryptionSuite: "AES-256-GCM";
    keyBindingRef: string;
    keyVersion: number;
    wrappedPayloadKey: string;
    aadHash: string;
    encryptorSubject?: string;
    encryptorKeyId?: string;
    encryptionReceipt?: string;
});
export interface ResourcePayloadUploadIntent {
    resource: string;
    slot: string;
    payloadVersion: number;
    expectedPayloadVersion: number;
    uploadUrl: string;
    uploadMethod: "PUT";
    requiredHeaders: Record<string, string>;
    expiresAt: number;
    token: string;
}
interface ResourcePayloadCommon {
    resource: string;
    slot: string;
    payloadVersion: number;
    objectDigest: string;
    objectSize: number;
    resourceRevision: number;
    lifecycleGeneration: number;
}
export type ResourcePayloadManifest = ResourcePayloadCommon & {
    schemaId: string;
    state: "committed" | "deleting" | "deleted";
    committedAt: number;
    deletedAt?: number;
} & ({
    representation: "raw";
} | {
    representation: "encrypted-envelope-v1";
    encryptionSuite: "AES-256-GCM";
    keyBindingRef: string;
    keyVersion: number;
    wrappedPayloadKey: string;
    aadHash: string;
    encryptorSubject: string;
    encryptorKeyId: string;
});
export interface ResourcePayloadAccessLease extends ResourcePayloadCommon {
    representation: "raw" | "encrypted-envelope-v1";
    downloadUrl: string;
    downloadMethod: "GET";
    expiresAt: number;
    audience: string;
}
export {};
