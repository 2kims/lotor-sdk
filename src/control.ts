import { createHash } from "node:crypto";

export interface LotorControlClientOptions {
  baseUrl: string;
  clientId: string;
  secretKey: string;
  fetch?: typeof globalThis.fetch;
}

export interface SCIMDirectory {
  id: string; resource: string; organization: string; credentialResource: string;
  status: "disabled" | "active"; revision: number; baseUrl: string;
}
export interface SCIMDirectoryCreateInput {
  directoryResource: string; credentialResource: string;
  expectedResourceRevision: number; expectedLifecycleGeneration: number;
}
export interface SCIMDirectoryUpdateInput { enabled: boolean; expectedRevision: number }
export interface SCIMDirectoryList { directories: SCIMDirectory[]; nextCursor: string | null }

function mapSCIMDirectory(value: unknown): SCIMDirectory {
  const raw = object(value);
  if (Object.keys(raw).some(key => !["id", "resource", "organization", "credential_resource", "status", "revision", "base_url"].includes(key))) throw new Error("unexpected SCIM directory field");
  if (raw.status !== "disabled" && raw.status !== "active") throw new Error("invalid SCIM directory status");
  const revision = payloadInteger(raw.revision);
  if (revision < 1) throw new Error("invalid SCIM directory revision");
  const baseUrl = directoryString(raw.base_url), parsed = new URL(baseUrl);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("invalid SCIM directory URL");
  return { id: directoryString(raw.id, 256), resource: directoryString(raw.resource, 256), organization: directoryString(raw.organization, 256),
    credentialResource: directoryString(raw.credential_resource, 256), status: raw.status, revision, baseUrl };
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
  payload: { storage: "none" | "lotor" | "provider"; slots: Array<{ name: string; schemaIds: string[]; maximumObjectSize: number; required: boolean }> };
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
  encryption: { required: boolean; status: "not_required" | "provisioning" | "ready" | "failed"; keyScope?: "organization" | "resource"; effectiveKeyResource?: string; keyResource?: string; keyVersion?: number };
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
  id: string; resource: string; issuedTo: string; status: string; displayHint: string;
  version: number; createdAt: number; expiresAt?: number; revokeAt?: number;
  revokedAt?: number; lastUsedAt?: number;
}
export interface IssuedResourceCredential extends ResourceCredentialMetadata { credential: string }
export interface ResourceCredentialIssueInput { issuedTo: string; expiresAt?: number }
export interface ResourceCredentialRotateInput { revokePreviousAt: number; expiresAt?: number }

export type ResourceCollaboratorKind = "user" | "group" | "service_account" | "invitation";
export type ResourceLinkCandidateKind = Exclude<ResourceCollaboratorKind, "invitation">;
export interface ResourceLinkChange {
  action: "grant" | "revoke";
  linkId?: string; collaborator?: string; relation?: string; subject?: string; email?: string;
  subjectResource?: string; subjectRelation?: string;
  provisioning?: "existing_only" | "create_if_missing";
  delivery?: "email" | "in_app" | "external" | "none" | "notification_only";
  cascade?: boolean;
}
export interface ResourceLinkCandidateSearchInput {
  query: string; relation: string; kinds?: ResourceLinkCandidateKind[]; limit?: number; cursor?: string;
}
export interface ResourceLinkCandidate {
  kind: ResourceLinkCandidateKind; displayName: string; subject?: string; resource?: string;
  subjectRelation?: "member"; email?: string;
  linkState: "available" | "linked" | "pending_invitation"; selectable: boolean; reason?: string;
}
export interface ResourceLinkCandidateSearchResult { candidates: ResourceLinkCandidate[]; nextCursor: string | null }
export interface ResourceLinkOutcome {
  linkId?: string; resource: string; subject: string; relation: string;
  state: "active" | "pending_acceptance" | "pending_encryption" | "revoked" | "denied";
  allowed: boolean; reason?: string;
}
export interface ResourceLinkKeyRequirement {
  manifestItemId: string; grantId: string; resource: string; relation: string; keyResource: string; keyVersion: string;
  recipientSubject: string; recipientKeyId: string; encryptionAlgorithm: "X25519"; publicKey: Uint8Array;
  invitationId?: string; activation?: "active_access" | "pending_invitation";
}
export interface ResourceLinkEnvelopeSubmission {
  manifestItemId: string; encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: string; aadHash: string; issuer: string; issuerKeyId: string; signature: string;
}
export interface ResourceLinkResult {
  resource: string;
  status: "ready" | "committing" | "pending_acceptance" | "pending_encryption" | "active" | "failed" | "expired";
  failureReason?: string; expiresAt: number; idempotent: boolean; committable: boolean;
  revisions: { customer: string; graph: string; policy: string; identity: string; billing: string; seat: string; key: string };
  outcomes: ResourceLinkOutcome[];
  capacity: { scope: "per_organization" | "per_account"; before: number; after: number; claim: number; release: number };
  billing: { currentQuantity: number; nextCycleQuantity: number; increase: number; nextCycleReduction: number };
  invitationActions: Array<{ invitationId: string; action: "preserve" | "claim" | "activate" | "supersede" | "cancel"; reason?: string }>;
  keyRequirements: ResourceLinkKeyRequirement[];
  impact: { impactedResources: string[]; retainedResources: string[]; rekeyResources: string[] };
}
export interface ResourceLinkPreflight { result: ResourceLinkResult; token: string }
export interface ResourceLinkSendInput { changes: ResourceLinkChange[] }
export interface ResourceLinkSendResult { preflight: ResourceLinkPreflight; committed: ResourceLinkResult }
export interface UnlinkResult { id: string; resource: string; status: "revoked"; rekeyRequired: boolean; rekeySubjects: string[]; idempotent: boolean }
export interface CollaboratorPath {
  type: "direct" | "group"; relation: string; linkId?: string; group?: string; subjectRelation?: string;
  via: Array<{ resource: string; subjectRelation: string }>;
}
export interface ResourceCollaborator {
  kind: ResourceCollaboratorKind; id: string; linkId?: string; resource?: string; displayName?: string; email?: string;
  relations: string[]; status: string; subjectRelation?: string; memberCount?: number;
  access?: { direct: boolean; paths: CollaboratorPath[] };
  recipient?: { type: "user" | "email" | "group"; subject?: string; display?: string }; expiresAt?: number;
}
export interface ResourceCollaboratorList { resource: string; collaborators: ResourceCollaborator[]; nextCursor: string | null }
export interface ResourceCollaboratorListOptions {
  view?: "direct" | "effective"; search?: string; email?: string; subject?: string; resourceSubject?: string; viaGroup?: string;
  direct?: boolean; kind?: ResourceCollaboratorKind; kinds?: ResourceCollaboratorKind[]; status?: string; statuses?: string[];
  relations?: string[]; cursor?: string; limit?: number;
}
export interface ResourceSearchResourceFilters { search?: string; resources?: string[]; types?: string[]; parent?: string; statuses?: string[] }
export interface ResourceSearchCollaboratorFilters {
  search?: string; email?: string; subjects?: string[]; kinds?: ResourceCollaboratorKind[]; relations?: string[];
  statuses?: string[]; view?: "direct" | "effective"; viaGroups?: string[]; resourceSubject?: string; direct?: boolean;
}
export interface ResourceSearchInput {
  filters?: { resource?: ResourceSearchResourceFilters; collaborator?: ResourceSearchCollaboratorFilters };
  include?: Array<"parent" | "collaborator_matches">;
  sort?: { field?: "display_name" | "resource_type" | "resource"; direction?: "asc" | "desc" };
  page?: { limit?: number; cursor?: string };
}
export interface ResourceSearchParent { resource: string; resourceType: string; displayName: string }
export interface ResourceSearchResult {
  resource: string; resourceType: string; displayName: string; status: string;
  parent?: ResourceSearchParent; collaboratorMatches?: ResourceCollaborator[];
}
export interface ResourceSearchList { resources: ResourceSearchResult[]; nextCursor: string | null }
export interface OrganizationE2EEPolicyInput {
  requiredAccountCustody: "browser_passphrase" | "temporary_box_then_browser" | "enterprise_box";
  resourceKeyExecutor: "managed" | "customer_box" | "browser";
  automationExecutor: "managed" | "customer_box" | "none";
  functionBindingId?: string;
  resourceKeyPolicy: "organization_only" | "organization_default" | "resource_only";
}
export interface OrganizationE2EEPolicy extends OrganizationE2EEPolicyInput {
  organization: string; status: "pending" | "ready" | "unavailable"; revision: number;
}
export interface ResourceCollaborationPolicyOverride { guests: { allowed?: boolean; allowedDomains?: string[] } }
export interface ResourceCollaborationPolicyMutation { resource: string; revision: number }

export class LotorControlError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
  }
}

export class LotorControlClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly secretKey: string;
  private userToken?: string;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: LotorControlClientOptions) {
    const parsed = new URL(options.baseUrl);
    if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== "" && parsed.pathname !== "/")) throw new Error("baseUrl must contain only an origin");
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]"))) throw new Error("baseUrl must use HTTPS outside loopback development");
    this.baseUrl = parsed.origin;
    this.clientId = required(options.clientId, "clientId");
    this.secretKey = required(options.secretKey, "secretKey");
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new Error("fetch is required");
    this.fetcher = fetcher;
  }

  /** Separate user-scoped client; never elevates or retries as the application. */
  forUser(accessToken: string): LotorControlClient {
    const token = required(accessToken, "accessToken");
    if (/[\r\n]/.test(token)) throw new Error("accessToken must not contain line breaks");
    const delegated = new LotorControlClient({ baseUrl: this.baseUrl, clientId: this.clientId, secretKey: this.secretKey, fetch: this.fetcher });
    delegated.userToken = token;
    return delegated;
  }

  async createPortalSession(input: { organizationId: string; returnUrl: string }): Promise<{ id: string; url: string }> {
    const returnUrl = new URL(input.returnUrl);
    const loopback = returnUrl.hostname === "localhost" || returnUrl.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(returnUrl.hostname);
    if ((returnUrl.protocol !== "https:" && !(returnUrl.protocol === "http:" && loopback)) || returnUrl.username || returnUrl.password || returnUrl.search || returnUrl.hash) throw new Error("invalid portal return URL");
    const raw = object(await this.request("/billing/portal-sessions", { method: "POST", body: JSON.stringify({ organization_id: required(input.organizationId, "organizationId"), return_url: input.returnUrl }) }));
    const url = directoryString(raw.url);
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("invalid portal URL");
    return { id: directoryString(raw.id), url };
  }

  private scimDirectoryPath(organization: string, directoryId?: string): string {
    if (!this.userToken) throw new Error("SCIM directory setup requires forUser delegation");
    return `/resources/${encodeURIComponent(directoryString(organization, 256))}/scim-directories${directoryId === undefined ? "" : `/${encodeURIComponent(scimDirectoryID(directoryId))}`}`;
  }

  async createSCIMDirectory(organization: string, input: SCIMDirectoryCreateInput, idempotencyKey: string): Promise<SCIMDirectory> {
    const path = this.scimDirectoryPath(organization);
    for (const value of [input.expectedResourceRevision, input.expectedLifecycleGeneration]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("SCIM resource fences must be positive safe integers");
    }
    return mapSCIMDirectory(await this.request(path, { method: "POST", headers: { "Idempotency-Key": directoryString(idempotencyKey, 256) }, body: JSON.stringify({
      directory_resource: directoryString(input.directoryResource, 256), credential_resource: directoryString(input.credentialResource, 256),
      expected_resource_revision: input.expectedResourceRevision, expected_lifecycle_generation: input.expectedLifecycleGeneration,
    }) }));
  }

  async scimDirectory(organization: string, directoryId: string): Promise<SCIMDirectory> {
    const directory = mapSCIMDirectory(await this.request(this.scimDirectoryPath(organization, directoryId)));
    if (directory.id !== directoryId) throw new Error("SCIM directory response ID mismatch");
    return directory;
  }

  async updateSCIMDirectory(organization: string, directoryId: string, input: SCIMDirectoryUpdateInput, idempotencyKey: string): Promise<SCIMDirectory> {
    if (typeof input.enabled !== "boolean" || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 1) throw new Error("invalid SCIM directory update input");
    const directory = mapSCIMDirectory(await this.request(this.scimDirectoryPath(organization, directoryId), {
      method: "PUT", headers: { "Idempotency-Key": directoryString(idempotencyKey, 256) },
      body: JSON.stringify({ enabled: input.enabled, expected_revision: input.expectedRevision }),
    }));
    if (directory.id !== directoryId) throw new Error("SCIM directory response ID mismatch");
    return directory;
  }

  async scimDirectories(organization: string, options: { cursor?: string; limit?: number } = {}): Promise<SCIMDirectoryList> {
    const path = this.scimDirectoryPath(organization), query = new URLSearchParams();
    if (options.cursor !== undefined) query.set("cursor", directoryString(options.cursor, 4096));
    if (options.limit !== undefined) {
      if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new Error("SCIM page limit must be between 1 and 100");
      query.set("limit", String(options.limit));
    }
    const raw = object(await this.request(path + (query.size ? `?${query}` : "")));
    if (Object.keys(raw).some(key => key !== "directories" && key !== "next_cursor")) throw new Error("unexpected SCIM list field");
    const directories = array(raw.directories).map(mapSCIMDirectory);
    if (directories.length > 100) throw new Error("SCIM page exceeds maximum");
    return { directories, nextCursor: raw.next_cursor === null ? null : directoryString(raw.next_cursor, 4096) };
  }

  private organizationBindingPath(organization: string, bindingId?: string): string {
    if (!this.userToken) throw new Error("organization box operations require forUser delegation");
    return `/resources/${encodeURIComponent(directoryString(organization, 512))}/e2ee/function-bindings${bindingId === undefined ? "" : `/${encodeURIComponent(directoryString(bindingId, 256))}`}`;
  }

  async createOrganizationFunctionBinding(organization: string): Promise<OrganizationFunctionBindingBootstrap> {
    const raw = object(await this.request(this.organizationBindingPath(organization), { method: "POST" }));
    const bindingId = directoryString(raw.binding_id, 256), bootstrapToken = directoryString(raw.bootstrap_token, 2048);
    if (raw.status !== "pending" || !/^efb_[A-Za-z0-9_-]+$/.test(bindingId) || !bootstrapToken.startsWith("e2ee_bootstrap_") || bootstrapToken.length <= "e2ee_bootstrap_".length) throw new Error("invalid organization box bootstrap response");
    return { bindingId, status: "pending", bootstrapToken };
  }

  async organizationFunctionBindings(organization: string): Promise<OrganizationFunctionBindingStatus[]> {
    const raw = array(await this.request(this.organizationBindingPath(organization)));
    if (raw.length > 1) throw new Error("invalid current organization bindings response");
    return raw.map(value => {
      const binding = mapOrganizationFunctionBinding(value);
      if (binding.status === "revoked") throw new Error("invalid current organization binding state");
      return binding;
    });
  }

  async organizationFunctionBinding(organization: string, bindingId: string): Promise<OrganizationFunctionBindingStatus> {
    const binding = mapOrganizationFunctionBinding(await this.request(this.organizationBindingPath(organization, bindingId)));
    if (binding.bindingId !== bindingId) throw new Error("Lotor returned a different organization binding");
    return binding;
  }

  async revokeOrganizationFunctionBinding(organization: string, bindingId: string): Promise<void> {
    await this.request(this.organizationBindingPath(organization, bindingId), { method: "DELETE" });
  }

  async startOrganizationFunctionBindingChallenge(organization: string, bindingId: string): Promise<OrganizationFunctionBindingChallengeStatus> {
    if (!/^efb_[A-Za-z0-9_-]+$/.test(bindingId)) throw new Error("invalid binding ID");
    return mapOrganizationFunctionBindingChallenge(await this.request(`${this.organizationBindingPath(organization, bindingId)}/challenge`, { method: "POST" }));
  }

  async accountResources(options: AccountResourceListOptions = {}): Promise<AccountResourceList> {
    options.signal?.throwIfAborted();
    const query = new URLSearchParams(pageQuery(options));
    if (options.parent !== undefined) query.set("parent", directoryString(options.parent, 512));
    if (options.cursor !== undefined) query.set("cursor", directoryString(options.cursor, 2048));
    for (const type of options.types ?? []) query.append("type", directoryString(type, 128));
    for (const state of options.accessStates ?? []) {
      if (state !== "active" && state !== "pending_encryption") throw new Error("invalid resource access state");
      query.append("access_state", state);
    }
    const raw = object(await this.request(`/me/resources${query.size ? `?${query}` : ""}`, { signal: options.signal }));
    if (raw.next_cursor !== null && typeof raw.next_cursor !== "string") throw new Error("invalid directory cursor");
    return { resources: array(raw.resources).map(mapAccountResource), nextCursor: raw.next_cursor as string | null };
  }

  async accountInvitations(options: AccountInvitationListOptions = {}): Promise<AccountInvitationList> {
    options.signal?.throwIfAborted();
    if (options.cursor !== undefined) directoryString(options.cursor, 2048);
    const raw = object(await this.request(`/me/invitations${pageQuery(options)}`, { signal: options.signal }));
    if (raw.next_cursor !== null && typeof raw.next_cursor !== "string") throw new Error("invalid invitation cursor");
    return { invitations: array(raw.invitations).map(mapAccountInvitation), nextCursor: raw.next_cursor as string | null };
  }

  async acceptAccountInvitation(id: string): Promise<AccountInvitationMutation> {
    return this.mutateAccountInvitation(id, "accept");
  }

  async declineAccountInvitation(id: string): Promise<AccountInvitationMutation> {
    return this.mutateAccountInvitation(id, "decline");
  }

  private async mutateAccountInvitation(id: string, action: "accept" | "decline"): Promise<AccountInvitationMutation> {
    const invitationId = directoryString(required(id, "invitationId"), 256);
    const raw = object(await this.request(`/me/invitations/${encodeURIComponent(invitationId)}/${action}`, { method: "POST" }));
    if (raw.status !== "active" && raw.status !== "pending_encryption" && raw.status !== "declined") throw new Error("invalid invitation mutation status");
    return { id: directoryString(raw.id), status: raw.status };
  }

  async rewrapResourcePayload(resource: string, slot: string, input: ResourcePayloadRewrapInput): Promise<ResourcePayloadRewrapResult> {
    const raw = object(await this.request(`${payloadPath(resource, slot)}/rewraps`, { method: "POST", body: JSON.stringify({
      payload_version: timestamp(input.payloadVersion), expected_wrap_revision: timestamp(input.expectedWrapRevision),
      key_binding_ref: required(input.keyBindingRef, "keyBindingRef"), previous_key_version: timestamp(input.previousKeyVersion), key_version: timestamp(input.keyVersion),
      resource_revision: timestamp(input.resourceRevision), lifecycle_generation: timestamp(input.lifecycleGeneration),
      wrapped_payload_key: input.wrappedPayloadKey, rewrapper_subject: input.rewrapperSubject, rewrapper_key_id: input.rewrapperKeyId, rewrap_receipt: input.rewrapReceipt,
    }) }));
    return { resource: directoryString(raw.resource), slot: directoryString(raw.slot), payloadVersion: payloadInteger(raw.payload_version), wrapRevision: payloadInteger(raw.wrap_revision), previousKeyVersion: payloadInteger(raw.previous_key_version), keyVersion: payloadInteger(raw.key_version), resourceRevision: payloadInteger(raw.resource_revision), lifecycleGeneration: payloadInteger(raw.lifecycle_generation), keyBindingRef: directoryString(raw.key_binding_ref), wrappedPayloadKey: directoryString(raw.wrapped_payload_key), aadHash: directoryString(raw.aad_hash), rewrapperSubject: directoryString(raw.rewrapper_subject), rewrapperKeyId: directoryString(raw.rewrapper_key_id) };
  }

  async deleteResourcePayload(resource: string, slot: string, idempotencyKey: string): Promise<ResourcePayloadMutation> {
    const raw = object(await this.request(payloadPath(resource, slot), { method: "DELETE", headers: idempotency(idempotencyKey) }));
    if ((raw.state !== "deleting" && raw.state !== "deleted") || typeof raw.idempotent !== "boolean") throw new Error("invalid payload deletion state");
    return { resource: directoryString(raw.resource), slot: directoryString(raw.slot), payloadVersion: payloadInteger(raw.payload_version), state: raw.state, idempotent: raw.idempotent };
  }

  async createResourcePayloadUpload(resource: string, slot: string, input: ResourcePayloadUploadInput): Promise<ResourcePayloadUploadIntent> {
    const body: Record<string, unknown> = { schema_id: required(input.schemaId, "schemaId"), representation: input.representation, expected_payload_version: timestamp(input.expectedPayloadVersion), object_digest: required(input.objectDigest, "objectDigest"), object_size: timestamp(input.objectSize), resource_revision: timestamp(input.resourceRevision), lifecycle_generation: timestamp(input.lifecycleGeneration) };
    if (input.representation === "encrypted-envelope-v1") {
      if (input.encryptionSuite !== "AES-256-GCM") throw new Error("invalid encryption suite");
      Object.assign(body, { encryption_suite: input.encryptionSuite, key_binding_ref: required(input.keyBindingRef, "keyBindingRef"), key_version: timestamp(input.keyVersion), wrapped_payload_key: required(input.wrappedPayloadKey, "wrappedPayloadKey"), aad_hash: required(input.aadHash, "aadHash"), encryptor_subject: input.encryptorSubject, encryptor_key_id: input.encryptorKeyId, encryption_receipt: input.encryptionReceipt });
    } else if (input.representation !== "raw") throw new Error("invalid payload representation");
    const result = await this.requestWithMetadata(`${payloadPath(resource, slot)}/uploads`, { method: "POST", body: JSON.stringify(body) });
    const raw = object(result.body);
    const token = result.headers.get("Lotor-Payload-Token")?.trim();
    if (!token) throw new Error("payload upload response omitted its token");
    if (raw.upload_method !== "PUT") throw new Error("invalid payload upload method");
    const requiredHeaders = Object.fromEntries(Object.entries(object(raw.required_headers)).map(([name, value]) => [name, directoryString(value)]));
    return { resource: directoryString(raw.resource), slot: directoryString(raw.slot), payloadVersion: payloadInteger(raw.payload_version), expectedPayloadVersion: payloadInteger(raw.expected_payload_version), uploadUrl: directoryString(raw.upload_url), uploadMethod: "PUT", requiredHeaders, expiresAt: payloadInteger(raw.expires_at), token };
  }

  async commitResourcePayload(resource: string, slot: string, intent: ResourcePayloadUploadIntent): Promise<ResourcePayloadManifest> {
    if (intent.resource !== resource || intent.slot !== slot) throw new Error("payload upload intent target mismatch");
    const token = directoryString(required(intent.token, "payload token"), 512);
    return mapPayloadManifest(await this.request(`${payloadPath(resource, slot)}/commits`, { method: "POST", headers: { "Lotor-Payload-Token": token }, body: JSON.stringify({ expected_payload_version: timestamp(intent.expectedPayloadVersion) }) }));
  }

  /** Sends only storage-required headers. Custom fetch implementations must not inject credentials. */
  async uploadResourcePayloadObject(intent: ResourcePayloadUploadIntent, bytes: Uint8Array, options: { signal?: AbortSignal } = {}): Promise<void> {
    options.signal?.throwIfAborted();
    const url = payloadObjectURL(intent.uploadUrl);
    if (intent.uploadMethod !== "PUT" || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024 * 1024) throw new Error("invalid payload upload method or size");
    const headers = new Headers(intent.requiredHeaders);
    for (const name of headers.keys()) {
      if (["authorization", "proxy-authorization", "cookie", "cookie2", "host", "origin"].includes(name) || name.startsWith("x-lotor-") || name.startsWith("lotor-")) throw new Error("unsafe payload upload header");
    }
    const response = await this.fetcher(url.toString(), { method: "PUT", headers, body: new Uint8Array(bytes).buffer, credentials: "omit", redirect: "error", signal: options.signal });
    await response.body?.cancel();
    if (!response.ok) throw new Error(`payload upload failed with status ${response.status}`);
  }

  /** Verifies at most 64 MiB without decrypting. Custom fetch implementations must
   * not inject credentials; the SDK sends none to the signed storage URL. */
  async downloadResourcePayload(lease: ResourcePayloadAccessLease, options: { signal?: AbortSignal } = {}): Promise<Buffer> {
    options.signal?.throwIfAborted();
    const url = payloadObjectURL(lease.downloadUrl);
    if (lease.downloadMethod !== "GET") throw new Error("invalid payload download method");
    if (!Number.isSafeInteger(lease.objectSize) || lease.objectSize < 0 || lease.objectSize > 64 * 1024 * 1024) throw new Error("invalid payload object size");
    if (!/^[a-fA-F0-9]{64}$/.test(lease.objectDigest)) throw new Error("invalid payload object digest");
    const response = await this.fetcher(url.toString(), { method: "GET", credentials: "omit", redirect: "error", signal: options.signal });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`payload download failed with status ${response.status}`);
    }
    const chunks: Buffer[] = [];
    let size = 0;
    const reader = response.body?.getReader();
    try {
      while (reader) {
        options.signal?.throwIfAborted();
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > lease.objectSize) throw new Error("payload download size does not match lease");
        chunks.push(Buffer.from(part.value));
      }
    } finally {
      if (reader) {
        try { await reader.cancel(); } finally { reader.releaseLock(); }
      }
    }
    if (size !== lease.objectSize) throw new Error("payload download size does not match lease");
    const bytes = Buffer.concat(chunks, size);
    if (createHash("sha256").update(bytes).digest("hex") !== lease.objectDigest.toLowerCase()) throw new Error("payload download digest does not match lease");
    return bytes;
  }

  /** Reads metadata only; does not download or decrypt the object. */
  async resourcePayload(resource: string, slot: string): Promise<ResourcePayloadManifest> {
    return mapPayloadManifest(await this.request(payloadPath(resource, slot)));
  }

  /** Obtains a version-bound lease under this client's application or user authority. */
  async accessResourcePayload(resource: string, slot: string, payloadVersion?: number): Promise<ResourcePayloadAccessLease> {
    if (payloadVersion !== undefined) timestamp(payloadVersion);
    const raw = object(await this.request(`${payloadPath(resource, slot)}/access`, { method: "POST", body: JSON.stringify(payloadVersion === undefined ? {} : { payload_version: payloadVersion }) }));
    if (raw.download_method !== "GET") throw new Error("invalid payload download method");
    return { ...payloadCommon(raw), downloadUrl: directoryString(raw.download_url), downloadMethod: "GET", expiresAt: payloadInteger(raw.expires_at), audience: directoryString(raw.audience) };
  }

  async resource(resource: string): Promise<Resource> {
    return mapResource(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}`));
  }

  async putResource(resource: string, input: ResourceRegistration): Promise<Resource> {
    return mapResource(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}`, { method: "PUT", body: JSON.stringify(resourceRegistration(input)) }));
  }

  async createSystemResource(input: { resourceType: "group" | "service_account"; displayName: string; parent: string; keyScope?: "organization" | "resource" }, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request("/resources", { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ resource_type: input.resourceType, display_name: input.displayName, parent: input.parent, ...(input.keyScope ? { key_scope: input.keyScope } : {}) }) }));
  }

  async moveResource(resource: string, input: ResourceLifecycleFence & { parent: string }, idempotencyKey: string): Promise<DurableOperation> {
    return this.lifecycle(resource, "move", { ...fence(input), parent: input.parent }, idempotencyKey);
  }

  async disableResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation> {
    return this.lifecycle(resource, "disable", fence(input), idempotencyKey);
  }

  async restoreResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation> {
    return this.lifecycle(resource, "restore", fence(input), idempotencyKey);
  }

  async deleteResource(resource: string, input: ResourceLifecycleFence & { subtree: boolean }, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}`, { method: "DELETE", headers: idempotency(idempotencyKey), body: JSON.stringify({ ...fence(input), subtree: input.subtree }) }));
  }

  async operation(operationId: string, options: { signal?: AbortSignal } = {}): Promise<DurableOperation> {
    return mapOperation(await this.request(`/operations/${encodeURIComponent(required(operationId, "operationId"))}`, { signal: options.signal }));
  }

  async waitForOperation(operationId: string, options: OperationWaitOptions = {}): Promise<DurableOperation> {
    const maxAttempts = operationWaitBound(options.maxAttempts ?? 120, "maxAttempts", 1, 10_000);
    const intervalMs = operationWaitBound(options.intervalMs ?? 500, "intervalMs", 0, 60_000);
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      options.signal?.throwIfAborted();
      const operation = await this.operation(operationId, { signal: options.signal });
      options.signal?.throwIfAborted();
      if (["succeeded", "failed", "cancelled"].includes(operation.status)) return operation;
      if (attempt + 1 < maxAttempts) await operationWaitDelay(intervalMs, options.signal);
    }
    throw new Error("Lotor operation exceeded maxAttempts");
  }

  async issueResourceCredential(resource: string, input: ResourceCredentialIssueInput, idempotencyKey: string): Promise<IssuedResourceCredential> {
    return mapIssuedCredential(await this.request(credentialPath(resource), { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ issued_to: required(input.issuedTo, "issuedTo"), ...(input.expiresAt === undefined ? {} : { expires_at: timestamp(input.expiresAt) }) }) }));
  }

  async resourceCredentials(resource: string): Promise<ResourceCredentialMetadata[]> {
    const value = object(await this.request(credentialPath(resource)));
    return array(value.items).map(mapCredential);
  }

  async rotateResourceCredential(resource: string, credentialId: string, input: ResourceCredentialRotateInput, idempotencyKey: string): Promise<IssuedResourceCredential> {
    return mapIssuedCredential(await this.request(`${credentialPath(resource, credentialId)}/rotate`, { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ revoke_previous_at: timestamp(input.revokePreviousAt), ...(input.expiresAt === undefined ? {} : { expires_at: timestamp(input.expiresAt) }) }) }));
  }

  async revokeResourceCredential(resource: string, credentialId: string, idempotencyKey: string): Promise<ResourceCredentialMetadata> {
    return mapCredential(await this.request(credentialPath(resource, credentialId), { method: "DELETE", headers: idempotency(idempotencyKey) }));
  }

  async putResourceType(resourceType: string, definition: ResourceTypeDefinition): Promise<ResourceTypeDefinition> {
    const value = await this.request(`/resource-types/${encodeURIComponent(required(resourceType, "resourceType"))}`, { method: "PUT", body: JSON.stringify(resourceTypeWire(definition)) });
    return definitionFromWire(value);
  }

  async createCatalog(input: { namespace: string; catalogType: "api" | "generic"; visibility: "application_private" | "organization_private"; organization?: string; discoverable?: boolean }, idempotencyKey: string): Promise<Catalog> {
    return mapCatalog(await this.request("/catalogs", { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ namespace: input.namespace, catalog_type: input.catalogType, visibility: input.visibility, ...(input.discoverable === undefined ? {} : { discoverable: input.discoverable }), ...(input.organization ? { organization: input.organization } : {}) }) }));
  }

  async availableCatalogs(options: { cursor?: string; limit?: number } = {}): Promise<{ items: Catalog[]; nextCursor?: string }> {
    const value = object(await this.request(`/me/catalogs${pageQuery(options)}`));
    return { items: array(value.items).map(mapCatalog), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async availableCatalogEntries(catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogEntry[]; snapshotId: string; nextCursor?: string }> {
    const value = object(await this.request(`/me/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries${pageQuery(options)}`));
    if (typeof value.snapshot_id !== "string" || !value.snapshot_id) throw new Error("invalid published snapshot");
    return { items: array(value.items).map(mapEntry), snapshotId: value.snapshot_id, ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async catalogs(options: { cursor?: string; limit?: number } = {}): Promise<{ items: Catalog[]; nextCursor?: string }> {
    const query = pageQuery(options);
    const value = object(await this.request(`/catalogs${query}`));
    return { items: array(value.items).map(mapCatalog), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async catalog(catalogId: string): Promise<Catalog> {
    return mapCatalog(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}`));
  }

  async importOpenAPI(catalogId: string, input: { format: "openapi_3_0" | "openapi_3_1"; sourceDocument: string }, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/imports`, { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ format: input.format, source_document: input.sourceDocument }) }));
  }

  async importDefinitions(catalogId: string, entries: GenericCatalogDefinition[], idempotencyKey: string): Promise<DurableOperation> {
    const sourceDocument = JSON.stringify({ entries: entries.map(entry => ({ semantic_key: entry.semanticKey, entry_kind: entry.entryKind, definition: entry.definition })) });
    return mapOperation(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/imports`, { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ format: "definitions_v1", source_document: sourceDocument }) }));
  }

  async catalogSnapshots(catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogSnapshot[]; nextCursor?: string }> {
    const value = object(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/snapshots${pageQuery(options)}`));
    return { items: array(value.items).map(mapSnapshot), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async publishCatalogSnapshot(catalogId: string, snapshotId: string, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/snapshots/${encodeURIComponent(required(snapshotId, "snapshotId"))}/publish`, { method: "POST", headers: idempotency(idempotencyKey) }));
  }

  async resourceCatalogEntries(resource: string, catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogEntry[]; nextCursor?: string }> {
    const query = new URLSearchParams(pageQuery(options));
    query.set("resource", required(resource, "resource"));
    const value = object(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries?${query}`));
    return { items: array(value.items).map(mapEntry), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async resourceCatalogEntry(resource: string, catalogId: string, entryId: string): Promise<CatalogEntry> {
    const query = new URLSearchParams({ resource: required(resource, "resource") });
    return mapEntry(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries/${encodeURIComponent(required(entryId, "entryId"))}?${query}`));
  }

  async catalogEntries(catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogEntry[]; nextCursor?: string }> {
    const value = object(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries${pageQuery(options)}`));
    return { items: array(value.items).map(mapEntry), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async catalogEntry(catalogId: string, entryId: string): Promise<CatalogEntry> {
    return mapEntry(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries/${encodeURIComponent(required(entryId, "entryId"))}`));
  }

  async bindResourceCatalog(resource: string, input: ResourceLifecycleFence & { catalogId: string; snapshotId: string; entryKinds: string[] }, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}/catalog-binding`, { method: "PUT", headers: idempotency(idempotencyKey), body: JSON.stringify({ catalog_id: input.catalogId, snapshot_id: input.snapshotId, entry_kinds: input.entryKinds, expected_resource_revision: input.expectedRevision, expected_lifecycle_generation: input.expectedLifecycleGeneration }) }));
  }

  async searchResourceLinkCandidates(resource: string, input: ResourceLinkCandidateSearchInput): Promise<ResourceLinkCandidateSearchResult> {
    this.requireResourceGraphUser();
    const query = bounded(input.query, "query", 256);
    if (query.length < 2) throw new Error("query must contain at least two characters");
    if (input.limit !== undefined) pageLimit(input.limit);
    if (input.kinds !== undefined) validateUniqueEnums(input.kinds, resourceLinkCandidateKinds, "candidate kinds", 3);
    return mapResourceLinkCandidates(await this.request(`${resourcePath(resource)}/link-candidates/search`, {
      method: "POST", body: JSON.stringify({ query, relation: bounded(input.relation, "relation", 128),
        ...(input.kinds === undefined ? {} : { kinds: input.kinds }), ...(input.limit === undefined ? {} : { limit: input.limit }),
        ...(input.cursor === undefined ? {} : { cursor: bounded(input.cursor, "cursor", 2048) }) }),
    }));
  }

  async preflightResourceLinks(resource: string, changes: ResourceLinkChange[]): Promise<ResourceLinkPreflight> {
    this.requireResourceGraphUser();
    const normalizedResource = bounded(resource, "resource", 512);
    if (changes.length < 1 || changes.length > 1000) throw new Error("changes must contain between 1 and 1000 items");
    const response = await this.requestWithMetadata(`${resourcePath(normalizedResource)}/links/preflight`, {
      method: "POST", body: JSON.stringify({ changes: changes.map(wireResourceLinkChange) }),
    });
    const token = response.headers.get("Lotor-Link-Token")?.trim();
    if (!token) throw new Error("Lotor link preflight response is missing its token");
    const result = mapResourceLinkResult(response.body);
    if (result.resource !== normalizedResource) throw new Error("Lotor link preflight returned a different resource");
    return { result, token: bounded(token, "link token", 512) };
  }

  async commitResourceLinks(resource: string, preflight: ResourceLinkPreflight, envelopes: ResourceLinkEnvelopeSubmission[] = []): Promise<ResourceLinkResult> {
    this.requireResourceGraphUser();
    const normalizedResource = bounded(resource, "resource", 512);
    const token = bounded(preflight.token, "link token", 512);
    if (preflight.result.resource !== normalizedResource) throw new Error("link preflight resource does not match commit resource");
    if (envelopes.length > 10000) throw new Error("envelopes cannot contain more than 10000 items");
    const result = mapResourceLinkResult(await this.request(`${resourcePath(normalizedResource)}/links/commit`, {
      method: "POST", headers: { "Lotor-Link-Token": token },
      body: JSON.stringify(envelopes.length === 0 ? {} : { envelopes: envelopes.map(wireResourceLinkEnvelope) }),
    }));
    if (result.resource !== normalizedResource) throw new Error("Lotor link commit returned a different resource");
    return result;
  }

  async sendResourceLinks(resource: string, input: ResourceLinkSendInput): Promise<ResourceLinkSendResult> {
    const preflight = await this.preflightResourceLinks(resource, input.changes);
    if (!preflight.result.committable) throw new LotorControlError(409, preflight.result.failureReason ?? "link_denied", preflight.result.failureReason ?? "Lotor rejected a collaboration change");
    return { preflight, committed: await this.commitResourceLinks(resource, preflight) };
  }

  async unlinkResource(resource: string, linkId: string, idempotencyKey?: string): Promise<UnlinkResult> {
    this.requireResourceGraphUser();
    const normalizedResource = bounded(resource, "resource", 512);
    const headers = idempotencyKey === undefined ? undefined : idempotency(bounded(idempotencyKey, "idempotencyKey", 256));
    const result = mapUnlinkResult(await this.request(`${resourcePath(normalizedResource)}/links/${encodeURIComponent(bounded(linkId, "linkId", 256))}`, { method: "DELETE", headers }));
    if (result.resource !== normalizedResource) throw new Error("Lotor unlink returned a different resource");
    return result;
  }

  async resourceCollaborators(resource: string, options: ResourceCollaboratorListOptions = {}): Promise<ResourceCollaboratorList> {
    this.requireResourceGraphUser();
    const normalizedResource = bounded(resource, "resource", 512);
    const query = new URLSearchParams();
    if (options.view !== undefined) { validateEnum(options.view, ["direct", "effective"] as const, "view"); query.set("view", options.view); }
    if (options.search !== undefined) query.set("search", bounded(options.search, "search", 256));
    if (options.email !== undefined) query.set("email", bounded(options.email, "email", 320));
    if (options.subject !== undefined) query.set("subject", bounded(options.subject, "subject", 512));
    if (options.resourceSubject !== undefined) query.set("resource_subject", bounded(options.resourceSubject, "resourceSubject", 640));
    if (options.viaGroup !== undefined) query.set("via_group", bounded(options.viaGroup, "viaGroup", 512));
    if (options.direct !== undefined) { if (typeof options.direct !== "boolean") throw new Error("direct must be a boolean"); query.set("direct", String(options.direct)); }
    const kinds = [...(options.kind === undefined ? [] : [options.kind]), ...(options.kinds ?? [])];
    for (const kind of kinds) { validateEnum(kind, resourceCollaboratorKinds, "collaborator kind"); query.append("kind", kind); }
    for (const status of [...(options.status === undefined ? [] : [options.status]), ...(options.statuses ?? [])]) query.append("status", bounded(status, "status", 64));
    for (const relation of options.relations ?? []) query.append("relation", bounded(relation, "relation", 128));
    if (options.cursor !== undefined) query.set("cursor", bounded(options.cursor, "cursor", 2048));
    if (options.limit !== undefined) query.set("limit", String(pageLimit(options.limit)));
    const result = mapResourceCollaboratorList(await this.request(`${resourcePath(normalizedResource)}/collaborators${query.size ? `?${query}` : ""}`));
    if (result.resource !== normalizedResource) throw new Error("Lotor collaborator list returned a different resource");
    return result;
  }

  async searchResources(input: ResourceSearchInput = {}): Promise<ResourceSearchList> {
    this.requireResourceGraphUser();
    if (input.page?.limit !== undefined) pageLimit(input.page.limit);
    if (input.include !== undefined) validateUniqueEnums(input.include, ["parent", "collaborator_matches"] as const, "resource search includes", 2);
    if (input.sort?.field !== undefined) validateEnum(input.sort.field, ["display_name", "resource_type", "resource"] as const, "resource search sort field");
    if (input.sort?.direction !== undefined) validateEnum(input.sort.direction, ["asc", "desc"] as const, "resource search sort direction");
    const resource = input.filters?.resource, collaborator = input.filters?.collaborator;
    if (collaborator?.kinds !== undefined) for (const kind of collaborator.kinds) validateEnum(kind, resourceCollaboratorKinds, "collaborator kind");
    if (collaborator?.view !== undefined) validateEnum(collaborator.view, ["direct", "effective"] as const, "collaborator view");
    const payload = {
      ...(input.filters === undefined ? {} : { filters: {
        ...(resource === undefined ? {} : { resource: {
          ...(resource.search === undefined ? {} : { search: bounded(resource.search, "resource search", 256) }),
          ...(resource.resources === undefined ? {} : { resources: resource.resources.map(value => bounded(value, "resource", 512)) }),
          ...(resource.types === undefined ? {} : { types: resource.types.map(value => bounded(value, "resource type", 128)) }),
          ...(resource.parent === undefined ? {} : { parent: bounded(resource.parent, "resource parent", 512) }),
          ...(resource.statuses === undefined ? {} : { statuses: resource.statuses.map(value => bounded(value, "resource status", 64)) }),
        } }),
        ...(collaborator === undefined ? {} : { collaborator: {
          ...(collaborator.search === undefined ? {} : { search: bounded(collaborator.search, "collaborator search", 256) }),
          ...(collaborator.email === undefined ? {} : { email: bounded(collaborator.email, "collaborator email", 320) }),
          ...(collaborator.subjects === undefined ? {} : { subjects: collaborator.subjects.map(value => bounded(value, "collaborator subject", 512)) }),
          ...(collaborator.kinds === undefined ? {} : { kinds: collaborator.kinds }),
          ...(collaborator.relations === undefined ? {} : { relations: collaborator.relations.map(value => bounded(value, "collaborator relation", 128)) }),
          ...(collaborator.statuses === undefined ? {} : { statuses: collaborator.statuses.map(value => bounded(value, "collaborator status", 64)) }),
          ...(collaborator.view === undefined ? {} : { view: collaborator.view }),
          ...(collaborator.viaGroups === undefined ? {} : { via_groups: collaborator.viaGroups.map(value => bounded(value, "collaborator via group", 512)) }),
          ...(collaborator.resourceSubject === undefined ? {} : { resource_subject: bounded(collaborator.resourceSubject, "collaborator resource subject", 640) }),
          ...(collaborator.direct === undefined ? {} : { direct: collaborator.direct }),
        } }),
      } }),
      ...(input.include === undefined ? {} : { include: input.include }),
      ...(input.sort === undefined ? {} : { sort: input.sort }),
      ...(input.page === undefined ? {} : { page: { ...(input.page.limit === undefined ? {} : { limit: input.page.limit }), ...(input.page.cursor === undefined ? {} : { cursor: bounded(input.page.cursor, "resource search cursor", 2048) }) } }),
    };
    return mapResourceSearchList(await this.request("/resources/search", { method: "POST", body: JSON.stringify(payload) }));
  }

  async organizationE2EEPolicy(organization: string): Promise<OrganizationE2EEPolicy> {
    this.requireResourceGraphUser();
    const normalized = bounded(organization, "organization", 512);
    const policy = mapOrganizationE2EEPolicy(await this.request(`${resourcePath(normalized)}/e2ee`));
    if (policy.organization !== normalized) throw new Error("Lotor E2EE policy returned a different organization");
    return policy;
  }

  async configureOrganizationE2EE(organization: string, input: OrganizationE2EEPolicyInput): Promise<OrganizationE2EEPolicy> {
    this.requireResourceGraphUser();
    const normalized = bounded(organization, "organization", 512), body = organizationE2EEPolicyWire(input);
    const policy = mapOrganizationE2EEPolicy(await this.request(`${resourcePath(normalized)}/e2ee`, { method: "PUT", body: JSON.stringify(body) }));
    if (policy.organization !== normalized) throw new Error("Lotor E2EE policy returned a different organization");
    return policy;
  }

  async setResourceCollaborationPolicy(resource: string, input: ResourceCollaborationPolicyOverride): Promise<ResourceCollaborationPolicyMutation> {
    this.requireResourceGraphUser();
    const normalized = bounded(resource, "resource", 512), body = resourceCollaborationPolicyWire(input);
    const raw = object(await this.request(`${resourcePath(normalized)}/collaboration-policy`, { method: "PUT", body: JSON.stringify(body) }));
    if (Object.keys(raw).some(key => key !== "resource" && key !== "revision")) throw new Error("unexpected resource collaboration policy field");
    const result = { resource: directoryString(raw.resource, 512), revision: payloadInteger(raw.revision) };
    if (result.resource !== normalized || result.revision < 1) throw new Error("invalid resource collaboration policy response");
    return result;
  }

  private async lifecycle(resource: string, action: "move" | "disable" | "restore", body: Record<string, unknown>, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}/${action}`, { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify(body) }));
  }

  private requireResourceGraphUser(): void {
    if (!this.userToken) throw new Error("resource collaboration requires forUser delegation");
  }

  private async request(path: string, init: RequestInit = {}): Promise<unknown> {
    return (await this.requestWithMetadata(path, init)).body;
  }

  private async requestWithMetadata(path: string, init: RequestInit = {}): Promise<{ body: unknown; headers: Headers }> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    headers.set("X-Lotor-Secret-Key", this.secretKey);
    if (this.userToken !== undefined) headers.set("Authorization", `Bearer ${this.userToken}`);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    const response = await this.fetcher(`${this.baseUrl}/v1/public/applications/${encodeURIComponent(this.clientId)}${path}`, { ...init, headers, redirect: "error" });
    const value: unknown = response.status === 204 ? undefined : await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = object(value);
      throw new LotorControlError(response.status, typeof error.code === "string" ? error.code : "request_failed", typeof error.error === "string" ? error.error : `Lotor request failed with status ${response.status}`);
    }
    return { body: value, headers: response.headers };
  }
}

export interface OrganizationFunctionBindingBootstrap { bindingId: string; status: "pending"; bootstrapToken: string }
export interface OrganizationFunctionBindingStatus {
  challenge: OrganizationFunctionBindingChallengeStatus;
  bindingId: string; status: "pending" | "expired" | "active" | "revoked";
  /** Unix microseconds. */
  bootstrapExpiresAt?: number;
  /** Unix microseconds. */
  lastSeenAt?: number;
  boxSubject?: string; signingKeyId?: string;
}
export interface OrganizationFunctionBindingChallengeStatus {
  status: "not_started" | "pending" | "ready" | "expired" | "failed" | "unavailable";
  /** Unix microseconds; deadline for completing a pending challenge. */
  expiresAt?: number;
  /** Unix microseconds. */
  challengedAt?: number;
}
function mapOrganizationFunctionBindingChallenge(value: unknown): OrganizationFunctionBindingChallengeStatus {
  const raw = object(value);
  if (Object.keys(raw).some(key => !["status", "expires_at", "challenged_at"].includes(key)) || !["not_started", "pending", "ready", "expired", "failed", "unavailable"].includes(String(raw.status))) throw new Error("invalid organization box challenge response");
  const expiresAt = raw.expires_at === undefined ? undefined : payloadInteger(raw.expires_at);
  const challengedAt = raw.challenged_at === undefined ? undefined : payloadInteger(raw.challenged_at);
  if ((["pending", "expired"].includes(String(raw.status)) && !expiresAt) || (raw.status === "ready" && !challengedAt)) throw new Error("invalid organization box challenge evidence");
  return { status: raw.status as OrganizationFunctionBindingChallengeStatus["status"], ...(expiresAt === undefined ? {} : { expiresAt }), ...(challengedAt === undefined ? {} : { challengedAt }) };
}
function mapOrganizationFunctionBinding(value: unknown): OrganizationFunctionBindingStatus {
  const raw = object(value), bindingId = directoryString(raw.binding_id, 256);
  if (!/^efb_[A-Za-z0-9_-]+$/.test(bindingId) || !["pending", "expired", "active", "revoked"].includes(String(raw.status)) || ["bootstrap_token", "connector_token", "bootstrap_token_hash", "connector_token_hash"].some(field => field in raw)) throw new Error("invalid organization box status response");
  return { bindingId, status: raw.status as OrganizationFunctionBindingStatus["status"],
    challenge: mapOrganizationFunctionBindingChallenge(raw.challenge),
    ...(raw.bootstrap_expires_at === undefined ? {} : { bootstrapExpiresAt: payloadInteger(raw.bootstrap_expires_at) }),
    ...(raw.last_seen_at === undefined ? {} : { lastSeenAt: payloadInteger(raw.last_seen_at) }),
    ...(raw.box_subject === undefined ? {} : { boxSubject: directoryString(raw.box_subject) }),
    ...(raw.signing_key_id === undefined ? {} : { signingKeyId: directoryString(raw.signing_key_id) }),
  };
}

export interface AccountResourceReference { id: string; resource: string; type: string; name: string }
export interface AccountInvitation {
  id: string; resource: AccountResourceReference; relation: string;
  status: "pending_acceptance" | "pending_approval"; expiresAt: number; encryptionRequired: boolean;
}
export interface AccountInvitationList { invitations: AccountInvitation[]; nextCursor: string | null }
export interface AccountInvitationListOptions { cursor?: string; limit?: number; signal?: AbortSignal }
export interface AccountInvitationMutation { id: string; status: "active" | "pending_encryption" | "declined" }
export interface AccountResourcePathStep extends AccountResourceReference { subjectRelation: string }
export interface AccountResourceAccessPath { type: "direct" | "group"; relation: string; via: AccountResourcePathStep[] }
export interface AccountResource extends AccountResourceReference {
  parent?: AccountResourceReference;
  relations: string[];
  accessState: "active" | "pending_encryption";
  access: { direct: boolean; paths: AccountResourceAccessPath[] };
}
export interface AccountResourceList { resources: AccountResource[]; nextCursor: string | null }
export interface AccountResourceListOptions {
  parent?: string; types?: string[]; accessStates?: Array<"active" | "pending_encryption">;
  cursor?: string; limit?: number; signal?: AbortSignal;
}
function directoryString(value: unknown, maximum = Infinity): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) throw new Error("invalid directory string");
  return value;
}

function scimDirectoryID(value: unknown): string {
  const directoryId = directoryString(value, 256);
  if (directoryId === "." || directoryId === ".." || /[\\/]/.test(directoryId)) throw new Error("invalid SCIM directory ID");
  return directoryId;
}
function mapAccountReference(value: unknown): AccountResourceReference {
  const raw = object(value);
  if (typeof raw.name !== "string") throw new Error("invalid directory name");
  return { id: directoryString(raw.id), resource: directoryString(raw.resource), type: directoryString(raw.type), name: raw.name };
}
function mapAccountInvitation(value: unknown): AccountInvitation {
  const raw = object(value);
  if (raw.status !== "pending_acceptance" && raw.status !== "pending_approval") throw new Error("invalid invitation status");
  if (typeof raw.encryption_required !== "boolean" || typeof raw.expires_at !== "number") throw new Error("invalid invitation fields");
  return { id: directoryString(raw.id), resource: mapAccountReference(raw.resource), relation: directoryString(raw.relation),
    status: raw.status, expiresAt: timestamp(raw.expires_at), encryptionRequired: raw.encryption_required };
}
function mapAccountResource(value: unknown): AccountResource {
  const raw = object(value), access = object(raw.access);
  if (raw.access_state !== "active" && raw.access_state !== "pending_encryption") throw new Error("invalid directory access state");
  if (typeof access.direct !== "boolean") throw new Error("invalid directory access");
  const paths: AccountResourceAccessPath[] = array(access.paths).map(value => {
    const path = object(value);
    if (path.type !== "direct" && path.type !== "group") throw new Error("invalid directory access path");
    return { type: path.type, relation: directoryString(path.relation), via: array(path.via).map(step => ({ ...mapAccountReference(step), subjectRelation: directoryString(object(step).subject_relation) })) };
  });
  return { ...mapAccountReference(raw), ...(raw.parent === undefined ? {} : { parent: mapAccountReference(raw.parent) }),
    relations: array(raw.relations).map(value => directoryString(value)), accessState: raw.access_state, access: { direct: access.direct, paths } };
}

function required(value: string, name: string): string { const normalized = value?.trim(); if (!normalized) throw new Error(`${name} is required`); return normalized; }
function operationWaitBound(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return value;
}
function operationWaitDelay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  if (milliseconds === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); signal?.removeEventListener("abort", abort); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
function bounded(value: string, name: string, maximum: number): string {
  const normalized = required(value, name);
  if (normalized.length > maximum) throw new Error(`${name} must contain at most ${maximum} characters`);
  return normalized;
}
const resourceLinkCandidateKinds = ["user", "group", "service_account"] as const;
const resourceCollaboratorKinds = [...resourceLinkCandidateKinds, "invitation"] as const;
function validateEnum<T extends string>(value: string, allowed: readonly T[], name: string): asserts value is T {
  if (!(allowed as readonly string[]).includes(value)) throw new Error(`invalid ${name}`);
}
function validateUniqueEnums<T extends string>(values: T[], allowed: readonly T[], name: string, maximum: number): void {
  if (values.length < 1 || values.length > maximum || new Set(values).size !== values.length) throw new Error(`invalid ${name}`);
  for (const value of values) validateEnum(value, allowed, name);
}
function pageLimit(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > 100) throw new Error("limit must be between 1 and 100");
  return value;
}
function resourcePath(resource: string): string { return `/resources/${encodeURIComponent(bounded(resource, "resource", 512))}`; }
function credentialPath(resource: string, id?: string): string { return `/resources/${encodeURIComponent(required(resource, "resource"))}/credentials${id === undefined ? "" : `/${encodeURIComponent(required(id, "credentialId"))}`}`; }
export interface ResourcePayloadRewrapInput {
  payloadVersion: number; expectedWrapRevision: number; keyBindingRef: string;
  previousKeyVersion: number; keyVersion: number; resourceRevision: number; lifecycleGeneration: number;
  /** Browser custody attestation; omitted for box execution. */
  wrappedPayloadKey?: string; rewrapperSubject?: string; rewrapperKeyId?: string; rewrapReceipt?: string;
}
export interface ResourcePayloadRewrapResult {
  resource: string; slot: string; payloadVersion: number; wrapRevision: number;
  previousKeyVersion: number; keyVersion: number; resourceRevision: number; lifecycleGeneration: number;
  keyBindingRef: string; wrappedPayloadKey: string; aadHash: string; rewrapperSubject: string; rewrapperKeyId: string;
}
export interface ResourcePayloadMutation {
  resource: string; slot: string; payloadVersion: number; state: "deleting" | "deleted"; idempotent: boolean;
}
export type ResourcePayloadUploadInput = {
  schemaId: string; expectedPayloadVersion: number; objectDigest: string;
  objectSize: number; resourceRevision: number; lifecycleGeneration: number;
} & ({ representation: "raw" } | {
  representation: "encrypted-envelope-v1"; encryptionSuite: "AES-256-GCM";
  keyBindingRef: string; keyVersion: number; wrappedPayloadKey: string; aadHash: string;
  encryptorSubject?: string; encryptorKeyId?: string; encryptionReceipt?: string;
});
export interface ResourcePayloadUploadIntent {
  resource: string; slot: string; payloadVersion: number; expectedPayloadVersion: number;
  uploadUrl: string; uploadMethod: "PUT"; requiredHeaders: Record<string, string>;
  expiresAt: number; token: string;
}
function payloadObjectURL(value: string): URL {
  const url = new URL(value);
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) || url.username || url.password || url.hash) throw new Error("invalid payload object URL");
  return url;
}
interface ResourcePayloadCommon {
  resource: string; slot: string; payloadVersion: number;
  objectDigest: string; objectSize: number; resourceRevision: number; lifecycleGeneration: number;
}
export type ResourcePayloadManifest = ResourcePayloadCommon & {
  schemaId: string; state: "committed" | "deleting" | "deleted"; committedAt: number; deletedAt?: number;
} & ({ representation: "raw" } | {
  representation: "encrypted-envelope-v1"; encryptionSuite: "AES-256-GCM";
  keyBindingRef: string; keyVersion: number; wrappedPayloadKey: string;
  aadHash: string; encryptorSubject: string; encryptorKeyId: string;
});
export interface ResourcePayloadAccessLease extends ResourcePayloadCommon {
  representation: "raw" | "encrypted-envelope-v1";
  downloadUrl: string; downloadMethod: "GET"; expiresAt: number; audience: string;
}
function payloadPath(resource: string, slot: string): string {
  return `/resources/${encodeURIComponent(directoryString(required(resource, "resource"), 512))}/payloads/${encodeURIComponent(directoryString(required(slot, "slot"), 128))}`;
}
function payloadInteger(value: unknown): number {
  if (typeof value !== "number") throw new Error("invalid payload integer");
  return timestamp(value);
}
function payloadCommon(raw: Record<string, unknown>): ResourcePayloadCommon & { representation: "raw" | "encrypted-envelope-v1" } {
  if (raw.representation !== "raw" && raw.representation !== "encrypted-envelope-v1") throw new Error("invalid payload representation");
  return { resource: directoryString(raw.resource), slot: directoryString(raw.slot), representation: raw.representation, payloadVersion: payloadInteger(raw.payload_version), objectDigest: directoryString(raw.object_digest), objectSize: payloadInteger(raw.object_size), resourceRevision: payloadInteger(raw.resource_revision), lifecycleGeneration: payloadInteger(raw.lifecycle_generation) };
}
function mapPayloadManifest(value: unknown): ResourcePayloadManifest {
  const raw = object(value);
  if (raw.state !== "committed" && raw.state !== "deleting" && raw.state !== "deleted") throw new Error("invalid payload state");
  const common = { ...payloadCommon(raw), schemaId: directoryString(raw.schema_id), state: raw.state, committedAt: payloadInteger(raw.committed_at), ...(raw.deleted_at === undefined ? {} : { deletedAt: payloadInteger(raw.deleted_at) }) };
  if (common.representation === "raw") return { ...common, state: raw.state, representation: "raw" };
  if (raw.encryption_suite !== "AES-256-GCM") throw new Error("invalid payload encryption suite");
  return { ...common, state: raw.state, representation: "encrypted-envelope-v1", encryptionSuite: "AES-256-GCM", keyBindingRef: directoryString(raw.key_binding_ref), keyVersion: payloadInteger(raw.key_version), wrappedPayloadKey: directoryString(raw.wrapped_payload_key), aadHash: directoryString(raw.aad_hash), encryptorSubject: directoryString(raw.encryptor_subject), encryptorKeyId: directoryString(raw.encryptor_key_id) };
}
function timestamp(value: number): number { if (!Number.isSafeInteger(value) || value < 0) throw new Error("timestamp must be a non-negative safe integer"); return value; }
function credentialString(value: unknown): string { if (typeof value !== "string" || !value) throw new Error("invalid credential response field"); return value; }
function mapCredential(value: unknown): ResourceCredentialMetadata {
  const raw = object(value);
  const number = (value: unknown): number => { if (typeof value !== "number") throw new Error("invalid credential response number"); return timestamp(value); };
  return { id: credentialString(raw.id), resource: credentialString(raw.resource), issuedTo: credentialString(raw.issued_to), status: credentialString(raw.status), displayHint: credentialString(raw.display_hint), version: number(raw.version), createdAt: number(raw.created_at),
    ...(raw.expires_at == null ? {} : { expiresAt: number(raw.expires_at) }),
    ...(raw.revoke_at == null ? {} : { revokeAt: number(raw.revoke_at) }),
    ...(raw.revoked_at == null ? {} : { revokedAt: number(raw.revoked_at) }),
    ...(raw.last_used_at == null ? {} : { lastUsedAt: number(raw.last_used_at) }),
  };
}
function mapIssuedCredential(value: unknown): IssuedResourceCredential { return { ...mapCredential(value), credential: credentialString(object(value).credential) }; }
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid Lotor response"); return value as Record<string, unknown>; }
function array(value: unknown): unknown[] { if (!Array.isArray(value)) throw new Error("invalid Lotor list response"); return value; }
function idempotency(value: string): Record<string, string> { return { "Idempotency-Key": required(value, "idempotencyKey") }; }
function fence(value: ResourceLifecycleFence): Record<string, unknown> { return { expected_revision: value.expectedRevision, expected_lifecycle_generation: value.expectedLifecycleGeneration }; }
function pageQuery(options: { cursor?: string; limit?: number }): string {
  const query = new URLSearchParams();
  if (options.cursor) query.set("cursor", options.cursor);
  if (options.limit !== undefined) {
    if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new Error("limit must be between 1 and 100");
    query.set("limit", String(options.limit));
  }
  return query.size ? `?${query}` : "";
}
function nullableString(value: unknown, name: string, maximum = Infinity): string | null {
  if (value === null) return null;
  return directoryString(value, maximum);
}
function responseBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`invalid ${name}`);
  return value;
}
function wireResourceLinkChange(change: ResourceLinkChange): Record<string, unknown> {
  validateEnum(change.action, ["grant", "revoke"] as const, "link action");
  if (change.cascade !== undefined && typeof change.cascade !== "boolean") throw new Error("cascade must be a boolean");
  if (change.provisioning !== undefined) validateEnum(change.provisioning, ["existing_only", "create_if_missing"] as const, "link provisioning");
  if (change.delivery !== undefined) validateEnum(change.delivery, ["email", "in_app", "external", "none", "notification_only"] as const, "link delivery");
  const wire = {
    action: change.action,
    ...(change.linkId === undefined ? {} : { link_id: bounded(change.linkId, "linkId", 256) }),
    ...(change.collaborator === undefined ? {} : { collaborator: bounded(change.collaborator, "collaborator", 512) }),
    ...(change.relation === undefined ? {} : { relation: bounded(change.relation, "relation", 128) }),
    ...(change.subject === undefined ? {} : { subject: bounded(change.subject, "subject", 512) }),
    ...(change.email === undefined ? {} : { email: bounded(change.email, "email", 320) }),
    ...(change.subjectResource === undefined ? {} : { subject_resource: bounded(change.subjectResource, "subjectResource", 512) }),
    ...(change.subjectRelation === undefined ? {} : { subject_relation: bounded(change.subjectRelation, "subjectRelation", 128) }),
    ...(change.provisioning === undefined ? {} : { provisioning: change.provisioning }),
    ...(change.delivery === undefined ? {} : { delivery: change.delivery }),
    ...(change.cascade === undefined ? {} : { cascade: change.cascade }),
  };
  if (change.action === "grant" && change.relation === undefined) throw new Error("grant relation is required");
  if (change.action === "revoke" && change.linkId === undefined && change.collaborator === undefined) throw new Error("revoke linkId or collaborator is required");
  return wire;
}
function wireResourceLinkEnvelope(envelope: ResourceLinkEnvelopeSubmission): Record<string, string> {
  if (envelope.encryptionSuite !== "X25519-HKDF-SHA256-AES-256-GCM") throw new Error("invalid resource link envelope suite");
  return { manifest_item_id: bounded(envelope.manifestItemId, "manifestItemId", 256), encryption_suite: envelope.encryptionSuite,
    ciphertext: bounded(envelope.ciphertext, "ciphertext", 65536), aad_hash: bounded(envelope.aadHash, "aadHash", 128),
    issuer: bounded(envelope.issuer, "issuer", 512), issuer_key_id: bounded(envelope.issuerKeyId, "issuerKeyId", 256),
    signature: bounded(envelope.signature, "signature", 256) };
}
function mapResourceLinkCandidates(value: unknown): ResourceLinkCandidateSearchResult {
  const raw = object(value);
  return { candidates: array(raw.candidates).map(item => {
    const candidate = object(item), kind = directoryString(candidate.kind) as ResourceLinkCandidateKind;
    validateEnum(kind, resourceLinkCandidateKinds, "candidate kind");
    const linkState = directoryString(candidate.link_state) as ResourceLinkCandidate["linkState"];
    validateEnum(linkState, ["available", "linked", "pending_invitation"] as const, "candidate link state");
    const mapped: ResourceLinkCandidate = { kind, displayName: directoryString(candidate.display_name, 512), linkState,
      selectable: responseBoolean(candidate.selectable, "candidate selectable"),
      ...(candidate.subject === undefined ? {} : { subject: directoryString(candidate.subject, 512) }),
      ...(candidate.resource === undefined ? {} : { resource: directoryString(candidate.resource, 512) }),
      ...(candidate.email === undefined ? {} : { email: directoryString(candidate.email, 320) }),
      ...(candidate.reason === undefined ? {} : { reason: directoryString(candidate.reason, 128) }),
      ...(candidate.subject_relation === undefined ? {} : { subjectRelation: candidate.subject_relation as "member" }),
    };
    if (candidate.subject_relation !== undefined && candidate.subject_relation !== "member") throw new Error("invalid candidate subject relation");
    if (kind === "user" && mapped.subject === undefined) throw new Error("user candidate is missing its subject");
    if (kind !== "user" && mapped.resource === undefined) throw new Error("resource candidate is missing its resource");
    if (kind === "group" && mapped.subjectRelation !== "member") throw new Error("group candidate is missing its member subject relation");
    if (kind === "service_account" && mapped.subjectRelation !== undefined) throw new Error("service account candidate cannot be a subject set");
    return mapped;
  }), nextCursor: nullableString(raw.next_cursor, "candidate cursor", 2048) };
}
function decodeX25519PublicKey(value: unknown): Uint8Array {
  const encoded = directoryString(value, 128);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.includes("=")) throw new Error("invalid recipient public key");
  const decoded = new Uint8Array(Buffer.from(encoded, "base64url"));
  if (decoded.length !== 32 || Buffer.from(decoded).toString("base64url") !== encoded) throw new Error("invalid recipient public key");
  return decoded;
}
function mapResourceLinkResult(value: unknown): ResourceLinkResult {
  const raw = object(value), revisions = object(raw.revisions), capacity = object(raw.capacity), billing = object(raw.billing), impact = object(raw.impact);
  const status = directoryString(raw.status) as ResourceLinkResult["status"];
  validateEnum(status, ["ready", "committing", "pending_acceptance", "pending_encryption", "active", "failed", "expired"] as const, "resource link status");
  const scope = directoryString(capacity.scope) as ResourceLinkResult["capacity"]["scope"];
  validateEnum(scope, ["per_organization", "per_account"] as const, "resource link capacity scope");
  return {
    resource: directoryString(raw.resource, 512), status,
    ...(raw.failure_reason === undefined ? {} : { failureReason: directoryString(raw.failure_reason) }),
    expiresAt: payloadInteger(raw.expires_at), idempotent: responseBoolean(raw.idempotent, "link idempotency"), committable: responseBoolean(raw.committable, "link committability"),
    revisions: { customer: directoryString(revisions.customer), graph: directoryString(revisions.graph), policy: directoryString(revisions.policy), identity: directoryString(revisions.identity), billing: directoryString(revisions.billing), seat: directoryString(revisions.seat), key: directoryString(revisions.key) },
    outcomes: array(raw.outcomes).map(item => { const outcome = object(item), state = directoryString(outcome.state) as ResourceLinkOutcome["state"]; validateEnum(state, ["active", "pending_acceptance", "pending_encryption", "revoked", "denied"] as const, "link outcome state"); return {
      ...(outcome.link_id === undefined ? {} : { linkId: directoryString(outcome.link_id, 256) }), resource: directoryString(outcome.resource, 512), subject: directoryString(outcome.subject, 512), relation: directoryString(outcome.relation, 128), state,
      allowed: responseBoolean(outcome.allowed, "link outcome allowed"), ...(outcome.reason === undefined ? {} : { reason: directoryString(outcome.reason) }),
    }; }),
    capacity: { scope, before: payloadInteger(capacity.before), after: payloadInteger(capacity.after), claim: payloadInteger(capacity.claim), release: payloadInteger(capacity.release) },
    billing: { currentQuantity: payloadInteger(billing.current_quantity), nextCycleQuantity: payloadInteger(billing.next_cycle_quantity), increase: payloadInteger(billing.increase), nextCycleReduction: payloadInteger(billing.next_cycle_reduction) },
    invitationActions: array(raw.invitation_actions).map(item => { const action = object(item), name = directoryString(action.action) as ResourceLinkResult["invitationActions"][number]["action"]; validateEnum(name, ["preserve", "claim", "activate", "supersede", "cancel"] as const, "invitation action"); return { invitationId: directoryString(action.invitation_id), action: name, ...(action.reason === undefined ? {} : { reason: directoryString(action.reason) }) }; }),
    keyRequirements: array(raw.key_requirements).map(item => { const requirement = object(item); if (requirement.encryption_algorithm !== "X25519") throw new Error("invalid key requirement algorithm");
      let activation: ResourceLinkKeyRequirement["activation"];
      if (requirement.activation !== undefined) { const decoded = directoryString(requirement.activation); validateEnum(decoded, ["active_access", "pending_invitation"] as const, "key activation"); activation = decoded; }
      return { manifestItemId: directoryString(requirement.manifest_item_id), grantId: directoryString(requirement.grant_id), resource: directoryString(requirement.resource, 512), relation: directoryString(requirement.relation, 128), keyResource: directoryString(requirement.key_resource, 512), keyVersion: directoryString(requirement.key_version), recipientSubject: directoryString(requirement.recipient_subject, 512), recipientKeyId: directoryString(requirement.recipient_key_id, 256), encryptionAlgorithm: "X25519", publicKey: decodeX25519PublicKey(requirement.public_key), ...(requirement.invitation_id === undefined ? {} : { invitationId: directoryString(requirement.invitation_id) }), ...(activation === undefined ? {} : { activation }) };
    }),
    impact: { impactedResources: array(impact.impacted_resources).map(item => directoryString(item, 512)), retainedResources: array(impact.retained_resources).map(item => directoryString(item, 512)), rekeyResources: array(impact.rekey_resources).map(item => directoryString(item, 512)) },
  };
}
function mapUnlinkResult(value: unknown): UnlinkResult {
  const raw = object(value);
  if (raw.status !== "revoked") throw new Error("invalid unlink status");
  return { id: directoryString(raw.id, 256), resource: directoryString(raw.resource, 512), status: "revoked", rekeyRequired: responseBoolean(raw.rekey_required, "unlink rekey requirement"), rekeySubjects: array(raw.rekey_subjects).map(item => directoryString(item, 512)), idempotent: responseBoolean(raw.idempotent, "unlink idempotency") };
}
function mapResourceCollaborator(value: unknown): ResourceCollaborator {
  const raw = object(value), kind = directoryString(raw.kind) as ResourceCollaboratorKind;
  validateEnum(kind, resourceCollaboratorKinds, "collaborator kind");
  const access = raw.access === undefined ? undefined : object(raw.access), recipient = raw.recipient === undefined ? undefined : object(raw.recipient);
  return { kind, id: directoryString(raw.id, 512), ...(raw.link_id === undefined ? {} : { linkId: directoryString(raw.link_id, 256) }), ...(raw.resource === undefined ? {} : { resource: directoryString(raw.resource, 512) }),
    ...(raw.display_name === undefined ? {} : { displayName: directoryString(raw.display_name, 512) }), ...(raw.email === undefined ? {} : { email: directoryString(raw.email, 320) }),
    relations: array(raw.relations).map(item => directoryString(item, 128)), status: directoryString(raw.status, 64), ...(raw.subject_relation === undefined ? {} : { subjectRelation: directoryString(raw.subject_relation, 128) }),
    ...(raw.member_count === undefined ? {} : { memberCount: payloadInteger(raw.member_count) }),
    ...(access === undefined ? {} : { access: { direct: responseBoolean(access.direct, "collaborator direct access"), paths: array(access.paths).map(item => { const path = object(item), type = directoryString(path.type) as CollaboratorPath["type"]; validateEnum(type, ["direct", "group"] as const, "collaborator path type"); return { type, relation: directoryString(path.relation, 128), ...(path.link_id === undefined ? {} : { linkId: directoryString(path.link_id, 256) }), ...(path.group === undefined ? {} : { group: directoryString(path.group, 512) }), ...(path.subject_relation === undefined ? {} : { subjectRelation: directoryString(path.subject_relation, 128) }), via: array(path.via).map(item => { const step = object(item); return { resource: directoryString(step.resource, 512), subjectRelation: directoryString(step.subject_relation, 128) }; }) }; }) } }),
    ...(recipient === undefined ? {} : { recipient: mapCollaboratorRecipient(recipient) }), ...(raw.expires_at === undefined ? {} : { expiresAt: payloadInteger(raw.expires_at) }) };
}
function mapCollaboratorRecipient(raw: Record<string, unknown>): ResourceCollaborator["recipient"] {
  const type = directoryString(raw.type) as "user" | "email" | "group";
  validateEnum(type, ["user", "email", "group"] as const, "collaborator recipient type");
  return { type, ...(raw.subject === undefined ? {} : { subject: directoryString(raw.subject, 512) }), ...(raw.display === undefined ? {} : { display: directoryString(raw.display, 512) }) };
}
function mapResourceCollaboratorList(value: unknown): ResourceCollaboratorList {
  const raw = object(value);
  return { resource: directoryString(raw.resource, 512), collaborators: array(raw.collaborators).map(mapResourceCollaborator), nextCursor: nullableString(raw.next_cursor, "collaborator cursor", 2048) };
}
function mapResourceSearchList(value: unknown): ResourceSearchList {
  const raw = object(value);
  return { resources: array(raw.resources).map(item => { const resource = object(item), parent = resource.parent === undefined ? undefined : object(resource.parent); return {
    resource: directoryString(resource.resource, 512), resourceType: directoryString(resource.resource_type, 128), displayName: directoryString(resource.display_name, 512), status: directoryString(resource.status, 64),
    ...(parent === undefined ? {} : { parent: { resource: directoryString(parent.resource, 512), resourceType: directoryString(parent.resource_type, 128), displayName: directoryString(parent.display_name, 512) } }),
    ...(resource.collaborator_matches === undefined ? {} : { collaboratorMatches: array(resource.collaborator_matches).map(mapResourceCollaborator) }),
  }; }), nextCursor: nullableString(raw.next_cursor, "resource search cursor", 2048) };
}
function organizationE2EEPolicyWire(input: OrganizationE2EEPolicyInput): Record<string, string> {
  validateEnum(input.requiredAccountCustody, ["browser_passphrase", "temporary_box_then_browser", "enterprise_box"] as const, "required account custody");
  validateEnum(input.resourceKeyExecutor, ["managed", "customer_box", "browser"] as const, "resource key executor");
  validateEnum(input.automationExecutor, ["managed", "customer_box", "none"] as const, "automation executor");
  validateEnum(input.resourceKeyPolicy, ["organization_only", "organization_default", "resource_only"] as const, "resource key policy");
  return { required_account_custody: input.requiredAccountCustody, resource_key_executor: input.resourceKeyExecutor,
    automation_executor: input.automationExecutor, ...(input.functionBindingId === undefined ? {} : { function_binding_id: bounded(input.functionBindingId, "functionBindingId", 256) }),
    resource_key_policy: input.resourceKeyPolicy };
}
function mapOrganizationE2EEPolicy(value: unknown): OrganizationE2EEPolicy {
  const raw = object(value), allowed = ["organization", "required_account_custody", "resource_key_executor", "automation_executor", "function_binding_id", "resource_key_policy", "status", "revision"];
  if (Object.keys(raw).some(key => !allowed.includes(key))) throw new Error("unexpected organization E2EE policy field");
  const input = { requiredAccountCustody: directoryString(raw.required_account_custody) as OrganizationE2EEPolicyInput["requiredAccountCustody"], resourceKeyExecutor: directoryString(raw.resource_key_executor) as OrganizationE2EEPolicyInput["resourceKeyExecutor"], automationExecutor: directoryString(raw.automation_executor) as OrganizationE2EEPolicyInput["automationExecutor"], resourceKeyPolicy: directoryString(raw.resource_key_policy) as OrganizationE2EEPolicyInput["resourceKeyPolicy"] };
  organizationE2EEPolicyWire(input);
  const status = directoryString(raw.status) as OrganizationE2EEPolicy["status"];
  validateEnum(status, ["pending", "ready", "unavailable"] as const, "organization E2EE policy status");
  const revision = payloadInteger(raw.revision);
  if (revision < 1) throw new Error("invalid organization E2EE policy revision");
  return { organization: directoryString(raw.organization, 512), ...input, ...(raw.function_binding_id === undefined ? {} : { functionBindingId: directoryString(raw.function_binding_id, 256) }), status, revision };
}
function resourceCollaborationPolicyWire(input: ResourceCollaborationPolicyOverride): Record<string, unknown> {
  const guests = input?.guests;
  if (!guests || (guests.allowed === undefined && guests.allowedDomains === undefined)) throw new Error("guest policy must contain a restriction");
  if (guests.allowed !== undefined && typeof guests.allowed !== "boolean") throw new Error("guest allowed must be a boolean");
  if (guests.allowedDomains !== undefined && (guests.allowedDomains.length < 1 || guests.allowedDomains.length > 100 || new Set(guests.allowedDomains).size !== guests.allowedDomains.length)) throw new Error("invalid guest allowed domains");
  const domains = guests.allowedDomains?.map(domain => { const value = bounded(domain, "allowed domain", 253); if (value.length < 3) throw new Error("allowed domain must contain at least 3 characters"); return value; });
  return { guests: { ...(guests.allowed === undefined ? {} : { allowed: guests.allowed }), ...(domains === undefined ? {} : { allowed_domains: domains }) } };
}
function resourceRegistration(input: ResourceRegistration): Record<string, unknown> { return { resource_type: input.resourceType, ...(input.displayName ? { display_name: input.displayName } : {}), ...(input.parent ? { parent: input.parent } : {}), ...(input.keyScope ? { key_scope: input.keyScope } : {}) }; }
function resourceTypeWire(value: ResourceTypeDefinition): Record<string, unknown> { return { resource_type: value.resourceType, kind: value.kind, allowed_parent_types: value.allowedParentTypes, lifecycle: value.lifecycle, direct_links: value.directLinks, relations: value.relations, ...(value.inheritedRelations ? { inherited_relations: value.inheritedRelations } : {}), ...(value.mayActAsPrincipal !== undefined ? { may_act_as_principal: value.mayActAsPrincipal } : {}), ...(value.mayActAsSubjectSet !== undefined ? { may_act_as_subject_set: value.mayActAsSubjectSet } : {}), key_behavior: value.keyBehavior, ...(value.catalogEntryKinds ? { catalog_entry_kinds: value.catalogEntryKinds } : {}), payload: { storage: value.payload.storage, slots: value.payload.slots.map(slot => ({ name: slot.name, schema_ids: slot.schemaIds, maximum_object_size: slot.maximumObjectSize, required: slot.required })) } }; }
function definitionFromWire(value: unknown): ResourceTypeDefinition { const raw = object(value); const payload = object(raw.payload); return { resourceType: String(raw.resource_type), kind: raw.kind as ResourceTypeDefinition["kind"], allowedParentTypes: array(raw.allowed_parent_types).map(String), lifecycle: "application", directLinks: Boolean(raw.direct_links), relations: array(raw.relations).map(String), ...(Array.isArray(raw.inherited_relations) ? { inheritedRelations: raw.inherited_relations.map(String) } : {}), ...(typeof raw.may_act_as_principal === "boolean" ? { mayActAsPrincipal: raw.may_act_as_principal } : {}), ...(typeof raw.may_act_as_subject_set === "boolean" ? { mayActAsSubjectSet: raw.may_act_as_subject_set } : {}), keyBehavior: raw.key_behavior as ResourceTypeDefinition["keyBehavior"], ...(Array.isArray(raw.catalog_entry_kinds) ? { catalogEntryKinds: raw.catalog_entry_kinds.map(String) as ResourceTypeDefinition["catalogEntryKinds"] } : {}), payload: { storage: payload.storage as ResourceTypeDefinition["payload"]["storage"], slots: array(payload.slots).map(item => { const slot = object(item); return { name: String(slot.name), schemaIds: array(slot.schema_ids).map(String), maximumObjectSize: Number(slot.maximum_object_size), required: Boolean(slot.required) }; }) } }; }
function mapOperation(value: unknown): DurableOperation {
  const raw = object(value);
  if (typeof raw.kind !== "string" || !["resource_create", "resource_move", "resource_disable", "resource_restore", "resource_delete", "catalog_import", "catalog_publish", "catalog_binding"].includes(raw.kind)) throw new Error("invalid durable operation kind");
  if (typeof raw.status !== "string" || !["pending", "running", "succeeded", "failed", "cancelled"].includes(raw.status)) throw new Error("invalid durable operation status");
  if (typeof raw.target_kind !== "string" || !["resource", "catalog", "catalog_snapshot"].includes(raw.target_kind)) throw new Error("invalid durable operation target kind");
  if (typeof raw.created_at !== "number" || typeof raw.updated_at !== "number") throw new Error("invalid durable operation timestamps");
  return {
    id: directoryString(raw.id), kind: raw.kind as DurableOperation["kind"], status: raw.status as DurableOperation["status"],
    targetKind: raw.target_kind as DurableOperation["targetKind"], targetId: directoryString(raw.target_id), requestHash: directoryString(raw.request_hash),
    ...(raw.error_code === undefined ? {} : { errorCode: directoryString(raw.error_code) }),
    createdAt: timestamp(raw.created_at), updatedAt: timestamp(raw.updated_at),
  };
}
function mapCatalog(value: unknown): Catalog { const raw = object(value); if (raw.catalog_type !== "api" && raw.catalog_type !== "generic") throw new Error("invalid catalog type"); if (raw.discoverable !== undefined && typeof raw.discoverable !== "boolean") throw new Error("invalid catalog discoverability"); return { id: String(raw.id), namespace: String(raw.namespace), catalogType: raw.catalog_type, visibility: raw.visibility as Catalog["visibility"], ...(typeof raw.discoverable === "boolean" ? { discoverable: raw.discoverable } : {}), ...(typeof raw.organization === "string" ? { organization: raw.organization } : {}), status: raw.status as Catalog["status"], ...(typeof raw.published_snapshot_id === "string" ? { publishedSnapshotId: raw.published_snapshot_id } : {}), createdAt: Number(raw.created_at) }; }
function mapSnapshot(value: unknown): CatalogSnapshot { const raw = object(value); return { id: String(raw.id), catalogId: String(raw.catalog_id), sourceDigest: String(raw.source_digest), importerVersion: String(raw.importer_version), digest: String(raw.digest), status: raw.status as CatalogSnapshot["status"], entryCount: Number(raw.entry_count), ...(typeof raw.published_at === "number" ? { publishedAt: raw.published_at } : {}), createdAt: Number(raw.created_at) }; }
function mapEntry(value: unknown): CatalogEntry { const raw = object(value); return { id: String(raw.id), catalogId: String(raw.catalog_id), semanticKey: String(raw.semantic_key), entryKind: raw.entry_kind as CatalogEntry["entryKind"], revisionId: String(raw.revision_id), revisionDigest: String(raw.revision_digest), definition: object(raw.definition) }; }
function mapResource(value: unknown): Resource {
  const raw = object(value);
  const encryption = object(raw.encryption);
  const binding = raw.catalog_binding === undefined ? undefined : object(raw.catalog_binding);
  if (typeof raw.display_name !== "string") throw new Error("invalid resource display name");
  if (typeof raw.status !== "string" || !["pending_encryption", "pending_payload", "pending_encryption_payload", "active", "disabled", "deleting", "failed", "deleted"].includes(raw.status)) throw new Error("invalid resource status");
  if (typeof encryption.required !== "boolean" || typeof encryption.status !== "string" || !["not_required", "provisioning", "ready", "failed"].includes(encryption.status)) throw new Error("invalid resource encryption state");
  if (encryption.key_scope !== undefined && encryption.key_scope !== "organization" && encryption.key_scope !== "resource") throw new Error("invalid resource key scope");
  const integer = (value: unknown): number => {
    if (typeof value !== "number") throw new Error("invalid resource integer");
    return timestamp(value);
  };
  return {
    id: directoryString(raw.id), resource: directoryString(raw.resource), resourceType: directoryString(raw.resource_type), displayName: raw.display_name,
    ...(raw.principal_subject === undefined ? {} : { principalSubject: directoryString(raw.principal_subject) }),
    ...(raw.parent === undefined ? {} : { parent: directoryString(raw.parent) }),
    status: raw.status as Resource["status"], revision: integer(raw.revision), lifecycleGeneration: integer(raw.lifecycle_generation),
    encryption: {
      required: encryption.required, status: encryption.status as Resource["encryption"]["status"],
      ...(typeof encryption.key_scope === "string" ? { keyScope: encryption.key_scope as "organization" | "resource" } : {}),
      ...(encryption.effective_key_resource === undefined ? {} : { effectiveKeyResource: directoryString(encryption.effective_key_resource) }),
      ...(encryption.key_resource === undefined ? {} : { keyResource: directoryString(encryption.key_resource) }),
      ...(encryption.key_version === undefined ? {} : { keyVersion: integer(encryption.key_version) }),
    },
    ...(binding ? { catalogBinding: {
      resource: directoryString(binding.resource), catalogId: directoryString(binding.catalog_id), snapshotId: directoryString(binding.snapshot_id), snapshotDigest: directoryString(binding.snapshot_digest),
      entryKinds: array(binding.entry_kinds).map(value => directoryString(value)), resourceRevision: integer(binding.resource_revision),
    } } : {}),
  };
}
