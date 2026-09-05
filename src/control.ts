export interface LotorControlClientOptions {
  baseUrl: string;
  clientId: string;
  secretKey: string;
  fetch?: typeof globalThis.fetch;
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
  catalogEntryKinds?: Array<"api.operation" | "api.schema">;
  payload: { storage: "none" | "lotor" | "provider"; slots: Array<{ name: string; schemaIds: string[]; maximumObjectSize: number; required: boolean }> };
}

export interface ResourceRegistration {
  resourceType: string;
  displayName?: string;
  parent?: string;
  keyScope?: "organization" | "resource";
}

export interface ResourceCatalogBinding {
  catalogId: string;
  snapshotId: string;
  snapshotDigest: string;
  entryKinds: Array<"api.operation">;
  resourceRevision: number;
}

export interface Resource {
  id: string;
  resource: string;
  resourceType: string;
  displayName: string;
  parent?: string;
  status: "pending_encryption" | "pending_payload" | "pending_encryption_payload" | "active" | "disabled" | "deleting" | "failed" | "deleted";
  revision: number;
  lifecycleGeneration: number;
  encryption: { required: boolean; status: "not_required" | "provisioning" | "ready" | "failed"; keyScope?: "organization" | "resource"; effectiveKeyResource?: string };
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

export interface Catalog {
  id: string;
  namespace: string;
  catalogType: "api";
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
  entryKind: "api.operation" | "api.schema";
  revisionId: string;
  revisionDigest: string;
  definition: Record<string, unknown>;
}

export interface ResourceLifecycleFence {
  expectedRevision: number;
  expectedLifecycleGeneration: number;
}

export class LotorControlError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
  }
}

export class LotorControlClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly secretKey: string;
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

  async operation(operationId: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/operations/${encodeURIComponent(required(operationId, "operationId"))}`));
  }

  async putResourceType(resourceType: string, definition: ResourceTypeDefinition): Promise<ResourceTypeDefinition> {
    const value = await this.request(`/resource-types/${encodeURIComponent(required(resourceType, "resourceType"))}`, { method: "PUT", body: JSON.stringify(resourceTypeWire(definition)) });
    return definitionFromWire(value);
  }

  async createCatalog(input: { namespace: string; catalogType: "api"; visibility: "application_private" | "organization_private"; organization?: string }, idempotencyKey: string): Promise<Catalog> {
    return mapCatalog(await this.request("/catalogs", { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify({ namespace: input.namespace, catalog_type: input.catalogType, visibility: input.visibility, ...(input.organization ? { organization: input.organization } : {}) }) }));
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

  async catalogSnapshots(catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogSnapshot[]; nextCursor?: string }> {
    const value = object(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/snapshots${pageQuery(options)}`));
    return { items: array(value.items).map(mapSnapshot), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async publishCatalogSnapshot(catalogId: string, snapshotId: string, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/snapshots/${encodeURIComponent(required(snapshotId, "snapshotId"))}/publish`, { method: "POST", headers: idempotency(idempotencyKey) }));
  }

  async catalogEntries(catalogId: string, options: { cursor?: string; limit?: number } = {}): Promise<{ items: CatalogEntry[]; nextCursor?: string }> {
    const value = object(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries${pageQuery(options)}`));
    return { items: array(value.items).map(mapEntry), ...(typeof value.next_cursor === "string" ? { nextCursor: value.next_cursor } : {}) };
  }

  async catalogEntry(catalogId: string, entryId: string): Promise<CatalogEntry> {
    return mapEntry(await this.request(`/catalogs/${encodeURIComponent(required(catalogId, "catalogId"))}/entries/${encodeURIComponent(required(entryId, "entryId"))}`));
  }

  async bindResourceCatalog(resource: string, input: ResourceLifecycleFence & { catalogId: string; snapshotId: string; entryKinds: Array<"api.operation"> }, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}/catalog-binding`, { method: "PUT", headers: idempotency(idempotencyKey), body: JSON.stringify({ catalog_id: input.catalogId, snapshot_id: input.snapshotId, entry_kinds: input.entryKinds, expected_resource_revision: input.expectedRevision, expected_lifecycle_generation: input.expectedLifecycleGeneration }) }));
  }

  private async lifecycle(resource: string, action: "move" | "disable" | "restore", body: Record<string, unknown>, idempotencyKey: string): Promise<DurableOperation> {
    return mapOperation(await this.request(`/resources/${encodeURIComponent(required(resource, "resource"))}/${action}`, { method: "POST", headers: idempotency(idempotencyKey), body: JSON.stringify(body) }));
  }

  private async request(path: string, init: RequestInit = {}): Promise<unknown> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    headers.set("X-Lotor-Secret-Key", this.secretKey);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    const response = await this.fetcher(`${this.baseUrl}/v1/public/applications/${encodeURIComponent(this.clientId)}${path}`, { ...init, headers, redirect: "error" });
    const value: unknown = response.status === 204 ? undefined : await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = object(value);
      throw new LotorControlError(response.status, typeof error.code === "string" ? error.code : "request_failed", typeof error.error === "string" ? error.error : `Lotor request failed with status ${response.status}`);
    }
    return value;
  }
}

function required(value: string, name: string): string { const normalized = value?.trim(); if (!normalized) throw new Error(`${name} is required`); return normalized; }
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid Lotor response"); return value as Record<string, unknown>; }
function array(value: unknown): unknown[] { if (!Array.isArray(value)) throw new Error("invalid Lotor list response"); return value; }
function idempotency(value: string): Record<string, string> { return { "Idempotency-Key": required(value, "idempotencyKey") }; }
function fence(value: ResourceLifecycleFence): Record<string, unknown> { return { expected_revision: value.expectedRevision, expected_lifecycle_generation: value.expectedLifecycleGeneration }; }
function pageQuery(options: { cursor?: string; limit?: number }): string { const query = new URLSearchParams(); if (options.cursor) query.set("cursor", options.cursor); if (options.limit) query.set("limit", String(options.limit)); return query.size ? `?${query}` : ""; }
function resourceRegistration(input: ResourceRegistration): Record<string, unknown> { return { resource_type: input.resourceType, ...(input.displayName ? { display_name: input.displayName } : {}), ...(input.parent ? { parent: input.parent } : {}), ...(input.keyScope ? { key_scope: input.keyScope } : {}) }; }
function resourceTypeWire(value: ResourceTypeDefinition): Record<string, unknown> { return { resource_type: value.resourceType, kind: value.kind, allowed_parent_types: value.allowedParentTypes, lifecycle: value.lifecycle, direct_links: value.directLinks, relations: value.relations, ...(value.inheritedRelations ? { inherited_relations: value.inheritedRelations } : {}), ...(value.mayActAsPrincipal !== undefined ? { may_act_as_principal: value.mayActAsPrincipal } : {}), ...(value.mayActAsSubjectSet !== undefined ? { may_act_as_subject_set: value.mayActAsSubjectSet } : {}), key_behavior: value.keyBehavior, ...(value.catalogEntryKinds ? { catalog_entry_kinds: value.catalogEntryKinds } : {}), payload: { storage: value.payload.storage, slots: value.payload.slots.map(slot => ({ name: slot.name, schema_ids: slot.schemaIds, maximum_object_size: slot.maximumObjectSize, required: slot.required })) } }; }
function definitionFromWire(value: unknown): ResourceTypeDefinition { const raw = object(value); const payload = object(raw.payload); return { resourceType: String(raw.resource_type), kind: raw.kind as ResourceTypeDefinition["kind"], allowedParentTypes: array(raw.allowed_parent_types).map(String), lifecycle: "application", directLinks: Boolean(raw.direct_links), relations: array(raw.relations).map(String), ...(Array.isArray(raw.inherited_relations) ? { inheritedRelations: raw.inherited_relations.map(String) } : {}), ...(typeof raw.may_act_as_principal === "boolean" ? { mayActAsPrincipal: raw.may_act_as_principal } : {}), ...(typeof raw.may_act_as_subject_set === "boolean" ? { mayActAsSubjectSet: raw.may_act_as_subject_set } : {}), keyBehavior: raw.key_behavior as ResourceTypeDefinition["keyBehavior"], ...(Array.isArray(raw.catalog_entry_kinds) ? { catalogEntryKinds: raw.catalog_entry_kinds.map(String) as ResourceTypeDefinition["catalogEntryKinds"] } : {}), payload: { storage: payload.storage as ResourceTypeDefinition["payload"]["storage"], slots: array(payload.slots).map(item => { const slot = object(item); return { name: String(slot.name), schemaIds: array(slot.schema_ids).map(String), maximumObjectSize: Number(slot.maximum_object_size), required: Boolean(slot.required) }; }) } }; }
function mapOperation(value: unknown): DurableOperation { const raw = object(value); return { id: String(raw.id), kind: raw.kind as DurableOperation["kind"], status: raw.status as DurableOperation["status"], targetKind: raw.target_kind as DurableOperation["targetKind"], targetId: String(raw.target_id), requestHash: String(raw.request_hash), ...(typeof raw.error_code === "string" ? { errorCode: raw.error_code } : {}), createdAt: Number(raw.created_at), updatedAt: Number(raw.updated_at) }; }
function mapCatalog(value: unknown): Catalog { const raw = object(value); return { id: String(raw.id), namespace: String(raw.namespace), catalogType: "api", visibility: raw.visibility as Catalog["visibility"], ...(typeof raw.organization === "string" ? { organization: raw.organization } : {}), status: raw.status as Catalog["status"], ...(typeof raw.published_snapshot_id === "string" ? { publishedSnapshotId: raw.published_snapshot_id } : {}), createdAt: Number(raw.created_at) }; }
function mapSnapshot(value: unknown): CatalogSnapshot { const raw = object(value); return { id: String(raw.id), catalogId: String(raw.catalog_id), sourceDigest: String(raw.source_digest), importerVersion: String(raw.importer_version), digest: String(raw.digest), status: raw.status as CatalogSnapshot["status"], entryCount: Number(raw.entry_count), ...(typeof raw.published_at === "number" ? { publishedAt: raw.published_at } : {}), createdAt: Number(raw.created_at) }; }
function mapEntry(value: unknown): CatalogEntry { const raw = object(value); return { id: String(raw.id), catalogId: String(raw.catalog_id), semanticKey: String(raw.semantic_key), entryKind: raw.entry_kind as CatalogEntry["entryKind"], revisionId: String(raw.revision_id), revisionDigest: String(raw.revision_digest), definition: object(raw.definition) }; }
function mapResource(value: unknown): Resource { const raw = object(value); const encryption = object(raw.encryption); const binding = raw.catalog_binding === undefined ? undefined : object(raw.catalog_binding); return { id: String(raw.id), resource: String(raw.resource), resourceType: String(raw.resource_type), displayName: String(raw.display_name), ...(typeof raw.parent === "string" ? { parent: raw.parent } : {}), status: raw.status as Resource["status"], revision: Number(raw.revision), lifecycleGeneration: Number(raw.lifecycle_generation), encryption: { required: Boolean(encryption.required), status: encryption.status as Resource["encryption"]["status"], ...(typeof encryption.key_scope === "string" ? { keyScope: encryption.key_scope as "organization" | "resource" } : {}), ...(typeof encryption.effective_key_resource === "string" ? { effectiveKeyResource: encryption.effective_key_resource } : {}) }, ...(binding ? { catalogBinding: { catalogId: String(binding.catalog_id), snapshotId: String(binding.snapshot_id), snapshotDigest: String(binding.snapshot_digest), entryKinds: array(binding.entry_kinds).map(String) as Array<"api.operation">, resourceRevision: Number(binding.resource_revision) } } : {}) }; }
