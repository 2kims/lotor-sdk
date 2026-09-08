# Changelog

All notable public API and compatibility changes are documented here. This
project follows Semantic Versioning; breaking changes during `0.x` releases are
called out explicitly.

## Unreleased

### 0.2.0-rc.1 candidate (not published)

- Add bounded, abortable durable-operation polling to the Control client.
  Failed and cancelled operations are returned for caller handling; mutations
  are never retried.

- Add `LotorResourceClient.exchangeCredential` for workload authentication using
  only a resource credential and publishable key. Responses retain the
  server-selected environment and assertion header type. Redirects, ambient
  cookies and application-authority fallback are disabled.
- Add typed workload execution preflight/commit, preserving the capability token,
  resource/catalog/payload revisions and encrypted execution context. Responses
  must match the preflight binding.
- Add caller-key `protectProviderRequest` and `openProviderResponse` helpers,
  using the existing Go AES-256-GCM envelope and command-bound AAD. A Docker
  Go/Node cross-language certificate covers both directions with a 1 MiB body.
  Real Control/box execution certification remains follow-up work.

- Add isolated `forUser` clients. User denials never retry with application
  authority; application credentials stay on the server.
- Add typed member directories, invitation inbox operations, resource
  credentials and organization billing portal sessions.
- Add generic resource candidate search, link preflight/commit/send, unlink,
  collaborator listing and structured resource search. Link capabilities remain
  header-only and delegated denials never retry with application authority.
- Add delegated organization E2EE policy read/configuration and resource guest
  policy mutation. The application secret selects scope; `forUser` supplies the
  required actor and denied requests never elevate.
- Add published Catalog discovery, resource-bound reads and generic imports.
- Breaking: directory projections and catalog bindings require canonical
  resource references rather than reconstructed IDs. Match the Control API
  deployment before upgrading consumers.
- Preserve principal identity, resource-key metadata and pending encryption.
- Add typed resource payload manifests and version-bound access leases, retaining
  delegated user authority and raw versus encrypted representation. These reads
  do not download or decrypt objects.
- Add bounded, cancellable payload downloads with size/digest verification and
  no SDK-injected Control credentials or cookies on storage requests.
- Add raw/encrypted payload upload intents, credential-isolated object uploads
  and capability-bound commits with resource/version fencing.
- Add payload rewrap and idempotent deletion, preserving custody attestations
  and pending deletion state.
- Customer-organization SSO/SCIM runtime support is not included in this candidate.

- Add framework-neutral gateway assertion verification and Node HTTP
  middleware with exact authority, request, origin, expiry, and replay checks.

## 0.1.0-rc.2

- Keep the npm package page intentionally free of repository README content.

## 0.1.0-rc.1

- Add the ESM-only `@lotor.dev/sdk` Node.js package.
- Add LWP/LWPS connectivity, ownership discovery, authenticated owner retry,
  reconnect, watch events, and data-plane operations.
- License the public distribution under Apache-2.0.
