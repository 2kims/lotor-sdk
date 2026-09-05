export {
  LotorClient, LotorError, ErrorCode, withOwnerRetry,
  type ClientOptions, type OwnerRetryOptions, type LotorTlsOptions, type LotorEvent, type EventHandler,
  type CompositionPin, type LifecycleResult, type OrganizationInvitation,
} from "./client.js";
export {
  OwnershipResolver, ownershipAddress, verifyOwnership,
  type Ownership, type OwnershipScope, type OwnershipDiscoveryOptions,
} from "./ownership.js";
export {
  GATEWAY_ASSERTION_HEADER,
  GatewayAssertionError,
  GatewayAssertionVerifier,
  gatewayAssertionMiddleware,
  type GatewayAssertionAuthority,
  type GatewayAssertionClaims,
  type GatewayAssertionMiddlewareContext,
  type GatewayAssertionMiddlewareOptions,
  type GatewayAssertionNext,
  type GatewayAssertionReplayStore,
  type GatewayAssertionRequest,
  type GatewayAssertionVerifierOptions,
} from "./gateway-assertion.js";
export {
  LotorControlClient,
  LotorControlError,
  type LotorControlClientOptions,
  type ResourceTypeDefinition,
  type ResourceRegistration,
  type Resource,
  type ResourceCatalogBinding,
  type DurableOperation,
  type Catalog,
  type CatalogSnapshot,
  type CatalogEntry,
} from "./control.js";
