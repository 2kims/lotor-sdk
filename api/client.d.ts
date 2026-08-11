import { type OwnershipResolver } from "./ownership.js";
export declare const ErrorCode: {
    readonly MOVED: 20;
};
export declare class LotorError extends Error {
    code: number;
    detail: string;
    constructor(code: number, detail: string);
}
/** A server-pushed change event (from a WATCH subscription). */
export interface LotorEvent {
    type: string;
    target: string;
    detail: Record<string, unknown>;
    logSeq: number;
}
export interface CompositionPin {
    operation: string;
    resultHash: string;
    version: number;
    poolRef?: string;
    compositionSubject?: string;
}
export interface PolicyInput {
    pin: CompositionPin;
    scopeRef: string;
    destinationRef?: string;
    regionRef?: string;
    executionPolicyRef?: string;
    evidenceRefs?: string[];
    retentionDays?: number;
    reveal?: boolean;
    export?: boolean;
}
export interface LifecycleResult {
    accepted: boolean;
    reason: string;
    invitationId: string;
    seatId: string;
    active: number;
    reserved: number;
    used: number;
    maximum: number;
    remaining: number;
    logSeq: number;
    evidence: string;
    compositionVersion: number;
}
export interface OrganizationInvitation {
    id: string;
    invitee: string;
    role: string;
    seatId: string;
    expiresAt: number;
    seatReserved: boolean;
}
export type EventHandler = (ev: LotorEvent) => void;
/** TLS settings for the LWP connection (the data plane serves server-TLS; mTLS via cert/key is
 *  supported if a deployment requires a client cert). */
export interface LotorTlsOptions {
    ca?: string | Buffer | Array<string | Buffer>;
    servername?: string;
    rejectUnauthorized?: boolean;
    cert?: string | Buffer;
    key?: string | Buffer;
}
export interface ClientOptions {
    host?: string;
    port?: number;
    /** Connect over TLS. `true` uses defaults (system roots); an object configures CA/SNI/mTLS. */
    tls?: boolean | LotorTlsOptions;
    /** Auto-reconnect on unexpected drop (default true). */
    reconnect?: boolean;
    /** Backoff cap, ms (default 5000). */
    maxRetryDelayMs?: number;
    onDisconnect?: () => void;
    onReconnect?: () => void;
    /** Resolve the exact signed scope owner before opening the LWP connection. */
    ownership?: OwnershipResolver;
}
export interface OwnerRetryOptions extends Omit<ClientOptions, "host" | "port" | "ownership"> {
    ownership: OwnershipResolver;
    apiKey: string;
}
export declare class LotorClient {
    private host;
    private port;
    private reconnect;
    private maxRetryDelayMs;
    private tlsOpts;
    private onDisconnect?;
    private onReconnect?;
    private sock;
    private buf;
    private nextId;
    private pending;
    private subs;
    private apiKey?;
    private closing;
    private reconnecting;
    private ready;
    private readyResolve;
    private constructor();
    /** Connect, then complete the HELLO handshake. */
    static connect(opts?: ClientOptions): Promise<LotorClient>;
    private resetReady;
    /** Open a socket + replay the session (HELLO, AUTH, WATCH subscriptions). Throws on any failure. */
    private establish;
    private dial;
    /** A live connection dropped — start (at most one) reconnect loop. */
    private handleDrop;
    private reconnectLoop;
    private onData;
    /** Low-level send (no readiness gate) — used by the handshake/reconnect path. */
    private sendRaw;
    /** Public request path — waits until the connection is ready (queues during a reconnect). */
    private request;
    private doHello;
    private doAuth;
    private doWatch;
    /** AUTH binds the connection to a tenant. The key is remembered and replayed on reconnect. */
    auth(apiKey: string): Promise<{
        tenant: string;
        plan: string;
        scope: string;
        connId: string;
    }>;
    /** AUTH.VERIFY — validate an end-user credential (1=JWT, 2=sealed cookie) against the tenant's keys. */
    authVerify(credType: 1 | 2, credential: string): Promise<{
        valid: boolean;
        subject: string;
        org: string;
        expiresAt: number;
        reason: string;
    }>;
    /** ACCESS.CHECK — "is (subject, relation, object) allowed?" */
    accessCheck(subject: string, relation: string, object: string): Promise<{
        allow: boolean;
        reason: string;
        ttl: number;
    }>;
    /** Resolve a canonical entitlement or authorization decision against one immutable composition. */
    accessCheckPinned(subject: string, relation: string, object: string, pin: CompositionPin): Promise<{
        allow: boolean;
        reason: string;
        ttl: number;
        evidence: string;
        compositionVersion: number;
    }>;
    /** Evaluate canonical approval/protection/security/residency policy without executing effects. */
    policyCheck(subject: string, input: PolicyInput): Promise<{
        state: "allow" | "deny" | "requires_approval";
        reasons: string[];
        evidence: string;
        compositionVersion: number;
        sourcePins: string[];
    }>;
    /** ACCESS.GRANT — add a (subject, relation, object) tuple (durable). Publishes grant_changed. */
    accessGrant(subject: string, relation: string, object: string, expiresAt?: number): Promise<{
        committed: boolean;
        logSeq: number;
    }>;
    /** ACCESS.EXPAND — list subjects that have `relation` to `object` (e.g. members of an org). */
    accessExpand(object: string, relation: string, limit?: number): Promise<string[]>;
    /** METER.CONSUME — durable, idempotent usage. When the meter has an overage rule and the quota is
     *  exceeded, the consume auto-buys blocks from the wallet: `reason` is `overage_granted` and
     *  `blocksPurchased` / `walletBalance` are set (the `max` reflects the extended allowance). */
    meterConsume(scope: string, meter: string, n?: number, idempotencyKey?: string): Promise<{
        accepted: boolean;
        reason: string;
        remaining: number;
        used: number;
        max: number;
        logSeq: number;
        blocksPurchased?: number;
        walletBalance?: number;
        grantDrawn?: number;
        grantRemaining?: number;
    }>;
    /** Durable canonical usage against one exact composition pin. */
    meterConsumePinned(scope: string, meter: string, n: number, idempotencyKey: string, pin: CompositionPin): Promise<{
        accepted: boolean;
        reason: string;
        remaining: number;
        used: number;
        max: number;
        logSeq: number;
        evidence: string;
        compositionVersion: number;
    }>;
    meterReleasePinned(scope: string, meter: string, n: number, idempotencyKey: string, pin: CompositionPin): Promise<{
        released: boolean;
        remaining: number;
        logSeq: number;
        evidence: string;
        compositionVersion: number;
        reason: string;
    }>;
    seatClaimPinned(scope: string, seatType: string, user: string, idempotencyKey: string, pin: CompositionPin): Promise<{
        outcome: number;
        reason: string;
        used: number;
        max: number;
        seatId: string;
        logSeq: number;
        evidence: string;
        compositionVersion: number;
    }>;
    seatReleasePinned(scope: string, seatType: string, user: string, pin: CompositionPin): Promise<{
        released: boolean;
        used: number;
        logSeq: number;
        evidence: string;
        compositionVersion: number;
        reason: string;
    }>;
    /** Create an invitation and apply its executable Seat Board policy in one durable transition. */
    invitationCreatePinned(input: {
        scope: string;
        actor: string;
        invitationId: string;
        invitee: string;
        role: string;
        ticket: string;
        expiresAt: number;
        idempotencyKey: string;
        pin: CompositionPin;
    }): Promise<LifecycleResult>;
    /** Convert a reserved invitation into membership and role access without a seat gap. */
    invitationAccept(ticket: string, authenticatedInvitee: string, memberSubject: string, idempotencyKey: string): Promise<LifecycleResult>;
    invitationCancel(scope: string, actor: string, invitationId: string, idempotencyKey: string): Promise<LifecycleResult>;
    invitationList(scope: string): Promise<OrganizationInvitation[]>;
    memberRemove(scope: string, actor: string, memberSubject: string, idempotencyKey: string): Promise<LifecycleResult>;
    memberRoleSetPinned(scope: string, actor: string, memberSubject: string, role: string, idempotencyKey: string, pin: CompositionPin): Promise<LifecycleResult>;
    /** ALLOWANCE.GRANT — issue a one-time purchase addon: durable extra `units` of `meter` that carry
     *  across billing cycles until used up or `expiresAt` (epoch micros; 0 = never). Two funding modes:
     *  omit `wallet`/`cost` for a control-issued grant (already paid via Stripe), or pass them to fund
     *  it from a prepaid wallet (atomic debit + grant; rejected if the balance is short). */
    allowanceGrant(scope: string, meter: string, units: number, opts?: {
        expiresAt?: number;
        wallet?: string;
        cost?: number;
        idempotencyKey?: string;
    }): Promise<{
        accepted: boolean;
        reason: string;
        unitsTotal: number;
        walletBalance: number;
    }>;
    /** ALLOWANCE.GET — remaining (non-expired) one-time addon units for a meter. */
    allowanceBalance(scope: string, meter: string): Promise<{
        remaining: number;
        grants: number;
    }>;
    /** METER.GET — current usage for a counter. */
    meterGet(scope: string, meter: string): Promise<{
        used: number;
        max: number;
        remaining: number;
        interval: string;
    }>;
    meterGetPinned(scope: string, meter: string, pin: CompositionPin): Promise<{
        used: number;
        max: number;
        remaining: number;
        interval: string;
        resetsAt: number;
        evidence: string;
        compositionVersion: number;
        reason: string;
    }>;
    /** WALLET.CREDIT — add credits to a prepaid wallet (top-up / control auto-reload). Idempotent
     *  when `idempotencyKey` is set: a retried reload never double-credits. */
    walletCredit(scope: string, wallet: string, amount: number, idempotencyKey?: string): Promise<{
        accepted: boolean;
        reason: string;
        balance: number;
    }>;
    /** WALLET.DEBIT — draw down a prepaid wallet on consumption; `accepted` is false (reason
     *  `insufficient_funds`) when the balance is too low. Idempotent when `idempotencyKey` is set. */
    walletDebit(scope: string, wallet: string, amount: number, idempotencyKey?: string): Promise<{
        accepted: boolean;
        reason: string;
        balance: number;
    }>;
    private walletOp;
    /** WALLET.GET — current prepaid balance. */
    walletBalance(scope: string, wallet: string): Promise<number>;
    /** WATCH — subscribe to change selectors; `handler` fires on each matching event. Re-established
     *  automatically across reconnects. Returns the watch id. */
    watch(selectors: string[], handler: EventHandler): Promise<string>;
    /** Subscribe to a wallet's low-balance events (`wallet_low`). `handler` fires when the balance
     *  crosses below its configured per-account threshold; re-armed once a credit recovers it. Sugar over
     *  `watch(["wallet:<scope>:<wallet>"])`. Returns the watch id. */
    onWalletLow(scope: string, wallet: string, handler: (e: {
        scope: string;
        wallet: string;
        balance: number;
        threshold: number;
    }) => void): Promise<string>;
    /** UNWATCH — cancel a subscription (by the id from `watch`). */
    unwatch(watchId: string): Promise<void>;
    /** PING — returns the server time (ms). */
    ping(): Promise<number>;
    quit(): Promise<void>;
}
/**
 * Run one logical operation and follow at most one authenticated MOVED assertion. Mutating
 * callbacks must reuse their original idempotency key when invoked a second time.
 */
export declare function withOwnerRetry<T>(opts: OwnerRetryOptions, operation: (client: LotorClient) => Promise<T>): Promise<T>;
