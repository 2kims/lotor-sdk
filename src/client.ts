// A minimal Lotor LWP client for Node. One warm TCP connection, pipelined: each request gets a unique
// request_id and resolves when its response frame arrives. Auto-reconnects on drop — re-dialing,
// replaying HELLO+AUTH, and re-establishing WATCH subscriptions — so callers see a stable client.

import net from "node:net";
import tls from "node:tls";
import {
  decodeFrame, encodeFrame, FrameType, Op, Status, PROTO_VERSION,
  addr, bool, str, u64, type Frame, type Value,
} from "./wire.js";
import { ownershipAddress, type OwnershipResolver } from "./ownership.js";

export const ErrorCode = {
  MOVED: 0x0014,
} as const;

export class LotorError extends Error {
  constructor(public code: number, public detail: string) {
    super(`LWP error ${code}: ${detail}`);
  }
}

interface Pending {
  resolve: (args: Value[]) => void;
  reject: (err: Error) => void;
}

/** A server-pushed change event (from a WATCH subscription). */
export interface LotorEvent {
  type: string; // e.g. "grant_changed", "config_changed", "revoked"
  target: string; // the addr the change is about
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

function capacityPin(pin: CompositionPin): Value {
  const values: Array<[string, Value]> = [
    ["composition_hash", str(pin.resultHash)],
    ["composition_version", u64(pin.version)],
    ["operation", str(pin.operation)],
  ];
  if (pin.poolRef) values.push(["pool_ref", str(pin.poolRef)]);
  return { t: "map", v: values };
}
export type EventHandler = (ev: LotorEvent) => void;

/** TLS settings for the LWP connection (the data plane serves server-TLS; mTLS via cert/key is
 *  supported if a deployment requires a client cert). */
export interface LotorTlsOptions {
  ca?: string | Buffer | Array<string | Buffer>; // CA(s) to verify the server (PEM). Omit for system roots.
  servername?: string; // SNI / name to verify against the cert SAN (defaults to host)
  rejectUnauthorized?: boolean; // verify the server cert (default true)
  cert?: string | Buffer; // client cert (only if the server requires mTLS)
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

interface Subscription {
  selectors: string[];
  handler: EventHandler;
  id?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class LotorClient {
  private sock!: net.Socket;
  private buf: Buffer = Buffer.alloc(0);
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private subs: Subscription[] = [];

  private apiKey?: string;
  private closing = false;
  private reconnecting = false;
  private ready!: Promise<void>;
  private readyResolve!: () => void;

  private constructor(
    private host: string,
    private port: number,
    private reconnect: boolean,
    private maxRetryDelayMs: number,
    private tlsOpts: LotorTlsOptions | undefined,
    private onDisconnect?: () => void,
    private onReconnect?: () => void,
  ) {
    this.resetReady();
  }

  /** Connect, then complete the HELLO handshake. */
  static async connect(opts: ClientOptions = {}): Promise<LotorClient> {
    let host = opts.host ?? "127.0.0.1";
    let port = opts.port ?? 7420;
    let tlsOpts = opts.tls === true ? {} : (opts.tls || undefined);
    if (opts.ownership) {
      const owner = ownershipAddress(await opts.ownership.resolve());
      host = owner.host;
      port = owner.port;
      if (owner.tls && tlsOpts === undefined) tlsOpts = {};
      if (!owner.tls && tlsOpts !== undefined) {
        throw new Error("ownership endpoint requires plaintext LWP but TLS was configured");
      }
    }
    const c = new LotorClient(
      host, port,
      opts.reconnect ?? true, opts.maxRetryDelayMs ?? 5000,
      tlsOpts, opts.onDisconnect, opts.onReconnect,
    );
    await c.establish();
    c.readyResolve();
    return c;
  }

  private resetReady(): void {
    this.ready = new Promise<void>((resolve) => { this.readyResolve = resolve; });
  }

  /** Open a socket + replay the session (HELLO, AUTH, WATCH subscriptions). Throws on any failure. */
  private async establish(): Promise<void> {
    await this.dial();
    await this.doHello();
    if (this.apiKey) await this.doAuth(this.apiKey);
    for (const s of this.subs) s.id = await this.doWatch(s.selectors);
  }

  private dial(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.buf = Buffer.alloc(0);
      const useTls = this.tlsOpts !== undefined;
      const sock: net.Socket = useTls
        ? tls.connect({
            host: this.host, port: this.port,
            servername: this.tlsOpts!.servername ?? (net.isIP(this.host) === 0 ? this.host : undefined),
            ca: this.tlsOpts!.ca, cert: this.tlsOpts!.cert, key: this.tlsOpts!.key,
            rejectUnauthorized: this.tlsOpts!.rejectUnauthorized ?? true,
          })
        : net.createConnection({ host: this.host, port: this.port });
      this.sock = sock;
      sock.setNoDelay(true);
      let connected = false;
      sock.once(useTls ? "secureConnect" : "connect", () => { connected = true; resolve(); });
      sock.on("error", (e) => { if (!connected) reject(e); }); // post-connect errors precede 'close'
      sock.on("data", (d) => { if (this.sock === sock) this.onData(d); });
      sock.on("close", () => {
        if (this.sock !== sock) return; // a stale socket from a previous attempt
        for (const p of this.pending.values()) p.reject(new Error("connection closed"));
        this.pending.clear();
        if (connected) this.handleDrop(); // only a *live* socket dropping triggers recovery
      });
    });
  }

  /** A live connection dropped — start (at most one) reconnect loop. */
  private handleDrop(): void {
    if (this.closing || !this.reconnect || this.reconnecting) return;
    this.reconnecting = true;
    this.onDisconnect?.();
    this.resetReady(); // gate new requests until we're back
    void this.reconnectLoop();
  }

  private async reconnectLoop(): Promise<void> {
    let delay = 100;
    for (;;) {
      if (this.closing) { this.reconnecting = false; return; }
      try {
        await this.establish();
        this.reconnecting = false;
        this.readyResolve();
        this.onReconnect?.();
        return;
      } catch {
        await sleep(delay);
        delay = Math.min(delay * 2, this.maxRetryDelayMs);
      }
    }
  }

  private onData(d: Buffer): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    for (;;) {
      const got = decodeFrame(this.buf);
      if (!got) break;
      this.buf = this.buf.subarray(got.consumed);
      const f = got.frame;
      if (f.typ === FrameType.RESP) {
        const p = this.pending.get(f.requestId);
        if (!p) continue;
        this.pending.delete(f.requestId);
        if (f.opcode === Status.ERR) {
          const code = f.args[0]?.t === "u64" ? Number(f.args[0].v) : -1;
          const msg = f.args[1]?.t === "str" ? f.args[1].v : "";
          p.reject(new LotorError(code, msg));
        } else {
          p.resolve(f.args);
        }
      } else if (f.typ === FrameType.EVENT) {
        const ev: LotorEvent = {
          type: asStr(f.args[0]),
          target: asStr(f.args[1]),
          detail: f.args[2]?.t === "map" ? Object.fromEntries(f.args[2].v.map(([k, v]) => [k, valueToJs(v)])) : {},
          logSeq: asNum(f.args[3]),
        };
        // Route by the watch id the server stamped on the frame, so multiple subscriptions on one
        // connection don't cross-deliver. (Fallback to all handlers if the id is absent.)
        const watchId = asStr(f.args[4]);
        if (watchId) {
          this.subs.find((s) => s.id === watchId)?.handler(ev);
        } else {
          for (const s of this.subs) s.handler(ev);
        }
      }
      // PONG is ignored.
    }
  }

  /** Low-level send (no readiness gate) — used by the handshake/reconnect path. */
  private sendRaw(opcode: number, args: Value[]): Promise<Value[]> {
    const requestId = this.nextId++;
    const frame: Frame = { ver: PROTO_VERSION, typ: FrameType.REQ, flags: 0, requestId, opcode, args };
    return new Promise<Value[]>((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject });
      this.sock.write(encodeFrame(frame), (err) => {
        if (err) { this.pending.delete(requestId); reject(err); }
      });
    });
  }

  /** Public request path — waits until the connection is ready (queues during a reconnect). */
  private async request(opcode: number, args: Value[]): Promise<Value[]> {
    await this.ready;
    return this.sendRaw(opcode, args);
  }

  private doHello(): Promise<Value[]> {
    return this.sendRaw(Op.HELLO, [u64(PROTO_VERSION), u64(0), str("lotor-ts")]);
  }
  private doAuth(apiKey: string): Promise<Value[]> {
    return this.sendRaw(Op.AUTH, [str(apiKey)]);
  }
  private async doWatch(selectors: string[]): Promise<string> {
    const a = await this.sendRaw(Op.WATCH, [{ t: "list", v: selectors.map(str) }]);
    return asStr(a[0]);
  }

  /** AUTH binds the connection to a tenant. The key is remembered and replayed on reconnect. */
  async auth(apiKey: string): Promise<{ tenant: string; plan: string; scope: string; connId: string }> {
    await this.ready;
    this.apiKey = apiKey;
    const a = await this.doAuth(apiKey);
    return { tenant: asStr(a[0]), plan: asStr(a[1]), scope: asStr(a[2]), connId: asStr(a[3]) };
  }

  /** AUTH.VERIFY — validate an end-user credential (1=JWT, 2=sealed cookie) against the tenant's keys. */
  async authVerify(credType: 1 | 2, credential: string): Promise<{
    valid: boolean; subject: string; org: string; expiresAt: number; reason: string;
  }> {
    const a = await this.request(Op.AUTH_VERIFY, [u64(credType), str(credential)]);
    return {
      valid: a[0]?.t === "bool" ? a[0].v : false,
      subject: asStr(a[1]), org: asStr(a[2]),
      expiresAt: asNum(a[4]), reason: asStr(a[5]),
    };
  }

  /** ACCESS.CHECK — "is (subject, relation, object) allowed?" */
  async accessCheck(subject: string, relation: string, object: string): Promise<{ allow: boolean; reason: string; ttl: number }> {
    const a = await this.request(Op.ACCESS_CHECK, [addr(subject), str(relation), addr(object)]);
    return { allow: asNum(a[0]) === 1, reason: asStr(a[1]), ttl: asNum(a[2]) };
  }

  /** Resolve a canonical entitlement or authorization decision against one immutable composition. */
  async accessCheckPinned(subject: string, relation: string, object: string, pin: CompositionPin): Promise<{
    allow: boolean; reason: string; ttl: number; evidence: string; compositionVersion: number;
  }> {
    const values: Array<[string, Value]> = [
      ["composition_hash", str(pin.resultHash)],
      ["composition_version", u64(pin.version)],
      ["operation", str(pin.operation)],
    ];
    if (pin.compositionSubject) values.push(["composition_subject", addr(pin.compositionSubject)]);
    values.sort(([left], [right]) => left.localeCompare(right));
    const a = await this.request(Op.ACCESS_CHECK, [
      addr(subject), str(relation), addr(object), { t: "map", v: values },
    ]);
    return {
      allow: asNum(a[0]) === 1, reason: asStr(a[1]), ttl: asNum(a[2]),
      evidence: asStr(a[3]), compositionVersion: asNum(a[4]),
    };
  }

  /** Evaluate canonical approval/protection/security/residency policy without executing effects. */
  async policyCheck(subject: string, input: PolicyInput): Promise<{
    state: "allow" | "deny" | "requires_approval";
    reasons: string[];
    evidence: string;
    compositionVersion: number;
    sourcePins: string[];
  }> {
    const evidenceRefs = [...(input.evidenceRefs ?? [])].sort();
    const values: Array<[string, Value]> = [
      ["composition_hash", str(input.pin.resultHash)],
      ["composition_subject", addr(input.pin.compositionSubject ?? subject)],
      ["composition_version", u64(input.pin.version)],
      ["destination_ref", str(input.destinationRef ?? "")],
      ["evidence_refs", { t: "list", v: evidenceRefs.map(str) }],
      ["execution_policy_ref", str(input.executionPolicyRef ?? "")],
      ["export", bool(input.export ?? false)],
      ["region_ref", str(input.regionRef ?? "")],
      ["retention_days", u64(input.retentionDays ?? 0)],
      ["reveal", bool(input.reveal ?? false)],
      ["scope_ref", str(input.scopeRef)],
    ];
    values.sort(([left], [right]) => left.localeCompare(right));
    const args = await this.request(Op.POLICY_CHECK, [
      addr(subject), str(input.pin.operation), { t: "map", v: values },
    ]);
    const state = asStr(args[0]);
    if (state !== "allow" && state !== "deny" && state !== "requires_approval") {
      throw new Error(`invalid policy decision state: ${state}`);
    }
    return {
      state,
      reasons: args[1]?.t === "list" ? args[1].v.map(asStr) : [],
      evidence: asStr(args[2]),
      compositionVersion: asNum(args[3]),
      sourcePins: args[4]?.t === "list" ? args[4].v.map(asStr) : [],
    };
  }

  /** ACCESS.GRANT — add a (subject, relation, object) tuple (durable). Publishes grant_changed. */
  async accessGrant(subject: string, relation: string, object: string, expiresAt = 0): Promise<{ committed: boolean; logSeq: number }> {
    const a = await this.request(Op.ACCESS_GRANT, [addr(subject), str(relation), addr(object), u64(expiresAt)]);
    return { committed: a[0]?.t === "bool" ? a[0].v : false, logSeq: asNum(a[1]) };
  }

  /** ACCESS.EXPAND — list subjects that have `relation` to `object` (e.g. members of an org). */
  async accessExpand(object: string, relation: string, limit = 0): Promise<string[]> {
    const a = await this.request(Op.ACCESS_EXPAND, [addr(object), str(relation), u64(limit)]);
    return a[0]?.t === "list" ? a[0].v.map((v) => (v.t === "addr" || v.t === "str" ? v.v : "")) : [];
  }

  /** METER.CONSUME — durable, idempotent usage. When the meter has an overage rule and the quota is
   *  exceeded, the consume auto-buys blocks from the wallet: `reason` is `overage_granted` and
   *  `blocksPurchased` / `walletBalance` are set (the `max` reflects the extended allowance). */
  async meterConsume(scope: string, meter: string, n = 1, idempotencyKey?: string): Promise<{
    accepted: boolean; reason: string; remaining: number; used: number; max: number; logSeq: number;
    blocksPurchased?: number; walletBalance?: number; grantDrawn?: number; grantRemaining?: number;
  }> {
    const args: Value[] = [addr(scope), str(meter), u64(n)];
    if (idempotencyKey) args.push({ t: "null" }, str(idempotencyKey));
    const a = await this.request(Op.METER_CONSUME, args);
    const r = {
      accepted: asNum(a[0]) === 1, reason: asStr(a[1]),
      remaining: asNum(a[2]), used: asNum(a[3]), max: asNum(a[4]), logSeq: asNum(a[5]),
    } as { accepted: boolean; reason: string; remaining: number; used: number; max: number; logSeq: number; blocksPurchased?: number; walletBalance?: number; grantDrawn?: number; grantRemaining?: number };
    if (a.length >= 8) { r.blocksPurchased = asNum(a[6]); r.walletBalance = asNum(a[7]); }
    if (a.length >= 10) { r.grantDrawn = asNum(a[8]); r.grantRemaining = asNum(a[9]); }
    return r;
  }

  /** Durable canonical usage against one exact composition pin. */
  async meterConsumePinned(scope: string, meter: string, n: number, idempotencyKey: string, pin: CompositionPin): Promise<{
    accepted: boolean; reason: string; remaining: number; used: number; max: number; logSeq: number;
    evidence: string; compositionVersion: number;
  }> {
    const a = await this.request(Op.METER_CONSUME, [
      addr(scope), str(meter), u64(n), { t: "null" }, str(idempotencyKey), capacityPin(pin),
    ]);
    return {
      accepted: asNum(a[0]) === 1, reason: asStr(a[1]),
      remaining: asNum(a[2]), used: asNum(a[3]), max: asNum(a[4]), logSeq: asNum(a[5]),
      evidence: asStr(a[6]), compositionVersion: asNum(a[7]),
    };
  }

  async meterReleasePinned(scope: string, meter: string, n: number, idempotencyKey: string, pin: CompositionPin): Promise<{
    released: boolean; remaining: number; logSeq: number; evidence: string; compositionVersion: number; reason: string;
  }> {
    const a = await this.request(Op.METER_RELEASE, [
      addr(scope), str(meter), u64(n), str(idempotencyKey), capacityPin(pin),
    ]);
    return {
      released: a[0]?.t === "bool" ? a[0].v : false,
      remaining: asNum(a[1]), logSeq: asNum(a[2]), evidence: asStr(a[3]),
      compositionVersion: asNum(a[4]), reason: asStr(a[5]),
    };
  }

  async seatClaimPinned(scope: string, seatType: string, user: string, idempotencyKey: string, pin: CompositionPin): Promise<{
    outcome: number; reason: string; used: number; max: number; seatId: string; logSeq: number;
    evidence: string; compositionVersion: number;
  }> {
    const a = await this.request(Op.SEAT_CLAIM, [
      addr(scope), str(seatType), addr(user), str(idempotencyKey), capacityPin(pin),
    ]);
    return {
      outcome: asNum(a[0]), reason: asStr(a[1]), used: asNum(a[2]), max: asNum(a[3]),
      seatId: asStr(a[4]), logSeq: asNum(a[5]), evidence: asStr(a[6]),
      compositionVersion: asNum(a[7]),
    };
  }

  async seatReleasePinned(scope: string, seatType: string, user: string, pin: CompositionPin): Promise<{
    released: boolean; used: number; logSeq: number; evidence: string; compositionVersion: number; reason: string;
  }> {
    const a = await this.request(Op.SEAT_RELEASE, [
      addr(scope), str(seatType), addr(user), capacityPin(pin),
    ]);
    return {
      released: a[0]?.t === "bool" ? a[0].v : false, used: asNum(a[1]), logSeq: asNum(a[2]),
      evidence: asStr(a[3]), compositionVersion: asNum(a[4]), reason: asStr(a[5]),
    };
  }

  /** Create an invitation and apply its executable Seat Board policy in one durable transition. */
  async invitationCreatePinned(input: {
    scope: string; actor: string; invitationId: string; invitee: string; role: string; ticket: string;
    expiresAt: number; idempotencyKey: string; pin: CompositionPin;
  }): Promise<LifecycleResult> {
    const a = await this.request(Op.INVITATION_CREATE, [
      addr(input.scope), addr(input.actor), str(input.invitationId), addr(input.invitee),
      str(input.role), str(input.ticket), u64(input.expiresAt), str(input.idempotencyKey),
      capacityPin(input.pin),
    ]);
    return lifecycleResult(a);
  }

  /** Convert a reserved invitation into membership and role access without a seat gap. */
  async invitationAccept(ticket: string, authenticatedInvitee: string, memberSubject: string, idempotencyKey: string): Promise<LifecycleResult> {
    return lifecycleResult(await this.request(Op.INVITATION_ACCEPT, [
      str(ticket), addr(authenticatedInvitee), addr(memberSubject), str(idempotencyKey),
    ]));
  }

  async invitationCancel(scope: string, actor: string, invitationId: string, idempotencyKey: string): Promise<LifecycleResult> {
    return lifecycleResult(await this.request(Op.INVITATION_CANCEL, [
      addr(scope), addr(actor), str(invitationId), str(idempotencyKey),
    ]));
  }

  async invitationList(scope: string): Promise<OrganizationInvitation[]> {
    const a = await this.request(Op.INVITATION_LIST, [addr(scope)]);
    if (a[0]?.t !== "list") return [];
    return a[0].v.flatMap((value) => {
      if (value.t !== "map") return [];
      const fields = Object.fromEntries(value.v);
      return [{
        id: asStr(fields.invitation_id), invitee: asStr(fields.invitee), role: asStr(fields.role),
        seatId: asStr(fields.seat_id), expiresAt: asNum(fields.expires_at),
        seatReserved: asBool(fields.seat_reserved),
      }];
    });
  }

  async memberRemove(scope: string, actor: string, memberSubject: string, idempotencyKey: string): Promise<LifecycleResult> {
    return lifecycleResult(await this.request(Op.MEMBER_REMOVE, [
      addr(scope), addr(actor), addr(memberSubject), str(idempotencyKey),
    ]));
  }

  async memberRoleSetPinned(scope: string, actor: string, memberSubject: string, role: string, idempotencyKey: string, pin: CompositionPin): Promise<LifecycleResult> {
    return lifecycleResult(await this.request(Op.MEMBER_ROLE_SET, [
      addr(scope), addr(actor), addr(memberSubject), str(role), str(idempotencyKey), capacityPin(pin),
    ]));
  }

  /** ALLOWANCE.GRANT — issue a one-time purchase addon: durable extra `units` of `meter` that carry
   *  across billing cycles until used up or `expiresAt` (epoch micros; 0 = never). Two funding modes:
   *  omit `wallet`/`cost` for a control-issued grant (already paid via Stripe), or pass them to fund
   *  it from a prepaid wallet (atomic debit + grant; rejected if the balance is short). */
  async allowanceGrant(scope: string, meter: string, units: number, opts: {
    expiresAt?: number; wallet?: string; cost?: number; idempotencyKey?: string;
  } = {}): Promise<{ accepted: boolean; reason: string; unitsTotal: number; walletBalance: number }> {
    const args: Value[] = [
      addr(scope), str(meter), u64(units), u64(opts.expiresAt ?? 0),
      str(opts.wallet ?? ""), u64(opts.cost ?? 0),
    ];
    if (opts.idempotencyKey) args.push(str(opts.idempotencyKey));
    const a = await this.request(Op.ALLOWANCE_GRANT, args);
    return { accepted: asNum(a[0]) === 1, reason: asStr(a[1]), unitsTotal: asNum(a[2]), walletBalance: asNum(a[3]) };
  }

  /** ALLOWANCE.GET — remaining (non-expired) one-time addon units for a meter. */
  async allowanceBalance(scope: string, meter: string): Promise<{ remaining: number; grants: number }> {
    const a = await this.request(Op.ALLOWANCE_GET, [addr(scope), str(meter)]);
    return { remaining: asNum(a[0]), grants: asNum(a[1]) };
  }

  /** METER.GET — current usage for a counter. */
  async meterGet(scope: string, meter: string): Promise<{ used: number; max: number; remaining: number; interval: string }> {
    const a = await this.request(Op.METER_GET, [addr(scope), str(meter)]);
    return { used: asNum(a[0]), max: asNum(a[1]), remaining: asNum(a[2]), interval: asStr(a[3]) };
  }

  async meterGetPinned(scope: string, meter: string, pin: CompositionPin): Promise<{
    used: number; max: number; remaining: number; interval: string; resetsAt: number;
    evidence: string; compositionVersion: number; reason: string;
  }> {
    const a = await this.request(Op.METER_GET, [addr(scope), str(meter), capacityPin(pin)]);
    return {
      used: asNum(a[0]), max: asNum(a[1]), remaining: asNum(a[2]), interval: asStr(a[3]),
      resetsAt: asNum(a[4]), evidence: asStr(a[8]), compositionVersion: asNum(a[9]),
      reason: asStr(a[10]),
    };
  }

  /** WALLET.CREDIT — add credits to a prepaid wallet (top-up / control auto-reload). Idempotent
   *  when `idempotencyKey` is set: a retried reload never double-credits. */
  async walletCredit(scope: string, wallet: string, amount: number, idempotencyKey?: string): Promise<{
    accepted: boolean; reason: string; balance: number;
  }> {
    return this.walletOp(Op.WALLET_CREDIT, scope, wallet, amount, idempotencyKey);
  }

  /** WALLET.DEBIT — draw down a prepaid wallet on consumption; `accepted` is false (reason
   *  `insufficient_funds`) when the balance is too low. Idempotent when `idempotencyKey` is set. */
  async walletDebit(scope: string, wallet: string, amount: number, idempotencyKey?: string): Promise<{
    accepted: boolean; reason: string; balance: number;
  }> {
    return this.walletOp(Op.WALLET_DEBIT, scope, wallet, amount, idempotencyKey);
  }

  private async walletOp(op: number, scope: string, wallet: string, amount: number, idempotencyKey?: string) {
    const args: Value[] = [addr(scope), str(wallet), u64(amount)];
    if (idempotencyKey) args.push(str(idempotencyKey));
    const a = await this.request(op, args);
    return { accepted: asNum(a[0]) === 1, reason: asStr(a[1]), balance: asNum(a[2]) };
  }

  /** WALLET.GET — current prepaid balance. */
  async walletBalance(scope: string, wallet: string): Promise<number> {
    const a = await this.request(Op.WALLET_GET, [addr(scope), str(wallet)]);
    return asNum(a[0]);
  }

  /** WATCH — subscribe to change selectors; `handler` fires on each matching event. Re-established
   *  automatically across reconnects. Returns the watch id. */
  async watch(selectors: string[], handler: EventHandler): Promise<string> {
    await this.ready;
    const sub: Subscription = { selectors, handler };
    this.subs.push(sub);
    sub.id = await this.doWatch(selectors);
    return sub.id;
  }

  /** Subscribe to a wallet's low-balance events (`wallet_low`). `handler` fires when the balance
   *  crosses below its configured per-account threshold; re-armed once a credit recovers it. Sugar over
   *  `watch(["wallet:<scope>:<wallet>"])`. Returns the watch id. */
  async onWalletLow(
    scope: string,
    wallet: string,
    handler: (e: { scope: string; wallet: string; balance: number; threshold: number }) => void,
  ): Promise<string> {
    return this.watch([`wallet:${scope}:${wallet}`], (ev) => {
      if (ev.type !== "wallet_low") return;
      const i = ev.target.lastIndexOf("/");
      handler({
        scope: i >= 0 ? ev.target.slice(0, i) : ev.target,
        wallet: i >= 0 ? ev.target.slice(i + 1) : "",
        balance: Number(ev.detail.balance ?? 0),
        threshold: Number(ev.detail.threshold ?? 0),
      });
    });
  }

  /** UNWATCH — cancel a subscription (by the id from `watch`). */
  async unwatch(watchId: string): Promise<void> {
    this.subs = this.subs.filter((s) => s.id !== watchId);
    await this.request(Op.UNWATCH, [str(watchId)]);
  }

  /** PING — returns the server time (ms). */
  async ping(): Promise<number> {
    const a = await this.request(Op.PING, []);
    return asNum(a[0]);
  }

  async quit(): Promise<void> {
    this.closing = true; // suppress reconnect
    try { await this.sendRaw(Op.QUIT, []); } catch { /* server closes the socket */ }
    this.sock.end();
  }
}

/**
 * Run one logical operation and follow at most one authenticated MOVED assertion. Mutating
 * callbacks must reuse their original idempotency key when invoked a second time.
 */
export async function withOwnerRetry<T>(
  opts: OwnerRetryOptions,
  operation: (client: LotorClient) => Promise<T>,
): Promise<T> {
  const first = await opts.ownership.resolve();
  let client = await LotorClient.connect({ ...opts, ownership: opts.ownership });
  await client.auth(opts.apiKey);
  try {
    return await operation(client);
  } catch (error) {
    if (!(error instanceof LotorError) || error.code !== ErrorCode.MOVED) throw error;
    const moved = opts.ownership.acceptMoved(error.detail, first);
    try { await client.quit(); } catch { /* stale owner may close first */ }
    const address = ownershipAddress(moved);
    const tlsOptions = address.tls ? (opts.tls === true ? true : (opts.tls || true)) : false;
    client = await LotorClient.connect({
      ...opts, ownership: undefined, host: address.host, port: address.port, tls: tlsOptions,
    });
    await client.auth(opts.apiKey);
    return operation(client);
  } finally {
    try { await client.quit(); } catch { /* connection may already be closed */ }
  }
}

function asStr(v: Value | undefined): string {
  return v && (v.t === "str" || v.t === "addr") ? v.v : "";
}
function asNum(v: Value | undefined): number {
  return v && (v.t === "u64" || v.t === "i64") ? Number(v.v) : 0;
}
function asBool(v: Value | undefined): boolean {
  return v?.t === "bool" && v.v;
}
function lifecycleResult(values: Value[]): LifecycleResult {
  return {
    accepted: asBool(values[0]), reason: asStr(values[1]), invitationId: asStr(values[2]),
    seatId: asStr(values[3]), active: asNum(values[4]), reserved: asNum(values[5]),
    used: asNum(values[6]), maximum: asNum(values[7]), remaining: asNum(values[8]),
    logSeq: asNum(values[9]), evidence: asStr(values[10]), compositionVersion: asNum(values[11]),
  };
}
function valueToJs(v: Value): unknown {
  switch (v.t) {
    case "null": return null;
    case "bool": return v.v;
    case "u64": case "i64": return Number(v.v);
    case "str": case "addr": return v.v;
    case "bytes": return v.v.toString("base64");
    case "list": return v.v.map(valueToJs);
    case "map": return Object.fromEntries(v.v.map(([k, x]) => [k, valueToJs(x)]));
  }
}
