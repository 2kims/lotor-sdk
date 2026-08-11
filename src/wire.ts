// LWP/1 wire codec: varint (LEB128), TLV values, and frames. Fixed-width ints
// are big-endian; lengths and counts are unsigned LEB128 varints; u64/i64 use
// bigint to stay lossless.

export const PROTO_VERSION = 1;

export const FrameType = { REQ: 1, RESP: 2, EVENT: 3, PING: 4, PONG: 5 } as const;
export const Status = { OK: 0, ERR: 1 } as const;

export const Op = {
  HELLO: 0x0001, AUTH: 0x0002, PING: 0x0003, QUIT: 0x0004,
  AUTH_VERIFY: 0x0010,
  ACCESS_CHECK: 0x0020, ACCESS_GRANT: 0x0021, ACCESS_REVOKE: 0x0022, ACCESS_EXPAND: 0x0023,
  METER_CONSUME: 0x0030, METER_RELEASE: 0x0031, METER_GET: 0x0032, METER_SERIES: 0x0033,
  SEAT_CLAIM: 0x0040, SEAT_RELEASE: 0x0041,
  WALLET_CREDIT: 0x0070, WALLET_DEBIT: 0x0071, WALLET_GET: 0x0072,
  ALLOWANCE_GRANT: 0x0073, ALLOWANCE_GET: 0x0074,
  POLICY_CHECK: 0x0080,
  INVITATION_CREATE: 0x0090, INVITATION_ACCEPT: 0x0091, INVITATION_CANCEL: 0x0092,
  INVITATION_LIST: 0x0093, MEMBER_REMOVE: 0x0094, MEMBER_ROLE_SET: 0x0095,
  CONF_GET: 0x0050, WATCH: 0x0060, UNWATCH: 0x0061,
} as const;

const Tag = { NULL: 0, BOOL: 1, U64: 2, I64: 3, STR: 4, BYTES: 5, ADDR: 6, LIST: 7, MAP: 8 } as const;

// ── values ───────────────────────────────────────────────────────────────────
export type Value =
  | { t: "null" }
  | { t: "bool"; v: boolean }
  | { t: "u64"; v: bigint }
  | { t: "i64"; v: bigint }
  | { t: "str"; v: string }
  | { t: "bytes"; v: Buffer }
  | { t: "addr"; v: string }
  | { t: "list"; v: Value[] }
  | { t: "map"; v: Array<[string, Value]> };

// constructors
export const u64 = (v: number | bigint): Value => ({ t: "u64", v: BigInt(v) });
export const i64 = (v: number | bigint): Value => ({ t: "i64", v: BigInt(v) });
export const str = (v: string): Value => ({ t: "str", v });
export const addr = (v: string): Value => ({ t: "addr", v });
export const bytes = (v: Buffer): Value => ({ t: "bytes", v });
export const bool = (v: boolean): Value => ({ t: "bool", v });

export class ShortRead extends Error {}

// ── varint ───────────────────────────────────────────────────────────────────
function writeUvarint(out: number[], value: bigint): void {
  let v = value;
  for (;;) {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) b |= 0x80;
    out.push(b);
    if (v === 0n) break;
  }
}
function readUvarint(buf: Buffer, pos: { i: number }): bigint {
  let result = 0n, shift = 0n;
  for (;;) {
    if (pos.i >= buf.length) throw new ShortRead();
    const b = buf[pos.i++];
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return result;
}
const zigzagEncode = (v: bigint): bigint => (v << 1n) ^ (v >> 63n);
const zigzagDecode = (v: bigint): bigint => (v >> 1n) ^ -(v & 1n);

function writeLenPrefixed(out: number[], b: Buffer): void {
  writeUvarint(out, BigInt(b.length));
  for (const x of b) out.push(x);
}

// ── value codec ──────────────────────────────────────────────────────────────
function encodeValue(out: number[], val: Value): void {
  switch (val.t) {
    case "null": out.push(Tag.NULL); break;
    case "bool": out.push(Tag.BOOL, val.v ? 1 : 0); break;
    case "u64": out.push(Tag.U64); writeUvarint(out, val.v); break;
    case "i64": out.push(Tag.I64); writeUvarint(out, zigzagEncode(val.v)); break;
    case "str": out.push(Tag.STR); writeLenPrefixed(out, Buffer.from(val.v, "utf8")); break;
    case "bytes": out.push(Tag.BYTES); writeLenPrefixed(out, val.v); break;
    case "addr": out.push(Tag.ADDR); writeLenPrefixed(out, Buffer.from(val.v, "utf8")); break;
    case "list":
      out.push(Tag.LIST); writeUvarint(out, BigInt(val.v.length));
      for (const it of val.v) encodeValue(out, it);
      break;
    case "map":
      out.push(Tag.MAP); writeUvarint(out, BigInt(val.v.length));
      for (const [k, v] of val.v) { writeLenPrefixed(out, Buffer.from(k, "utf8")); encodeValue(out, v); }
      break;
  }
}

function readBuf(buf: Buffer, pos: { i: number }): Buffer {
  const n = Number(readUvarint(buf, pos));
  if (pos.i + n > buf.length) throw new ShortRead();
  const s = buf.subarray(pos.i, pos.i + n);
  pos.i += n;
  return s;
}

function decodeValue(buf: Buffer, pos: { i: number }): Value {
  if (pos.i >= buf.length) throw new ShortRead();
  const tag = buf[pos.i++];
  switch (tag) {
    case Tag.NULL: return { t: "null" };
    case Tag.BOOL: { if (pos.i >= buf.length) throw new ShortRead(); return { t: "bool", v: buf[pos.i++] !== 0 }; }
    case Tag.U64: return { t: "u64", v: readUvarint(buf, pos) };
    case Tag.I64: return { t: "i64", v: zigzagDecode(readUvarint(buf, pos)) };
    case Tag.STR: return { t: "str", v: readBuf(buf, pos).toString("utf8") };
    case Tag.BYTES: return { t: "bytes", v: Buffer.from(readBuf(buf, pos)) };
    case Tag.ADDR: return { t: "addr", v: readBuf(buf, pos).toString("utf8") };
    case Tag.LIST: {
      const n = Number(readUvarint(buf, pos));
      const items: Value[] = [];
      for (let k = 0; k < n; k++) items.push(decodeValue(buf, pos));
      return { t: "list", v: items };
    }
    case Tag.MAP: {
      const n = Number(readUvarint(buf, pos));
      const entries: Array<[string, Value]> = [];
      for (let k = 0; k < n; k++) entries.push([readBuf(buf, pos).toString("utf8"), decodeValue(buf, pos)]);
      return { t: "map", v: entries };
    }
    default: throw new Error(`unknown TLV tag ${tag}`);
  }
}

// ── frames ───────────────────────────────────────────────────────────────────
export interface Frame {
  ver: number;
  typ: number;
  flags: number;
  requestId: number;
  opcode: number; // REQ: opcode; RESP: status
  args: Value[];
}

export function encodeFrame(f: Frame): Buffer {
  const payload: number[] = [];
  payload.push(f.ver, f.typ);
  payload.push((f.flags >> 8) & 0xff, f.flags & 0xff);
  payload.push((f.requestId >>> 24) & 0xff, (f.requestId >>> 16) & 0xff, (f.requestId >>> 8) & 0xff, f.requestId & 0xff);
  payload.push((f.opcode >> 8) & 0xff, f.opcode & 0xff);
  writeUvarint(payload, BigInt(f.args.length));
  for (const a of f.args) encodeValue(payload, a);

  const out = Buffer.allocUnsafe(4 + payload.length);
  out.writeUInt32BE(payload.length, 0);
  Buffer.from(payload).copy(out, 4);
  return out;
}

// Decode one frame from the front of `buf`. Returns null if it hasn't fully arrived yet.
export function decodeFrame(buf: Buffer): { frame: Frame; consumed: number } | null {
  if (buf.length < 4) return null;
  const len = buf.readUInt32BE(0);
  const total = 4 + len;
  if (buf.length < total) return null;
  const pos = { i: 4 };
  const ver = buf[pos.i++];
  const typ = buf[pos.i++];
  const flags = buf.readUInt16BE(pos.i); pos.i += 2;
  const requestId = buf.readUInt32BE(pos.i); pos.i += 4;
  const opcode = buf.readUInt16BE(pos.i); pos.i += 2;
  const argc = Number(readUvarint(buf, pos));
  const args: Value[] = [];
  for (let k = 0; k < argc; k++) args.push(decodeValue(buf, pos));
  return { frame: { ver, typ, flags, requestId, opcode, args }, consumed: total };
}
