import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTotpSecret(): { raw: Buffer; base32: string } {
  const raw = randomBytes(20);
  return { raw, base32: toBase32(raw) };
}

export function totpCode(secret: Buffer, atMs = Date.now(), stepSec = 30): string {
  const counter = BigInt(Math.floor(atMs / 1000 / stepSec));
  return hotp(secret, counter);
}

export function verifyTotp(
  secret: Buffer,
  code: string,
  opts: { atMs?: number; window?: number } = {},
): boolean {
  const expected = String(code ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(expected)) return false;
  const atMs = opts.atMs ?? Date.now();
  const window = opts.window ?? 1;
  const want = Buffer.from(expected, "utf8");
  for (let i = -window; i <= window; i++) {
    const got = totpCode(secret, atMs + i * 30_000);
    const gb = Buffer.from(got, "utf8");
    if (want.length === gb.length && timingSafeEqual(want, gb)) return true;
  }
  return false;
}

export function otpauthUrl(opts: {
  issuer: string;
  account: string;
  base32: string;
}): string {
  const label = encodeURIComponent(`${opts.issuer}:${opts.account}`);
  const issuer = encodeURIComponent(opts.issuer);
  return `otpauth://totp/${label}?secret=${opts.base32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

export function fromBase32(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) continue;
    bits += i.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function toBase32(buf: Buffer): string {
  let bits = "";
  for (const b of buf) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += ALPHABET[parseInt(chunk, 2)]!;
  }
  return out;
}

function hotp(secret: Buffer, counter: bigint): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter);
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0xf;
  const bin =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(bin % 1_000_000).padStart(6, "0");
}
