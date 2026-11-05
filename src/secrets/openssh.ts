/**
 * OpenSSH wire format for keypair secrets (Secrets §3).
 * Public lines and unencrypted openssh-key-v1 private blobs. PEM is handled by Node.
 */

function sshBytes(body: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length);
  return Buffer.concat([len, body]);
}

function sshText(text: string): Buffer {
  return sshBytes(Buffer.from(text, "utf8"));
}

/** Positive mpint. Leading zeros are stripped; a high bit gets a leading 0x00. */
export function sshMpint(raw: Buffer): Buffer {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0) i++;
  let body = raw.subarray(i);
  if (body.length === 0) body = Buffer.from([0]);
  if ((body[0]! & 0x80) !== 0) body = Buffer.concat([Buffer.from([0]), body]);
  return sshBytes(body);
}

function b64(buf: Buffer): string {
  return buf.toString("base64");
}

function wrapPem(label: string, body: Buffer): string {
  const lines = b64(body).match(/.{1,70}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function ed25519PublicLine(pub: Buffer): string {
  if (pub.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  const blob = Buffer.concat([sshText("ssh-ed25519"), sshBytes(pub)]);
  return `ssh-ed25519 ${b64(blob)}`;
}

export function ed25519PrivateOpenSsh(seed: Buffer, pub: Buffer): string {
  if (seed.length !== 32 || pub.length !== 32) throw new Error("ed25519 key length");
  const pubBlob = Buffer.concat([sshText("ssh-ed25519"), sshBytes(pub)]);
  const check = Buffer.alloc(4);
  check.writeUInt32BE(0x5a5a5a5a);
  let secret = Buffer.concat([
    check,
    check,
    sshText("ssh-ed25519"),
    sshBytes(pub),
    sshBytes(Buffer.concat([seed, pub])),
    sshText("mcp-flow"),
  ]);
  const pad = (8 - (secret.length % 8)) % 8;
  if (pad) {
    const padding = Buffer.alloc(pad);
    for (let i = 0; i < pad; i++) padding[i] = i + 1;
    secret = Buffer.concat([secret, padding]);
  }
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    sshText("none"),
    sshText("none"),
    sshBytes(Buffer.alloc(0)),
    Buffer.from([0, 0, 0, 1]),
    sshBytes(pubBlob),
    sshBytes(secret),
  ]);
  return wrapPem("OPENSSH PRIVATE KEY", body);
}

export function rsaPublicLine(exponent: Buffer, modulus: Buffer): string {
  const blob = Buffer.concat([sshText("ssh-rsa"), sshMpint(exponent), sshMpint(modulus)]);
  return `ssh-rsa ${b64(blob)}`;
}

export function rsaPrivateOpenSsh(parts: {
  n: Buffer;
  e: Buffer;
  d: Buffer;
  iqmp: Buffer;
  p: Buffer;
  q: Buffer;
}): string {
  const pubBlob = Buffer.concat([sshText("ssh-rsa"), sshMpint(parts.e), sshMpint(parts.n)]);
  const check = Buffer.alloc(4);
  check.writeUInt32BE(0xa5a5a5a5);
  let secret = Buffer.concat([
    check,
    check,
    sshText("ssh-rsa"),
    sshMpint(parts.n),
    sshMpint(parts.e),
    sshMpint(parts.d),
    sshMpint(parts.iqmp),
    sshMpint(parts.p),
    sshMpint(parts.q),
    sshText("mcp-flow"),
  ]);
  const pad = (8 - (secret.length % 8)) % 8;
  if (pad) {
    const padding = Buffer.alloc(pad);
    for (let i = 0; i < pad; i++) padding[i] = i + 1;
    secret = Buffer.concat([secret, padding]);
  }
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    sshText("none"),
    sshText("none"),
    sshBytes(Buffer.alloc(0)),
    Buffer.from([0, 0, 0, 1]),
    sshBytes(pubBlob),
    sshBytes(secret),
  ]);
  return wrapPem("OPENSSH PRIVATE KEY", body);
}

export function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, "base64url");
}
