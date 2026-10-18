// Regression: QA's PR #36 redaction probe set (145 cases), run through sanitizeForAudit exactly
// as Store.writeAudit stores detail_json (JSON.stringify of the sanitized detail). Fake values.
import { describe, expect, it } from "vitest";
import { isSecretName, redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";

type C = { id: string; detail: unknown; mark: string; expect: "redact" | "keep"; bytes?: boolean };
const cases: C[] = [];
let n = 0;
const F = () => `FAKEVAL${++n}Q`;
const key = (g: string, k: string, expect: "redact" | "keep" = "redact", nest?: (o: unknown) => unknown) => {
  const m = F();
  const o = { [k]: m };
  cases.push({ id: `${g}:${k.slice(0, 40)}${nest ? "(nested)" : ""}`, detail: nest ? nest(o) : o, mark: m, expect });
};
const str = (g: string, label: string, mk: (m: string) => string, expect: "redact" | "keep" = "redact", m2?: boolean) => {
  const m = F();
  const extra = m2 ? F() : null;
  const s = extra ? mk(m).replace("@@2", extra) : mk(m);
  cases.push({ id: `${g}:${label}`, detail: { cmd: s }, mark: m, expect });
  if (extra) cases.push({ id: `${g}:${label}#2`, detail: { cmd: s }, mark: extra, expect });
};

for (const k of ["DB_PASS", "POSTGRES_PWD", "JWT_KEY", "STRIPE_SECRET", "GH_TOKEN", "SMTP_AUTH", "GCP_CREDENTIALS",
  "db_pass", "Db_Pass", "jwt_key", "db-pass", "x-auth-token", "db.password", "MCP_FLOW_MASTER_KEY", "API_TOKENS",
  "TOKEN", "PASSWORD", "PASS", "PWD", "SECRET", "AUTH", "CREDENTIALS", "token", "password",
  "apiKey", "authToken", "githubToken", "clientSecret", "dbPassword", "ghCredentials", "privateKey", "sessionKey",
  "dbPass", "dbPwd", "smtpAuth", "jwtKey", "stripeKey", "masterKey", "signingKey", "encryptionKey", "webhookSecret", "basicAuth"]) key("k2", k);
key("k2", "DB_PASS", "redact", (o) => ({ a: { b: { c: o } } }));
key("k2", "GH_TOKEN", "redact", (o) => ({ list: [1, o, [o]] }));
key("k2", "x".repeat(260) + "_KEY", "redact");
{ const m = F(); cases.push({ id: "k2:env-array {name,value}", detail: { env: [{ name: "DB_PASS", value: m }] }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "k2:env-array {key,val} jwtKey", detail: { env: [{ key: "jwtKey", value: m }] }, mark: m, expect: "redact" }); }
for (const k of ["MONKEY", "KEY", "key", "max_tokens", "max_output_tokens", "total_tokens", "KEY_COUNT", "session_name", "turkey"]) key("k2fp", k, "keep");
for (const k of ["primary_key", "sort_key", "public_key", "idempotency_key", "PWD_DIR"]) key("k2fp", k, "keep");

str("s3", "unquoted", (m) => `DB_PASS=${m} ./run`);
str("s3", "double-quoted", (m) => `DB_PASS="${m}" ./run`);
str("s3", "single-quoted", (m) => `DB_PASS='${m}' ./run`);
str("s3", "quoted with spaces", (m) => `DB_PASS="a b ${m} c" ./run`);
str("s3", "end of line", (m) => `./run --x DB_PASS=${m}`);
str("s3", "multiple pairs", (m) => `A=1 DB_PASS=${m} B=2 GH_TOKEN=@@2 C=3`, "redact", true);
str("s3", "multi-line", (m) => `X=1\nDB_PASS=${m}\nGH_TOKEN=@@2\nY=2`, "redact", true);
str("s3", "quoted multi-line value", (m) => `DB_PASS="l1\n${m}\nl3" ./run`);
str("s3", "export prefix", (m) => `export GH_TOKEN=${m}`);
str("s3", "spaces around =", (m) => `DB_PASS = ${m}`);
str("s3", "lowercase", (m) => `db_pass=${m}`);
str("s3", "yaml colon", (m) => `password: ${m}`);
str("s3", "json text", (m) => `{"DB_PASS":"${m}","n":1}`);
str("s3", "escaped json text", (m) => JSON.stringify(JSON.stringify({ STRIPE_SECRET: m })));
str("s3", "PGPASSWORD", (m) => `PGPASSWORD=${m} psql`);
str("s3", "AWS_SECRET_ACCESS_KEY", (m) => `AWS_SECRET_ACCESS_KEY=${m}`);
str("s3", "bare TOKEN", (m) => `TOKEN=${m}`);
str("s3", "--password flag", (m) => `tool --password ${m}`);
str("s3", "mysql -p", (m) => `mysql -u root -p${m} db`);
str("s3", "camel apiKey=", (m) => `apiKey=${m}`);
str("s3", "camel jwtKey=", (m) => `jwtKey=${m}`);
str("s3", "camel dbPass=", (m) => `dbPass=${m}`);
str("s3", "name >128 chars", (m) => `${"A".repeat(130)}_PASS=${m}`);
str("s3", "fish set (no =)", (m) => `set -x DB_PASS ${m}`);
str("s3fp", "KEY=value stays", (m) => `KEY=${m}`, "keep");
str("s3fp", "KEY_COUNT stays", (m) => `KEY_COUNT=${m}`, "keep");

for (const [label, mk] of [
  ["https user:pass", (m: string) => `https://alice:${m}@example.com/x`],
  ["postgres", (m: string) => `postgres://app:${m}@db:5432/app`],
  ["redis empty user", (m: string) => `redis://:${m}@cache:6379`],
  ["mongodb+srv", (m: string) => `mongodb+srv://u:${m}@cluster0.example.net/db`],
  ["ftp", (m: string) => `ftp://u:${m}@ftp.example.com`],
  ["custom scheme", (m: string) => `myproto-x://u:${m}@h`],
  ["long scheme >32", (m: string) => `${"s".repeat(40)}://u:${m}@h`],
  ["jdbc", (m: string) => `jdbc:postgresql://u:${m}@h/db`],
  ["user-only token", (m: string) => `https://${m}@github.com/o/r.git`],
  ["percent-encoded", (m: string) => `postgres://u:${m}%40%2Fx@h/db`],
  ["@ in password", (m: string) => `postgres://u:p@${m}@h/db`],
  ["embedded in text", (m: string) => `clone https://u:${m}@h/x.git now`],
  ["in quotes", (m: string) => `url="postgres://u:${m}@h/db"`],
  ["query password=", (m: string) => `postgres://h/db?user=u&password=${m}`],
  ["raw / in password", (m: string) => `postgres://u:${m}/x@h/db`],
  ["raw # in password", (m: string) => `postgres://u:${m}#x@h/db`],
  ["raw ' in password", (m: string) => `postgres://u:${m}'x@h/db`],
] as const) str("u4", label, mk);

const b64 = (m: string) => Buffer.from(`user:${m}`).toString("base64");
str("h5", "Authorization: Bearer", (m) => `Authorization: Bearer ${m}`);
str("h5", "lowercase authorization: bearer", (m) => `authorization: bearer ${m}`);
str("h5", "Authorization: token", (m) => `Authorization: token ${m}`);
str("h5", "Authorization raw value", (m) => `Authorization: ${m}`);
str("h5", "Authorization AWS4", (m) => `Authorization: AWS4-HMAC-SHA256 Credential=x, Signature=${m}`);
str("h5", "curl -H", (m) => `curl -H 'Authorization: Bearer ${m}' https://h`);
str("h5", "Proxy-Authorization: Bearer", (m) => `Proxy-Authorization: Bearer ${m}`);
str("h5", "bare Bearer in text", (m) => `use Bearer ${m} please`);
str("h5", "X-Api-Key header", (m) => `X-Api-Key: ${m}`);
str("h5", "x-access-token header", (m) => `x-access-token: ${m}`);
str("h5", "PRIVATE-TOKEN header", (m) => `PRIVATE-TOKEN: ${m}`);
str("h5", "Cookie header", (m) => `Cookie: sid=${m}`);
for (const [label, fn] of [
  ["Authorization: Basic", (b: string) => `Authorization: Basic ${b}`],
  ["Proxy-Authorization: Basic", (b: string) => `Proxy-Authorization: Basic ${b}`],
  ["bare Basic in text", (b: string) => `creds Basic ${b} end`],
] as const) { const m = F(); const b = b64(m); cases.push({ id: `h5:${label}`, detail: { cmd: fn(b) }, mark: b, expect: "redact" }); }
key("h5", "authorization"); key("h5", "Proxy-Authorization"); key("h5", "X-Api-Key"); key("h5", "x-goog-api-key"); key("h5", "Ocp-Apim-Subscription-Key");
{ const m = F(); cases.push({ id: "h5:headers obj {authorization:'Bearer'}", detail: { headers: { authorization: `Bearer ${m}` } }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "h5:headers tuple [['X-Api-Key',v]]", detail: { headers: [["X-Api-Key", m]] }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "h5:headers tuple [['Authorization','Basic b64']]", detail: { headers: [["Authorization", `Basic ${b64(m)}`]] }, mark: b64(m), expect: "redact" }); }

{ const m = F(); cases.push({ id: "b10:Error object", detail: { err: new Error(`DB_PASS=${m}`) }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:URL object", detail: { u: new URL(`https://u:${m}@h/`) }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:Map", detail: { m: new Map([["DB_PASS", m]]) }, mark: m, expect: "redact" }); }
{ const m = F(); class Cfg { DB_PASS = m; other = `GH_TOKEN=${m}`; } cases.push({ id: "b10:class instance", detail: { c: new Cfg() }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:Buffer (bytes)", detail: { b: Buffer.from(`DB_PASS=${m}`) }, mark: m, expect: "redact", bytes: true }); }
{ const m = F(); const o: Record<string, unknown> = { DB_PASS_X: 1 }; let cur = o; for (let i = 0; i < 20; i++) { cur.n = {}; cur = cur.n as Record<string, unknown>; } cur.v = m; cases.push({ id: "b10:depth 21 plain value", detail: o, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:straddling maxString cut", detail: { s: "x".repeat(16380) + ` DB_PASS=${m}` }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:secret beyond kept window", detail: { s: "x".repeat(30000) + ` DB_PASS=${m}` }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:value longer than window", detail: { s: "DB_PASS=" + "y".repeat(25000) + m }, mark: m, expect: "redact" }); }
{ const m = F(); const o: Record<string, unknown> = {}; for (let i = 0; i < 150; i++) o["k" + i] = i; o.zz = m; cases.push({ id: "b10:key #151 (omitted)", detail: o, mark: m, expect: "redact" }); }
{ const m = F(); const a: unknown[] = Array.from({ length: 250 }, (_, i) => i); a.push(m); cases.push({ id: "b10:array idx 250 (omitted)", detail: { a }, mark: m, expect: "redact" }); }
{ const m = F(); const big: Record<string, unknown> = { DB: `DB_PASS=${m}` }; for (let i = 0; i < 10; i++) big["f" + i] = "z".repeat(15000); cases.push({ id: "b10:>64KB detail (preview)", detail: big, mark: m, expect: "redact" }); }
{ const m = F(); const o: Record<string, unknown> = { a: `DB_PASS=${m}` }; o.self = o; cases.push({ id: "b10:cyclic object", detail: o, mark: m, expect: "redact" }); }
{ const m = F(); const o: Record<string, unknown> = { a: `GH_TOKEN=${m}` }; Object.defineProperty(o, "boom", { enumerable: true, get() { throw new Error("x"); } }); cases.push({ id: "b10:throwing getter", detail: o, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:secret in object KEY name", detail: { [`https://u:${m}@h`]: 1 }, mark: m, expect: "redact" }); }
{ const m = F(); cases.push({ id: "b10:opaque high-entropy value", detail: { value: "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz" + m }, mark: m, expect: "redact" }); }

describe("QA PR #36 probe set", () => {
  it("has the full case list", () => expect(cases.length).toBe(145));
  it.each(cases.map((c) => [c.id, c] as const))("%s", (_id, c) => {
    const stored = JSON.stringify(sanitizeForAudit(c.detail as Record<string, unknown>) ?? null);
    let present = stored.includes(c.mark);
    if (c.bytes) {
      const bytes = [...Buffer.from(c.mark)].join(",");
      present = present || stored.replace(/"\d+":/g, "").replace(/[{}[\]]/g, "").includes(bytes);
    }
    expect(present).toBe(c.expect === "keep");
  });
});

describe("QA PR #36 follow-up details", () => {
  it("camelCase names: redacted as keys, pairs and text; benign camelCase stays", () => {
    for (const k of ["dbPass", "dbPwd", "smtpAuth", "jwtKey", "stripeKey", "masterKey", "signingKey", "encryptionKey", "basicAuth", "apiToken", "clientSecret", "apiTokens", "dbPassword"])
      expect(isSecretName(k)).toBe(true);
    for (const k of ["primaryKey", "sortKey", "idempotencyKey", "partitionKey", "cacheKey", "publicKey", "maxTokens", "maxOutputTokens", "promptTokens", "totalTokens", "compass", "bypass", "keyId", "author", "monkey"])
      expect(isSecretName(k)).toBe(false);
    expect(isSecretName("maxAccessTokens")).toBe(true);
    expect(redactSecrets("jwtKey=abc dbPass=x")).toBe("jwtKey=[redacted]");
  });

  it("header tuples and flat header lists", () => {
    expect(sanitizeForAudit({ h: [["X-Api-Key", "k1"], ["Accept", "json"]] })).toEqual({ h: [["X-Api-Key", "[redacted]"], ["Accept", "json"]] });
    expect(sanitizeForAudit({ h: ["Authorization", "Bearer x"] })).toEqual({ h: ["Authorization", "[redacted]"] });
    expect(sanitizeForAudit({ raw: ["Host", "h", "Cookie", "sid=1", "Accept", "*/*"] })).toEqual({ raw: ["Host", "h", "Cookie", "[redacted]", "Accept", "*/*"] });
    // non-string-name arrays are not treated as pairs
    expect(sanitizeForAudit({ a: ["HOST", "h", "PORT"] })).toEqual({ a: ["HOST", "h", "PORT"] });
    expect(sanitizeForAudit({ a: [1, "x"] })).toEqual({ a: [1, "x"] });
  });

  it.each([
    ["postgres://u:p/x@h/db", "postgres://[redacted]@h/db"],
    ["postgres://u:p#x@h/db", "postgres://[redacted]@h/db"],
    ["postgres://u:p'x@h/db", "postgres://[redacted]@h/db"],
    ["mysql://root:a/b#c@db:3306/app", "mysql://[redacted]@db:3306/app"],
  ])("raw / # ' in a URL password: %s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("raw-char URL rule keeps normal URLs", () => {
    for (const s of ["https://h:8080/a@b", "https://example.com/a/@user", "https://h/x?email=a@b.c", "https://h:443/p?x=1#f@g",
      "see 'https://h:8080' and 'x@y'", "http://localhost:3000/@scope/pkg", "https://h/a:b/c@d"]) expect(redactSecrets(s)).toBe(s);
  });

  it("raw-char URL scan stays linear", () => {
    const t = Date.now();
    redactSecrets("a://u:p/".repeat(30_000));
    redactSecrets("://u:x" + "/".repeat(200_000) + "@");
    redactSecrets("x://u:p#" + "a".repeat(200_000));
    expect(Date.now() - t).toBeLessThan(1000);
  });

  it("Buffer, Uint8Array, DataView and ArrayBuffer never emit their bytes", () => {
    const b = Buffer.from("DB_PASS=FAKE");
    expect(sanitizeForAudit({ b, u: new Uint8Array([1, 2, 3]), d: new DataView(new ArrayBuffer(4)), ab: new ArrayBuffer(2) })).toEqual({
      b: { _omitted: "binary", byteLength: 12 }, u: { _omitted: "binary", byteLength: 3 },
      d: { _omitted: "binary", byteLength: 4 }, ab: { _omitted: "binary", byteLength: 2 },
    });
  });

  it("key names holding secrets are redacted, value too; collisions kept apart", () => {
    const out = sanitizeForAudit({ "Bearer abc.def": 1, "postgres://u:p@h": 2, "postgres://u:q@h": 3, ok: 4 }) as Record<string, unknown>;
    const s = JSON.stringify(out);
    for (const x of ["abc.def", "u:p", "u:q"]) expect(s).not.toContain(x);
    expect(Object.keys(out)).toHaveLength(4);
    expect(out.ok).toBe(4);
  });

  it("names over the length cap fail closed", () => {
    expect(isSecretName("x".repeat(300))).toBe(true);
    const out = JSON.stringify(sanitizeForAudit({ ["k".repeat(300)]: "v-long" }));
    expect(out).not.toContain("v-long");
    expect(out).not.toContain("k".repeat(100));
    expect(redactSecrets(`${"A".repeat(600)}_PASS=v1`)).not.toContain("v1");
  });

  it("fish / csh set", () => {
    expect(redactSecrets("set -x DB_PASS hunter 2\necho ok")).toBe("set -x DB_PASS [redacted]\necho ok");
    expect(redactSecrets("setenv GH_TOKEN abc")).toBe("setenv GH_TOKEN [redacted]");
    for (const s of ["set -e", "set -o pipefail", "set -x PATH /usr/bin"]) expect(redactSecrets(s)).toBe(s);
  });

  it("self-referential wide arrays are bounded", () => {
    const a: unknown[] = [];
    for (let i = 0; i < 6; i++) a.push(a);
    const t = Date.now();
    const out = JSON.stringify(sanitizeForAudit({ a }));
    expect(Date.now() - t).toBeLessThan(2000);
    expect(out.length).toBeLessThan(100_000);
  });
});
