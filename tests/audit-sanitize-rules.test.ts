// A0 rule fix: suffix-rule secret names, line/quoted values, URL userinfo in any scheme,
// Authorization / Bearer / Basic. Fake values only.
import { describe, expect, it } from "vitest";
import { isSecretName, redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";

const R = "[redacted]";

describe("secret names: suffix rule, not an allowlist", () => {
  const secret = [
    "DB_PASS", "POSTGRES_PWD", "JWT_KEY", "ENCRYPTION_KEY", "STRIPE_KEY", "SMTP_AUTH", "GH_CREDENTIALS",
    "MCP_FLOW_MASTER_KEY", "db_pass", "Mysql_Root_Passwd", "REDIS_PASSWORD", "AWS_SECRET", "SLACK_TOKEN",
    "GH_CREDENTIAL", "SSH_KEYS", "APP_SECRETS", "GPG_PASSPHRASE", "x-auth-token", "X-Api-Key", "spring.datasource.password",
    "PASSWORD", "passwd", "PASS", "PWD", "SECRET", "TOKEN", "AUTH", "Authorization", "Proxy-Authorization",
    "CREDENTIALS", "Cookie", "Set-Cookie", "DSN", "DATABASE_URL", "aws_secret_access_key", "GITHUB_TOKEN_V2",
  ];
  const benign = [
    "KEY", "key", "KEY_COUNT", "KEYCLOAK_URL", "MONKEY", "max_tokens", "TOKENIZER", "session_name", "PASSAGE",
    "AUTHOR", "OAUTH_CLIENT_ID", "GPG_KEY_ID", "SSH_AUTH_SOCK", "HOSTNAME", "COMPASS", "primaryKey",
  ];
  it.each(secret)("%s is a secret name", (n) => expect(isSecretName(n)).toBe(true));
  it.each(benign)("%s is not a secret name", (n) => expect(isSecretName(n)).toBe(false));

  it("object keys use the same rule", () => {
    const out = sanitizeForAudit({
      DB_PASS: "a", POSTGRES_PWD: "b", JWT_KEY: "c", ENCRYPTION_KEY: "d", STRIPE_KEY: "e", SMTP_AUTH: "f",
      GH_CREDENTIALS: { user: "u", pass: "g" }, MCP_FLOW_MASTER_KEY: "h",
      KEY_COUNT: 5, key: "name", max_tokens: 10, primaryKey: "id",
    }) as Record<string, unknown>;
    for (const k of ["DB_PASS", "POSTGRES_PWD", "JWT_KEY", "ENCRYPTION_KEY", "STRIPE_KEY", "SMTP_AUTH", "GH_CREDENTIALS", "MCP_FLOW_MASTER_KEY"])
      expect(out[k]).toBe(R);
    expect(out).toMatchObject({ KEY_COUNT: 5, key: "name", max_tokens: 10, primaryKey: "id" });
  });

  it("documented false positives: *_KEY names that are not secrets are redacted (fail closed)", () => {
    expect(sanitizeForAudit({ sort_key: "created_at", PUBLIC_KEY: "ssh-ed25519 AAAA" })).toEqual({ sort_key: R, PUBLIC_KEY: R });
    expect(redactSecrets("PWD=/home/app")).toBe(`PWD=${R}`);
  });
});

describe("assignment values", () => {
  it.each([
    ["DB_PASS=hunter2", `DB_PASS=${R}`],
    ["DB_PASS=hunter 2 with spaces", `DB_PASS=${R}`],
    ["export POSTGRES_PWD=p@ss word && echo", `export POSTGRES_PWD=${R}`],
    ["ENCRYPTION_KEY = abc def", `ENCRYPTION_KEY = ${R}`],
    ["stripe_key: sk_live_fake", `stripe_key: ${R}`],
    ["SMTP_AUTH=user:pw", `SMTP_AUTH=${R}`],
    ["MCP_FLOW_MASTER_KEY=AAAA==", `MCP_FLOW_MASTER_KEY=${R}`],
    ["--password=hunter2 --verbose", `--password=${R}`],
  ])("unquoted runs to end of line: %s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("multi-line env text keeps the other lines", () => {
    const env = "A=1\nDB_PASS=hunter 2\r\nJWT_KEY=k1\nKEY_COUNT=5\nB=two";
    expect(redactSecrets(env)).toBe(`A=1\nDB_PASS=${R}\r\nJWT_KEY=${R}\nKEY_COUNT=5\nB=two`);
  });

  it.each([
    [`DB_PASS="hunter 2" next`, `DB_PASS="${R}" next`],
    [`DB_PASS='hunter 2' next`, `DB_PASS='${R}' next`],
    [`JWT_KEY="a\\"b c" next`, `JWT_KEY="${R}" next`],
    [`JWT_KEY='a\\'b c' next`, `JWT_KEY='${R}' next`],
    [`GH_CREDENTIALS="multi\nline" X=1`, `GH_CREDENTIALS="${R}" X=1`],
    [`DB_PASS="unterminated value\nX=1`, `DB_PASS=${R}\nX=1`],
  ])("quoted values are redacted whole, escaped quotes included: %s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("value ends at the quote that opened the pair", () => {
    expect(redactSecrets(`docker run -e "DB_PASS=a b" img`)).toBe(`docker run -e "DB_PASS=${R}" img`);
    expect(redactSecrets(`curl -H 'Authorization: Bearer abc.def' https://x`)).toBe(`curl -H 'Authorization: ${R}' https://x`);
  });

  it("env text inside JSON strings with literal \\n", () => {
    const json = JSON.stringify({ env: "A=1\nDB_PASS=s3cr3t pw\nSTRIPE_KEY=\"q\\\"x\"\nB=2" });
    const out = redactSecrets(json);
    expect(out).not.toContain("s3cr3t");
    expect(out).not.toContain("q\\\\\\\"x");
    expect(out).toContain("A=1\\nDB_PASS=[redacted]\\nSTRIPE_KEY=");
    expect(out).toContain("\\nB=2");
    // the same text as a parsed argument value
    expect(sanitizeForAudit({ env: "A=1\nDB_PASS=s3cr3t pw\nB=2" })).toEqual({ env: `A=1\nDB_PASS=${R}\nB=2` });
  });

  it("JSON key form in text, plain and double-encoded", () => {
    expect(redactSecrets(`{"DB_PASS": "q\\"uo ted", "x": 1}`)).toBe(`{"DB_PASS": "${R}", "x": 1}`);
    expect(redactSecrets(`{"DB_PASS": 12345, "x": 1}`)).toBe(`{"DB_PASS": ${R}, "x": 1}`);
    expect(redactSecrets(`{"cmd":"DB_PASS=hunter2","u":"bob"}`)).toBe(`{"cmd":"DB_PASS=${R}","u":"bob"}`);
    const twice = JSON.stringify(JSON.stringify({ JWT_KEY: "zz top", u: 1 }));
    const out = redactSecrets(twice);
    expect(out).not.toContain("zz top");
    expect(out).toContain('u\\":1');
  });

  it("negatives: ordinary assignments stay readable", () => {
    for (const s of ["KEY_COUNT=5", "key=value", "max_tokens: 100", "MONKEY=banana", "OAUTH_CLIENT_ID=abc",
      "see https://example.com/a:b", "GPG_KEY_ID=ABCD1234", "time 12:30", "x=1 y=2"]) expect(redactSecrets(s)).toBe(s);
  });
});

describe("URL userinfo in any scheme", () => {
  it.each([
    ["redis://:pw@host:6379/0", `redis://${R}@host:6379/0`],
    ["postgres://u:p@h/db", `postgres://${R}@h/db`],
    ["postgresql://user:p%40ss@db:5432/app", `postgresql://${R}@db:5432/app`],
    ["amqp://guest:guest@mq:5672", `amqp://${R}@mq:5672`],
    ["mongodb+srv://u:p@cluster0.example.net/x", `mongodb+srv://${R}@cluster0.example.net/x`],
    ["https://user:tok@github.com/org/repo.git", `https://${R}@github.com/org/repo.git`],
    ["https://ghp_faketoken@github.com/x", `https://${R}@github.com/x`],
    ["git clone https://x:y@h/r && cd r", `git clone https://${R}@h/r && cd r`],
  ])("%s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("DSN in an env line is redacted as a whole", () => {
    expect(redactSecrets("DATABASE_URL=postgres://u:p@h/db")).toBe(`DATABASE_URL=${R}`);
  });

  it("negatives: URLs without userinfo and @ in paths stay", () => {
    for (const s of ["https://example.com/a/@user", "https://h/x?email=a@b.c", "mailto:a@b.c", "ssh host"]) expect(redactSecrets(s)).toBe(s);
  });
});

describe("Authorization headers, Bearer and Basic", () => {
  it.each([
    ["Authorization: Bearer abc.def-ghi", `Authorization: ${R}`],
    ["authorization: Basic dXNlcjpwYXNz", `authorization: ${R}`],
    ["Proxy-Authorization: Digest username=x", `Proxy-Authorization: ${R}`],
    ["GET / HTTP/1.1\r\nHost: h\r\nAuthorization: token ghx_fake\r\nAccept: */*", `GET / HTTP/1.1\r\nHost: h\r\nAuthorization: ${R}\r\nAccept: */*`],
    [`{"Authorization":"Bearer abc123","ok":1}`, `{"Authorization":"${R}","ok":1}`],
    [`{"headers":{"authorization": "Basic dXNlcjpwYXNz"}}`, `{"headers":{"authorization": "${R}"}}`],
    ["token is Bearer abc.def", `token is Bearer ${R}`],
    ["creds Basic dXNlcjpwYXNz here", `creds Basic ${R} here`],
  ])("%s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("header objects are redacted by key", () => {
    expect(sanitizeForAudit({ headers: { Authorization: "Bearer x", "X-Api-Key": "k", Accept: "a" } }))
      .toEqual({ headers: { Authorization: R, "X-Api-Key": R, Accept: "a" } });
  });

  it("negatives: prose about auth stays", () => {
    for (const s of ["Basic authentication is supported", "use basic settings", "the author: Chen"]) expect(redactSecrets(s)).toBe(s);
  });
});

describe("bounded cost", () => {
  it("large adversarial inputs finish quickly", () => {
    const inputs = [
      "A=".repeat(200_000), "a://".repeat(100_000), "\"DB_PASS\":".repeat(50_000), "x".repeat(127) + "=" + "y:".repeat(100_000),
      "DB_PASS=\"" + "\\\\".repeat(100_000),
    ];
    const t = Date.now();
    for (const s of inputs) redactSecrets(s);
    expect(Date.now() - t).toBeLessThan(2000);
  });
});
