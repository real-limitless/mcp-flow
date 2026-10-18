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

describe("A0 review follow-ups", () => {
  it("name/value pairs redact the sibling value (Dokploy env arrays)", () => {
    const env = [
      { name: "DB_PASS", value: "pw-1" },
      { key: "STRIPE_KEY", value: "pw-2" },
      { variable: "GH_CREDENTIALS", value: "pw-3" },
      { env: "SMTP_AUTH", val: "pw-4" },
      { Name: "MCP_FLOW_MASTER_KEY", Value: "pw-5" },
      { name: " JWT_KEY ", value: "pw-6", type: "secret" },
      { name: "HOST", value: "db.internal" },
      { key: "KEY_COUNT", value: "5" },
    ];
    const out = sanitizeForAudit({ env, compose: { environment: [{ name: "POSTGRES_PWD", value: "pw-7" }] } }) as {
      env: Array<Record<string, unknown>>; compose: { environment: Array<Record<string, unknown>> };
    };
    const s = JSON.stringify(out);
    for (let i = 1; i <= 7; i++) expect(s).not.toContain(`pw-${i}`);
    expect(out.env[0]).toEqual({ name: "DB_PASS", value: R });
    expect(out.env[5]).toEqual({ name: " JWT_KEY ", value: R, type: "secret" });
    expect(out.env[6]).toEqual({ name: "HOST", value: "db.internal" });
    expect(out.env[7]).toEqual({ key: "KEY_COUNT", value: "5" });
    expect(out.compose.environment[0]).toEqual({ name: "POSTGRES_PWD", value: R });
  });

  it.each([
    ["postgres://u:p@ss@h/db", `postgres://${R}@h/db`],
    ["redis://:p@ss@w0rd@cache:6379/0", `redis://${R}@cache:6379/0`],
    ["https://u:a@b@c@host?x=1 then mail me@x.y", `https://${R}@host?x=1 then mail me@x.y`],
    ["amqp://u:p@ss@mq#frag", `amqp://${R}@mq#frag`],
  ])("userinfo ends at the last @ of the authority: %s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("_TOKENS is a secret suffix except token counts and limits", () => {
    for (const n of ["API_TOKENS", "slack_tokens", "GH_TOKENS"]) expect(isSecretName(n)).toBe(true);
    for (const n of ["max_tokens", "MAX_TOKENS", "model_max_tokens", "max_output_tokens", "max_new_tokens",
      "max_completion_tokens", "prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens"])
      expect(isSecretName(n)).toBe(false);
    expect(redactSecrets("API_TOKENS=a,b")).toBe(`API_TOKENS=${R}`);
    expect(sanitizeForAudit({ usage: { prompt_tokens: 3, total_tokens: 5 }, max_tokens: 9 }))
      .toEqual({ usage: { prompt_tokens: 3, total_tokens: 5 }, max_tokens: 9 });
  });

  it("PEM blocks: terminated, unterminated (fail closed), several, and non-key PEM kept", () => {
    const k = "-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----";
    expect(redactSecrets(`a ${k} b ${k} c`)).toBe(`a ${R} b ${R} c`);
    expect(redactSecrets("x -----BEGIN PRIVATE KEY-----\nMIIfake-truncated")).toBe(`x ${R}`);
    const cert = "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----";
    expect(redactSecrets(cert)).toBe(cert);
    expect(redactSecrets(`-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END CERTIFICATE-----\nmore\n-----END OPENSSH PRIVATE KEY----- tail`)).toBe(`${R} tail`);
  });

  it("PEM scan is linear on repeated unterminated BEGIN headers", () => {
    const s = "-----BEGIN RSA PRIVATE KEY-----\n".repeat(20_000) + "x".repeat(100_000);
    const t = Date.now();
    expect(redactSecrets(s)).toBe(R);
    const s2 = "-----BEGIN RSA PRIVATE KEY----- -----END CERT-----".repeat(10_000);
    redactSecrets(s2);
    redactSecrets("-----BEGIN ".repeat(50_000));
    expect(Date.now() - t).toBeLessThan(1000);
  });

  it.each([
    ["mysql -u root -phunter2 app", `mysql -u root -p${R} app`],
    ["mysqldump -h db -p'p w' app > x.sql", `mysqldump -h db -p${R} app > x.sql`],
    ["mariadb -uroot -p\"pw\" -e 'select 1'", `mariadb -uroot -p${R} -e 'select 1'`],
  ])("mysql -p<password>: %s", (input, want) => expect(redactSecrets(input)).toBe(want));

  it("mysql negatives: -p alone prompts, -P is the port, other tools keep -p", () => {
    for (const s of ["mysql -u root -p app", "mysql -h db -P3306 -u x", "mkdir -p /tmp/x", "ssh -p 2222 host"])
      expect(redactSecrets(s)).toBe(s);
  });

  it("a literal \\n inside a value does not cut it short unless a new pair follows", () => {
    expect(redactSecrets("DB_PASS=ab\\ncd ef")).toBe(`DB_PASS=${R}`);
    expect(redactSecrets("DB_PASS=ab\\nNEXT=1")).toBe(`DB_PASS=${R}\\nNEXT=1`);
    expect(redactSecrets("DB_PASS=ab\\n\\nNEXT=1")).toBe(`DB_PASS=${R}\\n\\nNEXT=1`);
    expect(redactSecrets(`{"env":"DB_PASS=ab\\nB=2"}`)).toBe(`{"env":"DB_PASS=${R}\\nB=2"}`);
  });

  it("literal-escape scan stays linear", () => {
    const t = Date.now();
    redactSecrets("DB_PASS=" + "\\n".repeat(200_000) + "x");
    redactSecrets("DB_PASS=" + "\\nx".repeat(100_000));
    expect(Date.now() - t).toBeLessThan(1000);
  });
});

describe("A0 second-round follow-ups", () => {
  it("token-count carve-out lists count words only", () => {
    for (const n of ["MAX_ACCESS_TOKENS", "max_refresh_tokens", "max_api_tokens", "MAX_GH_TOKENS", "app_max_secret_tokens"])
      expect(isSecretName(n)).toBe(true);
    for (const n of ["max_tokens", "max_input_tokens", "max_output_tokens", "max_completion_tokens", "max_prompt_tokens",
      "max_new_tokens", "max_context_tokens", "model_max_tokens", "MAX-OUTPUT-TOKENS"])
      expect(isSecretName(n)).toBe(false);
    expect(redactSecrets("MAX_ACCESS_TOKENS=a,b")).toBe(`MAX_ACCESS_TOKENS=${R}`);
    expect(sanitizeForAudit({ max_refresh_tokens: "x", max_new_tokens: 7 })).toEqual({ max_refresh_tokens: R, max_new_tokens: 7 });
  });

  it("userinfo is redacted after schemes longer than 32 chars", () => {
    const scheme = "x" + "a".repeat(40);
    expect(redactSecrets(`${scheme}://u:p@ss@host/db`)).toBe(`${scheme}://${R}@host/db`);
    expect(redactSecrets("weird_scheme!://tok@h")).toBe(`weird_scheme!://${R}@h`);
    expect(redactSecrets(`${scheme}://host/path@x`)).toBe(`${scheme}://host/path@x`);
  });

  it("userinfo scan stays linear (long schemes, many '://', long runs)", () => {
    const t = Date.now();
    redactSecrets("a".repeat(200_000) + "://" + "b".repeat(200_000));
    redactSecrets("://".repeat(100_000));
    redactSecrets("x.".repeat(100_000) + "://u@h");
    redactSecrets("://" + "@".repeat(200_000));
    expect(Date.now() - t).toBeLessThan(1000);
  });

  it("valueFrom and envName/envValue pairs", () => {
    expect(sanitizeForAudit({ name: "DB_PASS", valueFrom: { secretKeyRef: { name: "db", key: "pw" } } }))
      .toEqual({ name: "DB_PASS", valueFrom: R });
    expect(sanitizeForAudit({ envName: "STRIPE_KEY", envValue: "pw-x" })).toEqual({ envName: "STRIPE_KEY", envValue: R });
    expect(sanitizeForAudit({ envName: "HOST", envValue: "db" })).toEqual({ envName: "HOST", envValue: "db" });
  });
});
