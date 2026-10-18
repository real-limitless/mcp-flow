// Redaction tests copied verbatim from feat/agents-policy-audit-db
// (tests/security-t25.test.ts "M-2 embedded secrets are redacted" and
// tests/security-rereview.test.ts "M-2 redaction (re-review gaps)"), which also
// cover governance-only modules; only the sanitize blocks are carried here.
import { describe, expect, it } from "vitest";
import { redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";

describe("M-2 embedded secrets are redacted", () => {
  it("mid-string and common formats", () => {
    const pat = "ghp_" + "A".repeat(36);
    const samples = [
      `curl -H "Authorization: Bearer abc.def.ghi123" https://x`,
      "postgres://user:hunter2@db:5432/app",
      "https://x.example/cb?access_token=SECRETVALUE123&ok=1",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      `echo ${pat} > x`, "github_pat_" + "B".repeat(30), "glpat-" + "c".repeat(20), "AKIAABCDEFGHIJKLMNOP",
      "https://hooks.slack.com/services/T000/B000/XXXX", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
      "DATABASE_PASSWORD=hunter2 ./run", "aws_secret_access_key = wJalrXUtnFEMI",
    ];
    const secrets = ["abc.def.ghi123", "hunter2", "SECRETVALUE123", "dozjgNryP4J3", pat, "B".repeat(30), "c".repeat(20),
      "AKIAABCDEFGHIJKLMNOP", "XXXX", "\nabc\n", "wJalrXUtnFEMI"];
    const out = JSON.stringify(sanitizeForAudit({ cmd: samples }));
    for (const s of secrets) expect(out).not.toContain(s);
    // secret past the 16 KB truncation point is still caught
    expect(JSON.stringify(sanitizeForAudit({ c: "x".repeat(20_000) + pat }))).not.toContain(pat);
    expect(redactSecrets("postgres://u:pw@h/db")).toBe("postgres://[redacted]@h/db");
  });
  it("benign keys stay readable; secret keys redacted", () => {
    expect(sanitizeForAudit({ max_tokens: 100, session_name: "s1", dsn: "x", pwd: "y", api_key: "z", session_id: "q" }))
      .toEqual({ max_tokens: 100, session_name: "s1", dsn: "[redacted]", pwd: "[redacted]", api_key: "[redacted]", session_id: "[redacted]" });
  });
});

describe("M-2 redaction (re-review gaps)", () => {
  it("camelCase keys, Authorization: token, opaque high-entropy values; digests/uuids/benign keys kept", () => {
    const opaque = "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ2cD4eF6gH8j";
    const out = sanitizeForAudit({
      apiToken: "a", authToken: "b", githubToken: "c", clientSecret: "d", accessKeyId: "AKIAABCDEFGHIJKLMNOP",
      header: "Authorization: token ghx_abc123secretvalue", value: opaque,
      sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", uuid: "123e4567-e89b-12d3-a456-426614174000",
      primaryKey: "id", idempotencyKey: "k-1", max_tokens: 5,
    }) as Record<string, unknown>;
    for (const k of ["apiToken", "authToken", "githubToken", "clientSecret", "value"]) expect(out[k]).toBe("[redacted]");
    expect(JSON.stringify(out)).not.toContain("ghx_abc123secretvalue");
    expect(JSON.stringify(out)).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(out).toMatchObject({ sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", uuid: "123e4567-e89b-12d3-a456-426614174000", primaryKey: "id", idempotencyKey: "k-1", max_tokens: 5 });
  });
  it("a secret straddling the 16 KB cut is still caught; nothing past the kept prefix is stored", () => {
    const pat = "ghp_" + "Z".repeat(36);
    const s = JSON.stringify(sanitizeForAudit({ c: "x".repeat(16_384 - 10) + pat + "y".repeat(5_000_000) }));
    expect(s).not.toContain("ZZZZZZZZZZ");
    expect(s.length).toBeLessThan(20_000);
  });
});
