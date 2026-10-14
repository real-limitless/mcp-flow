/**
 * Maintenance only (never run by the gateway): archive + delete call_audit rows older than a month boundary.
 *   tsx scripts/audit-retention.ts --workspace ws_… --before 2025-10-01T00:00:00.000Z --archive ./archive --actor agt_… [--execute] [--min-months 12]
 * DRY RUN by default: prints what would be archived/deleted. Nothing is written or deleted without --execute.
 * `before` must be ≥ --min-months (default 12) in the past. Lifecycle rows are never deleted.
 * Also (R2-6) archives + deletes resolved call_outcome / pending_call rows older than `before`
 * (never open holds, approved-undispatched holds, or holds a grant still references; no ciphertext archived).
 * Requires MCP_FLOW_DB_PATH. Take a DB backup first; Chen approval before any non-dev run.
 */
import { DatabaseSync } from "node:sqlite";
import { applyConnectionPragmas } from "../src/db/migrations/index.js";
import { runAuditRetention } from "../src/audit/call-audit.js";

function arg(name: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const v = i >= 0 ? process.argv[i + 1] : undefined;
  if (!v) throw new Error(`--${name} is required`);
  return v;
}

const dbPath = process.env.MCP_FLOW_DB_PATH;
if (!dbPath) throw new Error("MCP_FLOW_DB_PATH is required");
const db = new DatabaseSync(dbPath);
applyConnectionPragmas(db);
const out = runAuditRetention(db, {
  workspaceId: arg("workspace"),
  before: arg("before"),
  archiveDir: arg("archive"),
  actor: arg("actor"),
  execute: process.argv.includes("--execute"),
  // validated in runAuditRetention: integer ≥ 1 (NaN, 0 and negatives are rejected)
  minMonths: process.argv.includes("--min-months") ? Number(arg("min-months")) : undefined,
});
if (out.dryRun) console.error("DRY RUN: nothing written or deleted. Re-run with --execute after review.");
console.log(JSON.stringify(out, null, 2));
db.close();
