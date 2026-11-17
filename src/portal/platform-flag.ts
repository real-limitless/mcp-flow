import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

/** True when this database has enabled platform logins. Missing file or table is false. */
export function platformLoginsEnabledAt(dbPath: string): boolean {
  if (!dbPath || dbPath === ":memory:" || !existsSync(dbPath)) return false;
  let db: DatabaseSync | null = null;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    const row = db
      .prepare(`SELECT enabled_at FROM portal_platform WHERE id = 'platform'`)
      .get() as { enabled_at: string | null } | undefined;
    return Boolean(row?.enabled_at);
  } catch {
    return false;
  } finally {
    db?.close();
  }
}
