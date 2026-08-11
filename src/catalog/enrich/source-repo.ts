/**
 * Probe public GitHub/GitLab source repos. 404 → not_found (mark inactive).
 */

export type SourceRepoProbeStatus =
  | "ok"
  | "not_found"
  | "unreachable"
  | "skipped"
  | "unsupported";

export interface SourceRepoProbeResult {
  status: SourceRepoProbeStatus;
  url?: string;
  checkedAt: string;
  httpStatus?: number;
  error?: string;
  host?: "github" | "gitlab";
}

export interface ProbeSourceRepoOptions {
  timeoutMs?: number;
  /** Optional GET that returns status + optional body (factory proxy) */
  headOrGet?: (url: string) => Promise<{ status: number; ok: boolean }>;
}

function parseGithubRepo(url: string): { owner: string; repo: string } | null {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    if (host !== "github.com" && host !== "www.github.com") return null;
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    if (["orgs", "users", "settings", "marketplace"].includes(parts[0]!))
      return null;
    return {
      owner: parts[0]!,
      repo: parts[1]!.replace(/\.git$/, ""),
    };
  } catch {
    return null;
  }
}

function parseGitlabRepo(url: string): { path: string } | null {
  try {
    const u = new URL(url);
    if (!u.hostname.toLowerCase().includes("gitlab")) return null;
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const cut = parts.indexOf("-");
    const pathParts = cut >= 0 ? parts.slice(0, cut) : parts.slice(0, 2);
    if (pathParts.length < 2) return null;
    return { path: pathParts.join("/") };
  } catch {
    return null;
  }
}

/** Canonical HTML repo URL to probe (no .git, no tree path). */
export function canonicalRepoUrl(sourceUrl: string | undefined): {
  probeUrl: string;
  host: "github" | "gitlab";
} | null {
  if (!sourceUrl?.trim()) return null;
  const gh = parseGithubRepo(sourceUrl);
  if (gh) {
    return {
      probeUrl: `https://github.com/${gh.owner}/${gh.repo}`,
      host: "github",
    };
  }
  const gl = parseGitlabRepo(sourceUrl);
  if (gl) {
    return {
      probeUrl: `https://gitlab.com/${gl.path}`,
      host: "gitlab",
    };
  }
  return null;
}

async function defaultProbe(
  url: string,
  timeoutMs: number,
): Promise<{ status: number; ok: boolean }> {
  // Prefer HEAD; some hosts block it — fall back to GET
  try {
    const head = await fetch(url, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: "text/html", "User-Agent": "mcp-flow-catalog/0.1" },
    });
    if (head.status !== 405 && head.status !== 501) {
      return { status: head.status, ok: head.ok };
    }
  } catch {
    /* try GET */
  }
  const get = await fetch(url, {
    method: "GET",
    redirect: "follow",
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: "text/html", "User-Agent": "mcp-flow-catalog/0.1" },
  });
  return { status: get.status, ok: get.ok };
}

/**
 * Check whether the public source repository still exists.
 * 404/410 → not_found. Other errors → unreachable (do not mark inactive).
 */
export async function probeSourceRepo(
  sourceUrl: string | undefined,
  opts: ProbeSourceRepoOptions = {},
): Promise<SourceRepoProbeResult> {
  const checkedAt = new Date().toISOString();
  const canon = canonicalRepoUrl(sourceUrl);
  if (!canon) {
    return {
      status: sourceUrl?.trim() ? "unsupported" : "skipped",
      url: sourceUrl,
      checkedAt,
      error: sourceUrl?.trim()
        ? "not a public GitHub/GitLab repo URL"
        : "no sourceUrl",
    };
  }

  const timeoutMs = opts.timeoutMs ?? 12_000;
  const probe = opts.headOrGet ?? ((u: string) => defaultProbe(u, timeoutMs));

  try {
    const res = await probe(canon.probeUrl);
    if (res.status === 404 || res.status === 410) {
      return {
        status: "not_found",
        url: canon.probeUrl,
        host: canon.host,
        checkedAt,
        httpStatus: res.status,
        error: `repository HTTP ${res.status}`,
      };
    }
    if (res.ok || res.status === 401 || res.status === 403) {
      // 401/403 = exists but private — still "online" as a repo target
      return {
        status: "ok",
        url: canon.probeUrl,
        host: canon.host,
        checkedAt,
        httpStatus: res.status,
      };
    }
    return {
      status: "unreachable",
      url: canon.probeUrl,
      host: canon.host,
      checkedAt,
      httpStatus: res.status,
      error: `repository HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      status: "unreachable",
      url: canon.probeUrl,
      host: canon.host,
      checkedAt,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
