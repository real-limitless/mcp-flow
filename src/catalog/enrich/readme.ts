import type { GalleryReadme } from "../types.js";

const ALLOWED_HOSTS = new Set([
  "github.com",
  "www.github.com",
  "raw.githubusercontent.com",
  "gitlab.com",
  "www.gitlab.com",
]);

export interface FetchReadmeOptions {
  maxBytes?: number;
  timeoutMs?: number;
  /** Optional proxied GET text */
  getText?: (url: string) => Promise<string>;
}

function parseGithub(url: string): { owner: string; repo: string } | null {
  try {
    const u = new URL(url);
    if (!ALLOWED_HOSTS.has(u.hostname.toLowerCase())) return null;
    if (!u.hostname.includes("github")) return null;
    // github.com/owner/repo[/...]
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const owner = parts[0]!;
    const repo = parts[1]!.replace(/\.git$/, "");
    return { owner, repo };
  } catch {
    return null;
  }
}

function parseGitlab(url: string): { path: string } | null {
  try {
    const u = new URL(url);
    if (!u.hostname.includes("gitlab")) return null;
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    // strip /- /blob/...
    const cut = parts.indexOf("-");
    const pathParts = cut >= 0 ? parts.slice(0, cut) : parts;
    return { path: pathParts.join("/") };
  } catch {
    return null;
  }
}

async function tryGet(
  url: string,
  opts: FetchReadmeOptions,
): Promise<{ text: string; url: string } | null> {
  try {
    const getText =
      opts.getText ??
      (async (u: string) => {
        const res = await fetch(u, {
          signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000),
          headers: { Accept: "text/plain, text/markdown, */*" },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.text();
      });
    const text = await getText(url);
    return { text, url };
  } catch {
    return null;
  }
}

/**
 * Fetch README markdown from a public GitHub/GitLab repo URL.
 * Never follows arbitrary hosts (SSRF allowlist).
 */
export async function fetchReadmeFromSourceUrl(
  sourceUrl: string | undefined,
  opts: FetchReadmeOptions = {},
): Promise<GalleryReadme> {
  const maxBytes = opts.maxBytes ?? 200_000;
  const now = new Date().toISOString();

  if (!sourceUrl?.trim()) {
    return { source: "none", fetchedAt: now, error: "no sourceUrl" };
  }

  let host: string;
  try {
    host = new URL(sourceUrl).hostname.toLowerCase();
  } catch {
    return { source: "none", fetchedAt: now, error: "invalid sourceUrl" };
  }

  if (!ALLOWED_HOSTS.has(host) && !host.endsWith(".github.io")) {
    // allow project pages only as none for readme
    return {
      source: "none",
      fetchedAt: now,
      error: `host not allowlisted: ${host}`,
    };
  }

  const gh = parseGithub(sourceUrl);
  if (gh) {
    const candidates = [
      `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/main/README.md`,
      `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/master/README.md`,
      `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/main/readme.md`,
      `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/master/readme.md`,
    ];
    for (const url of candidates) {
      const hit = await tryGet(url, opts);
      if (hit) {
        const buf = Buffer.from(hit.text, "utf8");
        const truncated = buf.length > maxBytes;
        const markdown = truncated
          ? buf.subarray(0, maxBytes).toString("utf8")
          : hit.text;
        return {
          source: "github",
          url: hit.url,
          markdown,
          fetchedAt: now,
          truncated: truncated || undefined,
        };
      }
    }
    return {
      source: "github",
      fetchedAt: now,
      error: "README.md not found on main/master",
    };
  }

  const gl = parseGitlab(sourceUrl);
  if (gl) {
    const candidates = [
      `https://gitlab.com/${gl.path}/-/raw/main/README.md`,
      `https://gitlab.com/${gl.path}/-/raw/master/README.md`,
    ];
    for (const url of candidates) {
      const hit = await tryGet(url, opts);
      if (hit) {
        const buf = Buffer.from(hit.text, "utf8");
        const truncated = buf.length > maxBytes;
        const markdown = truncated
          ? buf.subarray(0, maxBytes).toString("utf8")
          : hit.text;
        return {
          source: "gitlab",
          url: hit.url,
          markdown,
          fetchedAt: now,
          truncated: truncated || undefined,
        };
      }
    }
    return {
      source: "gitlab",
      fetchedAt: now,
      error: "README.md not found",
    };
  }

  return { source: "none", fetchedAt: now, error: "unsupported repo host" };
}
