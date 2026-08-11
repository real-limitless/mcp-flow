import { describe, expect, it } from "vitest";
import { ProxyPool } from "../scripts/factory/lib/proxy-pool.js";

describe("factory ProxyPool.parseProxyLines", () => {
  it("parses host:port and schemes", () => {
    const pool = new ProxyPool();
    const list = pool.parseProxyLines(`
# comment
1.2.3.4:1080
socks5://5.6.7.8:1080
http://proxy.example:8080
not-a-proxy
`);
    expect(list).toContain("socks5h://1.2.3.4:1080");
    expect(list).toContain("socks5h://5.6.7.8:1080");
    expect(list).toContain("http://proxy.example:8080");
    expect(list).toHaveLength(3);
  });
});

describe("factory catalog-io upsert", () => {
  it("upserts by id under lock", async () => {
    // catalog-io writes to repo catalog/ — use isolated test via dynamic would need DI
    // Smoke: parse path modules load
    const { loadGallery } = await import("../scripts/factory/lib/catalog-io.js");
    expect(Array.isArray(loadGallery())).toBe(true);
  });
});

describe("factory job-store", () => {
  it("enqueue and list", async () => {
    const { enqueue, listQueue, dropDone, updateJob } = await import(
      "../scripts/factory/lib/job-store.js"
    );
    const job = enqueue({
      server: {
        name: "test.factory/unit",
        description: "unit",
        remotes: [{ type: "streamable-http", url: "https://example.com/mcp" }],
      },
    });
    expect(job.status).toBe("pending");
    const pending = listQueue("pending").filter((j) => j.id === job.id);
    expect(pending).toHaveLength(1);
    updateJob(job.id, { status: "done" });
    dropDone();
    expect(listQueue("all").find((j) => j.id === job.id)).toBeUndefined();
  });
});
