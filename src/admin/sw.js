/* mcp-flow admin service worker: cache the shell, never /v1 or /mcp. */
const CACHE = "mcp-flow-admin-v1";
const PRECACHE = [
  "/admin/",
  "/admin/app.js",
  "/admin/styles.css",
  "/admin/manifest.webmanifest",
  "/admin/icon.svg",
  "/admin/icon-192.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET") return;
  if (url.pathname.startsWith("/v1/") || url.pathname === "/mcp") return;
  if (!url.pathname.startsWith("/admin")) return;
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return res;
      })
      .catch(() => caches.match(event.request)),
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { body: event.data ? event.data.text() : "" };
  }
  const title = data.title || "mcp-flow approval";
  const actions = data.token
    ? [
        { action: "approve", title: "Approve" },
        { action: "deny", title: "Deny" },
      ]
    : [{ action: "open", title: "Open Admin" }];
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body || "A gated tool is waiting",
      icon: "/admin/icon-192.png",
      badge: "/admin/icon-192.png",
      tag: data.approvalId || "authz",
      renotify: true,
      data,
      actions,
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const openUrl = data.url || "/admin/#approvals";
  const action = event.action;
  const focusOrOpen = async () => {
    const windows = await self.clients.matchAll({
      type: "window",
      includeUncontrolled: true,
    });
    for (const client of windows) {
      if (String(client.url).includes("/admin")) {
        await client.focus();
        if (data.approvalId) {
          client.postMessage({
            type: "authz-open",
            approvalId: data.approvalId,
          });
        }
        return;
      }
    }
    await self.clients.openWindow(openUrl);
  };

  if (
    (action === "approve" || action === "deny") &&
    data.token &&
    data.approvalId
  ) {
    event.waitUntil(
      fetch(`/v1/approvals/${encodeURIComponent(data.approvalId)}/push-decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: action, token: data.token }),
      })
        .then(async (res) => {
          if (!res.ok) {
            await self.clients.openWindow(openUrl);
            return;
          }
          const windows = await self.clients.matchAll({
            type: "window",
            includeUncontrolled: true,
          });
          for (const client of windows) {
            if (String(client.url).includes("/admin")) {
              await client.focus();
              client.postMessage({
                type: "authz-decided",
                approvalId: data.approvalId,
                decision: action,
              });
              return;
            }
          }
          await self.clients.openWindow(openUrl);
        })
        .catch(() => focusOrOpen()),
    );
    return;
  }

  event.waitUntil(focusOrOpen());
});
