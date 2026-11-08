# Named sidecar connections

Outbound traffic from a backend stays on the gateway's normal network until you select a named connection for that backend. Publishing the gateway on a tailnet does not give backend processes a route or MagicDNS. Sharing the sidecar's network namespace in userspace mode does not either.

A connection is a name plus a proxy the operator chose. The model is not Tailscale-specific. Another VPN can register the same way when it exposes an HTTP or SOCKS proxy.

## Attach the bundled Tailscale sidecar

Compose starts a userspace Tailscale sidecar (no TUN). Set `TS_AUTHKEY`, `TS_HOSTNAME`, and `TS_LOGIN_SERVER` as in `.env.example`. The sidecar listens on the compose network for an HTTP proxy and a SOCKS5 proxy. Those ports are not published on the host.

`MCP_FLOW_SIDECARS` registers that listener as a connection when the gateway starts. Compose sets the variable. You can rename the connection in Admin. A later restart refreshes the proxy endpoints and keeps the display name. No backend uses it until you select it.

To add another tailnet, run another sidecar with its own state and proxy ports, then add another object to `MCP_FLOW_SIDECARS` or register it in Admin. Each connection is one network. A backend names one connection, or none.

## Select it on a backend

In Admin, open Backends. **Connect via** lists the connections that match the placement, plus Direct. Direct is the default and is the same path as before.

- `mcp-flow connection list`
- `mcp-flow connection add --slug office --name "Office" --kind tailscale --http-proxy <proxy> --socks-proxy <proxy>`
- `mcp-flow connection rename office --name "Lab"`
- `mcp-flow backend add --slug example --url https://mcp.example.com/mcp --connection office`
- `mcp-flow connection assign office --backend example`
- `mcp-flow connection unassign --backend example`

Remote HTTP and SSE calls from the gateway go through the selected proxy. Stdio and OCI backends receive proxy environment on that process only:

- `HTTP_PROXY` and `HTTPS_PROXY` (and the lowercase names) when the connection has an HTTP proxy
- `ALL_PROXY` and `SOCKS_PROXY` using `socks5h`, so the sidecar resolves names, when the connection has a SOCKS proxy
- `NODE_USE_ENV_PROXY=1`, so Node's HTTP client and `fetch` honor those variables
- `NO_PROXY` includes loopback so local traffic is not sent into the sidecar

Axios on Node honors `HTTP_PROXY` and `HTTPS_PROXY`. A SOCKS-only connection is not enough for Axios or Node `fetch`. The bundled sidecar sets both.

A sealed `HTTP_PROXY` on the backend does not override the connection you selected. Other backends do not inherit these variables.

Central-sandbox OCI containers join `MCP_FLOW_EGRESS_NETWORK` when they have no network mode of their own, so the proxy hostname resolves. Compose sets that to the stack network. An explicit sandbox network mode is left as you set it.

An edge backend can select a connection whose scope is that device. Register it with a proxy URL the process on that device can reach. The gateway does not assume the compose sidecar is reachable from an edge device.

## Names

MagicDNS names are sent to the sidecar proxy and resolved there. They do not need to resolve in Docker DNS. Tailnet addresses use the same proxy. Other private addresses still follow `MCP_FLOW_ALLOW_PRIVATE_URLS`. Selecting a connection does not turn that flag on, and turning the flag on does not create a route.

Example backend URL: `https://mcp.example.com/mcp`.

## Health

Admin shows each connection's name, kind, and whether a proxy port accepted a connection. Offline means the listener is down. A selected connection that cannot be used fails the backend call. The gateway does not fall back to the normal network.
