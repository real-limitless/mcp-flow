import type { Config } from "../config.js";
import { Store } from "../db/store.js";
import { UpstreamPool } from "../mcp/upstream.js";
import type { BackendPublic, ApiKeyPublic } from "../types.js";
import { DEFAULT_PLACEMENT } from "../types.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";
import {
  c,
  clearScreen,
  cols,
  enterAltScreen,
  hideCursor,
  isTty,
  leaveAltScreen,
  pad,
  rows,
  setKeyHandler,
  showCursor,
  startInput,
  stopInput,
  truncate,
  type Key,
  writeAt,
} from "./term.js";

interface HeaderPair {
  name: string;
  value: string;
}

type HeadersReturn =
  | { kind: "add"; slug: string; url: string; transport: "streamable-http" | "sse"; enable: boolean }
  | { kind: "merge"; slug: string };

type Screen =
  | { id: "home"; cursor: number }
  | { id: "backends"; cursor: number; status: string }
  | {
      id: "backend";
      slug: string;
      cursor: number;
      status: string;
      tools?: string[];
    }
  | {
      id: "add";
      field: number;
      slug: string;
      url: string;
      headers: HeaderPair[];
      enable: boolean;
      transport: "streamable-http" | "sse";
      status: string;
    }
  | {
      id: "headers-editor";
      returnTo: HeadersReturn;
      /** committed pairs */
      pairs: HeaderPair[];
      /** list cursor; pairs.length = "+ add another", pairs.length+1 = Done */
      cursor: number;
      /** drafting a new/edit pair */
      drafting: boolean;
      draftName: string;
      draftValue: string;
      draftFocus: "name" | "value";
      editIndex: number | null;
      status: string;
    }
  | { id: "keys"; cursor: number; status: string; lastToken?: string }
  | {
      id: "key-create";
      name: string;
      status: string;
    }
  | { id: "confirm-delete"; slug: string; status: string };

function pairsToRecord(pairs: HeaderPair[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of pairs) {
    const n = p.name.trim();
    if (n) out[n] = p.value;
  }
  return out;
}

const HOME_ITEMS = ["Upstream backends", "API keys", "Quit"] as const;

export async function runTui(cfg: Config): Promise<void> {
  if (!isTty()) {
    console.error("mcp-flow tui requires an interactive TTY");
    process.exit(1);
  }

  const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
  const ws = store.ensureWorkspace(cfg.workspaceName);
  const pool = new UpstreamPool(store);

  let screen: Screen = { id: "home", cursor: 0 };
  let alive = true;
  let paintScheduled = false;

  const quit = async () => {
    alive = false;
    stopInput();
    showCursor();
    leaveAltScreen();
    await pool.closeAll();
    store.close();
  };

  const schedulePaint = () => {
    if (paintScheduled || !alive) return;
    paintScheduled = true;
    setImmediate(() => {
      paintScheduled = false;
      if (alive) paint();
    });
  };

  const backends = (): BackendPublic[] => store.listBackends(ws.id);
  const keys = (): ApiKeyPublic[] => store.listApiKeys(ws.id);

  function paint(): void {
    const w = cols();
    const h = rows();
    clearScreen();

    // header
    const title = `${c.bold}${c.cyan} mcp-flow${c.reset}${c.dim}  workspace:${c.reset} ${ws.name}`;
    writeAt(1, 1, pad(title, w));
    writeAt(2, 1, c.dim + "─".repeat(Math.max(0, w - 1)) + c.reset);

    let footer = "q quit · esc back";
    let bodyRow = 3;

    const writeLine = (text: string) => {
      if (bodyRow >= h - 1) return;
      writeAt(bodyRow, 1, pad(text, w));
      bodyRow++;
    };

    const writeBlank = () => writeLine("");

    if (screen.id === "home") {
      const s = screen;
      writeLine(`${c.bold}Home${c.reset}`);
      writeBlank();
      HOME_ITEMS.forEach((label, i) => {
        const sel = i === s.cursor;
        writeLine(
          sel
            ? `${c.reverse} › ${label} ${c.reset}`
            : `   ${label}`,
        );
      });
      footer = "↑↓ move · enter select · q quit";
    }

    if (screen.id === "backends") {
      const s = screen;
      writeLine(`${c.bold}Upstream backends${c.reset}  ${c.dim}${s.status}${c.reset}`);
      writeBlank();
      const list = backends();
      if (list.length === 0) {
        writeLine(`${c.dim}No backends yet. Press n to add one.${c.reset}`);
      } else {
        const maxSlug = Math.min(
          20,
          Math.max(4, ...list.map((b) => b.slug.length)),
        );
        writeLine(
          c.dim +
            pad("  ", 2) +
            pad("SLUG", maxSlug + 1) +
            pad("ON", 4) +
            pad("TRANSPORT", 16) +
            "URL" +
            c.reset,
        );
        list.forEach((b, i) => {
          const sel = i === s.cursor;
          const on = b.enabled
            ? `${c.green}yes${c.reset}`
            : `${c.dim}no${c.reset}`;
          const line =
            pad(b.slug, maxSlug + 1) +
            pad(stripForPad(on, 3), 4) +
            pad(b.transport, 16) +
            truncate(b.url ?? "—", Math.max(10, w - maxSlug - 28));
          writeLine(sel ? `${c.reverse} › ${line}${c.reset}` : `   ${line}`);
        });
      }
      footer = "↑↓ · enter open · n add · t test · e enable · d disable · x delete · r refresh · esc";
    }

    if (screen.id === "backend") {
      const s = screen;
      const b = store.getBackendPublic(ws.id, s.slug);
      writeLine(`${c.bold}Backend${c.reset}  ${c.cyan}${s.slug}${c.reset}`);
      writeBlank();
      if (!b) {
        writeLine(`${c.red}Not found${c.reset}`);
      } else {
        const lines = [
          `title:      ${b.title}`,
          `enabled:    ${b.enabled ? c.green + "yes" + c.reset : c.yellow + "no" + c.reset}`,
          `transport:  ${b.transport}`,
          `url:        ${b.url ?? "—"}`,
          `placement:  ${b.placement.mode}`,
          `headers:    ${
            b.hasHeaders
              ? c.green +
                "sealed " +
                c.reset +
                c.dim +
                "[" +
                (store.listBackendHeaderNames(ws.id, b.slug) ?? []).join(", ") +
                "]" +
                c.reset
              : c.dim + "none" + c.reset
          }`,
          `env:        ${b.hasEnv ? c.green + "sealed" + c.reset : c.dim + "none" + c.reset}`,
          `allowlist:  ${b.toolAllowlist?.join(", ") ?? "—"}`,
        ];
        for (const line of lines) writeLine("  " + line);
        writeBlank();
        const actions = [
          b.enabled ? "Disable" : "Enable",
          "Test connection (tools/list)",
          "Merge headers (multi)",
          "Clear sealed headers",
          "Delete backend",
          "Back",
        ];
        actions.forEach((a, i) => {
          const sel = i === s.cursor;
          writeLine(sel ? `${c.reverse} › ${a} ${c.reset}` : `   ${a}`);
        });
        if (s.tools) {
          writeBlank();
          writeLine(`${c.bold}Upstream tools${c.reset}`);
          for (const t of s.tools.slice(0, Math.max(0, h - bodyRow - 3))) {
            writeLine(`  ${c.dim}•${c.reset} ${t}`);
          }
          if (s.tools.length > h - bodyRow - 3) {
            writeLine(`  ${c.dim}… +${s.tools.length - (h - bodyRow - 3)} more${c.reset}`);
          }
        }
      }
      if (s.status) writeLine(`${c.dim}${s.status}${c.reset}`);
      footer = "↑↓ · enter · esc back";
    }

    if (screen.id === "add") {
      const s = screen;
      writeLine(`${c.bold}Add remote backend${c.reset}`);
      writeBlank();
      const headerSummary =
        s.headers.length === 0
          ? `${c.dim}none — enter to add${c.reset}`
          : s.headers.map((p) => `${p.name}=••••`).join(", ");
      const fields: Array<[string, string]> = [
        ["slug", s.slug],
        ["url", s.url],
        ["transport", s.transport],
        ["headers", headerSummary],
        ["enable now", s.enable ? "yes" : "no"],
      ];
      fields.forEach(([label, value], i) => {
        const sel = i === s.field;
        const marker = sel ? `${c.cyan}>${c.reset}` : " ";
        const val = sel
          ? `${c.reverse}${stripForPad(value || " ", Math.max(1, w - 16))}${c.reset}`
          : value || `${c.dim}—${c.reset}`;
        writeLine(`${marker} ${pad(label + ":", 12)} ${val}`);
      });
      writeBlank();
      writeLine(
        s.field === 5
          ? `${c.reverse} › Save ${c.reset}`
          : `   Save`,
      );
      writeLine(
        s.field === 6
          ? `${c.reverse} › Cancel ${c.reset}`
          : `   Cancel`,
      );
      if (s.status) {
        writeBlank();
        writeLine(`${c.yellow}${s.status}${c.reset}`);
      }
      footer =
        "↑↓/tab fields · type slug/url · enter on headers to edit multi · space toggle · save";
    }

    if (screen.id === "headers-editor") {
      const s = screen;
      const title =
        s.returnTo.kind === "merge"
          ? `Headers for ${s.returnTo.slug} (merge)`
          : "Upstream headers (multi)";
      writeLine(`${c.bold}${title}${c.reset}`);
      writeBlank();
      writeLine(
        `${c.dim}Add as many as you need (e.g. x-api-host + x-api-key). Values stay sealed.${c.reset}`,
      );
      writeBlank();

      if (s.drafting) {
        writeLine(`${c.bold}Editing pair${c.reset}`);
        const nameVal =
          s.draftFocus === "name"
            ? `${c.reverse}${s.draftName || " "}${c.reset}`
            : s.draftName || `${c.dim}Name${c.reset}`;
        const valVal =
          s.draftFocus === "value"
            ? `${c.reverse}${s.draftValue ? "••••••••" : " "}${c.reset}`
            : s.draftValue
              ? "••••••••"
              : `${c.dim}value${c.reset}`;
        writeLine(`  name:  ${nameVal}`);
        writeLine(`  value: ${valVal}`);
        writeBlank();
        writeLine(
          `${c.dim}tab switch field · enter accept pair · esc cancel draft${c.reset}`,
        );
      } else {
        if (s.pairs.length === 0) {
          writeLine(`${c.dim}(no headers yet)${c.reset}`);
        }
        s.pairs.forEach((p, i) => {
          const sel = i === s.cursor;
          const line = `${pad(p.name, 22)} ${c.dim}••••${c.reset}`;
          writeLine(sel ? `${c.reverse} › ${line}${c.reset}` : `   ${line}`);
        });
        const addIdx = s.pairs.length;
        const doneIdx = s.pairs.length + 1;
        writeLine(
          s.cursor === addIdx
            ? `${c.reverse} › + Add header ${c.reset}`
            : `   + Add header`,
        );
        writeLine(
          s.cursor === doneIdx
            ? `${c.reverse} › Done ${c.reset}`
            : `   Done`,
        );
      }
      if (s.status) {
        writeBlank();
        writeLine(`${c.yellow}${s.status}${c.reset}`);
      }
      footer = s.drafting
        ? "type · tab · enter save pair · esc"
        : "↑↓ · enter add/edit · x delete pair · Done · esc back";
    }

    if (screen.id === "keys") {
      const s = screen;
      writeLine(`${c.bold}API keys${c.reset}  ${c.dim}${s.status}${c.reset}`);
      writeBlank();
      const list = keys();
      if (list.length === 0) {
        writeLine(`${c.dim}No keys. Press n to mint one.${c.reset}`);
      } else {
        list.forEach((k, i) => {
          const sel = i === s.cursor;
          const rev = k.revokedAt
            ? `${c.red}revoked${c.reset}`
            : `${c.green}active${c.reset}`;
          const line = `${pad(k.name, 20)} ${pad(k.prefix + "…", 14)} ${rev}`;
          writeLine(sel ? `${c.reverse} › ${line}${c.reset}` : `   ${line}`);
        });
      }
      if (s.lastToken) {
        writeBlank();
        writeLine(
          `${c.yellow}New token (copy now — not shown again):${c.reset}`,
        );
        writeLine(`  ${c.bold}${s.lastToken}${c.reset}`);
      }
      footer = "↑↓ · n create · x revoke · r refresh · esc";
    }

    if (screen.id === "key-create") {
      writeLine(`${c.bold}Create API key${c.reset}`);
      writeBlank();
      writeLine(`  name: ${c.reverse}${screen.name || " "}${c.reset}`);
      if (screen.status) writeLine(`${c.yellow}${screen.status}${c.reset}`);
      footer = "type name · enter create · esc cancel";
    }

    if (screen.id === "confirm-delete") {
      writeLine(`${c.bold}Delete backend?${c.reset}`);
      writeBlank();
      writeLine(`  ${c.red}${screen.slug}${c.reset}`);
      writeBlank();
      writeLine("  y confirm · n / esc cancel");
      if (screen.status) writeLine(screen.status);
    }

    // footer
    writeAt(h, 1, pad(`${c.bgGray}${c.white} ${footer} ${c.reset}`, w));
  }

  function stripForPad(s: string, width: number): string {
    // approximate visible pad helper for mixed ansi
    const plain = s.replace(/\x1b\[[0-9;]*m/g, "");
    if (plain.length >= width) return plain.slice(0, width);
    return plain + " ".repeat(width - plain.length);
  }

  async function testBackend(slug: string): Promise<{ ok: boolean; msg: string; tools?: string[] }> {
    const b = store.getBackend(ws.id, slug);
    if (!b) return { ok: false, msg: "not found" };
    const result = await pool.testBackend(b);
    if (!result.ok) return { ok: false, msg: result.error ?? "failed" };
    return {
      ok: true,
      msg: `ok · ${result.toolCount ?? 0} tools`,
      tools: result.tools,
    };
  }

  async function handle(key: Key): Promise<void> {
    if (key.name === "ctrl" && (key.sequence === "c" || key.sequence === "d")) {
      await quit();
      return;
    }

    // global q on non-input screens
    if (
      key.name === "char" &&
      key.sequence === "q" &&
      screen.id !== "add" &&
      screen.id !== "headers-editor" &&
      screen.id !== "key-create" &&
      screen.id !== "confirm-delete"
    ) {
      await quit();
      return;
    }

    if (screen.id === "home") {
      if (key.name === "up") screen = { ...screen, cursor: Math.max(0, screen.cursor - 1) };
      if (key.name === "down")
        screen = {
          ...screen,
          cursor: Math.min(HOME_ITEMS.length - 1, screen.cursor + 1),
        };
      if (key.name === "return") {
        if (screen.cursor === 0)
          screen = { id: "backends", cursor: 0, status: "" };
        else if (screen.cursor === 1)
          screen = { id: "keys", cursor: 0, status: "" };
        else await quit();
      }
      schedulePaint();
      return;
    }

    if (screen.id === "backends") {
      const list = backends();
      if (key.name === "escape") {
        screen = { id: "home", cursor: 0 };
        schedulePaint();
        return;
      }
      if (key.name === "up")
        screen = { ...screen, cursor: Math.max(0, screen.cursor - 1) };
      if (key.name === "down")
        screen = {
          ...screen,
          cursor: Math.min(Math.max(0, list.length - 1), screen.cursor + 1),
        };
      if (key.name === "char" && key.sequence === "r") {
        screen = { ...screen, status: "refreshed" };
      }
      if (key.name === "char" && key.sequence === "n") {
        screen = {
          id: "add",
          field: 0,
          slug: "",
          url: "",
          headers: [],
          enable: true,
          transport: "streamable-http",
          status: "",
        };
        schedulePaint();
        return;
      }
      const current = list[screen.cursor];
      if (current) {
        if (key.name === "return") {
          screen = {
            id: "backend",
            slug: current.slug,
            cursor: 0,
            status: "",
          };
        }
        if (key.name === "char" && key.sequence === "e") {
          store.updateBackend(ws.id, current.slug, { enabled: true });
          pool.invalidate(current.id);
          screen = { ...screen, status: `enabled ${current.slug}` };
        }
        if (key.name === "char" && key.sequence === "d") {
          store.updateBackend(ws.id, current.slug, { enabled: false });
          pool.invalidate(current.id);
          screen = { ...screen, status: `disabled ${current.slug}` };
        }
        if (key.name === "char" && key.sequence === "x") {
          screen = { id: "confirm-delete", slug: current.slug, status: "" };
        }
        if (key.name === "char" && key.sequence === "t") {
          screen = { ...screen, status: `testing ${current.slug}…` };
          schedulePaint();
          const result = await testBackend(current.slug);
          if (screen.id === "backends") {
            screen = {
              ...screen,
              status: result.ok
                ? `${current.slug}: ${result.msg}`
                : `${current.slug}: ${result.msg}`,
            };
          }
        }
      }
      schedulePaint();
      return;
    }

    if (screen.id === "backend") {
      const actionsCount = 6;
      if (key.name === "escape") {
        screen = { id: "backends", cursor: 0, status: "" };
        schedulePaint();
        return;
      }
      if (key.name === "up")
        screen = { ...screen, cursor: Math.max(0, screen.cursor - 1) };
      if (key.name === "down")
        screen = {
          ...screen,
          cursor: Math.min(actionsCount - 1, screen.cursor + 1),
        };
      if (key.name === "return") {
        const b = store.getBackendPublic(ws.id, screen.slug);
        if (!b) {
          screen = { id: "backends", cursor: 0, status: "missing" };
          schedulePaint();
          return;
        }
        switch (screen.cursor) {
          case 0: {
            const next = !b.enabled;
            store.updateBackend(ws.id, b.slug, { enabled: next });
            pool.invalidate(b.id);
            screen = {
              ...screen,
              status: next ? "enabled" : "disabled",
              tools: undefined,
            };
            break;
          }
          case 1: {
            screen = { ...screen, status: "testing…" };
            schedulePaint();
            const result = await testBackend(screen.slug);
            if (screen.id === "backend") {
              screen = {
                ...screen,
                status: result.msg,
                tools: result.tools,
              };
            }
            break;
          }
          case 2:
            screen = {
              id: "headers-editor",
              returnTo: { kind: "merge", slug: screen.slug },
              pairs: [],
              cursor: 0,
              drafting: true,
              draftName: "",
              draftValue: "",
              draftFocus: "name",
              editIndex: null,
              status: "add headers to merge (existing kept)",
            };
            break;
          case 3: {
            store.updateBackend(ws.id, screen.slug, { headers: null });
            pool.invalidate(b.id);
            screen = { ...screen, status: "headers cleared", tools: undefined };
            break;
          }
          case 4:
            screen = {
              id: "confirm-delete",
              slug: screen.slug,
              status: "",
            };
            break;
          case 5:
            screen = { id: "backends", cursor: 0, status: "" };
            break;
        }
      }
      schedulePaint();
      return;
    }

    if (screen.id === "add") {
      if (key.name === "escape") {
        screen = { id: "backends", cursor: 0, status: "cancelled" };
        schedulePaint();
        return;
      }
      if (key.name === "tab" || key.name === "down") {
        screen = { ...screen, field: Math.min(6, screen.field + 1) };
        schedulePaint();
        return;
      }
      if (key.name === "up") {
        screen = { ...screen, field: Math.max(0, screen.field - 1) };
        schedulePaint();
        return;
      }
      // fields: 0 slug, 1 url, 2 transport, 3 headers, 4 enable, 5 save, 6 cancel
      if (key.name === "char" && key.sequence === " " && screen.field === 4) {
        screen = { ...screen, enable: !screen.enable };
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence === " " && screen.field === 2) {
        screen = {
          ...screen,
          transport:
            screen.transport === "streamable-http" ? "sse" : "streamable-http",
        };
        schedulePaint();
        return;
      }
      if (key.name === "backspace") {
        if (screen.field === 0)
          screen = { ...screen, slug: screen.slug.slice(0, -1) };
        if (screen.field === 1)
          screen = { ...screen, url: screen.url.slice(0, -1) };
        schedulePaint();
        return;
      }
      if (key.name === "char" && (screen.field === 0 || screen.field === 1)) {
        const ch = key.sequence;
        if (ch.length === 1 && ch >= " ") {
          if (screen.field === 0)
            screen = { ...screen, slug: screen.slug + ch };
          if (screen.field === 1) screen = { ...screen, url: screen.url + ch };
        }
        schedulePaint();
        return;
      }
      if (key.name === "return") {
        if (screen.field === 6) {
          screen = { id: "backends", cursor: 0, status: "cancelled" };
          schedulePaint();
          return;
        }
        if (screen.field === 3) {
          // open multi-header editor
          screen = {
            id: "headers-editor",
            returnTo: {
              kind: "add",
              slug: screen.slug,
              url: screen.url,
              transport: screen.transport,
              enable: screen.enable,
            },
            pairs: [...screen.headers],
            cursor: screen.headers.length,
            drafting: screen.headers.length === 0,
            draftName: "",
            draftValue: "",
            draftFocus: "name",
            editIndex: null,
            status: "",
          };
          schedulePaint();
          return;
        }
        if (screen.field !== 5 && screen.field < 5) {
          // enter advances field except save
          screen = { ...screen, field: Math.min(6, screen.field + 1) };
          schedulePaint();
          return;
        }
        try {
          if (!screen.slug.trim()) throw new Error("slug required");
          if (!screen.url.trim()) throw new Error("url required");
          await assertSafeUrl(screen.url.trim(), cfg.allowPrivateUrls);
          const headers = pairsToRecord(screen.headers);
          const created = store.createBackend(ws.id, {
            slug: screen.slug.trim(),
            url: screen.url.trim(),
            transport: screen.transport,
            headers: Object.keys(headers).length ? headers : undefined,
            enabled: screen.enable,
            placement: { ...DEFAULT_PLACEMENT },
          });
          screen = {
            id: "backends",
            cursor: 0,
            status: `added ${created.slug}${
              Object.keys(headers).length
                ? ` (${Object.keys(headers).length} headers)`
                : ""
            }`,
          };
        } catch (err) {
          const msg =
            err instanceof SsrfError
              ? err.message
              : err instanceof Error
                ? err.message
                : String(err);
          screen = { ...screen, status: msg };
        }
      }
      schedulePaint();
      return;
    }

    if (screen.id === "headers-editor") {
      const s = screen;
      const maxCursor = s.pairs.length + 1; // + add, Done

      const backFromEditor = () => {
        if (s.returnTo.kind === "add") {
          screen = {
            id: "add",
            field: 3,
            slug: s.returnTo.slug,
            url: s.returnTo.url,
            transport: s.returnTo.transport,
            enable: s.returnTo.enable,
            headers: s.pairs,
            status: `${s.pairs.length} header(s)`,
          };
        } else {
          screen = {
            id: "backend",
            slug: s.returnTo.slug,
            cursor: 2,
            status: "cancelled",
          };
        }
      };

      if (s.drafting) {
        if (key.name === "escape") {
          screen = {
            ...s,
            drafting: false,
            draftName: "",
            draftValue: "",
            draftFocus: "name",
            editIndex: null,
            cursor: s.pairs.length,
            status: "",
          };
          schedulePaint();
          return;
        }
        if (key.name === "tab") {
          screen = {
            ...s,
            draftFocus: s.draftFocus === "name" ? "value" : "name",
          };
          schedulePaint();
          return;
        }
        if (key.name === "backspace") {
          if (s.draftFocus === "name")
            screen = { ...s, draftName: s.draftName.slice(0, -1) };
          else screen = { ...s, draftValue: s.draftValue.slice(0, -1) };
          schedulePaint();
          return;
        }
        if (key.name === "char" && key.sequence.length === 1 && key.sequence >= " ") {
          if (s.draftFocus === "name")
            screen = { ...s, draftName: s.draftName + key.sequence };
          else screen = { ...s, draftValue: s.draftValue + key.sequence };
          schedulePaint();
          return;
        }
        if (key.name === "return") {
          if (s.draftFocus === "name") {
            if (!s.draftName.trim()) {
              screen = { ...s, status: "header name required" };
            } else {
              screen = { ...s, draftFocus: "value", status: "" };
            }
            schedulePaint();
            return;
          }
          // accept pair
          if (!s.draftName.trim() || !s.draftValue) {
            screen = { ...s, status: "name and value required" };
            schedulePaint();
            return;
          }
          const pair = {
            name: s.draftName.trim(),
            value: s.draftValue,
          };
          const pairs = [...s.pairs];
          if (s.editIndex != null && s.editIndex >= 0) pairs[s.editIndex] = pair;
          else pairs.push(pair);
          screen = {
            ...s,
            pairs,
            drafting: false,
            draftName: "",
            draftValue: "",
            draftFocus: "name",
            editIndex: null,
            cursor: pairs.length, // land on "+ Add header"
            status: `saved ${pair.name}`,
          };
        }
        schedulePaint();
        return;
      }

      // list mode
      if (key.name === "escape") {
        backFromEditor();
        schedulePaint();
        return;
      }
      if (key.name === "up")
        screen = { ...s, cursor: Math.max(0, s.cursor - 1) };
      if (key.name === "down")
        screen = { ...s, cursor: Math.min(maxCursor, s.cursor + 1) };
      if (key.name === "char" && key.sequence === "x" && s.cursor < s.pairs.length) {
        const pairs = s.pairs.filter((_, i) => i !== s.cursor);
        screen = {
          ...s,
          pairs,
          cursor: Math.min(s.cursor, Math.max(0, pairs.length)),
          status: "removed",
        };
      }
      if (key.name === "return") {
        if (s.cursor < s.pairs.length) {
          const p = s.pairs[s.cursor]!;
          screen = {
            ...s,
            drafting: true,
            draftName: p.name,
            draftValue: p.value,
            draftFocus: "value",
            editIndex: s.cursor,
            status: "",
          };
        } else if (s.cursor === s.pairs.length) {
          // add
          screen = {
            ...s,
            drafting: true,
            draftName: "",
            draftValue: "",
            draftFocus: "name",
            editIndex: null,
            status: "",
          };
        } else {
          // Done
          if (s.returnTo.kind === "add") {
            screen = {
              id: "add",
              field: 4,
              slug: s.returnTo.slug,
              url: s.returnTo.url,
              transport: s.returnTo.transport,
              enable: s.returnTo.enable,
              headers: s.pairs,
              status: `${s.pairs.length} header(s) ready`,
            };
          } else {
            const partial = pairsToRecord(s.pairs);
            if (!Object.keys(partial).length) {
              screen = {
                id: "backend",
                slug: s.returnTo.slug,
                cursor: 2,
                status: "no headers to merge",
              };
            } else {
              const b = store.getBackendPublic(ws.id, s.returnTo.slug);
              store.mergeBackendHeaders(ws.id, s.returnTo.slug, partial);
              if (b) pool.invalidate(b.id);
              screen = {
                id: "backend",
                slug: s.returnTo.slug,
                cursor: 0,
                status: `merged ${Object.keys(partial).length} header(s)`,
              };
            }
          }
        }
      }
      schedulePaint();
      return;
    }

    if (screen.id === "keys") {
      const s = screen;
      const list = keys();
      if (key.name === "escape") {
        screen = { id: "home", cursor: 1 };
        schedulePaint();
        return;
      }
      if (key.name === "up")
        screen = { ...s, cursor: Math.max(0, s.cursor - 1) };
      if (key.name === "down")
        screen = {
          ...s,
          cursor: Math.min(Math.max(0, list.length - 1), s.cursor + 1),
        };
      if (key.name === "char" && key.sequence === "r") {
        screen = { ...s, status: "refreshed", lastToken: undefined };
      }
      if (key.name === "char" && key.sequence === "n") {
        screen = { id: "key-create", name: "", status: "" };
      }
      if (key.name === "char" && key.sequence === "x") {
        const k = list[s.cursor];
        if (k && !k.revokedAt) {
          store.revokeApiKey(ws.id, k.id);
          screen = {
            ...s,
            status: `revoked ${k.name}`,
            lastToken: undefined,
          };
        }
      }
      schedulePaint();
      return;
    }

    if (screen.id === "key-create") {
      if (key.name === "escape") {
        screen = { id: "keys", cursor: 0, status: "cancelled" };
        schedulePaint();
        return;
      }
      if (key.name === "backspace") {
        screen = { ...screen, name: screen.name.slice(0, -1) };
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence.length === 1 && key.sequence >= " ") {
        screen = { ...screen, name: screen.name + key.sequence };
        schedulePaint();
        return;
      }
      if (key.name === "return") {
        const name = screen.name.trim() || "default";
        const created = store.createApiKey(ws.id, name);
        screen = {
          id: "keys",
          cursor: 0,
          status: `created ${created.name}`,
          lastToken: created.token,
        };
      }
      schedulePaint();
      return;
    }

    if (screen.id === "confirm-delete") {
      if (
        key.name === "escape" ||
        (key.name === "char" && key.sequence === "n")
      ) {
        screen = { id: "backends", cursor: 0, status: "delete cancelled" };
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence === "y") {
        const b = store.getBackend(ws.id, screen.slug);
        store.deleteBackend(ws.id, screen.slug);
        if (b) pool.invalidate(b.id);
        screen = {
          id: "backends",
          cursor: 0,
          status: `deleted ${screen.slug}`,
        };
      }
      schedulePaint();
    }
  }

  enterAltScreen();
  hideCursor();
  startInput((k) => {
    void handle(k);
  });
  setKeyHandler((k) => {
    void handle(k);
  });

  process.stdout.on("resize", schedulePaint);
  paint();

  await new Promise<void>((resolve) => {
    const iv = setInterval(() => {
      if (!alive) {
        clearInterval(iv);
        resolve();
      }
    }, 100);
  });
}
