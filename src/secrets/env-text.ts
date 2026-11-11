/**
 * Pure helpers for Dokploy env text (Secrets phase C).
 * Env text is newline-separated `KEY=value` lines; comments and blanks are preserved.
 */

import { createHash } from "node:crypto";
import { containsPlaceholder } from "../audit/placeholder-guard.js";

export class EnvSinkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvSinkError";
  }
}

export interface EnvLine {
  raw: string;
  kind: "blank" | "comment" | "entry" | "other";
  key?: string;
  exportPrefix?: string;
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

interface ParsedLine {
  kind: "entry" | "other";
  key?: string;
  exportPrefix?: string;
}

function parseLine(line: string): ParsedLine {
  let m = /^export ([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
  if (m && KEY_RE.test(m[1])) {
    return { kind: "entry", key: m[1], exportPrefix: "export " };
  }
  m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
  if (m && KEY_RE.test(m[1])) {
    return { kind: "entry", key: m[1], exportPrefix: "" };
  }
  return { kind: "other" };
}

export function parseEnvText(text: string): EnvLine[] {
  const lines = text.split("\n");
  return lines.map((line) => {
    if (line.trim() === "") return { raw: line, kind: "blank" };
    const trimmed = line.trimStart();
    if (trimmed.startsWith("#")) return { raw: line, kind: "comment" };
    const parsed = parseLine(line);
    if (parsed.kind !== "entry") return { raw: line, kind: "other" };
    return { raw: line, kind: "entry", key: parsed.key, exportPrefix: parsed.exportPrefix };
  });
}

export function envKeyNames(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of parseEnvText(text)) {
    if (line.kind === "entry" && line.key) {
      if (!seen.has(line.key)) {
        seen.add(line.key);
        out.push(line.key);
      }
    }
  }
  return out;
}

export function mergeEnvText(text: string, set: Record<string, string>, unset: string[]): string {
  const unsetSet = new Set(unset);
  const consumed = new Set<string>();
  const lines = text.split("\n");
  const out: string[] = [];
  for (const line of lines) {
    const parsed = parseLine(line);
    if (parsed.kind !== "entry" || !parsed.key) {
      out.push(line);
      continue;
    }
    const key = parsed.key;
    if (unsetSet.has(key)) continue; // drop
    if (Object.prototype.hasOwnProperty.call(set, key)) {
      if (consumed.has(key)) continue;
      consumed.add(key);
      out.push(`${parsed.exportPrefix ?? ""}${key}=${set[key]}`);
    } else {
      out.push(line);
    }
  }
  const newKeys = Object.keys(set).filter((k) => !consumed.has(k));
  let insertAt = out.length;
  if (out.length > 0 && out[out.length - 1] === "") insertAt = out.length - 1;
  const additions = newKeys.map((k) => `${k}=${set[k]}`);
  out.splice(insertAt, 0, ...additions);
  for (const k of newKeys) consumed.add(k);
  return out.join("\n");
}

export function envDigest(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function assertEnvValueSafe(value: string): void {
  if (typeof value !== "string") throw new EnvSinkError("invalid env value");
  if (value.includes("\r") || value.includes("\n") || value.includes("\u0000")) {
    throw new EnvSinkError("env value contains a control character");
  }
  if (containsPlaceholder(value)) {
    throw new EnvSinkError("env value contains a redaction placeholder");
  }
}

export const MASK = "***";
