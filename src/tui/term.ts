import { emitKeypressEvents } from "node:readline";

export type Key =
  | { name: "up" | "down" | "left" | "right" | "return" | "escape" | "tab" | "backspace" | "delete" }
  | { name: "char"; sequence: string }
  | { name: "ctrl"; sequence: string };

type KeyHandler = (key: Key) => void;

let active = false;
let onKey: KeyHandler | null = null;
let stdinListener: ((str: string, key: readlineKey) => void) | null = null;

interface readlineKey {
  name?: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  sequence?: string;
}

export function isTty(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

export function enterAltScreen(): void {
  process.stdout.write("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
}

export function leaveAltScreen(): void {
  process.stdout.write("\x1b[?25h\x1b[?1049l");
}

export function hideCursor(): void {
  process.stdout.write("\x1b[?25l");
}

export function showCursor(): void {
  process.stdout.write("\x1b[?25h");
}

export function clearScreen(): void {
  process.stdout.write("\x1b[2J\x1b[H");
}

export function moveTo(row: number, col: number): void {
  process.stdout.write(`\x1b[${row};${col}H`);
}

export function writeAt(row: number, col: number, text: string): void {
  moveTo(row, col);
  process.stdout.write(text);
}

export function cols(): number {
  return process.stdout.columns || 80;
}

export function rows(): number {
  return process.stdout.rows || 24;
}

export function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

export function pad(s: string, width: number): string {
  const vis = stripAnsi(s);
  if (vis.length >= width) {
    // truncate carefully ignoring ansi is hard; simple path
    return vis.slice(0, Math.max(0, width - 1)) + (width > 0 ? "…" : "");
  }
  return s + " ".repeat(width - vis.length);
}

export function truncate(s: string, width: number): string {
  if (s.length <= width) return s;
  if (width <= 1) return "…".slice(0, width);
  return s.slice(0, width - 1) + "…";
}

export const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  reverse: "\x1b[7m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgBlue: "\x1b[44m",
  bgGray: "\x1b[100m",
};

export function startInput(handler: KeyHandler): void {
  if (active) {
    onKey = handler;
    return;
  }
  active = true;
  onKey = handler;
  emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  process.stdin.resume();

  stdinListener = (_str, key) => {
    if (!key || !onKey) return;
    if (key.ctrl && key.name === "c") {
      onKey({ name: "ctrl", sequence: "c" });
      return;
    }
    if (key.ctrl && key.name === "d") {
      onKey({ name: "ctrl", sequence: "d" });
      return;
    }
    switch (key.name) {
      case "up":
      case "down":
      case "left":
      case "right":
      case "return":
      case "escape":
      case "tab":
      case "backspace":
      case "delete":
        onKey({ name: key.name });
        return;
      default:
        break;
    }
    const seq = key.sequence ?? "";
    if (seq && !key.ctrl && !key.meta) {
      onKey({ name: "char", sequence: seq });
    }
  };
  process.stdin.on("keypress", stdinListener);
}

export function stopInput(): void {
  if (!active) return;
  active = false;
  onKey = null;
  if (stdinListener) {
    process.stdin.off("keypress", stdinListener);
    stdinListener = null;
  }
  if (process.stdin.isTTY) process.stdin.setRawMode(false);
  process.stdin.pause();
}

export function setKeyHandler(handler: KeyHandler): void {
  onKey = handler;
}
