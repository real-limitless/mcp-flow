import { randomBytes } from "node:crypto";
import { hashToken } from "../crypto.js";

export function mintDecideToken(): { token: string; hash: string } {
  const token = `apd_${randomBytes(32).toString("base64url")}`;
  return { token, hash: hashToken(token) };
}

export function hashDecideToken(token: string): string {
  return hashToken(String(token ?? "").trim());
}
