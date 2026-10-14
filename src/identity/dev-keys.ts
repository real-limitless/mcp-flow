import { hkdfSync } from "node:crypto";

/**
 * Per-purpose keys for identity + policy (T1.3 / T2.2).
 * DEV ONLY until SecOPS supplies real key management (db-t2.1 Q2/Q3):
 * derived via HKDF from MCP_FLOW_POLICY_DEV_KEY, or from the master key when unset.
 */
export interface PolicyKeys {
  /** HMAC pepper for api key / session secret hashes */
  pepper: Buffer;
  /** AES-256-GCM key for pending_call.args_ciphertext */
  argsEnc: Buffer;
  /** HMAC key for args_hash (audit + pending) */
  argsHmac: Buffer;
  /** Stored in args_key_ref / hash scheme ids; never the key itself */
  keyRef: string;
}

export const DEV_KEY_REF = "dev-v1";

function derive(raw: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(raw, "utf8"), "mcp-flow/policy", info, 32));
}

export function derivePolicyKeys(raw: string): PolicyKeys {
  if (!raw) throw new Error("policy dev key material is required");
  return {
    pepper: derive(raw, "key-pepper"),
    argsEnc: derive(raw, "args-enc"),
    argsHmac: derive(raw, "args-hmac"),
    keyRef: DEV_KEY_REF,
  };
}
