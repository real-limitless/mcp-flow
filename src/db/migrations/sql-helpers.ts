/** ISO-8601 UTC with millis — same lexical format as Date#toISOString(). */
export const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

/** CHECK fragment: `<prefix><24 lowercase hex>`. */
export function idCheck(col: string, prefix: string): string {
  return `length(${col}) = ${prefix.length + 24} AND substr(${col}, 1, ${prefix.length}) = '${prefix}' AND substr(${col}, ${prefix.length + 1}) NOT GLOB '*[^0-9a-f]*'`;
}

/** Nullable variant of idCheck. */
export function idCheckNullable(col: string, prefix: string): string {
  return `${col} IS NULL OR (${idCheck(col, prefix)})`;
}

/** CHECK fragment: TEXT column holds a JSON array. */
export function jsonArrayCheck(col: string): string {
  return `json_valid(${col}) AND json_type(${col}) = 'array'`;
}
