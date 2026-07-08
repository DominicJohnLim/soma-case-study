// Canonical JSON encoding: the byte representation that gets hashed and signed.
// Two records with the same content must produce identical bytes regardless of
// key insertion order, so canonicalization is its own tested module rather than
// an inline JSON.stringify.

import { createHash } from "node:crypto";

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export function canonicalize(value: Json): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError(`non-finite number is not canonicalizable: ${value}`);
      }
      if (!Number.isSafeInteger(value)) {
        // Floats round-trip differently across JSON implementations; the record
        // schema only needs integers (sizes, counts) and stringified decimals.
        throw new TypeError(`only safe integers may appear in signed content, got: ${value}`);
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((v) => canonicalize(v)).join(",")}]`;
      }
      const keys = Object.keys(value).sort();
      const parts: string[] = [];
      for (const k of keys) {
        const v = value[k];
        if (v === undefined) continue;
        parts.push(`${JSON.stringify(k)}:${canonicalize(v as Json)}`);
      }
      return `{${parts.join(",")}}`;
    }
    default:
      throw new TypeError(`value of type ${typeof value} is not canonicalizable`);
  }
}

export function canonicalBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

/** sha256 over raw bytes, rendered as the address form used everywhere: "sha256:<hex>". */
export function sha256(bytes: Uint8Array | string): string {
  const h = createHash("sha256");
  h.update(bytes);
  return `sha256:${h.digest("hex")}`;
}

/** sha256 over the canonical encoding of a JSON value. */
export function sha256Canonical(value: Json): string {
  return sha256(canonicalBytes(value));
}
