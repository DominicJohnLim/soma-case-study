// Content-addressed store: the hash IS the identity. "Has this been modified?"
// is definitionally answerable because a modified artifact is a different
// artifact with a different address. Reads re-verify, so even a corrupted
// backing store cannot silently return altered bytes.

import { sha256 } from "./canonical.ts";

export class IntegrityError extends Error {}

export class ContentStore {
  private readonly blobs = new Map<string, Uint8Array>();

  /** Store bytes, return their address. Idempotent by construction. */
  put(bytes: Uint8Array): string {
    const address = sha256(bytes);
    if (!this.blobs.has(address)) {
      this.blobs.set(address, Uint8Array.from(bytes));
    }
    return address;
  }

  putText(text: string): string {
    return this.put(new TextEncoder().encode(text));
  }

  has(address: string): boolean {
    return this.blobs.has(address);
  }

  /**
   * Retrieve bytes by address, re-verifying the hash on the way out.
   * Tampered backing bytes throw instead of being returned.
   */
  get(address: string): Uint8Array {
    const bytes = this.blobs.get(address);
    if (bytes === undefined) {
      throw new IntegrityError(`no artifact at ${address}`);
    }
    if (sha256(bytes) !== address) {
      throw new IntegrityError(`artifact at ${address} failed hash re-verification`);
    }
    return Uint8Array.from(bytes);
  }

  getText(address: string): string {
    return new TextDecoder().decode(this.get(address));
  }

  /** Test-only escape hatch for simulating storage-layer tampering. */
  unsafeRawMap(): Map<string, Uint8Array> {
    return this.blobs;
  }
}
