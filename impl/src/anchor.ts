// External anchoring stub with the same interface a real RFC 3161 timestamping
// authority integration would have. An auditor who trusts only the TSA can
// verify that an anchored tree head existed by the receipt's time and was
// never subsequently rewritten.

import { canonicalBytes, type Json } from "./canonical.ts";
import { exportPublicKey, generateKeys, signBytes, verifyBytes, type KeyPair } from "./identity.ts";
import type { SignedTreeHead } from "./tlog.ts";

export interface AnchorReceipt {
  tree_size: number;
  root: string; // hex, copied from the anchored STH
  anchored_at: string; // ISO 8601, the TSA's clock
  tsa: string; // authority name
  signature: string;
}

function receiptSigningPayload(receipt: AnchorReceipt): Uint8Array {
  const { signature: _omitted, ...unsigned } = receipt;
  return canonicalBytes(unsigned as unknown as Json);
}

export class TimestampAuthority {
  readonly name: string;
  private readonly keys: KeyPair;

  constructor(name: string) {
    this.name = name;
    this.keys = generateKeys();
  }

  publicKey(): string {
    return exportPublicKey(this.keys.publicKey);
  }

  anchor(sth: SignedTreeHead, now: Date): AnchorReceipt {
    const unsigned: Omit<AnchorReceipt, "signature"> = {
      tree_size: sth.tree_size,
      root: sth.root,
      anchored_at: now.toISOString(),
      tsa: this.name,
    };
    const signature = signBytes(this.keys.privateKey, canonicalBytes(unsigned as unknown as Json));
    return { ...unsigned, signature };
  }
}

export function verifyAnchorReceipt(receipt: AnchorReceipt, tsaPublicKey: string): boolean {
  return verifyBytes(tsaPublicKey, receiptSigningPayload(receipt), receipt.signature);
}
