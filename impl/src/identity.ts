// Identity and key management: an organizational CA issues short-lived
// certificates to agent instances and humans. Each agent cert carries a
// delegation chain terminating at a human principal. No long-lived agent
// secrets exist; rotation is automatic by expiry.

import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { sha256Canonical, signingPayload, type Json } from "./canonical.ts";

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function generateKeys(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

export function exportPublicKey(key: KeyObject): string {
  return (key.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

export function importPublicKey(spkiBase64: string): KeyObject {
  return createPublicKey({
    key: Buffer.from(spkiBase64, "base64"),
    type: "spki",
    format: "der",
  });
}

export function signBytes(privateKey: KeyObject, bytes: Uint8Array): string {
  return `ed25519:${edSign(null, bytes, privateKey).toString("base64")}`;
}

export function verifyBytes(publicKeySpki: string, bytes: Uint8Array, signature: string): boolean {
  if (!signature.startsWith("ed25519:")) return false;
  const sig = Buffer.from(signature.slice("ed25519:".length), "base64");
  try {
    return edVerify(null, bytes, importPublicKey(publicKeySpki), sig);
  } catch {
    return false;
  }
}

/**
 * A short-lived certificate binding a subject identity to a public key,
 * with a delegation chain that terminates at a human principal.
 */
export interface Certificate {
  subject: string; // "agent:memo-writer/v2.3.1" | "human:jane@soma.vc"
  public_key: string; // spki DER, base64
  delegation_chain: string[]; // ["human:jane@soma.vc", "role:memo-agents"]; empty for humans
  not_before: string; // ISO 8601
  not_after: string; // ISO 8601
  issuer: string; // "ca:soma-org"
  signature: string; // CA signature over the canonical cert minus this field
}

export function certFingerprint(cert: Certificate): string {
  return sha256Canonical(cert as unknown as Json);
}

export class CertificateAuthority {
  readonly name: string;
  private readonly keys: KeyPair;

  constructor(name: string) {
    this.name = name;
    this.keys = generateKeys();
  }

  publicKey(): string {
    return exportPublicKey(this.keys.publicKey);
  }

  issue(opts: {
    subject: string;
    subjectPublicKey: string;
    delegationChain: string[];
    notBefore: Date;
    ttlMs: number;
  }): Certificate {
    const unsigned: Omit<Certificate, "signature"> = {
      subject: opts.subject,
      public_key: opts.subjectPublicKey,
      delegation_chain: opts.delegationChain,
      not_before: opts.notBefore.toISOString(),
      not_after: new Date(opts.notBefore.getTime() + opts.ttlMs).toISOString(),
      issuer: this.name,
    };
    const signature = signBytes(this.keys.privateKey, signingPayload(unsigned));
    return { ...unsigned, signature };
  }
}

export type CertVerification = { ok: true } | { ok: false; reason: string };

/**
 * Verify a certificate against a trusted CA public key at a point in time.
 * Agent identities must carry a delegation chain terminating at a human.
 */
export function verifyCertificate(
  cert: Certificate,
  caPublicKey: string,
  at: Date,
): CertVerification {
  if (!verifyBytes(caPublicKey, signingPayload(cert), cert.signature)) {
    return { ok: false, reason: `certificate for ${cert.subject} not signed by trusted CA` };
  }
  const atMs = at.getTime();
  const notBeforeMs = new Date(cert.not_before).getTime();
  const notAfterMs = new Date(cert.not_after).getTime();
  if (Number.isNaN(atMs)) {
    return { ok: false, reason: `certificate for ${cert.subject} cannot be validated at an unparseable time` };
  }
  if (Number.isNaN(notBeforeMs) || Number.isNaN(notAfterMs)) {
    return { ok: false, reason: `certificate for ${cert.subject} has an unparseable validity window` };
  }
  if (atMs < notBeforeMs) {
    return { ok: false, reason: `certificate for ${cert.subject} not yet valid at ${at.toISOString()}` };
  }
  if (atMs > notAfterMs) {
    return { ok: false, reason: `certificate for ${cert.subject} expired at ${cert.not_after}` };
  }
  if (cert.subject.startsWith("agent:")) {
    const principal = cert.delegation_chain[0];
    if (principal === undefined || !principal.startsWith("human:")) {
      return {
        ok: false,
        reason: `agent certificate for ${cert.subject} lacks a delegation chain terminating at a human`,
      };
    }
  }
  return { ok: true };
}
