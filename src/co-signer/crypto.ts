/**
 * Ticket verification and attestation signing (lld/sentinel.md §5, §8).
 *
 * - Ticket (payments §8.2, spec `AttestationTicketPayload`): `base64url(JCS(payload)) + "." +
 *   base64url(Ed25519(payments ticket key, JCS bytes))`. Only a rate gate, never evidence.
 * - Attestation: Ed25519 over the UTF-8 bytes of the RFC 8785 canonical JSON of `attestation`,
 *   base64url without padding; `kid` names the key checkout pins.
 */
import { createHash, createPrivateKey, createPublicKey, type KeyObject, sign, verify } from "node:crypto";
import { type Attestation, AttestationTicketPayload, type SignedAttestation } from "@nearpay-money/spec";
import canonicalize from "canonicalize";

export function jcs(v: unknown): string {
  const s = canonicalize(v);
  if (s === undefined) throw new TypeError("value cannot be canonicalised");
  return s;
}

/** Ed25519 public key from its raw 32 bytes (base64url). */
export function ed25519PublicKey(rawBase64Url: string): KeyObject {
  const raw = Buffer.from(rawBase64Url, "base64url");
  if (raw.length !== 32) throw new RangeError("expected a 32-byte Ed25519 public key (base64url)");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}

export type TicketResult =
  | { readonly ok: true; readonly payload: AttestationTicketPayload }
  | { readonly ok: false; readonly reason: string };

export function verifyTicket(ticket: string, key: KeyObject, nowS: number): TicketResult {
  const parts = ticket.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "malformed" };
  const bytes = Buffer.from(parts[0], "base64url");
  const sig = Buffer.from(parts[1], "base64url");
  let valid = false;
  try {
    valid = sig.length === 64 && verify(null, bytes, key, sig);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "signature" };
  let payload: AttestationTicketPayload;
  try {
    const parsed = AttestationTicketPayload.safeParse(JSON.parse(bytes.toString("utf8")));
    if (!parsed.success) return { ok: false, reason: "payload" };
    payload = parsed.data;
  } catch {
    return { ok: false, reason: "payload" };
  }
  // the signed bytes must be the canonical form (no second reading of the same claims)
  if (jcs(payload) !== bytes.toString("utf8")) return { ok: false, reason: "not canonical" };
  if (payload.exp <= nowS) return { ok: false, reason: "expired" };
  return { ok: true, payload };
}

export interface SigningKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicRaw: string;
}

/** `sentinel-<kid>.pem` names the key (lld/sentinel.md §10); otherwise `local-` + 12 hex of its sha256. */
export function loadSigningKey(pem: string, path?: string): SigningKey {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("the sentinel signing key must be Ed25519");
  const publicRaw = createPublicKey(privateKey).export({ format: "jwk" }).x as string;
  const m = path ? /(?:^|\/)sentinel-([a-z0-9-]{1,64})\.pem$/.exec(path) : null;
  const kid =
    m?.[1] ?? `local-${createHash("sha256").update(Buffer.from(publicRaw, "base64url")).digest("hex").slice(0, 12)}`;
  return { kid, privateKey, publicRaw };
}

export function signAttestation(a: Attestation, key: SigningKey): SignedAttestation {
  const signature = sign(null, Buffer.from(jcs(a), "utf8"), key.privateKey).toString("base64url");
  return { attestation: a, kid: key.kid, signature };
}

export function verifyAttestation(s: SignedAttestation, publicRaw: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(jcs(s.attestation), "utf8"),
      ed25519PublicKey(publicRaw),
      Buffer.from(s.signature, "base64url"),
    );
  } catch {
    return false;
  }
}
