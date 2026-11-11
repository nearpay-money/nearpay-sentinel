/**
 * Ticket verification and attestation signing against the spec test vectors shared with payments
 * (tickets) and checkout (attestations): the same bytes, keys and signatures in every repo (§13).
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import type { SignedAttestation } from "@nearpay-money/spec";
import { describe, expect, it } from "vitest";
import {
  ed25519PublicKey,
  jcs,
  loadSigningKey,
  signAttestation,
  verifyAttestation,
  verifyTicket,
} from "../../src/co-signer/crypto.js";
import { mintTicket, newKeyPair, pemFromSeed, vector } from "../support/keys.js";

interface TicketVector {
  key: { seed_hex: string; public_key_base64url: string };
  payload: { attempt_id: string; livemode: boolean; deposit_key: string; exp: number };
  canonical_json: string;
  ticket: string;
}
interface AttestationVector {
  key: { kid: string; seed_hex: string; public_key_base64url: string };
  valid: { canonical_json: string; signed: SignedAttestation }[];
  invalid: { reason: string; signed: SignedAttestation }[];
}

describe("attestation ticket (spec vector)", () => {
  const v = vector<TicketVector>("attestation-ticket");
  const key = ed25519PublicKey(v.key.public_key_base64url);
  const before = v.payload.exp - 60;

  it("verifies the payments ticket and returns its claims", () => {
    expect(jcs(v.payload)).toBe(v.canonical_json);
    const r = verifyTicket(v.ticket, key, before);
    expect(r).toEqual({ ok: true, payload: v.payload });
  });

  it("re-mints the vector byte for byte from its seed (deterministic Ed25519 over JCS)", () => {
    const pem = pemFromSeed(v.key.seed_hex);
    expect(mintTicket(loadSigningKey(pem).privateKey, v.payload)).toBe(v.ticket);
  });

  it("refuses an expired ticket (exp is exclusive)", () => {
    expect(verifyTicket(v.ticket, key, v.payload.exp)).toEqual({ ok: false, reason: "expired" });
  });

  it("refuses a ticket signed by another key", () => {
    expect(verifyTicket(v.ticket, ed25519PublicKey(newKeyPair().publicRaw), before)).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("refuses tampered claims", () => {
    const [, sig] = v.ticket.split(".");
    const forged = Buffer.from(JSON.stringify({ ...v.payload, livemode: false })).toString("base64url");
    expect(verifyTicket(`${forged}.${sig}`, key, before).ok).toBe(false);
  });

  it("refuses signed bytes that are not the canonical form", () => {
    const k = newKeyPair();
    const bytes = Buffer.from(JSON.stringify(v.payload, null, 1));
    const t = `${bytes.toString("base64url")}.${sign(null, bytes, k.privateKey).toString("base64url")}`;
    expect(verifyTicket(t, ed25519PublicKey(k.publicRaw), before)).toEqual({ ok: false, reason: "not canonical" });
  });

  it("refuses signed claims that do not match the schema", () => {
    const k = newKeyPair();
    const t = mintTicket(k.privateKey, { ...v.payload, attempt_id: "not-an-attempt" });
    expect(verifyTicket(t, ed25519PublicKey(k.publicRaw), before)).toEqual({ ok: false, reason: "payload" });
    const bytes = Buffer.from("not json");
    const junk = `${bytes.toString("base64url")}.${sign(null, bytes, k.privateKey).toString("base64url")}`;
    expect(verifyTicket(junk, ed25519PublicKey(k.publicRaw), before)).toEqual({ ok: false, reason: "payload" });
  });

  it.each(["", "abc", "a.b.c", ".sig", "payload.", "a.AAAA"])("refuses malformed ticket %j", (t) => {
    expect(verifyTicket(t, key, before).ok).toBe(false);
  });
});

describe("attestation signature (spec vector shared with checkout)", () => {
  const v = vector<AttestationVector>("sentinel-attestation");
  const key = loadSigningKey(pemFromSeed(v.key.seed_hex), `/run/secrets/sentinel-${v.key.kid}.pem`);

  it("takes the kid from the key file name and the public key from the key", () => {
    expect(key.kid).toBe(v.key.kid);
    expect(key.publicRaw).toBe(v.key.public_key_base64url);
  });

  it.each(v.valid.map((x) => [x.signed.attestation.kind, x] as const))("signs %s exactly like the vector", (_k, x) => {
    expect(jcs(x.signed.attestation)).toBe(x.canonical_json);
    expect(signAttestation(x.signed.attestation, key)).toEqual(x.signed);
    expect(verifyAttestation(x.signed, v.key.public_key_base64url)).toBe(true);
  });

  it.each(v.invalid.map((x) => [x.reason, x] as const))(
    "an attestation with %s does not verify for kid %s",
    (_r, x) => {
      const pinned = x.signed.kid === v.key.kid ? v.key.public_key_base64url : null;
      expect(pinned !== null && verifyAttestation(x.signed, pinned)).toBe(false);
    },
  );

  it("does not verify with a malformed signature or key", () => {
    const x = v.valid[0]?.signed as SignedAttestation;
    expect(verifyAttestation({ ...x, signature: "!!" }, v.key.public_key_base64url)).toBe(false);
    expect(verifyAttestation(x, "short")).toBe(false);
  });
});

describe("signing key", () => {
  it("falls back to local-<12 hex of sha256(raw public key)>, the kid scripts/seed.sh keys writes", () => {
    const k = newKeyPair();
    const kid = `local-${createHash("sha256").update(Buffer.from(k.publicRaw, "base64url")).digest("hex").slice(0, 12)}`;
    expect(loadSigningKey(k.pem).kid).toBe(kid);
    expect(loadSigningKey(k.pem, "/run/secrets/signing.pem").kid).toBe(kid);
    expect(loadSigningKey(k.pem, "/run/secrets/sentinel-Bad_Kid.pem").kid).toBe(kid);
  });

  it("refuses a non-Ed25519 key", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => loadSigningKey(ec.toString())).toThrow(/Ed25519/);
  });

  it("parses a raw public key and refuses a wrong length", () => {
    expect(ed25519PublicKey(newKeyPair().publicRaw).asymmetricKeyType).toBe("ed25519");
    expect(() => ed25519PublicKey("AAAA")).toThrow(RangeError);
  });

  it("jcs refuses values that have no JSON form", () => {
    expect(() => jcs(undefined)).toThrow(TypeError);
  });
});
