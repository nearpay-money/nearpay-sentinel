/**
 * Property (§13): any mutation of a signed attestation fails checkout's verification — any field,
 * any value, added or removed — while key order and re-serialisation never matter (RFC 8785).
 */
import type { SignedAttestation } from "@nearpay-money/spec";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { jcs, loadSigningKey, signAttestation, verifyAttestation } from "../../src/co-signer/crypto.js";
import { pemFromSeed, vector } from "../support/keys.js";

interface AttestationVector {
  key: { kid: string; seed_hex: string; public_key_base64url: string };
  valid: { signed: SignedAttestation }[];
}

const v = vector<AttestationVector>("sentinel-attestation");
const key = loadSigningKey(pemFromSeed(v.key.seed_hex), `sentinel-${v.key.kid}.pem`);
const pub = v.key.public_key_base64url;

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** Paths to every leaf and object of a JSON value. */
function paths(x: Json, at: (string | number)[] = []): (string | number)[][] {
  if (x === null || typeof x !== "object") return [at];
  const keys = Array.isArray(x) ? x.map((_, i) => i) : Object.keys(x);
  return [at, ...keys.flatMap((k) => paths((x as Record<string | number, Json>)[k] as Json, [...at, k]))];
}

function setAt(x: Json, path: (string | number)[], value: Json | undefined): Json {
  if (path.length === 0) return value ?? null;
  const copy = structuredClone(x) as Record<string | number, Json>;
  let cur = copy;
  for (const k of path.slice(0, -1)) cur = cur[k] as Record<string | number, Json>;
  const last = path[path.length - 1] as string | number;
  if (value === undefined) delete cur[last];
  else cur[last] = value;
  return copy as Json;
}

function shuffleKeys(x: Json, seed: number): Json {
  if (x === null || typeof x !== "object") return x;
  if (Array.isArray(x)) return x.map((e) => shuffleKeys(e, seed));
  const keys = Object.keys(x).sort((a, b) => ((a.charCodeAt(0) * seed) % 7) - ((b.charCodeAt(0) * seed) % 7));
  return Object.fromEntries(keys.map((k) => [k, shuffleKeys(x[k] as Json, seed + 1)]));
}

const leaf = fc.oneof(
  fc.string(),
  fc.integer(),
  fc.boolean(),
  fc.constant(null),
  fc.double({ noNaN: true, noDefaultInfinity: true }),
);

describe("signed attestations", () => {
  for (const { signed } of v.valid) {
    const base = signed.attestation as unknown as Json;
    const all = paths(base).filter((p) => p.length > 0);

    it(`${signed.attestation.kind}: changing any field invalidates the signature`, () => {
      fc.assert(
        fc.property(fc.constantFrom(...all), leaf, (path, value) => {
          const mutated = setAt(base, path, value);
          fc.pre(jcs(mutated) !== jcs(base));
          expect(verifyAttestation({ ...signed, attestation: mutated as never }, pub)).toBe(false);
        }),
        { numRuns: 500 },
      );
    });

    it(`${signed.attestation.kind}: removing any field or adding one invalidates the signature`, () => {
      fc.assert(
        fc.property(fc.constantFrom(...all), fc.string({ minLength: 1 }), leaf, (path, extra, value) => {
          expect(verifyAttestation({ ...signed, attestation: setAt(base, path, undefined) as never }, pub)).toBe(false);
          const parent = path.slice(0, -1);
          const target = parent.reduce<Json>((o, k) => (o as Record<string | number, Json>)[k] as Json, base);
          fc.pre(target !== null && typeof target === "object" && !Array.isArray(target) && !(extra in target));
          expect(
            verifyAttestation({ ...signed, attestation: setAt(base, [...parent, extra], value) as never }, pub),
          ).toBe(false);
        }),
        { numRuns: 300 },
      );
    });

    it(`${signed.attestation.kind}: key order and re-serialisation do not matter`, () => {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 1000 }), (seed) => {
          const reordered = JSON.parse(JSON.stringify(shuffleKeys(base, seed)));
          expect(verifyAttestation({ ...signed, attestation: reordered }, pub)).toBe(true);
          expect(signAttestation(reordered, key).signature).toBe(signed.signature);
        }),
        { numRuns: 100 },
      );
    });

    it(`${signed.attestation.kind}: flipping any signature bit invalidates it`, () => {
      const sig = Buffer.from(signed.signature, "base64url");
      fc.assert(
        fc.property(fc.integer({ min: 0, max: sig.length * 8 - 1 }), (bit) => {
          const flipped = Buffer.from(sig);
          flipped[bit >> 3] = (flipped[bit >> 3] as number) ^ (1 << (bit & 7));
          expect(verifyAttestation({ ...signed, signature: flipped.toString("base64url") }, pub)).toBe(false);
        }),
        { numRuns: 512 },
      );
    });
  }
});
