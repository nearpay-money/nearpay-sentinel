/**
 * Property (CR-15-07, §5): the attestation sentinel signs carries exactly the verified deposit /
 * requirement fields (field-by-field equal, nothing added), the asset the payer sends with the registry's
 * symbol and decimals (never anything from the request), expires at the deadline, parses with the spec's
 * `Attestation`, and verifies once signed. And a full-precision `amountInFormatted` pins the decimals.
 * Spec 0.2.1: the attested token contract never names a contract other than the one the asset id names.
 */
import { Attestation } from "@nearpay/spec";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { assetShape, formattedMatches, reconcileToken } from "../../src/address-integrity/assets.js";
import { buildAttestation } from "../../src/co-signer/attestation.js";
import { loadSigningKey, signAttestation, verifyAttestation } from "../../src/co-signer/crypto.js";
import { pemFromSeed } from "../support/keys.js";

const key = loadSigningKey(pemFromSeed("11".repeat(32)), "sentinel-prop-1.pem");
const amount = fc.bigInt({ min: 1n, max: 10n ** 30n }).map(String);
const time = fc.integer({ min: 1_800_000_000, max: 1_900_000_000 }).map((t) => new Date(t * 1000).toISOString());
const b58 = fc.stringMatching(/^[1-9A-HJ-NP-Za-km-z]{43}$/);
const asset = fc.constantFrom(
  "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
  "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  "nep141:wrap.near",
);
const deposit = fc.record({
  address: fc.constantFrom("0x77B262Cb4dB1Ca5021F773388F244F05b66bE8F2", "abc.near"),
  memo: fc.option(fc.stringMatching(/^[0-9]{1,10}$/), { nil: null }),
  chain: fc.constantFrom("eip155:8453", "near:mainnet"),
  origin_asset_id: asset,
  amount_in: amount,
  deadline: time,
});
const requirement = fc.record({
  pay_to: fc.constantFrom("merchant.near", "shop.near"),
  token: asset,
  amount,
  fee_to: fc.constant("treasury.nearpay.near"),
  fee_amount: amount,
  binding: b58.map((x) => `np1:${x}`),
  deadline: time,
});
const token = fc.option(
  fc.record({
    standard: fc.constantFrom("erc20" as const, "native" as const, "nep141" as const, "spl" as const, "other" as const),
    address: fc.option(fc.stringMatching(/^[a-z0-9.]{1,64}$/), { nil: null }),
  }),
  { nil: null },
);
const display = fc.record({
  symbol: fc.stringMatching(/^[A-Z]{1,10}$/),
  decimals: fc.integer({ min: 0, max: 255 }),
  token,
});
const row = {
  merchant_name: "Acme GmbH",
  kyb_verified: true,
  asset_id: "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
  chain: "near:mainnet",
  address_norm: "merchant.near",
};

describe("attestation fields (property)", () => {
  it("route_quote: deposit equal field by field, asset = origin asset with the registry's display data", () => {
    fc.assert(
      fc.property(deposit, display, fc.integer({ min: 0, max: 2 ** 40 }), (d, disp, now) => {
        const a = buildAttestation(
          { kind: "route_quote", attempt_id: "pa_01m6vree6ye928jvj2vxkyyz08", livemode: true, deposit: d },
          row,
          disp,
          now,
        );
        expect(a.deposit).toEqual(d);
        expect(Object.keys(a.deposit ?? {}).sort()).toEqual(Object.keys(d).sort());
        expect(a.requirement).toBeUndefined();
        expect(a.asset).toEqual({
          asset_id: d.origin_asset_id,
          symbol: disp.symbol,
          decimals: disp.decimals,
          token: disp.token,
        });
        expect(a.expires_at).toBe(d.deadline);
        expect(Attestation.safeParse(a).success).toBe(true);
        const signed = signAttestation(a, key);
        expect(verifyAttestation(signed, key.publicRaw)).toBe(true);
        // the token contract is inside the signed object: changing it breaks the signature (spec 0.2.1)
        const forged = {
          ...signed,
          attestation: {
            ...signed.attestation,
            asset: { ...a.asset, token: { standard: "erc20", address: "0xevil" } },
          },
        } as typeof signed;
        expect(verifyAttestation(forged, key.publicRaw)).toBe(false);
      }),
      { numRuns: 300 },
    );
  });

  it("intents_transfer: requirement equal field by field, asset = token; extra request keys never leak", () => {
    fc.assert(
      fc.property(requirement, display, (r, disp) => {
        const withExtra = { ...r, symbol: "FAKE", decimals: 99 } as typeof r;
        const a = buildAttestation(
          {
            kind: "intents_transfer",
            attempt_id: "pa_01m6vree6ye928jvj2vxkyyz08",
            livemode: false,
            requirement: withExtra,
          },
          row,
          disp,
          0,
        );
        expect(a.requirement).toEqual(r);
        expect(Object.keys(a.requirement ?? {}).sort()).toEqual(Object.keys(r).sort());
        expect(a.deposit).toBeUndefined();
        expect(a.asset).toEqual({ asset_id: r.token, symbol: disp.symbol, decimals: disp.decimals, token: disp.token });
        expect(Attestation.safeParse(a).success).toBe(true);
      }),
      { numRuns: 300 },
    );
  });

  it("a full-precision amountInFormatted matches its own decimals and no other", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: 10n ** 40n }),
        fc.integer({ min: 0, max: 40 }),
        fc.integer({ min: 0, max: 40 }),
        (n, d, other) => {
          const s = n.toString().padStart(d + 1, "0");
          const int = s.slice(0, s.length - d);
          const frac = s.slice(s.length - d).replace(/0+$/, "");
          const formatted = frac ? `${int}.${frac}` : int;
          expect(formattedMatches(n.toString(), formatted, d)).toBe(true);
          if (other !== d) expect(formattedMatches(n.toString(), formatted, other)).toBe(false);
        },
      ),
      { numRuns: 1000 },
    );
  });

  it("an attested token never contradicts the contract the asset id names (spec 0.2.1)", () => {
    const hex40 = fc.stringMatching(/^[0-9a-f]{40}$/);
    const id = fc.oneof(
      hex40.map((h) => `nep141:base-0x${h}.omft.near`),
      fc.stringMatching(/^[a-z][a-z0-9]{0,10}\.near$/).map((a) => `nep141:${a}`),
      fc.constantFrom("nep141:base.omft.near", "nep141:sol.omft.near", "nep245:v2_1.omni.hot.tg:56_11"),
    );
    const listed = fc.option(
      fc.record({
        standard: fc.constantFrom(
          "erc20" as const,
          "native" as const,
          "nep141" as const,
          "spl" as const,
          "other" as const,
        ),
        address: fc.option(
          fc.oneof(
            hex40.map((h) => `0x${h}`),
            fc.stringMatching(/^[a-z]{1,8}\.near$/),
          ),
          {
            nil: null,
          },
        ),
      }),
      { nil: null },
    );
    fc.assert(
      fc.property(id, listed, (assetId, t) => {
        const r = reconcileToken(assetId, t);
        if (!r.ok || r.token === null) return;
        const shape = assetShape(assetId);
        if (shape.kind === "erc20" || shape.kind === "nep141") {
          expect(r.token.standard).toBe(shape.kind);
          expect(r.token.address).toBe(shape.contract);
        }
        if (shape.kind === "native") expect(r.token.standard).toBe("native");
      }),
      { numRuns: 1000 },
    );
  });
});
