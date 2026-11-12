/**
 * Property (SENTINEL-1): an R2-only failure never reaches containment. Over arbitrary combinations of failing
 * and passing rules, a `security` outcome (the only one the co-signer hands to `containBreach`) always carries a
 * reason other than the signature; a bad signature with everything else passing is `unavailable` drift; and a
 * bad signature next to any other failure is never drift.
 */
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { checkRouteQuote, type RegistryRow, type RouteQuoteInput } from "../../src/address-integrity/checks.js";
import { fixture } from "../support/keys.js";

const TREASURY = "intents.near";
const NOW = Date.parse("2026-11-05T18:10:00.000Z");
const DEADLINE = "2026-11-05T18:26:53.000Z";
const DEPOSIT = "0x76b4c56085ed136a8744d52be956396624a730e8";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const RECIPIENT = "0x52908400098527886e0f7030069857d2e4169ee7";

const row = (o: Partial<RegistryRow> = {}): RegistryRow => ({
  id: "01900000-0000-7000-8000-0000000d0001",
  account_id: "01900000-0000-7000-8000-0000000a0c01",
  livemode: true,
  asset_id: USDC_NEAR,
  type: "intents_account",
  chain: "near:mainnet",
  address_norm: RECIPIENT,
  status: "active",
  merchant_name: "Acme GmbH",
  kyb_verified: true,
  verification: "signature",
  ...o,
});

const flags = fc.record({
  signatureValid: fc.boolean(),
  referral: fc.boolean(),
  address: fc.boolean(),
  memo: fc.boolean(),
  lifetime: fc.boolean(),
  fees: fc.constantFrom("ok", "none", "attacker", "three", "share", "total"),
  registry: fc.constantFrom("ok", "empty", "disabled", "ambiguous"),
  treasury: fc.boolean(),
  amount: fc.boolean(),
  deadline: fc.boolean(),
  unreadable: fc.boolean(),
  status: fc.constantFrom("PENDING_DEPOSIT", "SUCCESS"),
  rereadAs: fc.constantFrom(undefined, "stale", "unavailable"),
});

type Flags = typeof flags extends fc.Arbitrary<infer T> ? T : never;

function build(f: Flags): RouteQuoteInput {
  const q = fixture<OneClickQuoteResponse>("oneclick/dry-quote.json");
  q.quoteRequest.dry = false;
  q.quote.depositAddress = f.address ? DEPOSIT : `0x${"b".repeat(40)}`;
  q.quote.depositMemo = f.memo ? null : "9";
  q.quoteRequest.deadline = DEADLINE;
  q.quote.deadline = f.unreadable ? "soon" : f.lifetime ? DEADLINE : "2026-11-05T18:00:00.000Z";
  if (!f.referral) q.quoteRequest.referral = "someone";
  const fees = {
    ok: q.quoteRequest.appFees,
    none: [],
    attacker: [{ recipient: "attacker.near", fee: 50 }],
    three: [
      { recipient: TREASURY, fee: 30 },
      { recipient: "p", fee: 10 },
      { recipient: "q", fee: 10 },
    ],
    share: [
      { recipient: TREASURY, fee: 10 },
      { recipient: "p", fee: 40 },
    ],
    total: [
      { recipient: TREASURY, fee: 300 },
      { recipient: "p", fee: 300 },
    ],
  }[f.fees];
  q.quoteRequest.appFees = fees;
  const registry = {
    ok: [row()],
    empty: [],
    disabled: [row({ status: "disabled" })],
    ambiguous: [row({ verification: "unverified" }), row({ id: "x", verification: "unverified" })],
  }[f.registry];
  return {
    livemode: true,
    deposit: {
      address: DEPOSIT,
      memo: null,
      chain: "eip155:8453",
      origin_asset_id: USDC_BASE,
      amount_in: f.amount ? q.quote.amountIn : "1",
      deadline: f.deadline ? DEADLINE : "2026-11-05T18:26:54.000Z",
    },
    status: { status: f.status, quoteResponse: q },
    signatureValid: f.signatureValid,
    registry,
    treasury: f.treasury ? TREASURY : null,
    referral: "nearpay",
    split: { shareBps: 5000, floorBps: 20, stableFloorBps: 1 },
    nowMs: NOW,
    ...(f.rereadAs ? { recipientUnknownAs: { class: f.rereadAs, reason: "re-read" } } : {}),
  };
}

describe("SENTINEL-1 property: no R2-only outcome ever reaches containment", () => {
  it("security always carries a non-signature reason; drift only when everything else passes", () => {
    fc.assert(
      fc.property(flags, (f) => {
        const r = checkRouteQuote(build(f));
        if (!r.ok && r.class === "security") {
          expect(r.reasons.some((x) => !x.startsWith("R2 "))).toBe(true);
          expect(r).not.toHaveProperty("drift");
        }
        if (!r.ok && r.drift) {
          expect(f.signatureValid).toBe(false);
          expect(r.class).toBe("unavailable");
        }
        // a bad signature is never silently accepted
        if (!f.signatureValid) expect(r.ok).toBe(false);
        // a bad signature with everything else genuine is drift, never a breach
        const allElse =
          f.referral &&
          f.address &&
          f.memo &&
          f.lifetime &&
          !f.unreadable &&
          ["ok", "none"].includes(f.fees) &&
          f.registry === "ok" &&
          f.treasury &&
          f.amount &&
          f.deadline;
        if (!f.signatureValid && allElse) expect(r).toMatchObject({ class: "unavailable", drift: "R2" });
        if (!f.signatureValid && !allElse) expect(r).not.toHaveProperty("drift");
      }),
      { numRuns: 2000 },
    );
  });
});
