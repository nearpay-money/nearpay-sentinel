/**
 * Co-signing rules R2–R7 and the intents checks (§5, §13): every rule has a failing fixture that lands
 * in the right class. The base quote is a recorded 1Click quote (2026-11-05).
 */
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import { describe, expect, it } from "vitest";
import { assetChain, assetShape } from "../../src/address-integrity/assets.js";
import {
  appFeesFailures,
  checkIntents,
  checkRouteQuote,
  matchRegistry,
  type RegistryRow,
  type RouteQuoteInput,
} from "../../src/address-integrity/checks.js";
import { oneClickStatus } from "../../src/infra/clients/providers.js";
import { fixture } from "../support/keys.js";

const TREASURY = "intents.near"; // the recorded quote paid its appFee to intents.near
const SPLIT = { shareBps: 5000, floorBps: 20, stableFloorBps: 1 };
const NOW = Date.parse("2026-11-05T18:10:00.000Z");
const DEADLINE = "2026-11-05T18:26:53.000Z";
const DEPOSIT = "0x76b4c56085ed136a8744d52be956396624a730e8";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const RECIPIENT = "0x52908400098527886e0f7030069857d2e4169ee7"; // an Intents account (eth-implicit)

const recorded = () => fixture<OneClickQuoteResponse>("oneclick/dry-quote.json");

function quote(mut?: (q: OneClickQuoteResponse) => void): OneClickQuoteResponse {
  const q = recorded();
  q.quoteRequest.dry = false;
  q.quote.depositAddress = DEPOSIT;
  q.quoteRequest.deadline = DEADLINE;
  q.quote.deadline = DEADLINE;
  mut?.(q);
  return q;
}

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

function input(
  o: { q?: OneClickQuoteResponse; status?: string } & Partial<Omit<RouteQuoteInput, "status">> = {},
): RouteQuoteInput {
  const { q: given, status, ...rest } = o;
  const q = given ?? quote();
  return {
    livemode: true,
    deposit: {
      address: DEPOSIT,
      memo: null,
      chain: "eip155:8453",
      origin_asset_id: USDC_BASE,
      amount_in: recorded().quote.amountIn,
      deadline: DEADLINE,
    },
    status: { status: status ?? "PENDING_DEPOSIT", quoteResponse: q },
    signatureValid: true,
    registry: [row()],
    treasury: TREASURY,
    referral: "nearpay",
    split: SPLIT,
    nowMs: NOW,
    ...rest,
  };
}

describe("R2 provider signature (recorded quote, SDK-pinned 1Click key)", () => {
  const provider = oneClickStatus({ baseUrl: "http://127.0.0.1:9" });
  it("verifies the recorded quote", () => {
    expect(provider.verifySignature(recorded())).toBe(true);
  });
  it("fails when a signed field changes", () => {
    const q = recorded();
    q.quote.amountIn = "1";
    expect(provider.verifySignature(q)).toBe(false);
    const r = recorded();
    r.quoteRequest.recipient = "attacker.near";
    expect(provider.verifySignature(r)).toBe(false);
  });
  it("does not cover appFees — which is why R6 checks them", () => {
    const q = recorded();
    q.quoteRequest.appFees = [{ recipient: "attacker.near", fee: 50 }];
    expect(provider.verifySignature(q)).toBe(true);
  });
  it("is false (not a throw) for a malformed signature", () => {
    const q = recorded();
    q.signature = "ed25519:!!!";
    expect(provider.verifySignature(q)).toBe(false);
  });
  it("fails a valid signature under another manager key", () => {
    const other = oneClickStatus({ baseUrl: "http://127.0.0.1:9", managerPublicKey: "A".repeat(43) });
    expect(other.verifySignature(recorded())).toBe(false);
  });
});

describe("route_quote checks", () => {
  it("passes a genuine quote and returns the matched destination", () => {
    expect(checkRouteQuote(input())).toEqual({ ok: true, row: row() });
  });

  it("R4 live shape: quote.deadline (address inactive) days after the request deadline (refunds begin) passes", () => {
    // mainnet 1Click, 2026-11-07: quoteRequest.deadline 12:29:33Z, quote.deadline 3 days later
    const q = quote((x) => (x.quote.deadline = "2026-11-08T18:26:53.000Z"));
    expect(checkRouteQuote(input({ q }))).toEqual({ ok: true, row: row() });
  });

  const security: [string, Partial<Parameters<typeof input>[0]>, RegExp][] = [
    ["R2 signature", { signatureValid: false }, /^R2 /],
    ["R3 referral", { q: quote((q) => (q.quoteRequest.referral = "someone")) }, /^R3 /],
    ["R3 no referral", { q: quote((q) => delete q.quoteRequest.referral) }, /^R3 /],
    [
      "R4 address",
      { q: quote((q) => (q.quote.depositAddress = "0x0000000000000000000000000000000000000bad")) },
      /R4 deposit address/,
    ],
    ["R4 memo", { q: quote((q) => (q.quote.depositMemo = "123")) }, /R4 deposit memo/],
    ["R4 origin asset", { q: quote((q) => (q.quoteRequest.originAsset = USDC_NEAR)) }, /R4 origin asset/],
    ["R4 amount", { q: quote((q) => (q.quote.amountIn = "1")) }, /R4 amount/],
    ["R4 deadline", { q: quote((q) => (q.quoteRequest.deadline = "2026-11-05T18:26:54.000Z")) }, /R4 deadline differs/],
    [
      "R4 address inactive before the deadline",
      { q: quote((q) => (q.quote.deadline = "2026-11-05T18:00:00.000Z")) },
      /R4 deposit address goes inactive/,
    ],
    ["R4 no address deadline", { q: quote((q) => delete q.quote.deadline) }, /R4 deposit address goes inactive/],
    [
      "R5 unknown recipient",
      { registry: [row({ address_norm: "0x1111111111111111111111111111111111111111" })] },
      /^R5 /,
    ],
    ["R5 other asset", { registry: [row({ asset_id: USDC_BASE })] }, /^R5 /],
    ["R5 other mode", { registry: [row({ livemode: false })] }, /^R5 /],
    ["R5 other type", { registry: [row({ type: "chain_address" })] }, /^R5 /],
    ["R5 not active (pending)", { registry: [row({ status: "pending_approval" })] }, /^R5 /],
    [
      "R6 attacker fee",
      { q: quote((q) => (q.quoteRequest.appFees = [{ recipient: "attacker.near", fee: 50 }])) },
      /^R6 /,
    ],
    ["R6 no treasury configured", { treasury: null }, /^R6 no treasury/],
  ];
  it.each(security)("%s → security", (_n, o, reason) => {
    const r = checkRouteQuote(input(o));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.class).toBe("security");
    expect(r.reasons.some((x) => reason.test(x))).toBe(true);
  });

  it("R4: the deposit chain must be the origin asset's chain (an EVM address is valid on every EVM chain)", () => {
    const i = input();
    const r = checkRouteQuote({ ...i, deposit: { ...i.deposit, chain: "eip155:1" } });
    expect(r).toMatchObject({ ok: false, class: "security", reasons: ["R4 deposit chain differs"] });
  });

  it("R4: an Intents deposit lives on NEAR", () => {
    const q = quote((x) => (x.quoteRequest.depositType = "INTENTS"));
    expect(checkRouteQuote(input({ q })).ok).toBe(false);
    const i = input({ q });
    expect(checkRouteQuote({ ...i, deposit: { ...i.deposit, chain: "near:mainnet" } }).ok).toBe(true);
  });

  it("R4: an origin asset whose chain its id does not say is not checked for the chain", () => {
    const hot = "nep245:v2_1.omni.hot.tg:56_11111111111111111111";
    const q = quote((x) => (x.quoteRequest.originAsset = hot));
    const i = input({ q });
    expect(checkRouteQuote({ ...i, deposit: { ...i.deposit, origin_asset_id: hot, chain: "eip155:56" } }).ok).toBe(
      true,
    );
  });

  it("collects every security reason at once", () => {
    const r = checkRouteQuote(input({ signatureValid: false, q: quote((q) => (q.quoteRequest.referral = "x")) }));
    expect(r).toMatchObject({ ok: false, class: "security" });
    if (!r.ok) expect(r.reasons).toHaveLength(2);
  });

  it("R5: a recipient that only matches a disabled destination is stale, never security", () => {
    const r = checkRouteQuote(input({ registry: [row({ status: "disabled" })] }));
    expect(r).toEqual({ ok: false, class: "stale", reasons: ["R5 the destination has been disabled"] });
    // an active destination still wins over a disabled one
    expect(checkRouteQuote(input({ registry: [row({ status: "disabled", id: "d" }), row()] }))).toEqual({
      ok: true,
      row: row(),
    });
    // and security failures still outrank it
    expect(checkRouteQuote(input({ signatureValid: false, registry: [row({ status: "disabled" })] }))).toMatchObject({
      class: "security",
    });
  });

  it("R5 ambiguous: several unverified matches are never guessed between", () => {
    const r = checkRouteQuote(
      input({ registry: [row({ verification: "unverified" }), row({ id: "x", verification: "unverified" })] }),
    );
    expect(r).toMatchObject({ ok: false, class: "ambiguous" });
  });

  it("R5: the single signature-verified row wins among several matches", () => {
    const verified = row({ id: "v" });
    const r = checkRouteQuote(input({ registry: [row({ id: "u", verification: "unverified" }), verified] }));
    expect(r).toEqual({ ok: true, row: verified });
  });

  it("security outranks ambiguity", () => {
    const r = checkRouteQuote(
      input({
        signatureValid: false,
        registry: [row({ verification: "unverified" }), row({ id: "x", verification: "unverified" })],
      }),
    );
    expect(r).toMatchObject({ ok: false, class: "security" });
  });

  it.each(["SUCCESS", "REFUNDED", "FAILED", "SOMETHING_NEW"])("R7 status %s → stale", (status) => {
    expect(checkRouteQuote(input({ status }))).toMatchObject({ ok: false, class: "stale" });
  });

  it.each(["PENDING_DEPOSIT", "KNOWN_DEPOSIT_TX", "INCOMPLETE_DEPOSIT", "PROCESSING"])(
    "R7 status %s is open",
    (status) => {
      expect(checkRouteQuote(input({ status })).ok).toBe(true);
    },
  );

  it("R7: the deadline must be more than 60 s away", () => {
    const d = Date.parse(DEADLINE);
    expect(checkRouteQuote(input({ nowMs: d - 60_000 }))).toMatchObject({ ok: false, class: "stale" });
    expect(checkRouteQuote(input({ nowMs: d - 60_001 })).ok).toBe(true);
  });

  it("R5 chain address: matches on the normal form of the destination chain", () => {
    const evmRow = row({ type: "chain_address", chain: "eip155:8453", asset_id: USDC_BASE, address_norm: RECIPIENT });
    const q = quote((x) => {
      x.quoteRequest.recipientType = "DESTINATION_CHAIN";
      x.quoteRequest.destinationAsset = USDC_BASE;
      x.quoteRequest.recipient = "0x52908400098527886E0F7030069857D2E4169EE7";
    });
    expect(checkRouteQuote(input({ q, registry: [evmRow] }))).toEqual({ ok: true, row: evmRow });
    const bad = quote((x) => {
      x.quoteRequest.recipientType = "DESTINATION_CHAIN";
      x.quoteRequest.destinationAsset = USDC_BASE;
      x.quoteRequest.recipient = "not-an-address";
    });
    expect(checkRouteQuote(input({ q: bad, registry: [evmRow] }))).toMatchObject({ ok: false, class: "security" });
  });
});

describe("R6 appFees (amended: 1Click splits and does not sign them)", () => {
  it("accepts the recorded split", () => {
    expect(appFeesFailures(recorded().quoteRequest.appFees, TREASURY, SPLIT)).toEqual([]);
  });
  it("accepts a fee-free quote (nothing is diverted)", () => {
    expect(appFeesFailures(undefined, TREASURY, SPLIT)).toEqual([]);
    expect(appFeesFailures([], TREASURY, SPLIT)).toEqual([]);
  });
  it("accepts a single treasury entry", () => {
    expect(appFeesFailures([{ recipient: TREASURY, fee: 50 }], TREASURY, SPLIT)).toEqual([]);
  });
  it.each([
    [
      "total above 500 bps",
      [
        { recipient: TREASURY, fee: 300 },
        { recipient: "p", fee: 300 },
      ],
      /total 600/,
    ],
    ["no treasury entry", [{ recipient: "attacker.near", fee: 50 }], /0 times/],
    [
      "two treasury entries",
      [
        { recipient: TREASURY, fee: 25 },
        { recipient: TREASURY, fee: 25 },
      ],
      /2 times/,
    ],
    [
      "three entries",
      [
        { recipient: TREASURY, fee: 30 },
        { recipient: "p", fee: 10 },
        { recipient: "q", fee: 10 },
      ],
      /3 entries/,
    ],
    [
      "treasury below its share",
      [
        { recipient: TREASURY, fee: 10 },
        { recipient: "p", fee: 40 },
      ],
      /below its share/,
    ],
    [
      "negative fee",
      [
        { recipient: TREASURY, fee: 30 },
        { recipient: "p", fee: -5 },
      ],
      /negative/,
    ],
    [
      "fractional fee",
      [
        { recipient: TREASURY, fee: 30.5 },
        { recipient: "p", fee: 20 },
      ],
      /non-integer/,
    ],
  ] as const)("refuses %s", (_n, fees, reason) => {
    const out = appFeesFailures(fees as never, TREASURY, SPLIT);
    expect(out.some((x) => reason.test(x))).toBe(true);
  });
  it("uses the larger floor: a low-fee volatile route is not refused", () => {
    // 20 bps total: the provider may take its 20 bps floor on a volatile route; rails checks the exact class
    expect(
      appFeesFailures(
        [
          { recipient: TREASURY, fee: 0 },
          { recipient: "p", fee: 20 },
        ],
        TREASURY,
        SPLIT,
      ),
    ).toEqual([]);
  });
});

describe("matchRegistry", () => {
  it("lower-cases Intents accounts", () => {
    const r = matchRegistry([row({ address_norm: "merchant.near" })], {
      recipient: "Merchant.NEAR",
      recipientType: "INTENTS",
      destinationAsset: USDC_NEAR,
      livemode: true,
    });
    expect(r.ok).toBe(true);
  });
});

describe("intents_transfer checks", () => {
  const req = {
    pay_to: "merchant.near",
    token: USDC_NEAR,
    amount: "2000000",
    fee_to: TREASURY,
    fee_amount: "6000",
    binding: "np1:AQDxa2L6a5d8egVC7YP85UgtUCYp3cUotS6S3EsGcF7h",
    deadline: "2026-11-05T18:12:00.000Z",
  };
  const base = {
    livemode: true,
    requirement: req,
    registry: [row({ address_norm: "merchant.near" })],
    treasury: TREASURY,
    nowMs: NOW,
  };

  it("passes a genuine requirement", () => {
    expect(checkIntents(base)).toMatchObject({ ok: true });
  });
  it.each([
    ["fee to someone else", { fee_to: "attacker.near" }],
    ["fee above 500 bps", { fee_amount: "100001" }],
    ["fee not a number", { fee_amount: "x" }],
    ["amount zero", { amount: "0" }],
    ["amount not a number", { amount: "-5" }],
    ["binding malformed", { binding: "np1:short" }],
    ["binding of another scheme", { binding: "np2:AQDxa2L6a5d8egVC7YP85UgtUCYp3cUotS6S3EsGcF7h" }],
    ["pay_to unknown", { pay_to: "attacker.near" }],
    ["token differs", { token: USDC_BASE }],
  ])("%s → security", (_n, patch) => {
    expect(checkIntents({ ...base, requirement: { ...req, ...patch } })).toMatchObject({
      ok: false,
      class: "security",
    });
  });
  it("the fee may be exactly ceil(amount × 5 %)", () => {
    expect(checkIntents({ ...base, requirement: { ...req, amount: "1999999", fee_amount: "100000" } }).ok).toBe(true);
    expect(checkIntents({ ...base, requirement: { ...req, amount: "1999999", fee_amount: "100001" } }).ok).toBe(false);
  });
  it("no treasury configured → security", () => {
    expect(checkIntents({ ...base, treasury: null })).toMatchObject({ ok: false, class: "security" });
  });
  it("ambiguous registry → ambiguous", () => {
    const rows = [
      row({ address_norm: "merchant.near", verification: "test" }),
      row({ id: "y", address_norm: "merchant.near", verification: "test" }),
    ];
    expect(checkIntents({ ...base, registry: rows })).toMatchObject({ ok: false, class: "ambiguous" });
  });
  it("pay_to of a disabled destination → stale", () => {
    expect(
      checkIntents({ ...base, registry: [row({ address_norm: "merchant.near", status: "disabled" })] }),
    ).toMatchObject({
      ok: false,
      class: "stale",
    });
  });
  it("deadline within 30 s → stale", () => {
    const d = Date.parse(req.deadline);
    expect(checkIntents({ ...base, nowMs: d - 30_000 })).toMatchObject({ ok: false, class: "stale" });
    expect(checkIntents({ ...base, nowMs: d - 30_001 }).ok).toBe(true);
  });
});

describe("asset ids", () => {
  it.each([
    [USDC_BASE, { kind: "erc20", chain: "eip155:8453", contract: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" }],
    ["nep141:eth.omft.near", { kind: "native", chain: "eip155:1" }],
    [
      "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near",
      {
        kind: "spl",
        chain: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        hash20: "5ce3bf3a31af18be40ba30f721101b4341690186",
      },
    ],
    ["nep141:btc.omft.near", { kind: "native", chain: "bip122:000000000019d6689c085ae165831e93" }],
    ["nep141:zzz.omft.near", { kind: "native", chain: null }],
    ["nep141:zzz-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near", { kind: "bridged", chain: null }],
    [USDC_NEAR, { kind: "nep141", contract: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1" }],
    ["nep245:v2_1.omni.hot.tg:56_11111111111111111111", { kind: "other" }],
    ["garbage", { kind: "other" }],
  ])("%s", (id, shape) => {
    expect(assetShape(id)).toEqual(shape);
  });
  it("assetChain", () => {
    expect(assetChain(USDC_BASE)).toBe("eip155:8453");
    expect(assetChain(USDC_NEAR)).toBe("near:mainnet");
    expect(assetChain("nep245:x")).toBeNull();
    expect(assetChain("nep141:zzz.omft.near")).toBeNull();
  });
});
