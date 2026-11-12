/**
 * Asset id shapes (spec 0.5.2 asset-ids.json; incident 2026-11-11 18:58 UTC "R4 deposit chain differs" on
 * `nep141:bnb-0x55d3….omdep.near`): sentinel derives the same chain as every other service, reads omdep ids like
 * omft ones (`bnb` → BSC), parses `1cs_v1:` ids, and never claims NEAR for a bridged-looking id.
 */
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import { describe, expect, it } from "vitest";
import { assetChain, assetShape, reconcileToken } from "../../src/address-integrity/assets.js";
import { checkRouteQuote, type RegistryRow } from "../../src/address-integrity/checks.js";
import { fixture } from "../support/keys.js";
import { specVector } from "../support/vectors.js";

const BSC = "eip155:56";
const USDT_BSC = "nep141:bnb-0x55d398326f99059ff775485246999027b3197955.omdep.near";
const V = specVector<{ cases: { asset_id: string; blockchain: string | null }[] }>("asset-ids.json");
const CAIP2: Record<string, string> = {
  near: "near:mainnet",
  eth: "eip155:1",
  base: "eip155:8453",
  pol: "eip155:137",
  bsc: BSC,
  avax: "eip155:43114",
  sol: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
  btc: "bip122:000000000019d6689c085ae165831e93",
};

describe("asset ids (spec asset-ids.json)", () => {
  it("assetChain agrees with the spec's blockchain for every vector (null when kit does not know the chain)", () => {
    expect(V.cases.length).toBeGreaterThan(25);
    for (const c of V.cases)
      expect(assetChain(c.asset_id), c.asset_id).toBe(c.blockchain ? (CAIP2[c.blockchain] ?? null) : null);
  });

  it.each([
    [USDT_BSC, { kind: "erc20", chain: BSC, contract: "0x55d398326f99059ff775485246999027b3197955" }],
    ["nep141:bnb.omdep.near", { kind: "native", chain: BSC }],
    ["nep141:pol-0x3c499c542cef5e3811e1192ce70d8cc03d5c3359.omdep.near", { kind: "erc20", chain: "eip155:137" }],
    ["nep141:avax-0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e.omdep.near", { kind: "erc20", chain: "eip155:43114" }],
    [
      "nep141:sol-0xaad74c68eecfc9f8c5bdcea614f6167048c795ef.omdep.near",
      { kind: "spl", chain: CAIP2.sol, hash20: "aad74c68eecfc9f8c5bdcea614f6167048c795ef" },
    ],
    ["nep141:abs.omdep.near", { kind: "native", chain: null }],
    ["1cs_v1:bsc:bep20:0x5382555840ef9f54ef6d3ee5da60f12bcabf4b87", { kind: "erc20", chain: BSC }],
    ["1cs_v1:btc:native:coin", { kind: "native", chain: CAIP2.btc }],
    ["1cs_v1:sol:spl:A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS", { kind: "bridged", chain: CAIP2.sol }],
    ["1cs_v1:near:nep141:zec.omft.near", { kind: "nep141", contract: "zec.omft.near" }],
    ["1cs_v1:hypercore:hip1:0x6d1e7cde53ba9467b783cb7c530ce054", { kind: "bridged", chain: null }],
    ["nep141:wrap.near", { kind: "nep141", contract: "wrap.near" }],
    ["nep141:eth.bridge.near", { kind: "other" }],
    ["nep141:bnb-0x55d398326f99059ff775485246999027b3197955.omxyz.near", { kind: "other" }],
  ])("%s", (id, shape) => expect(assetShape(id)).toMatchObject(shape));

  it("the registry's ERC-20 contract reconciles with an omdep id (was refused when read as NEP-141)", () => {
    const token = { standard: "erc20" as const, address: "0x55d398326f99059ff775485246999027b3197955" };
    expect(reconcileToken(USDT_BSC, token)).toEqual({ ok: true, token });
    expect(
      reconcileToken(USDT_BSC, { standard: "erc20", address: "0x0000000000000000000000000000000000000001" }),
    ).toEqual({
      ok: false,
    });
  });
});

describe("R4 with an omdep origin asset (the 2026-11-11 quote)", () => {
  const row: RegistryRow = {
    id: "01900000-0000-7000-8000-0000000d0001",
    account_id: "01900000-0000-7000-8000-0000000a0c01",
    livemode: true,
    asset_id: "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
    type: "intents_account",
    chain: "near:mainnet",
    address_norm: "0x52908400098527886e0f7030069857d2e4169ee7",
    status: "active",
    merchant_name: "Acme GmbH",
    kyb_verified: true,
    verification: "signature",
  };
  const q = fixture<OneClickQuoteResponse>("oneclick/dry-quote.json");
  const D = "2026-11-05T18:26:53.000Z";
  q.quoteRequest.dry = false;
  q.quoteRequest.originAsset = USDT_BSC;
  q.quoteRequest.deadline = D;
  q.quote.deadline = D;
  q.quote.depositAddress = "0x11D278921A31AB448c7e27F33c2313C130B05036";
  const input = (chain: string) => ({
    livemode: true,
    deposit: {
      address: "0x11D278921A31AB448c7e27F33c2313C130B05036",
      memo: null,
      chain,
      origin_asset_id: USDT_BSC,
      amount_in: q.quote.amountIn,
      deadline: D,
    },
    status: { status: "PENDING_DEPOSIT", quoteResponse: q },
    signatureValid: true,
    registry: [row],
    treasury: "intents.near",
    referral: "nearpay",
    split: { shareBps: 5000, floorBps: 20, stableFloorBps: 1 },
    nowMs: Date.parse("2026-11-05T18:10:00.000Z"),
  });
  it("a BSC deposit passes (payments/rails name eip155:56, as 1Click's blockchain bsc says)", () => {
    expect(checkRouteQuote(input(BSC))).toEqual({ ok: true, row });
  });
  it("a NEAR chain claim for it is refused (caller-supplied: request evidence)", () => {
    expect(checkRouteQuote(input("near:mainnet"))).toMatchObject({ class: "security", evidence: "request" });
  });
});
