/**
 * Stage 4 coverage for Solana and Bitcoin (lld/sentinel.md §16), checked against spec 0.4.0
 * `test-vectors/chains-solana-bitcoin.json`: omft asset ids and the SPL rule
 * `nep141:sol-<hex(keccak256(mint)[12..32])>.omft.near`, the attested token reconciliation, R4 on
 * Solana/Bitcoin deposits, and sentinel's own reads of Solana and Bitcoin settlements.
 */

import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import {
  BITCOIN_CONFIRMATION_TIERS,
  BITCOIN_DEFAULT_CONFIRMATION_TIERS,
  BITCOIN_MAINNET,
  parseOmftAssetId,
  requiredConfirmations,
  SOLANA_MAINNET,
} from "@nearpay-money/spec";
import { describe, expect, it } from "vitest";
import {
  assetChain,
  assetShape,
  attestedAsset,
  reconcileToken,
  registryTokenContract,
  splAssetHash,
} from "../../src/address-integrity/assets.js";
import { ATTESTED_CHAINS, attestedChain } from "../../src/address-integrity/attested-chains.js";
import { checkRouteQuote, type RouteQuoteInput } from "../../src/address-integrity/checks.js";
import { bitcoinReceived, bitcoinScript, solanaReceived } from "../../src/independent-reconciliation/chain-reads.js";
import { priceString, tokenMap } from "../../src/infra/clients/tokens.js";
import { fixture } from "../support/keys.js";
import { specVector } from "../support/vectors.js";

interface SolCase {
  name: string;
  expected_amount?: string;
  rpc_result: unknown;
  result: string;
  evidence: {
    recipient: string;
    asset_id: string;
    amount: string;
    solana: { slot: number; mint: string | null; token_accounts: string[] };
  } | null;
}
interface BtcCase {
  name: string;
  expected_amount: string;
  settlement_usd_micros: string;
  esplora_tx: { txid: string };
  tip_height: number;
  result: string;
  evidence: {
    recipient: string;
    amount: string;
    bitcoin: { confirmations: number; required_confirmations: number; block_height: number };
  } | null;
}
interface Vectors {
  omft: {
    cases: { asset_id: string; parsed: { blockchain: string; kind: string; token: string | null } | null }[];
    spl_mints: { mint: string; keccak256_hex: string; asset_id: string }[];
  };
  evidence: {
    solana: { expected_amount: string; cases: SolCase[] };
    bitcoin: {
      tiers: unknown;
      required_confirmations: { usd_micros: string; confirmations: number }[];
      cases: BtcCase[];
    };
  };
  assets: { asset_id: string; chain: string }[];
}

const V = specVector<Vectors>("chains-solana-bitcoin.json");
const USDC_SOL = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

describe("omft asset ids (vectors `omft`)", () => {
  it("the spec parser matches every vector", () => {
    for (const c of V.omft.cases) expect(parseOmftAssetId(c.asset_id), c.asset_id).toEqual(c.parsed);
  });
  it("assetShape agrees with the spec parser on chain and token", () => {
    for (const c of V.omft.cases) {
      const shape = assetShape(c.asset_id);
      if (!c.parsed) {
        expect(["nep141", "other"], c.asset_id).toContain(shape.kind);
        continue;
      }
      if (c.parsed.kind === "native") expect(shape.kind).toBe("native");
      if (c.parsed.kind === "evm") expect(shape).toMatchObject({ kind: "erc20", contract: c.parsed.token });
      if (c.parsed.kind === "hash20")
        expect(shape).toEqual({ kind: "spl", chain: SOLANA_MAINNET, hash20: c.parsed.token });
    }
    expect(assetChain(USDC_SOL)).toBe(SOLANA_MAINNET);
    expect(assetChain("nep141:btc.omft.near")).toBe(BITCOIN_MAINNET);
    for (const a of V.assets) expect(assetChain(a.asset_id), a.asset_id).toBe(a.chain);
  });
  it("splAssetHash reproduces every SPL asset id of the vectors", () => {
    for (const m of V.omft.spl_mints) {
      expect(splAssetHash(m.mint)).toBe(m.keccak256_hex.slice(24));
      expect(`nep141:sol-${splAssetHash(m.mint)}.omft.near`).toBe(m.asset_id);
    }
    for (const bad of ["", "0OIl", "7DUeBUtEcb7nujVZRJmeBju3X1mo6PpnWNtJ9EBhdY", `${USDC_MINT}1`])
      expect(splAssetHash(bad), bad).toBeNull();
  });
});

describe("attested token (Attestation.asset.token) on Solana and Bitcoin", () => {
  const spl = (address: string | null) => registryTokenContract("sol", address);
  it("an SPL id accepts only the registry mint that hashes to it", () => {
    expect(reconcileToken(USDC_SOL, spl(USDC_MINT))).toEqual({
      ok: true,
      token: { standard: "spl", address: USDC_MINT },
    });
    expect(reconcileToken(USDC_SOL, spl(USDT_MINT))).toEqual({ ok: false });
    expect(reconcileToken(USDC_SOL, { standard: "erc20", address: USDC_MINT })).toEqual({ ok: false });
    expect(reconcileToken(USDC_SOL, { standard: "spl", address: null })).toEqual({ ok: false });
    expect(reconcileToken(USDC_SOL, { standard: "spl", address: "not-a-mint" })).toEqual({ ok: false });
    // a listing without a mint: no token (manual path), never "send the native coin"
    expect(reconcileToken(USDC_SOL, spl(null))).toEqual({ ok: true, token: null });
  });
  it("SOL and BTC ids need the native coin", () => {
    expect(reconcileToken("nep141:sol.omft.near", spl(null))).toEqual({
      ok: true,
      token: { standard: "native", address: null },
    });
    expect(reconcileToken("nep141:sol.omft.near", spl(USDC_MINT))).toEqual({ ok: false });
    expect(reconcileToken("nep141:btc.omft.near", registryTokenContract("btc", null))).toEqual({
      ok: true,
      token: { standard: "native", address: null },
    });
  });
  it("attestedAsset refuses (unavailable) a registry whose mint contradicts the asset id", () => {
    const signed = { amountIn: "25000000", amountInFormatted: "25.0" };
    const good = attestedAsset(USDC_SOL, { symbol: "USDC", decimals: 6, token: spl(USDC_MINT) }, signed);
    expect(good).toEqual({
      ok: true,
      asset: { asset_id: USDC_SOL, symbol: "USDC", decimals: 6, token: { standard: "spl", address: USDC_MINT } },
    });
    const bad = attestedAsset(USDC_SOL, { symbol: "USDC", decimals: 6, token: spl(USDT_MINT) }, signed);
    expect(bad).toMatchObject({ ok: false, reason: expect.stringMatching(/does not match/) });
  });
  it("the token list carries the registry price as an exact decimal string (or null)", () => {
    const map = tokenMap([
      {
        assetId: USDC_SOL,
        decimals: 6,
        blockchain: "sol",
        symbol: "USDC",
        price: 0.9998,
        priceUpdatedAt: "x",
        contractAddress: USDC_MINT,
      },
      {
        assetId: "nep141:btc.omft.near",
        decimals: 8,
        blockchain: "btc",
        symbol: "BTC",
        price: 90123.5,
        priceUpdatedAt: "x",
      },
    ]);
    expect(map.get(USDC_SOL)).toMatchObject({ priceUsd: "0.9998", token: { standard: "spl", address: USDC_MINT } });
    expect(map.get("nep141:btc.omft.near")).toMatchObject({ priceUsd: "90123.5", token: { standard: "native" } });
    for (const p of [0, -1, Number.NaN, 1e-9, 1e21, "1", null, undefined]) expect(priceString(p), String(p)).toBeNull();
  });
});

describe("attested chains", () => {
  it("covers NEAR, the three EVM chains, Solana and Bitcoin with sentinel's own read", () => {
    expect([...ATTESTED_CHAINS.keys()].sort()).toEqual(
      ["near:mainnet", "eip155:1", "eip155:8453", "eip155:42161", SOLANA_MAINNET, BITCOIN_MAINNET].sort(),
    );
    expect(attestedChain(SOLANA_MAINNET)?.read).toBe("solana_finalized");
    expect(attestedChain(BITCOIN_MAINNET)?.read).toBe("bitcoin_confirmations");
    expect(attestedChain("xrp:mainnet")).toBeNull();
  });
});

describe("R4 on Solana and Bitcoin deposits", () => {
  const NOW = Date.parse("2026-11-05T18:10:00.000Z");
  const DEADLINE = "2026-11-05T18:26:53.000Z";
  const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
  const RECIPIENT = "0x52908400098527886e0f7030069857d2e4169ee7";
  const row = {
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
  };
  function input(
    origin: string,
    chain: string,
    address: string,
    mut?: (q: OneClickQuoteResponse) => void,
  ): RouteQuoteInput {
    const q = fixture<OneClickQuoteResponse>("oneclick/dry-quote.json");
    q.quoteRequest.dry = false;
    q.quoteRequest.originAsset = origin;
    q.quoteRequest.depositType = "ORIGIN_CHAIN";
    q.quote.depositAddress = address;
    q.quoteRequest.deadline = DEADLINE;
    q.quote.deadline = DEADLINE;
    mut?.(q);
    return {
      livemode: true,
      deposit: { address, memo: null, chain, origin_asset_id: origin, amount_in: q.quote.amountIn, deadline: DEADLINE },
      status: { status: "PENDING_DEPOSIT", quoteResponse: q },
      signatureValid: true,
      registry: [row],
      treasury: "intents.near",
      referral: "nearpay",
      split: { shareBps: 5000, floorBps: 20, stableFloorBps: 1 },
      nowMs: NOW,
    };
  }
  const SOL_DEPOSIT = "EyjEeiTxb4rvkoN3ZA2zTimuc6VyF8V1QuH9TT66Gkn6";
  const BTC_DEPOSIT = "bc1qpct5sxzppv204tth290uen85nqkhzw9sq5m0ku";

  it("passes a Solana (SPL and SOL) and a Bitcoin deposit on their own chains", () => {
    expect(checkRouteQuote(input(USDC_SOL, SOLANA_MAINNET, SOL_DEPOSIT)).ok).toBe(true);
    expect(checkRouteQuote(input("nep141:sol.omft.near", SOLANA_MAINNET, SOL_DEPOSIT)).ok).toBe(true);
    expect(checkRouteQuote(input("nep141:btc.omft.near", BITCOIN_MAINNET, BTC_DEPOSIT)).ok).toBe(true);
    // any valid Bitcoin address type may be a 1Click deposit address
    expect(
      checkRouteQuote(input("nep141:btc.omft.near", BITCOIN_MAINNET, "3EdC2tokZbqft8jYFdvN58YaCetzMUBRji")).ok,
    ).toBe(true);
  });
  it("a deposit chain other than the origin asset's is security", () => {
    for (const [origin, chain, addr] of [
      [USDC_SOL, "eip155:8453", SOL_DEPOSIT],
      [USDC_SOL, BITCOIN_MAINNET, SOL_DEPOSIT],
      ["nep141:btc.omft.near", SOLANA_MAINNET, BTC_DEPOSIT],
    ] as const) {
      const r = checkRouteQuote(input(origin, chain, addr));
      expect(r, `${origin} on ${chain}`).toMatchObject({ ok: false, class: "security" });
      if (!r.ok) expect(r.reasons).toContain("R4 deposit chain differs");
    }
  });
  it("a deposit address that is not a valid address of the deposit chain is security", () => {
    for (const [origin, chain, addr] of [
      [USDC_SOL, SOLANA_MAINNET, "7DUeBUtEcb7nujVZRJmeBju3X1mo6PpnWNtJ9EBhdY"],
      [USDC_SOL, SOLANA_MAINNET, "0x76b4c56085ed136a8744d52be956396624a730e8"],
      ["nep141:btc.omft.near", BITCOIN_MAINNET, "bc1qpct5sxzppv204tth290uen85nqkhzw9sq5m0kq"],
      ["nep141:btc.omft.near", BITCOIN_MAINNET, "tb1qpct5sxzppv204tth290uen85nqkhzw9s2jqud0"],
    ] as const) {
      const r = checkRouteQuote(input(origin, chain, addr));
      expect(r, addr).toMatchObject({ ok: false, class: "security" });
      if (!r.ok) expect(r.reasons.join(";")).toMatch(/R4 deposit address is not a valid/);
    }
  });
});

describe("Solana settlement read (vectors `evidence.solana`)", () => {
  for (const c of V.evidence.solana.cases)
    it(c.name, () => {
      const recipient = c.evidence?.recipient ?? "H314ws4NAZj5cXEzLVXyLZ3vrwWYuhDEz2cSa5EMs7DR";
      const assetId = c.evidence?.asset_id ?? USDC_SOL;
      const shape = assetShape(assetId);
      const asset =
        shape.kind === "spl" ? ({ kind: "spl", hash20: shape.hash20 } as const) : ({ kind: "native" } as const);
      const read = solanaReceived(c.rpc_result, recipient, asset);
      expect(read).not.toBeNull();
      if (!read) return;
      if (c.result === "mismatch") {
        expect(read.failed).toBe(true);
        return;
      }
      expect(read.failed).toBe(false);
      expect(read.amount.toString()).toBe(c.evidence?.amount);
      expect(read.amount >= BigInt(c.expected_amount ?? V.evidence.solana.expected_amount)).toBe(c.result === "pass");
      expect(read.slot).toBe(c.evidence?.solana.slot);
      expect(read.mint).toBe(c.evidence?.solana.mint);
      expect(read.tokenAccounts).toEqual(c.evidence?.solana.token_accounts);
    });
  it("another mint, owner or recipient counts nothing; a malformed answer is null", () => {
    const usdc = V.evidence.solana.cases[0] as SolCase;
    const rcpt = usdc.evidence?.recipient as string;
    expect(
      solanaReceived(usdc.rpc_result, rcpt, { kind: "spl", hash20: "c800a4bd850783ccb82c2b2c7e84175443606352" })
        ?.amount,
    ).toBe(0n);
    expect(
      solanaReceived(usdc.rpc_result, "EyjEeiTxb4rvkoN3ZA2zTimuc6VyF8V1QuH9TT66Gkn6", {
        kind: "spl",
        hash20: "5ce3bf3a31af18be40ba30f721101b4341690186",
      })?.amount,
    ).toBe(0n);
    for (const bad of [
      null,
      1,
      {},
      { slot: -1, meta: {} },
      { slot: 1 },
      { slot: 1, meta: { err: null, preTokenBalances: "x" } },
    ])
      expect(solanaReceived(bad, rcpt, { kind: "spl", hash20: "5ce3bf3a31af18be40ba30f721101b4341690186" })).toBeNull();
    expect(
      solanaReceived(
        {
          slot: 1,
          meta: { err: null, preBalances: [1], postBalances: [2] },
          transaction: { message: { accountKeys: [] } },
        },
        rcpt,
        { kind: "native" },
      ),
    ).toBeNull();
  });
  it("SOL: jsonParsed keys and loaded (lookup-table) addresses index the balances", () => {
    const R = "H314ws4NAZj5cXEzLVXyLZ3vrwWYuhDEz2cSa5EMs7DR";
    const meta = { err: null, preBalances: [10, 0, 5], postBalances: [3, 0, 12] };
    const parsed = {
      slot: 9,
      blockTime: null,
      meta,
      transaction: {
        message: { accountKeys: [{ pubkey: "a" }, { pubkey: "b" }, { pubkey: R, source: "lookupTable" }] },
      },
    };
    expect(solanaReceived(parsed, R, { kind: "native" })?.amount).toBe(7n);
    const raw = {
      slot: 9,
      meta: { ...meta, loadedAddresses: { writable: [R], readonly: [] } },
      transaction: { message: { accountKeys: ["a", "b"] } },
    };
    expect(solanaReceived(raw, R, { kind: "native" })?.amount).toBe(7n);
    // the recipient paying the fee nets negative: nothing received
    expect(solanaReceived(parsed, "a", { kind: "native" })?.amount).toBe(0n);
  });
});

describe("Bitcoin settlement read (vectors `evidence.bitcoin`)", () => {
  // Since spec 0.4.2 (ADR-0022 as amended) the vectors carry the default tiers (1 confirmation for every amount);
  // sentinel's independent audit deliberately stays on the stricter USD tiers (spec: "kept unchanged … for
  // sentinel's stricter independent audit").
  it("the spec default tiers reproduce the vector tiers", () => {
    expect(BITCOIN_DEFAULT_CONFIRMATION_TIERS).toEqual(V.evidence.bitcoin.tiers);
    for (const r of V.evidence.bitcoin.required_confirmations)
      expect(requiredConfirmations(BITCOIN_DEFAULT_CONFIRMATION_TIERS, BigInt(r.usd_micros))).toBe(r.confirmations);
  });
  it("the audit's stricter tiers still ask 2 confirmations from USD 1,000", () => {
    expect(requiredConfirmations(BITCOIN_CONFIRMATION_TIERS, 999_999_999n)).toBe(1);
    expect(requiredConfirmations(BITCOIN_CONFIRMATION_TIERS, 1_000_000_000n)).toBe(2);
  });
  for (const c of V.evidence.bitcoin.cases)
    it(c.name, () => {
      const recipient = c.evidence?.recipient ?? "bc1qgjvrfv789jcls63y95cgan53lq88jnuh32w0fq";
      const read = bitcoinReceived(c.esplora_tx, c.tip_height, recipient, c.esplora_tx.txid);
      expect(read).not.toBeNull();
      if (!read) return;
      const required = requiredConfirmations(BITCOIN_DEFAULT_CONFIRMATION_TIERS, BigInt(c.settlement_usd_micros));
      const final = read.confirmations >= required;
      expect(final).toBe(c.result === "pass");
      if (c.result === "pass") {
        expect(read.amount.toString()).toBe(c.evidence?.amount);
        expect(read.confirmations).toBe(c.evidence?.bitcoin.confirmations);
        expect(required).toBe(c.evidence?.bitcoin.required_confirmations);
        expect(read.blockHeight).toBe(c.evidence?.bitcoin.block_height);
      }
    });
  it("outputs are matched on the scriptPubKey re-derived from the address, not on Esplora's address field", () => {
    const c = V.evidence.bitcoin.cases[0] as BtcCase;
    const tx = structuredClone(c.esplora_tx) as { vout: { scriptpubkey_address: string }[]; txid: string };
    for (const o of tx.vout) o.scriptpubkey_address = "bc1qpct5sxzppv204tth290uen85nqkhzw9sq5m0ku";
    const read = bitcoinReceived(tx, c.tip_height, c.evidence?.recipient as string, tx.txid);
    expect(read?.amount.toString()).toBe(c.evidence?.amount);
    expect(bitcoinReceived(tx, c.tip_height, "bc1qpct5sxzppv204tth290uen85nqkhzw9sq5m0ku", tx.txid)?.amount).toBe(0n);
  });
  it("a different txid, a malformed answer or a non-mainnet recipient is null", () => {
    const c = V.evidence.bitcoin.cases[0] as BtcCase;
    const r = c.evidence?.recipient as string;
    expect(bitcoinReceived(c.esplora_tx, c.tip_height, r, "00".repeat(32))).toBeNull();
    expect(
      bitcoinReceived({ txid: c.esplora_tx.txid, vout: [{ scriptpubkey: 1, value: 1 }] }, 1, r, c.esplora_tx.txid),
    ).toBeNull();
    expect(
      bitcoinReceived({ txid: c.esplora_tx.txid, vout: [{ scriptpubkey: "00", value: 1.5 }] }, 1, r, c.esplora_tx.txid),
    ).toBeNull();
    expect(
      bitcoinReceived({ txid: c.esplora_tx.txid, vout: [], status: { confirmed: true } }, 1, r, c.esplora_tx.txid),
    ).toBeNull();
    expect(
      bitcoinReceived(c.esplora_tx, c.tip_height, "tb1qpct5sxzppv204tth290uen85nqkhzw9s2jqud0", c.esplora_tx.txid),
    ).toBeNull();
    expect(bitcoinReceived(null, 1, r, "x")).toBeNull();
    expect(bitcoinScript("bc1pzkakv8d86xwnrvzx262umfvz04dxjeegc4lez8aqdlx50zjfsr5qrjf5pr")).toMatch(
      /^5120[0-9a-f]{64}$/,
    );
    expect(bitcoinScript("3EdC2tokZbqft8jYFdvN58YaCetzMUBRji")).toMatch(/^a914[0-9a-f]{40}87$/);
  });
});
