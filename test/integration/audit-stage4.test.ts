/**
 * Settlement audit on Solana and Bitcoin (lld/sentinel.md §16) with sentinel's own readers against
 * recorded answers (spec `chains-solana-bitcoin.json` `evidence`; no live network): a Solana JSON-RPC
 * double serving `getTransaction` at `finalized`, an Esplora double serving `/tx/{txid}` and the tip
 * height, sentinel's own 1Click token registry for the Bitcoin tier's price, identity's registry view.
 * Covers pass, short/failed (mismatch), not final (retry → unverifiable), double use, the confirmation
 * tier and fail-closed coverage (no reader → unverifiable + `audit_coverage_missing`, never Tier B).
 */

import { BITCOIN_MAINNET, SOLANA_MAINNET } from "@nearpay/spec";
import { newId } from "@nearpay-internal/ids";
import type { Execution } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { AUDIT_MAX_ATTEMPTS, AuditRetry, auditExecution } from "../../src/independent-reconciliation/auditor.js";
import { bitcoinScript } from "../../src/independent-reconciliation/chain-reads.js";
import { esploraReader, solanaReader } from "../../src/infra/clients/chains.js";
import { execution } from "../support/executions.js";
import {
  FAKE_TOKENS,
  type FakeOneClick,
  type FakeServer,
  fakeEsplora,
  fakeOneClick,
  fakeSolanaRpc,
} from "../support/fakes.js";
import { type Stack, startStack } from "../support/stack.js";
import { specVector } from "../support/vectors.js";

const USDC_SOL = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
const SOL = "nep141:sol.omft.near";
const BTC = "nep141:btc.omft.near";
const SOL_MERCHANT = "H314ws4NAZj5cXEzLVXyLZ3vrwWYuhDEz2cSa5EMs7DR";
const BTC_MERCHANT = "bc1qgjvrfv789jcls63y95cgan53lq88jnuh32w0fq";
const BTC_PRICE = 100_000; // USD per BTC in sentinel's token registry: 1 sat = USD 0.001

interface SolCase {
  name: string;
  rpc_result: { transaction: { signatures: string[] } };
  evidence: { amount: string; asset_id: string; tx_hash: string } | null;
}
const V = specVector<{ evidence: { solana: { cases: SolCase[] } } }>("chains-solana-bitcoin.json");
const [usdcExisting, usdcNewAta, solPayout, failedTx] = V.evidence.solana.cases as [SolCase, SolCase, SolCase, SolCase];

let s: Stack;
let w: Sentinel;
let oc: FakeOneClick;
let sol: FakeServer;
let esplora: FakeServer & { failNext: number };
const solTxs = new Map<string, unknown>();
const btcTxs = new Map<string, unknown>();
const tip = { height: 900_000 };

beforeAll(async () => {
  oc = await fakeOneClick();
  oc.tokens = [
    ...FAKE_TOKENS,
    { assetId: BTC, decimals: 8, blockchain: "btc", symbol: "BTC", price: BTC_PRICE, priceUpdatedAt: "x" },
    { assetId: SOL, decimals: 9, blockchain: "sol", symbol: "SOL", price: 150, priceUpdatedAt: "x" },
  ];
  [sol, esplora] = await Promise.all([fakeSolanaRpc(solTxs), fakeEsplora(btcTxs, tip)]);
  s = await startStack({
    oneclick: oc,
    worker: { solana: solanaReader({ urls: [sol.url] }), bitcoin: esploraReader({ urls: [esplora.url] }) },
  });
  w = (s.worker as NonNullable<Stack["worker"]>).sentinel;
  const live = { livemode: true, verification: "signature", type: "chain_address" } as const;
  await s.destination({ ...live, asset_id: USDC_SOL, chain: SOLANA_MAINNET, address_norm: SOL_MERCHANT });
  await s.destination({ ...live, asset_id: SOL, chain: SOLANA_MAINNET, address_norm: SOL_MERCHANT });
  await s.destination({ ...live, asset_id: BTC, chain: BITCOIN_MAINNET, address_norm: BTC_MERCHANT });
  for (const c of V.evidence.solana.cases) solTxs.set(c.rpc_result.transaction.signatures[0] as string, c.rpc_result);
}, 240_000);
afterAll(async () => {
  await s?.stop();
  await Promise.all([sol?.stop(), esplora?.stop(), oc?.stop()]);
});

function settled(o: { asset: string; chain: string; recipient: string; amount: string; hash: string }): Execution {
  const x = execution({
    id: newId("ex"),
    account_id: s.account,
    settlement: {
      asset_id: o.asset,
      chain: o.chain,
      recipient: o.recipient,
      recipient_type: "destination_chain",
      amount_base: o.amount,
      tag: "0",
      expected: o.amount,
    },
    settled_amount: o.amount,
    created_at: new Date(Date.now() - 60_000).toISOString(),
  });
  return {
    ...x,
    evidence: {
      ...(x.evidence as NonNullable<Execution["evidence"]>),
      chain: o.chain,
      tx_hash: o.hash,
      recipient: o.recipient,
      asset_id: o.asset,
      amount: o.amount,
      tier: "A",
    },
  };
}
const findings = (id: string) =>
  s.admin.db.selectFrom("audit_findings").selectAll().where("execution_id", "=", id).orderBy("check_kind").execute();
const results = async (id: string) => Object.fromEntries((await findings(id)).map((f) => [f.check_kind, f.result]));
const settlementOf = async (id: string) =>
  (await findings(id)).find((f) => f.check_kind === "settlement") as {
    result: string;
    details: Record<string, unknown>;
    tx_hash: string | null;
  };

const solExec = (c: SolCase, amount = c.evidence?.amount as string) =>
  settled({
    asset: c.evidence?.asset_id as string,
    chain: SOLANA_MAINNET,
    recipient: SOL_MERCHANT,
    amount,
    hash: c.rpc_result.transaction.signatures[0] as string,
  });

describe("Solana: finalized transaction, owner balance delta", () => {
  it.each([
    ["USDC to an existing ATA", usdcExisting],
    ["USDC creating the ATA", usdcNewAta],
    ["SOL lamports", solPayout],
  ])("%s → pass with the chain read and the exact signature as the double-use key", async (_n, c) => {
    const x = solExec(c);
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
    const f = await settlementOf(x.id);
    expect(f.tx_hash).toBe(c.rpc_result.transaction.signatures[0]);
    expect(f.details).toMatchObject({ chain_read: { amount: c.evidence?.amount } });
    expect(sol.requests.at(-1)?.body).toMatchObject({
      method: "getTransaction",
      params: [c.rpc_result.transaction.signatures[0], { commitment: "finalized", maxSupportedTransactionVersion: 0 }],
    });
  });

  it("a settled amount above what the chain shows is a mismatch", async () => {
    const x = solExec(usdcExisting, (BigInt(usdcExisting.evidence?.amount as string) + 1n).toString());
    await auditExecution(w, x, 1);
    expect((await settlementOf(x.id)).result).toBe("mismatch");
  });

  it("the same transaction is never attributed twice", async () => {
    const x = solExec(usdcExisting);
    await auditExecution(w, x, 1);
    expect((await settlementOf(x.id)).details.reason).toMatch(/already attributed/);
  });

  it("a failed transaction (meta.err) is a mismatch", async () => {
    const sig = failedTx.rpc_result.transaction.signatures[0] as string;
    const x = settled({
      asset: USDC_SOL,
      chain: SOLANA_MAINNET,
      recipient: SOL_MERCHANT,
      amount: "25000000",
      hash: sig,
    });
    await auditExecution(w, x, 1);
    expect(await settlementOf(x.id)).toMatchObject({
      result: "mismatch",
      details: { reason: expect.stringMatching(/failed/) },
    });
  });

  it("not found / not finalized retries, then records unverifiable on the last attempt", async () => {
    const x = settled({
      asset: USDC_SOL,
      chain: SOLANA_MAINNET,
      recipient: SOL_MERCHANT,
      amount: "1",
      hash: "5".repeat(88),
    });
    await expect(auditExecution(w, x, 1)).rejects.toThrow(AuditRetry);
    await auditExecution(w, x, AUDIT_MAX_ATTEMPTS);
    expect((await settlementOf(x.id)).result).toBe("unverifiable");
  });
});

describe("Bitcoin: outputs to the destination, confirmations per tier", () => {
  let n = 0;
  function btcTx(sats: number[], height: number | null): string {
    const txid = (++n).toString(16).padStart(64, "a");
    btcTxs.set(txid, {
      txid,
      vout: [
        ...sats.map((value) => ({
          scriptpubkey: bitcoinScript(BTC_MERCHANT),
          scriptpubkey_address: BTC_MERCHANT,
          value,
        })),
        {
          scriptpubkey: `0014${"00".repeat(20)}`,
          scriptpubkey_address: "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
          value: 777,
        },
      ],
      status:
        height === null ? { confirmed: false } : { confirmed: true, block_height: height, block_hash: "cd".repeat(32) },
    });
    return txid;
  }
  const btcExec = (txid: string, amount: string) =>
    settled({ asset: BTC, chain: BITCOIN_MAINNET, recipient: BTC_MERCHANT, amount, hash: txid });

  it("USD 500 with 1 confirmation → pass (two outputs summed)", async () => {
    tip.height = 900_000;
    const x = btcExec(btcTx([300_000, 200_000], 900_000), "500000");
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
    expect((await settlementOf(x.id)).details).toMatchObject({
      chain_read: { block_height: 900_000, amount: "500000", confirmations: 1, required_confirmations: 1 },
    });
  });

  it("USD 1,500 needs 2 confirmations: retries at 1, passes at 2", async () => {
    tip.height = 900_010;
    const x = btcExec(btcTx([1_500_000], 900_010), "1500000");
    await expect(auditExecution(w, x, 1)).rejects.toThrow(/1\/2 confirmations/);
    tip.height = 900_011;
    await auditExecution(w, x, 2);
    expect((await settlementOf(x.id)).result).toBe("pass");
  });

  it("without a registry price the stricter tier (2) applies", async () => {
    tip.height = 900_020;
    const x = btcExec(btcTx([1_000], 900_020), "1000");
    await expect(auditExecution({ ...w, liveTokens: null }, x, 1)).rejects.toThrow(/1\/2 confirmations/);
  });

  it("in the mempool → retry; the last attempt records unverifiable", async () => {
    const x = btcExec(btcTx([1_000], null), "1000");
    await expect(auditExecution(w, x, 1)).rejects.toThrow(/0\/1 confirmations/);
    await auditExecution(w, x, AUDIT_MAX_ATTEMPTS);
    expect((await settlementOf(x.id)).result).toBe("unverifiable");
  });

  it("less to the destination than settled → mismatch; Esplora down → retry", async () => {
    tip.height = 900_030;
    const x = btcExec(btcTx([999], 900_030), "1000");
    await auditExecution(w, x, 1);
    expect((await settlementOf(x.id)).result).toBe("mismatch");
    const y = btcExec(btcTx([1_000], 900_030), "1000");
    esplora.failNext = 4;
    await expect(auditExecution(w, y, 1)).rejects.toThrow(/Esplora/);
    esplora.failNext = 0;
  });
});

describe("fail closed when a Stage 4 chain has no sentinel reader", () => {
  it("records unverifiable and counts audit_coverage_missing{chain}; never falls back to Tier B", async () => {
    const missing: string[] = [];
    const blind: Sentinel = {
      ...w,
      solana: null,
      bitcoin: null,
      metrics: { ...w.metrics, coverageMissing: (chain) => missing.push(chain) },
    };
    const a = settled({
      asset: USDC_SOL,
      chain: SOLANA_MAINNET,
      recipient: SOL_MERCHANT,
      amount: "1",
      hash: "6".repeat(88),
    });
    const b = settled({
      asset: BTC,
      chain: BITCOIN_MAINNET,
      recipient: BTC_MERCHANT,
      amount: "1",
      hash: "b".repeat(64),
    });
    await auditExecution(blind, a, 1);
    await auditExecution(blind, b, 1);
    for (const x of [a, b]) {
      const f = await settlementOf(x.id);
      expect(f.result).toBe("unverifiable");
      expect(f.details.reason).toMatch(/audit_coverage_missing/);
    }
    expect(missing).toEqual([SOLANA_MAINNET, BITCOIN_MAINNET]);
  });
});

describe("test mode: the sandbox's simulated transaction, same rules (sandbox §10)", () => {
  const sims = new Map<string, unknown>();
  let sim: Sentinel;
  beforeAll(async () => {
    const t = { livemode: false, verification: "test", type: "chain_address" } as const;
    await s.destination({ ...t, asset_id: USDC_SOL, chain: SOLANA_MAINNET, address_norm: SOL_MERCHANT });
    await s.destination({ ...t, asset_id: BTC, chain: BITCOIN_MAINNET, address_norm: BTC_MERCHANT });
    sim = {
      ...w,
      test: {
        status: async () => {
          throw new Error("not used");
        },
        verifySignature: () => false,
        tx: async (_chain: string, hash: string) => (sims.get(hash) as never) ?? null,
      } as unknown as NonNullable<Sentinel["test"]>,
      testTokens: { asset: async () => ({ symbol: "BTC", decimals: 8, priceUsd: String(BTC_PRICE) }) },
    };
  });
  const testExec = (o: Parameters<typeof settled>[0]) => ({ ...settled(o), livemode: false });

  it("Solana: base58 recipients compare exactly (not lower-cased) → pass; a failed tx → mismatch", async () => {
    sims.set("simsol1", {
      finalized: true,
      transfers: [{ token: USDC_SOL, to: SOL_MERCHANT, amount: "10" }],
      block_ref: "5",
    });
    const x = testExec({
      asset: USDC_SOL,
      chain: SOLANA_MAINNET,
      recipient: SOL_MERCHANT,
      amount: "10",
      hash: "simsol1",
    });
    await auditExecution(sim, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
    sims.set("simsol2", { finalized: true, transfers: [], failed: true });
    const y = testExec({
      asset: USDC_SOL,
      chain: SOLANA_MAINNET,
      recipient: SOL_MERCHANT,
      amount: "10",
      hash: "simsol2",
    });
    await auditExecution(sim, y, 1);
    expect((await settlementOf(y.id)).result).toBe("mismatch");
  });

  it("Bitcoin: confirmations below the tier retry (finalized alone is not enough); enough → pass", async () => {
    const hash = "e".repeat(64);
    sims.set(hash, {
      finalized: true,
      confirmations: 1,
      transfers: [{ token: BTC, to: BTC_MERCHANT, amount: "2000000", vout: 0 }],
    });
    const x = testExec({ asset: BTC, chain: BITCOIN_MAINNET, recipient: BTC_MERCHANT, amount: "2000000", hash });
    await expect(auditExecution(sim, x, 1)).rejects.toThrow(/1\/2 confirmations/); // USD 2,000 → 2
    sims.set(hash, {
      finalized: true,
      confirmations: 2,
      transfers: [{ token: BTC, to: BTC_MERCHANT, amount: "2000000", vout: 0 }],
    });
    await auditExecution(sim, x, 2);
    expect((await settlementOf(x.id)).result).toBe("pass");
  });
});
