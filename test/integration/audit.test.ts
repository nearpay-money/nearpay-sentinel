/**
 * Settlement audit (§7) with sentinel's own readers: Anvil as a real EVM chain (ERC-20 and native
 * transfers, finality, reverts), a NEAR RPC serving recorded and synthetic `EXPERIMENTAL_tx_status`
 * responses (Intents batches, NEP-141), the signed 1Click double for Tier B, identity's registry view
 * for the destination check, and the worker end to end over NATS (settled → audit job → finding event;
 * destination disabled → cache eviction; kill-switch events relayed).
 */

import { fromUuid, newId, toUuid } from "@nearpay-internal/ids";
import { AuditFinding, type Execution, KillSwitchEvent, OpsActionEvent, OpsApproval } from "@nearpay-internal/spec";
import { domainEvent, internalSettlementDestination } from "@nearpay-internal/testing";
import { routeQuoteDepositKey } from "@nearpay-money/spec";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { AUDIT_MAX_ATTEMPTS, AuditRetry, auditExecution } from "../../src/independent-reconciliation/auditor.js";
import { evmReader, nearReader } from "../../src/infra/clients/chains.js";
import { jobHandlers } from "../../src/workers/jobs.js";
import { type Anvil, startAnvil } from "../support/anvil.js";
import { execution, USDC_NEAR } from "../support/executions.js";
import {
  type FakeOneClick,
  type FakeServer,
  fakeNearRpc,
  fakeOneClick,
  mtTransfer,
  nearTx,
  PROVIDER_FEE_ACCOUNT,
} from "../support/fakes.js";
import { fixture } from "../support/keys.js";
import { LIVE_TREASURY, OPS_CLI_OPERATOR, type Stack, startStack } from "../support/stack.js";

const BASE = "eip155:8453";
const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const ETH_BASE = "nep141:base.omft.near";
const USDC_SOL = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";

let s: Stack;
let anvil: Anvil;
let near: FakeServer;
let oc: FakeOneClick;
let token: string;
let asset: string;
let w: Sentinel;
const nearTxs = new Map<string, unknown>();

beforeAll(async () => {
  [anvil, near, oc] = await Promise.all([startAnvil(), fakeNearRpc(nearTxs), fakeOneClick()]);
  token = await anvil.deployToken();
  asset = `nep141:base-${token}.omft.near`;
  s = await startStack({
    oneclick: oc,
    valkey: true,
    worker: {
      near: nearReader({ urls: [near.url], senderHint: "intents.near" }),
      evm: new Map([[BASE, evmReader({ urls: [anvil.url] })]]),
    },
  });
  w = (s.worker as NonNullable<Stack["worker"]>).sentinel;
  const live = { livemode: true, verification: "signature" } as const;
  await s.destination({ ...live, asset_id: asset, type: "chain_address", chain: BASE, address_norm: MERCHANT });
  await s.destination({ ...live, asset_id: ETH_BASE, type: "chain_address", chain: BASE, address_norm: MERCHANT });
  await s.destination({
    ...live,
    asset_id: USDC_NEAR,
    type: "intents_account",
    chain: "near:mainnet",
    address_norm: "merchant.near",
  });
  await s.destination({
    ...live,
    asset_id: USDC_NEAR,
    type: "chain_address",
    chain: "near:mainnet",
    address_norm: "v2.ref-finance.near",
  });
  await s.destination({
    ...live,
    asset_id: USDC_SOL,
    type: "chain_address",
    chain: SOL,
    address_norm: "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T",
  });
}, 240_000);
afterAll(async () => {
  await s?.stop();
  await Promise.all([anvil?.container.stop(), near?.stop(), oc?.stop()]);
});

/** A settled execution of the stack's account; amounts as strings. */
function settled(o: {
  asset?: string;
  chain?: string;
  recipient?: string;
  type?: "destination_chain" | "intents";
  amount: string;
  hash: string;
  tier?: "A" | "B";
  provider?: Execution["provider"];
  deposit?: Execution["deposit"];
}): Execution {
  const chain = o.chain ?? BASE;
  const recipient = o.recipient ?? MERCHANT;
  const type = o.type ?? "destination_chain";
  const x = execution({
    id: newId("ex"),
    account_id: s.account,
    settlement: {
      asset_id: o.asset ?? asset,
      chain,
      recipient,
      recipient_type: type,
      amount_base: o.amount,
      tag: "0",
      expected: o.amount,
    },
    settled_amount: o.amount,
    created_at: new Date(Date.now() - 60_000).toISOString(),
    ...(o.provider ? { provider: o.provider } : {}),
    ...(o.deposit !== undefined ? { deposit: o.deposit } : {}),
  });
  return {
    ...x,
    evidence: {
      ...(x.evidence as NonNullable<Execution["evidence"]>),
      chain: type === "intents" ? "near:mainnet" : chain,
      tx_hash: o.hash,
      recipient,
      asset_id: o.asset ?? asset,
      amount: o.amount,
      tier: o.tier ?? "A",
    },
  };
}

const findings = (id: string) =>
  s.admin.db.selectFrom("audit_findings").selectAll().where("execution_id", "=", id).orderBy("check_kind").execute();
const results = async (id: string) => Object.fromEntries((await findings(id)).map((f) => [f.check_kind, f.result]));
const reasonOf = async (id: string, kind: string) =>
  String(((await findings(id)).find((f) => f.check_kind === kind)?.details as { reason?: string })?.reason);

describe("EVM (Anvil): sentinel's own RPC", () => {
  it("passes a finalized ERC-20 transfer to the merchant and records the attribution", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 2_000_017n);
    await anvil.mine(64);
    const x = settled({ amount: "2000017", hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
    const f = (await findings(x.id)).find((r) => r.check_kind === "settlement");
    expect(f).toMatchObject({
      tx_chain: BASE,
      tx_hash: hash.toLowerCase(),
      recipient: MERCHANT,
      asset_id: asset,
      amount: "2000017",
    });
  });

  it("waits for finality (retry), then passes", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 5n);
    const x = settled({ amount: "5", hash });
    await expect(auditExecution(w, x, 1)).rejects.toThrow(AuditRetry);
    expect(await results(x.id)).toEqual({ destination: "pass" });
    await anvil.mine(64);
    await auditExecution(w, x, 2);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });

  it("mismatch when the chain shows less than rails settled (and the finding is emitted)", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 1_000n);
    await anvil.mine(64);
    const x = settled({ amount: "1001", hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "mismatch" });
    const out = await s.admin.db
      .selectFrom("outbox")
      .selectAll()
      .where("subject", "=", "evt.sentinel.audit_finding.created")
      .where("aggregate_type", "=", "audit_finding")
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    const object = AuditFinding.parse((out.payload as { data: { object: unknown } }).data.object);
    expect(object).toMatchObject({
      execution_id: x.id,
      account_id: s.account,
      check_kind: "settlement",
      result: "mismatch",
    });
    expect(out.account_id).toBe(toUuid(s.account, "acct"));
  });

  it("mismatch for a transfer of another token or to another address", async () => {
    const other = await anvil.deployToken();
    const h1 = await anvil.transfer(other, MERCHANT, 7n);
    const h2 = await anvil.transfer(token, "0x2222222222222222222222222222222222222222", 7n);
    await anvil.mine(64);
    for (const hash of [h1, h2]) {
      const x = settled({ amount: "7", hash });
      await auditExecution(w, x, 1);
      expect((await results(x.id)).settlement).toBe("mismatch");
    }
  });

  it("mismatch for a reverted transaction", async () => {
    const r = await anvil.deployReverter();
    const hash = await anvil.call(r, "0x");
    await anvil.mine(64);
    const x = settled({ amount: "1", hash });
    await auditExecution(w, x, 1);
    expect(await reasonOf(x.id, "settlement")).toMatch(/reverted/);
  });

  it("passes a native transfer (asset id: the chain's native asset)", async () => {
    const hash = await anvil.sendNative(MERCHANT, 10n ** 15n);
    await anvil.mine(64);
    const x = settled({ asset: ETH_BASE, amount: (10n ** 15n).toString(), hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });

  it("one transaction is never attributed twice", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 300n);
    await anvil.mine(64);
    const a = settled({ amount: "300", hash });
    const b = settled({ amount: "300", hash: hash.toUpperCase().replace("0X", "0x") });
    await auditExecution(w, a, 1);
    await auditExecution(w, b, 1);
    expect((await results(a.id)).settlement).toBe("pass");
    expect((await results(b.id)).settlement).toBe("mismatch");
    expect(await reasonOf(b.id, "settlement")).toMatch(/already attributed/);
  });

  it("an unknown transaction is retried, then unverifiable on the last attempt", async () => {
    const x = settled({ amount: "1", hash: `0x${"ab".repeat(32)}` });
    await expect(auditExecution(w, x, AUDIT_MAX_ATTEMPTS - 1)).rejects.toThrow(/not found/);
    await auditExecution(w, x, AUDIT_MAX_ATTEMPTS);
    expect((await results(x.id)).settlement).toBe("unverifiable");
    expect(await reasonOf(x.id, "settlement")).toMatch(new RegExp(`after ${AUDIT_MAX_ATTEMPTS} attempts`));
  });

  it("is idempotent: a second audit adds nothing", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 9n);
    await anvil.mine(64);
    const x = settled({ amount: "9", hash });
    await auditExecution(w, x, 1);
    const before = await findings(x.id);
    await auditExecution(w, x, 1);
    expect(await findings(x.id)).toEqual(before);
  });
});

describe("destination check (identity's registry view)", () => {
  it("mismatch when the recipient was never a destination of the account", async () => {
    const stranger = "0x3333333333333333333333333333333333333333";
    const hash = await anvil.transfer(token, stranger, 4n);
    await anvil.mine(64);
    const x = settled({ amount: "4", hash, recipient: stranger });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "mismatch", settlement: "pass" });
  });

  it("mismatch when the destination was disabled before the execution was created", async () => {
    const old = "0x4444444444444444444444444444444444444444";
    await s.destination({
      livemode: true,
      asset_id: asset,
      type: "chain_address",
      chain: BASE,
      address_norm: old,
      status: "disabled",
      disabled_at: new Date(Date.now() - 3_600_000),
    });
    const hash = await anvil.transfer(token, old, 4n);
    await anvil.mine(64);
    const x = settled({ amount: "4", hash, recipient: old });
    await auditExecution(w, x, 1);
    expect(await reasonOf(x.id, "destination")).toMatch(/not active/);
  });

  it("another account's destination is not this account's", async () => {
    const hash = await anvil.transfer(token, MERCHANT, 4n);
    await anvil.mine(64);
    const x = { ...settled({ amount: "4", hash }), account_id: newId("acct") };
    await auditExecution(w, x, 1);
    expect((await results(x.id)).destination).toBe("mismatch");
  });
});

describe("NEAR: Intents and NEP-141", () => {
  it("passes an Intents mt_transfer to the merchant's account", async () => {
    nearTxs.set(
      "NearHash1111111111111111111111111111111111111",
      nearTx("intents.near", [mtTransfer("merchant.near", USDC_NEAR, "2000017")]),
    );
    const x = settled({
      asset: USDC_NEAR,
      type: "intents",
      recipient: "merchant.near",
      amount: "2000017",
      hash: "NearHash1111111111111111111111111111111111111",
    });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });

  it("one Intents batch can settle two payments of a merchant — never a third", async () => {
    const hash = "NearBatch111111111111111111111111111111111111";
    nearTxs.set(
      hash,
      nearTx("intents.near", [
        mtTransfer("merchant.near", USDC_NEAR, "100"),
        mtTransfer("merchant.near", USDC_NEAR, "250"),
      ]),
    );
    const a = settled({ asset: USDC_NEAR, type: "intents", recipient: "merchant.near", amount: "100", hash });
    const b = settled({ asset: USDC_NEAR, type: "intents", recipient: "merchant.near", amount: "250", hash });
    const c = settled({ asset: USDC_NEAR, type: "intents", recipient: "merchant.near", amount: "1", hash });
    await Promise.all([auditExecution(w, a, 1), auditExecution(w, b, 1)]);
    await auditExecution(w, c, 1);
    expect([
      (await results(a.id)).settlement,
      (await results(b.id)).settlement,
      (await results(c.id)).settlement,
    ]).toEqual(["pass", "pass", "mismatch"]);
  });

  it("an mt_transfer logged by another contract does not count", async () => {
    nearTxs.set(
      "NearFake11111111111111111111111111111111111111",
      nearTx("evil.near", [mtTransfer("merchant.near", USDC_NEAR, "5")]),
    );
    const x = settled({
      asset: USDC_NEAR,
      type: "intents",
      recipient: "merchant.near",
      amount: "5",
      hash: "NearFake11111111111111111111111111111111111111",
    });
    await auditExecution(w, x, 1);
    expect((await results(x.id)).settlement).toBe("mismatch");
  });

  it("retries a transaction that is not final yet", async () => {
    nearTxs.set(
      "NearSlow11111111111111111111111111111111111111",
      nearTx("intents.near", [mtTransfer("merchant.near", USDC_NEAR, "5")], false),
    );
    const x = settled({
      asset: USDC_NEAR,
      type: "intents",
      recipient: "merchant.near",
      amount: "5",
      hash: "NearSlow11111111111111111111111111111111111111",
    });
    await expect(auditExecution(w, x, 1)).rejects.toThrow(/not final/);
  });

  it("passes a recorded NEP-141 ft_transfer on NEAR (destination_chain)", async () => {
    const hash = "AGK5b5iMegtbVeokGvUtWZ78XChEgTPbCWfcNUmGxR92";
    nearTxs.set(hash, fixture("near/tx-usdc-ft-transfer.json"));
    const x = settled({
      asset: USDC_NEAR,
      chain: "near:mainnet",
      recipient: "v2.ref-finance.near",
      amount: "232035480",
      hash,
    });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });
});

describe("refund legs (kind: refund): source and delivery to the payer", () => {
  /** An Intents refund leg: merchant.near (the account's destination) → the payer's Intents account. */
  function refundLeg(o: { source?: string; payer?: string; amount: string; hash: string }): Execution {
    const x = settled({
      asset: USDC_NEAR,
      type: "intents",
      recipient: o.payer ?? "payer.near",
      amount: o.amount,
      hash: o.hash,
    });
    return {
      ...x,
      kind: "refund",
      method: "intents_transfer",
      provider: "direct_intents",
      deposit: null,
      origin: {
        asset_id: USDC_NEAR,
        chain: "near:mainnet",
        refund_to: o.source ?? "merchant.near",
        refund_type: "intents",
      },
      refund: {
        swap_type: null,
        amount: o.amount,
        amount_out_expected: null,
        min_amount_out: null,
        token: null,
        transfer: {
          signer_id: o.source ?? "merchant.near",
          receiver_id: o.payer ?? "payer.near",
          token: USDC_NEAR,
          amount: o.amount,
          memo: "np1:4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
          deadline: new Date(Date.now() + 600_000).toISOString(),
        },
      },
    } as Execution;
  }

  it("passes a refund from the merchant's destination that reached the payer (no false destination mismatch)", async () => {
    const hash = "RefundHash111111111111111111111111111111111111";
    nearTxs.set(hash, nearTx("intents.near", [mtTransfer("payer.near", USDC_NEAR, "1500000")]));
    const x = refundLeg({ amount: "1500000", hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
    const d = (await findings(x.id)).find((f) => f.check_kind === "destination");
    expect(d?.details).toMatchObject({ side: "refund_source", source: "merchant.near" });
  });

  it("mismatch when the chain shows less reached the payer", async () => {
    const hash = "RefundHash222222222222222222222222222222222222";
    nearTxs.set(hash, nearTx("intents.near", [mtTransfer("payer.near", USDC_NEAR, "100")]));
    const x = refundLeg({ amount: "1500000", hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "mismatch" });
  });

  it("mismatch when the source is not a destination of the account", async () => {
    const hash = "RefundHash333333333333333333333333333333333333";
    nearTxs.set(hash, nearTx("intents.near", [mtTransfer("payer.near", USDC_NEAR, "1500000")]));
    const x = refundLeg({ source: "stranger.near", amount: "1500000", hash });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "mismatch", settlement: "pass" });
    expect(await reasonOf(x.id, "destination")).toMatch(/^refund source:/);
  });
});

describe("Tier B: the provider's signed status, with sentinel's own key", () => {
  const solana = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
  function tierB(status: string, swap: Record<string, unknown>, o: { hash?: string } = {}) {
    const q = oc.quote({
      request: {
        appFees: [
          { recipient: LIVE_TREASURY, fee: 25 },
          { recipient: PROVIDER_FEE_ACCOUNT, fee: 25 },
        ],
        recipient: solana,
        recipientType: "DESTINATION_CHAIN",
        destinationAsset: USDC_SOL,
      },
      status: { status, swapDetails: swap },
    });
    const deposit = {
      address: q.quote.depositAddress as string,
      memo: null,
      amount_in: q.quote.amountIn,
      min_amount_in: q.quote.minAmountIn,
      chain: BASE,
      deadline: q.quote.deadline as string,
    };
    return settled({
      asset: USDC_SOL,
      chain: SOL,
      recipient: solana,
      amount: "2000017",
      hash: o.hash ?? "SolTx1",
      tier: "B",
      deposit,
    });
  }

  it("passes when 1Click reports SUCCESS, the amount and the evidence transaction", async () => {
    const x = tierB("SUCCESS", {
      amountOut: "2000017",
      destinationChainTxHashes: [{ hash: "SolTx1", explorerUrl: "x" }],
    });
    await auditExecution(w, x, 1);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });

  it.each([
    [
      "the provider refunded",
      "REFUNDED",
      { amountOut: "2000017", destinationChainTxHashes: [{ hash: "SolTx1", explorerUrl: "x" }] },
    ],
    [
      "the provider delivered less",
      "SUCCESS",
      { amountOut: "2000016", destinationChainTxHashes: [{ hash: "SolTx1", explorerUrl: "x" }] },
    ],
    [
      "the evidence is not the provider's transaction",
      "SUCCESS",
      { amountOut: "2000017", destinationChainTxHashes: [{ hash: "Other", explorerUrl: "x" }] },
    ],
    ["no amountOut", "SUCCESS", { destinationChainTxHashes: [{ hash: "SolTx1", explorerUrl: "x" }] }],
  ])("mismatch when %s", async (_n, status, swap) => {
    const x = tierB(status, swap);
    await auditExecution(w, x, 1);
    expect((await results(x.id)).settlement).toBe("mismatch");
  });

  it("mismatch when 1Click does not know the deposit address", async () => {
    const x = tierB("SUCCESS", {});
    oc.statuses.delete(x.deposit?.address as string);
    await auditExecution(w, x, 1);
    expect(await reasonOf(x.id, "settlement")).toMatch(/does not know/);
  });

  it("retries when 1Click is unavailable", async () => {
    const x = tierB("SUCCESS", {
      amountOut: "2000017",
      destinationChainTxHashes: [{ hash: "SolTx1", explorerUrl: "x" }],
    });
    oc.failNext = 2;
    await expect(auditExecution(w, x, 1)).rejects.toThrow(AuditRetry);
  });

  it("unverifiable when there is no independent read (no deposit to look up)", async () => {
    const x = {
      ...settled({ asset: USDC_SOL, chain: SOL, recipient: solana, amount: "1", hash: "S", tier: "B" }),
      deposit: null,
    };
    await auditExecution(w, x, 1);
    expect((await results(x.id)).settlement).toBe("unverifiable");
  });
});

describe("rails' settlement must be self-consistent", () => {
  it("mismatch without a chain read when the evidence contradicts the settlement", async () => {
    const x = settled({ amount: "5", hash: "0x01" });
    await auditExecution(w, { ...x, settled_amount: "6" }, 1);
    expect(await reasonOf(x.id, "settlement")).toMatch(/settled 6 != evidence 5/);
  });
});

describe("sampling", () => {
  it("below rate 1, only the draw or a large/unknown value is audited", async () => {
    const sampled = jobHandlers({ ...w, auditSampleRate: 0.05, random: () => 0.99 });
    const run = (x: Execution) =>
      sampled["audit.execution"]?.(
        { execution: x },
        { id: "j", kind: "audit.execution", attempt: 1, extendLease: async () => {} },
      );
    const hash = await anvil.transfer(token, MERCHANT, 10_000_000_000n);
    await anvil.mine(64);
    const small = settled({ amount: "1000", hash: `0x${"cd".repeat(32)}` });
    await run(small);
    expect(await findings(small.id)).toEqual([]);
    const large = settled({ amount: "10000000000", hash }); // USD 10,000 at 6 decimals and price 1
    await run(large);
    expect(await results(large.id)).toEqual({ destination: "pass", settlement: "pass" });
    const unpriced = { ...settled({ amount: "1", hash: `0x${"ce".repeat(32)}` }), price_snapshot: null };
    s.rails.reset(); // rails unreachable: the value is unknown → audited
    try {
      await expect(run(unpriced)).rejects.toThrow(AuditRetry);
    } finally {
      s.mockRails();
    }
  });

  it("refuses a job payload that is not an execution", async () => {
    const h = jobHandlers(w);
    await expect(
      h["audit.execution"]?.(
        { execution: { id: "x" } },
        { id: "j", kind: "audit.execution", attempt: 1, extendLease: async () => {} },
      ),
    ).rejects.toThrow(/not an execution/);
  });
});

describe("worker end to end (NATS)", () => {
  it("settled → audit job → findings; a mismatch is published as evt.sentinel.audit_finding.created", async () => {
    const probe = await s.probe("evt.sentinel.audit_finding.created");
    const hash = await anvil.transfer(token, MERCHANT, 77n);
    await anvil.mine(64);
    const good = settled({ amount: "77", hash });
    const bad = settled({ amount: "78", hash: await anvil.transfer(token, MERCHANT, 1n) });
    await anvil.mine(64);
    for (const x of [good, bad])
      await s.publishEvent(
        domainEvent("evt.rails.execution.settled", x, {
          version: x.version,
          accountUuid: toUuid(s.account, "acct"),
          livemode: true,
        }) as never,
      );
    const e = await probe.next(
      "evt.sentinel.audit_finding.created",
      (m) => (m.data.object as { execution_id: string }).execution_id === bad.id,
      30_000,
    );
    expect(AuditFinding.parse(e.data.object)).toMatchObject({ result: "mismatch", check_kind: "settlement" });
    for (let i = 0; i < 100 && (await findings(good.id)).length < 2; i++) await new Promise((r) => setTimeout(r, 100));
    expect(await results(good.id)).toEqual({ destination: "pass", settlement: "pass" });
    await probe.close();
  });

  it("destination disabled → cached attestations for it are evicted from Valkey", async () => {
    const d = await s.destination({
      livemode: true,
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: "evict.near",
    });
    const q = oc.quote({
      request: {
        appFees: [
          { recipient: LIVE_TREASURY, fee: 25 },
          { recipient: PROVIDER_FEE_ACCOUNT, fee: 25 },
        ],
        recipient: "evict.near",
      },
    });
    const attempt = newId("pa");
    const key = routeQuoteDepositKey("oneclick", q.quote.depositAddress as string, null);
    const r = await s.call("POST", "/v1/attestations/deposit_instructions", {
      body: {
        livemode: true,
        kind: "route_quote",
        attempt_id: attempt,
        attestation_ticket: s.ticket(attempt, true, key),
        deposit: {
          address: q.quote.depositAddress,
          memo: null,
          chain: BASE,
          origin_asset_id: "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
          amount_in: q.quote.amountIn,
          deadline: q.quote.deadline,
        },
      },
    });
    expect(r.status).toBe(200);
    const redis = new Redis((s.valkey as NonNullable<Stack["valkey"]>).url);
    try {
      expect(await redis.get(`att:${key}`)).not.toBeNull();
      const object = internalSettlementDestination({
        id: fromUuid("sd", d),
        account: s.account,
        livemode: true,
        status: "disabled",
      });
      await s.publishEvent(
        domainEvent("evt.identity.settlement_destination.disabled", object, {
          version: 3,
          accountUuid: toUuid(s.account, "acct"),
          livemode: true,
        }) as never,
      );
      for (let i = 0; i < 100 && (await redis.get(`att:${key}`)) !== null; i++)
        await new Promise((res) => setTimeout(res, 100));
      expect(await redis.get(`att:${key}`)).toBeNull();
    } finally {
      redis.disconnect();
    }
  });

  it("the relay publishes kill-switch changes (rails stops live quotes on engaged)", async () => {
    const probe = await s.probe("evt.sentinel.kill_switch.>");
    const token = await s.opsToken();
    await s.call("POST", "/internal/kill-switch", { token, body: { engaged: true, reason: "e2e" } });
    const on = await probe.next("evt.sentinel.kill_switch.engaged", () => true, 15_000);
    expect(KillSwitchEvent.parse(on.data.object)).toEqual({
      engaged: true,
      reason: "e2e",
      actor: `ops:${OPS_CLI_OPERATOR}`,
    });
    await s.call("POST", "/internal/kill-switch", { token, body: { engaged: false, reason: "e2e over" } });
    const off = await probe.next("evt.sentinel.kill_switch.released", () => true, 15_000);
    expect(off.aggregate.version).toBe(on.aggregate.version + 1);
    expect(off.aggregate.id).toBe(on.aggregate.id);
    await probe.close();
  });

  it("the relay publishes the console's release request and operator actions (notify, identity)", async () => {
    const probe = await s.probe("evt.sentinel.>");
    const op = await s.operatorToken({ sub: newId("usr"), role: "ops" });
    await s.call("POST", "/ops/kill_switch/engage", { token: op, body: { reason: "e2e console" } });
    const req = await s.call("POST", "/ops/kill_switch/release_requests", { token: op, body: { reason: "fixed" } });
    expect(req.status).toBe(201);
    const requested = await probe.next("evt.sentinel.kill_switch.release_requested", () => true, 15_000);
    expect(OpsApproval.parse(requested.data.object)).toMatchObject({
      id: (req.body as { id: string }).id,
      status: "pending",
    });
    const action = await probe.next(
      "evt.sentinel.ops_action.recorded",
      (e) => (e.data.object as { action?: string }).action === "kill_switch.release_requested",
      15_000,
    );
    expect(OpsActionEvent.parse(action.data.object)).toMatchObject({ approval: (req.body as { id: string }).id });
    await probe.close();
  });
});
