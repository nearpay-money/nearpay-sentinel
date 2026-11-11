/**
 * Test mode end to end against the real nearpay-sandbox image (§5, §7): a sandbox quote is co-signed
 * with the sandbox's own signing key and deposit key `sandbox|…`; after the simulated deposit settles,
 * the auditor verifies the simulated destination chain; an Intents-transfer requirement is co-signed for
 * the test treasury.
 */

import { newId } from "@nearpay-internal/ids";
import { type Execution, OneClickQuoteResponse, OneClickStatusResponse } from "@nearpay-internal/spec";
import { routeQuoteDepositKey, SignedAttestation } from "@nearpay-money/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { verifyAttestation } from "../../src/co-signer/crypto.js";
import { AuditRetry, auditExecution } from "../../src/independent-reconciliation/auditor.js";
import { execution } from "../support/executions.js";
import { type Stack, startStack, TREASURY } from "../support/stack.js";

const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const USDC_ARB = "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near";
const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const PAYER = "0x52908400098527886e0f7030069857d2e4169ee7";
const MERCHANT = "0x9999999999999999999999999999999999999999";
const PATH = "/v1/attestations/deposit_instructions";

let s: Stack;
beforeAll(async () => {
  s = await startStack({ sandbox: true, worker: true });
  await s.destination({ asset_id: USDC_ARB, type: "chain_address", chain: "eip155:42161", address_norm: MERCHANT });
  await s.destination({
    asset_id: USDC_NEAR,
    type: "intents_account",
    chain: "near:mainnet",
    address_norm: "merchant.near",
  });
}, 240_000);
afterAll(async () => {
  await s?.stop();
});

async function sandboxQuote(
  o: { recipient?: string; recipientType?: string; destinationAsset?: string; quoteWaitingTimeMs?: number } = {},
) {
  const deadline = new Date(Date.now() + 30 * 60_000);
  deadline.setUTCMilliseconds(0);
  const r = await s.sandbox?.call("POST", "/v0/quote", {
    dry: false,
    swapType: "EXACT_OUTPUT",
    slippageTolerance: 50,
    originAsset: USDC_BASE,
    depositType: "ORIGIN_CHAIN",
    destinationAsset: o.destinationAsset ?? USDC_ARB,
    amount: "2000000",
    refundTo: PAYER,
    refundType: "ORIGIN_CHAIN",
    recipient: o.recipient ?? MERCHANT,
    recipientType: o.recipientType ?? "DESTINATION_CHAIN",
    deadline: deadline.toISOString(),
    referral: "nearpay",
    appFees: [{ recipient: TREASURY, fee: 50 }],
    quoteWaitingTimeMs: o.quoteWaitingTimeMs ?? 3000, // as rails quotes
  });
  expect(r?.status).toBe(200);
  return OneClickQuoteResponse.parse(r?.body);
}

function body(q: OneClickQuoteResponse) {
  const attempt = newId("pa");
  const address = q.quote.depositAddress as string;
  return {
    livemode: false,
    kind: "route_quote" as const,
    attempt_id: attempt,
    attestation_ticket: s.ticket(attempt, false, routeQuoteDepositKey("sandbox", address, q.quote.depositMemo ?? null)),
    deposit: {
      address,
      memo: q.quote.depositMemo ?? null,
      chain: "eip155:8453",
      origin_asset_id: USDC_BASE,
      amount_in: q.quote.amountIn,
      // the payer-facing deadline is the requested one (refunds begin), not quote.deadline (address inactive)
      deadline: q.quoteRequest.deadline,
    },
  };
}

async function settle(q: OneClickQuoteResponse) {
  const address = q.quote.depositAddress as string;
  expect((await s.sandbox?.call("POST", "/sim/deposits", { deposit_address: address }))?.status).toBe(202);
  for (let i = 0; i < 300; i++) {
    const r = await s.sandbox?.call("GET", `/v0/status?depositAddress=${address}`);
    const st = OneClickStatusResponse.parse(r?.body);
    if (st.status === "SUCCESS" && st.swapDetails.destinationChainTxHashes.length) return st;
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error("sandbox execution did not settle");
}

function settledExecution(
  q: OneClickQuoteResponse,
  st: OneClickStatusResponse,
  o: { intents?: boolean } = {},
): Execution {
  const chain = o.intents ? "near:mainnet" : "eip155:42161";
  const recipient = q.quoteRequest.recipient;
  const amount = st.swapDetails.amountOut as string;
  const x = execution({
    id: newId("ex"),
    account_id: s.account,
    livemode: false,
    provider: "sandbox",
    settlement: {
      asset_id: q.quoteRequest.destinationAsset,
      chain,
      recipient,
      recipient_type: o.intents ? "intents" : "destination_chain",
      expected: amount,
    },
    settled_amount: amount,
    created_at: new Date(Date.now() - 60_000).toISOString(),
  });
  return {
    ...x,
    evidence: {
      ...(x.evidence as NonNullable<Execution["evidence"]>),
      chain,
      tx_hash: st.swapDetails.destinationChainTxHashes[0]?.hash as string,
      recipient,
      asset_id: q.quoteRequest.destinationAsset,
      amount,
    },
  };
}

/** Audits like the job does: transient results (simulated tx not final yet) are retried. */
async function audited(w: Sentinel, x: Execution): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await auditExecution(w, x, attempt);
    } catch (e) {
      if (!(e instanceof AuditRetry) || attempt >= 50) throw e;
      await new Promise((res) => setTimeout(res, 100));
    }
  }
}

const results = async (id: string) =>
  Object.fromEntries(
    (await s.admin.db.selectFrom("audit_findings").selectAll().where("execution_id", "=", id).execute()).map((f) => [
      f.check_kind,
      f.result,
    ]),
  );

describe("test mode against the sandbox", () => {
  it("co-signs a sandbox quote (sandbox signing key, `sandbox|` deposit key) and audits its simulated settlement", async () => {
    const q = await sandboxQuote();
    // the sandbox mirrors live 1Click: the address stays active 3 days past the requested deadline, and the
    // status echo omits the signed quoteWaitingTimeMs (R2 puts rails' value back)
    expect(Date.parse(q.quote.deadline as string) - Date.parse(q.quoteRequest.deadline)).toBe(3 * 86_400_000);
    const echo = await s.sandbox?.call("GET", `/v0/status?depositAddress=${q.quote.depositAddress}`);
    expect(OneClickStatusResponse.parse(echo?.body).quoteResponse.quoteRequest).not.toHaveProperty(
      "quoteWaitingTimeMs",
    );
    const r = await s.call("POST", PATH, { body: body(q) });
    expect(r.status).toBe(200);
    const signed = SignedAttestation.parse(r.body);
    expect(verifyAttestation(signed, s.signingPublicRaw)).toBe(true);
    expect(signed.attestation).toMatchObject({
      livemode: false,
      destination: { asset_id: USDC_ARB, chain: "eip155:42161" },
      // display data from the sandbox's token registry, consistent with its signed amountInFormatted
      asset: {
        asset_id: USDC_BASE,
        symbol: "USDC",
        decimals: 6,
        token: { standard: "erc20", address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" },
      },
      expires_at: q.quoteRequest.deadline,
    });

    const st = await settle(q);
    // a settled deposit is no longer attested (R7)
    const again = await s.call("POST", PATH, { body: body(q) });
    expect(again.body).toMatchObject({ error: { code: "attestation_stale" } });

    const x = settledExecution(q, st);
    const w = (s.worker as NonNullable<Stack["worker"]>).sentinel;
    await audited(w, x);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });

    // the same simulated transaction cannot settle a second execution
    const twin = { ...x, id: newId("ex") };
    await auditExecution(w, twin, 1);
    expect((await results(twin.id)).settlement).toBe("mismatch");
  });

  it("audits an Intents settlement in test mode", async () => {
    const q = await sandboxQuote({ recipient: "merchant.near", recipientType: "INTENTS", destinationAsset: USDC_NEAR });
    expect((await s.call("POST", PATH, { body: body(q) })).status).toBe(200);
    const st = await settle(q);
    const x = settledExecution(q, st, { intents: true });
    const w = (s.worker as NonNullable<Stack["worker"]>).sentinel;
    await audited(w, x);
    expect(await results(x.id)).toEqual({ destination: "pass", settlement: "pass" });
  });

  it("refuses a sandbox quote signed with a waiting time other than rails' (R2)", async () => {
    const q = await sandboxQuote({ quoteWaitingTimeMs: 1000 });
    const res = await s.call("POST", PATH, { body: body(q) });
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ error: { code: "attestation_refused" } });
  });

  it("refuses a sandbox quote whose fee does not pay the test treasury", async () => {
    const deadline = new Date(Date.now() + 30 * 60_000);
    deadline.setUTCMilliseconds(0);
    const r = await s.sandbox?.call("POST", "/v0/quote", {
      dry: false,
      swapType: "EXACT_OUTPUT",
      slippageTolerance: 50,
      originAsset: USDC_BASE,
      depositType: "ORIGIN_CHAIN",
      destinationAsset: USDC_ARB,
      amount: "2000000",
      refundTo: PAYER,
      refundType: "ORIGIN_CHAIN",
      recipient: MERCHANT,
      recipientType: "DESTINATION_CHAIN",
      deadline: deadline.toISOString(),
      referral: "nearpay",
      appFees: [{ recipient: "attacker.near", fee: 50 }],
    });
    const q = OneClickQuoteResponse.parse(r?.body);
    const res = await s.call("POST", PATH, { body: body(q) });
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ error: { code: "attestation_refused" } });
  });

  it("co-signs an Intents-transfer requirement for the test treasury", async () => {
    const attempt = newId("pa");
    const deadline = new Date(Date.now() + 120_000);
    deadline.setUTCMilliseconds(0);
    const requirement = {
      pay_to: "merchant.near",
      token: USDC_NEAR,
      amount: "2000000",
      fee_to: TREASURY,
      fee_amount: "6000",
      binding: "np1:AQDxa2L6a5d8egVC7YP85UgtUCYp3cUotS6S3EsGcF7h",
      deadline: deadline.toISOString(),
    };
    const r = await s.call("POST", PATH, {
      body: {
        livemode: false,
        kind: "intents_transfer",
        attempt_id: attempt,
        attestation_ticket: s.ticket(attempt, false, requirement.binding),
        requirement,
      },
    });
    expect(r.status).toBe(200);
    const signed = SignedAttestation.parse(r.body);
    expect(signed.attestation).toMatchObject({
      kind: "intents_transfer",
      requirement,
      asset: { asset_id: requirement.token, decimals: 6 },
      expires_at: requirement.deadline,
    });
    expect(signed.attestation.deposit).toBeUndefined();
    expect(verifyAttestation(signed, s.signingPublicRaw)).toBe(true);
    // a fee to anyone but the treasury is refused
    const bad = newId("pa");
    const refused = await s.call("POST", PATH, {
      body: {
        livemode: false,
        kind: "intents_transfer",
        attempt_id: bad,
        attestation_ticket: s.ticket(bad, false, requirement.binding),
        requirement: { ...requirement, fee_to: "attacker.near" },
      },
    });
    expect(refused.status).toBe(409);
  });
});
