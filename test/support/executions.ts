/** A settled execution as rails emits it (`evt.rails.execution.settled`), for audit tests. */
import type { Execution } from "@nearpay-internal/spec";

export const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
export const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";

export function execution(
  o: Omit<Partial<Execution>, "settlement"> & { settlement?: Partial<Execution["settlement"]> } = {},
): Execution {
  const { settlement, ...rest } = o;
  const s = {
    asset_id: USDC_BASE,
    amount_base: "2000000",
    tag: "17",
    expected: "2000017",
    recipient: "0x1111111111111111111111111111111111111111",
    recipient_type: "destination_chain" as const,
    chain: "eip155:8453",
    ...settlement,
  };
  return {
    id: "ex_01jbz9k3m4n5p6q7r8s9t0v1w2",
    version: 5,
    account_id: "acct_01jbz9k3m4n5p6q7r8s9t0v1w2",
    livemode: true,
    kind: "payment",
    method: "route_quote",
    provider: "oneclick",
    state: "succeeded",
    provider_status: "SUCCESS",
    route_class: "stable_pair",
    applied_fee_bps: 50,
    origin: { asset_id: USDC_NEAR, chain: "near:mainnet", refund_to: "payer.near", refund_type: "origin_chain" },
    settlement: s,
    price_snapshot: {
      primary_usd: "1.0001",
      secondary_usd: "1",
      fx: null,
      par: true,
      as_of: "2026-11-05T10:00:00.000Z",
    },
    deposit: {
      address: "0x76b4c56085ed136a8744d52be956396624a730e8",
      memo: null,
      amount_in: "2010000",
      min_amount_in: "2000017",
      chain: "near:mainnet",
      deadline: "2026-11-05T10:15:00.000Z",
    },
    intents_requirement: null,
    deposit_tx_hashes: [],
    settled_amount: s.expected,
    refunded_amount: null,
    refund_reason: null,
    evidence: {
      chain: s.recipient_type === "intents" ? "near:mainnet" : s.chain,
      tx_hash: "0xabc",
      block_ref: "1",
      recipient: s.recipient,
      asset_id: s.asset_id,
      amount: s.expected,
      finality: "finalized",
      tier: "A",
      source: "watcher",
      observed_at: "2026-11-05T10:05:00.000Z",
      explorer_url: null,
    },
    failure_code: null,
    held_reason: null,
    deadline: "2026-11-05T10:15:00.000Z",
    terminal_at: "2026-11-05T10:05:00.000Z",
    created_at: "2026-11-05T10:00:00.000Z",
    updated_at: "2026-11-05T10:05:00.000Z",
    ...rest,
  } as Execution;
}
