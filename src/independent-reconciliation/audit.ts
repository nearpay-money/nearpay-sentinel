/**
 * Independent re-verification rules (lld/sentinel.md §7, ADR-0012), pure. Sentinel does not trust
 * rails' evidence: it re-reads the settlement with its own RPC credentials (or the sandbox's simulated
 * chains in test mode, or the provider's signed status for Tier B), derives the token contract from the
 * NEAR Intents asset id itself, and records a finding — `pass`, `mismatch` (page) or `unverifiable`.
 */
import { normalizeAddress } from "@nearpay-internal/chains";
import { parseEventLogs } from "@nearpay-internal/intents";
import type { Execution } from "@nearpay-internal/spec";
import { assetChain, NEAR } from "../address-integrity/assets.js";

export type AuditResult = "pass" | "mismatch" | "unverifiable";

/** How a transfer was observed: Intents `mt_transfer`, NEP-141 `ft_transfer`, an EVM read, or the sandbox. */
export type Via = "intents" | "ft" | "evm" | "sim";

export interface Observed {
  readonly via: Via;
  readonly to: string;
  readonly assetId: string;
  readonly amount: bigint;
}

/** Sum of what reached `recipient` in `assetId` through `via`. */
export function received(transfers: readonly Observed[], via: Via, recipient: string, assetId: string): bigint {
  return transfers
    .filter((t) => t.via === via && t.to === recipient && t.assetId === assetId)
    .reduce((s, t) => s + t.amount, 0n);
}

const AMOUNT = /^\d+$/;

/** Transfers in a NEAR transaction's successful receipts (Intents `mt_transfer`, NEP-141 `ft_transfer`). */
export function nearTransfers(
  receipts: readonly { executor: string; logs: readonly string[]; success: boolean }[],
  intentsContract: string,
): Observed[] {
  const out: Observed[] = [];
  for (const r of receipts) {
    if (!r.success) continue;
    for (const e of parseEventLogs(r.logs)) {
      if (!Array.isArray(e.data)) continue;
      if (r.executor === intentsContract && e.standard === "nep245" && e.event === "mt_transfer") {
        for (const d of e.data as { new_owner_id?: unknown; token_ids?: unknown; amounts?: unknown }[]) {
          if (typeof d.new_owner_id !== "string" || !Array.isArray(d.token_ids) || !Array.isArray(d.amounts)) continue;
          if (d.token_ids.length !== d.amounts.length) continue;
          d.token_ids.forEach((id, k) => {
            const a = (d.amounts as unknown[])[k];
            if (typeof id === "string" && typeof a === "string" && AMOUNT.test(a))
              out.push({
                via: "intents",
                to: (d.new_owner_id as string).toLowerCase(),
                assetId: id,
                amount: BigInt(a),
              });
          });
        }
      }
      if (e.standard === "nep141" && e.event === "ft_transfer") {
        for (const d of e.data as { new_owner_id?: unknown; amount?: unknown }[]) {
          if (typeof d.new_owner_id === "string" && typeof d.amount === "string" && AMOUNT.test(d.amount))
            out.push({
              via: "ft",
              to: d.new_owner_id.toLowerCase(),
              assetId: `nep141:${r.executor}`,
              amount: BigInt(d.amount),
            });
        }
      }
    }
  }
  return out;
}

/** The recipient as sentinel compares it: lower-case Intents account, or the chain's normal form. */
export function normalRecipient(x: Pick<Execution, "settlement">): string | null {
  const s = x.settlement;
  if (s.recipient_type === "intents") return s.recipient.toLowerCase();
  try {
    return normalizeAddress(s.chain, s.recipient);
  } catch {
    return null;
  }
}

/** The chain the settlement transaction lives on: Intents settlements happen on NEAR. */
export function settlementChain(x: Pick<Execution, "settlement">): string {
  return x.settlement.recipient_type === "intents" ? NEAR : x.settlement.chain;
}

/**
 * Rails' settlement must be self-consistent before any chain read: the execution succeeded, carries
 * evidence for the merchant's recipient and asset on the settlement chain, and settled exactly the
 * evidenced amount. Returns the reasons it is not (empty = consistent).
 */
export function consistencyFailures(x: Execution): string[] {
  const out: string[] = [];
  if (x.state !== "succeeded") out.push(`state is ${x.state}, not succeeded`);
  const e = x.evidence;
  if (!e) return [...out, "settled without evidence"];
  const recipient = normalRecipient(x);
  if (recipient === null) out.push("settlement recipient is not a valid address for its chain");
  let evidenced: string | null;
  try {
    evidenced =
      x.settlement.recipient_type === "intents" ? e.recipient.toLowerCase() : normalizeAddress(e.chain, e.recipient);
  } catch {
    evidenced = null;
  }
  if (recipient !== null && evidenced !== recipient) out.push("evidence recipient is not the settlement recipient");
  if (e.asset_id !== x.settlement.asset_id) out.push("evidence asset is not the settlement asset");
  if (e.chain !== settlementChain(x)) out.push(`evidence chain ${e.chain} is not ${settlementChain(x)}`);
  const lives = assetChain(x.settlement.asset_id);
  if (x.settlement.recipient_type === "destination_chain" && lives !== null && lives !== x.settlement.chain)
    out.push(`asset ${x.settlement.asset_id} does not live on ${x.settlement.chain}`);
  if (x.settled_amount === null) out.push("no settled amount");
  else if (x.settled_amount !== e.amount) out.push(`settled ${x.settled_amount} != evidence ${e.amount}`);
  return out;
}

/**
 * A transaction can never be attributed to more than it moved: `observed` (what the chain shows for
 * the recipient and asset) must cover this settlement plus what earlier passing audits already
 * attributed to the same transaction (one Intents batch can settle several payments of a merchant).
 */
export function attribute(
  observed: bigint,
  settled: bigint,
  others: bigint,
): { result: "pass" | "mismatch"; reason: string } {
  if (settled <= 0n) return { result: "mismatch", reason: "settled amount is not positive" };
  if (observed < settled) return { result: "mismatch", reason: `chain shows ${observed} < settled ${settled}` };
  if (observed < settled + others)
    return {
      result: "mismatch",
      reason: `chain shows ${observed}, settled ${settled} and ${others} already attributed to other executions`,
    };
  return { result: "pass", reason: "chain shows the settled amount" };
}

export interface RegistryEntry {
  readonly type: string;
  readonly chain: string;
  readonly address_norm: string;
  readonly active_at: Date | null;
  readonly disabled_at: Date | null;
}

/** Clock skew tolerated between identity's and rails' clocks. */
export const SKEW_MS = 5 * 60_000;

/**
 * The recipient was a registered destination of the account, active when the execution was created
 * (identity rows for the account, mode and settlement asset).
 */
export function destinationVerdict(
  x: Pick<Execution, "settlement" | "created_at">,
  rows: readonly RegistryEntry[],
): { result: "pass" | "mismatch"; reason: string } {
  const recipient = normalRecipient(x);
  if (recipient === null) return { result: "mismatch", reason: "settlement recipient is not a valid address" };
  const type = x.settlement.recipient_type === "intents" ? "intents_account" : "chain_address";
  const hits = rows.filter(
    (r) =>
      r.type === type &&
      (type === "intents_account"
        ? r.address_norm.toLowerCase() === recipient
        : r.chain === x.settlement.chain && r.address_norm === recipient),
  );
  if (hits.length === 0) return { result: "mismatch", reason: "recipient is not a destination of the account" };
  const created = Date.parse(x.created_at);
  const active = hits.some(
    (r) =>
      r.active_at !== null &&
      r.active_at.getTime() <= created + SKEW_MS &&
      (r.disabled_at === null || r.disabled_at.getTime() >= created - SKEW_MS),
  );
  if (!active) return { result: "mismatch", reason: "destination was not active when the execution was created" };
  return { result: "pass", reason: "recipient is an active destination of the account" };
}
