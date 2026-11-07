/**
 * Co-signing rules (lld/sentinel.md §5), pure. Sentinel trusts only the provider's signed status
 * response and identity's destination registry; the request is only what checkout wants signed.
 *
 * R6 amended (step 1.2, recorded 1Click quote 2026-11-05): 1Click echoes `appFees` split 50/50 with its
 * own fee account and does not sign them. The fee is accepted when the entries total at most 500 bps,
 * exactly one entry pays the treasury, at most one other (the provider) exists, and the treasury keeps
 * at least `total − max(ceil(total × share), floor)`. Sentinel does not know the route class, so it
 * uses the larger floor: it never refuses a genuine quote, and rails already checks the exact share
 * for the route class before it stores the quote. A fee-free quote (fee schedule at 0 bps) carries no
 * `appFees` and diverts nothing, so it passes.
 */
import { normalizeAddress } from "@nearpay-internal/chains";
import type { OneClickStatusQuoteResponse } from "@nearpay-internal/spec";
import { assetChain, NEAR } from "./assets.js";

export type FailureClass = "security" | "ambiguous" | "stale" | "unavailable";

export interface CheckFailure {
  readonly class: FailureClass;
  readonly reasons: readonly string[];
}

export interface ProviderSplit {
  readonly shareBps: number;
  readonly floorBps: number;
  readonly stableFloorBps: number;
}

export interface RegistryRow {
  readonly id: string;
  readonly account_id: string;
  readonly livemode: boolean;
  readonly asset_id: string;
  readonly type: string;
  readonly chain: string;
  readonly address_norm: string;
  readonly status: string;
  readonly merchant_name: string;
  readonly kyb_verified: boolean;
  readonly verification: string;
}

export interface Deposit {
  readonly address: string;
  readonly memo: string | null;
  readonly chain: string;
  readonly origin_asset_id: string;
  readonly amount_in: string;
  readonly deadline: string;
}

const OPEN = new Set(["PENDING_DEPOSIT", "KNOWN_DEPOSIT_TX", "INCOMPLETE_DEPOSIT", "PROCESSING"]);

/** R6: the treasury's appFee, split-aware (see module doc). */
export function appFeesFailures(
  fees: readonly { recipient: string; fee: number }[] | null | undefined,
  treasury: string,
  split: ProviderSplit,
): string[] {
  const list = fees ?? [];
  if (list.length === 0) return [];
  const total = list.reduce((s, f) => s + f.fee, 0);
  const ours = list.filter((f) => f.recipient === treasury);
  const out: string[] = [];
  if (total > 500) out.push(`appFees total ${total} bps > 500`);
  if (ours.length !== 1) {
    out.push(`appFees pay the treasury ${ours.length} times`);
    return out;
  }
  if (list.length > 2) out.push(`appFees has ${list.length} entries`);
  if (list.some((f) => !Number.isInteger(f.fee) || f.fee < 0)) out.push("appFees has a non-integer or negative fee");
  // the provider keeps at most its share (rounded up) or its floor, whichever is larger
  const floor = Math.max(split.floorBps, split.stableFloorBps);
  const providerTake = Math.max(Math.ceil((total * split.shareBps) / 10_000), floor);
  if ((ours[0]?.fee ?? 0) < total - providerTake)
    out.push(`treasury appFee ${ours[0]?.fee} bps of ${total} is below its share`);
  return out;
}

/**
 * R5: the registry rows the quote's recipient resolves to (`rows`: identity's view for the mode and
 * asset — active destinations and once-active disabled ones). A recipient that only matches a
 * destination the merchant (or compliance) has since disabled is `stale`, not `security`: disabling a
 * destination while a checkout is open must never engage the global kill switch (§5: no input an
 * account controls can), and the address is refused either way.
 */
export function matchRegistry(
  rows: readonly RegistryRow[],
  q: { recipient: string; recipientType: string; destinationAsset: string; livemode: boolean },
): { ok: true; row: RegistryRow } | { ok: false; class: "security" | "ambiguous" | "stale"; reason: string } {
  const type = q.recipientType === "INTENTS" ? "intents_account" : "chain_address";
  const matches = rows.filter((r) => {
    if (r.livemode !== q.livemode || r.type !== type || r.asset_id !== q.destinationAsset) return false;
    if (type === "intents_account") return r.address_norm === q.recipient.toLowerCase();
    try {
      return normalizeAddress(r.chain, q.recipient) === r.address_norm;
    } catch {
      return false;
    }
  });
  const hits = matches.filter((r) => r.status === "active");
  if (hits.length === 1) return { ok: true, row: hits[0] as RegistryRow };
  if (hits.length === 0) {
    if (matches.some((r) => r.status === "disabled"))
      return { ok: false, class: "stale", reason: "the destination has been disabled" };
    return { ok: false, class: "security", reason: "recipient is not an active NearPay destination" };
  }
  const verified = hits.filter((h) => h.verification === "signature");
  if (verified.length === 1) return { ok: true, row: verified[0] as RegistryRow };
  return { ok: false, class: "ambiguous", reason: `${hits.length} destinations match the recipient` };
}

export interface RouteQuoteInput {
  readonly livemode: boolean;
  readonly deposit: Deposit;
  readonly status: { status: string; quoteResponse: OneClickStatusQuoteResponse };
  readonly signatureValid: boolean;
  readonly registry: readonly RegistryRow[];
  readonly treasury: string | null;
  readonly referral: string;
  readonly split: ProviderSplit;
  readonly nowMs: number;
}

/** R2–R7 on a provider status response (R1 — the lookup itself — happens before). */
export function checkRouteQuote(i: RouteQuoteInput): { ok: true; row: RegistryRow } | ({ ok: false } & CheckFailure) {
  const q = i.status.quoteResponse;
  const security: string[] = [];
  if (!i.signatureValid) security.push("R2 provider signature does not verify");
  if (q.quoteRequest.referral !== i.referral) security.push("R3 referral is not NearPay's");
  if (q.quote.depositAddress !== i.deposit.address) security.push("R4 deposit address differs");
  if ((q.quote.depositMemo ?? null) !== i.deposit.memo) security.push("R4 deposit memo differs");
  if (q.quoteRequest.originAsset !== i.deposit.origin_asset_id) security.push("R4 origin asset differs");
  if (q.quote.amountIn !== i.deposit.amount_in) security.push("R4 amount differs");
  // the chain checkout names must be the one the deposit address lives on (an EVM address is valid on
  // every EVM chain, so a wrong chain would send funds where nobody watches): Intents deposits are on
  // NEAR; otherwise the origin asset's own chain, whenever its id says so
  const depositChain = q.quoteRequest.depositType === "INTENTS" ? NEAR : assetChain(q.quoteRequest.originAsset);
  if (depositChain !== null && i.deposit.chain !== depositChain) security.push("R4 deposit chain differs");
  // The payer-facing deadline is when 1Click starts refunding: quoteRequest.deadline. It is NOT covered by the
  // quote signature (the SDK hashes {...request, ...quote}, so quote.deadline overwrites it); it is trusted
  // because sentinel reads it from 1Click itself over TLS (R1), never from rails or checkout. Live 1Click's
  // quote.deadline is when the deposit address goes inactive (3 days later on mainnet, 2026-11-07; the sandbox
  // sets both equal), so it must not end before refunds begin.
  const qd = Date.parse(q.quoteRequest.deadline);
  if (!Number.isFinite(qd) || qd !== Date.parse(i.deposit.deadline)) security.push("R4 deadline differs");
  const inactive = q.quote.deadline ? Date.parse(q.quote.deadline) : Number.NaN;
  if (!Number.isFinite(inactive) || inactive < qd)
    security.push("R4 deposit address goes inactive before the deadline");
  if (!i.treasury) security.push("R6 no treasury configured for this mode");
  else security.push(...appFeesFailures(q.quoteRequest.appFees, i.treasury, i.split).map((r) => `R6 ${r}`));
  const match = matchRegistry(i.registry, {
    recipient: q.quoteRequest.recipient,
    recipientType: q.quoteRequest.recipientType,
    destinationAsset: q.quoteRequest.destinationAsset,
    livemode: i.livemode,
  });
  if (!match.ok && match.class === "security") security.push(`R5 ${match.reason}`);
  if (security.length) return { ok: false, class: "security", reasons: security };
  if (!match.ok) return { ok: false, class: match.class, reasons: [`R5 ${match.reason}`] };
  if (!OPEN.has(i.status.status)) return { ok: false, class: "stale", reasons: [`R7 status ${i.status.status}`] };
  if (qd <= i.nowMs + 60_000) return { ok: false, class: "stale", reasons: ["R7 deadline within 60 s"] };
  return { ok: true, row: match.row };
}

export interface Requirement {
  readonly pay_to: string;
  readonly token: string;
  readonly amount: string;
  readonly fee_to: string;
  readonly fee_amount: string;
  readonly binding: string;
  readonly deadline: string;
}

const BINDING = /^np1:[1-9A-HJ-NP-Za-km-z]{43,44}$/;

/** `intents_transfer` checks (§5). */
export function checkIntents(i: {
  livemode: boolean;
  requirement: Requirement;
  registry: readonly RegistryRow[];
  treasury: string | null;
  nowMs: number;
}): { ok: true; row: RegistryRow } | ({ ok: false } & CheckFailure) {
  const r = i.requirement;
  const security: string[] = [];
  if (!i.treasury || r.fee_to !== i.treasury) security.push("fee recipient is not the treasury");
  const amount = /^\d+$/.test(r.amount) ? BigInt(r.amount) : -1n;
  const fee = /^\d+$/.test(r.fee_amount) ? BigInt(r.fee_amount) : -1n;
  if (amount <= 0n) security.push("amount is not positive");
  if (fee < 0n || fee > (amount * 500n + 9_999n) / 10_000n) security.push("fee above 500 bps");
  if (!BINDING.test(r.binding)) security.push("binding is not an np1 binding");
  const match = matchRegistry(i.registry, {
    recipient: r.pay_to,
    recipientType: "INTENTS",
    destinationAsset: r.token,
    livemode: i.livemode,
  });
  if (!match.ok && match.class === "security") security.push(match.reason);
  if (security.length) return { ok: false, class: "security", reasons: security };
  if (!match.ok) return { ok: false, class: match.class, reasons: [match.reason] };
  if (Date.parse(r.deadline) <= i.nowMs + 30_000)
    return { ok: false, class: "stale", reasons: ["deadline within 30 s"] };
  return { ok: true, row: match.row };
}
