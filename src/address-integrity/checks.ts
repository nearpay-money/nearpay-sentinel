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
import { normalizeAddress, validateAddress } from "@nearpay-internal/chains";
import type { OneClickStatusQuoteResponse } from "@nearpay-internal/spec";
import { assetChain, NEAR } from "./assets.js";
import { attestedChain } from "./attested-chains.js";

export type FailureClass = "security" | "ambiguous" | "stale" | "unavailable";

/**
 * What a `security` refusal is evidence of (ADR-0028):
 * - `pipeline`: a field rails put into the quote, or the provider signed or echoed, disagrees with NearPay's
 *   own configuration, identity's registry or the deposit sentinel asked about (R2, R3, R4 address/memo/
 *   address lifetime/address shape, R5, R6). A payer cannot produce it: sentinel reads the quote from the
 *   provider itself, and the ticket binds the deposit address and memo. Only this evidence quarantines an
 *   account and counts toward the corroborated (systemic) global stop.
 * - `request`: only fields the caller supplied (checkout, i.e. the payer's browser) disagree with the signed
 *   quote (R4 origin asset, amount, chain, deadline; every `intents_transfer` requirement field). Anyone
 *   holding a ticket for their own attempt can send it at will, so it is refused, recorded and counted per IP
 *   but never stops anything beyond that request (L-SN-01).
 */
export type Evidence = "pipeline" | "request";

export interface CheckFailure {
  readonly class: FailureClass;
  readonly reasons: readonly string[];
  /** `security` only. */
  readonly evidence?: Evidence;
  /**
   * `security` only: R5 found no destination at all for the recipient and it is the only pipeline reason —
   * the co-signer re-reads identity's registry before it decides (stale view vs a recipient NearPay never had).
   */
  readonly recipientUnknown?: true;
  /** `security` only: the registry row the recipient matched (R5 passed), i.e. whose account the quote pays. */
  readonly row?: RegistryRow;
  /**
   * `unavailable` only (SENTINEL-1, ADR-0028 amendment 2026-11-12): the provider signature (R2) is the only
   * failure and every other check passed — referral is NearPay's, the deposit address and memo are the ones the
   * ticket binds, the address lives until refunds begin, the fees pay the treasury and the recipient is exactly
   * one active NearPay destination. A bad signature then cannot redirect funds; it means the provider's echo
   * cannot be verified (format drift, like the omitted `quoteWaitingTimeMs`). Refused, recorded, paged
   * (`ALERT integrity_drift_suspected`), never contained.
   */
  readonly drift?: "R2";
}

/** The reason recorded for an R2-only failure (every other check passed). */
export const R2_DRIFT_REASON =
  "R2 provider signature does not verify while every other check passes (provider echo drift suspected)";

/**
 * An ISO 8601 instant with an explicit offset (`Z` or `±hh:mm` / `±hhmm`), any number (1–9) of fraction
 * digits, as nanoseconds since the epoch; null for anything else — including a local time without an offset,
 * which `Date.parse` would read in the process's time zone. Comparing these values compares instants, so
 * `…:33Z`, `…:33.000Z`, `…:33.000000Z` and `…:33+00:00` are equal and `…:33.000001Z` is not.
 */
export function instantNs(s: unknown): bigint | null {
  if (typeof s !== "string") return null;
  const m =
    /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?(?:([Zz])|([+-])(\d{2}):?(\d{2}))$/.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null;
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  if (new Date(ms).getUTCDate() !== d) return null; // 2026-02-30
  let offsetMin = 0;
  if (!m[8]) {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offsetMin = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const frac = BigInt((m[7] ?? "").padEnd(9, "0"));
  return (BigInt(ms) - BigInt(offsetMin) * 60_000n) * 1_000_000n + frac;
}

/** A base-unit amount as an integer: plain decimal digits (an integral `.000…` tail allowed); null otherwise. */
export function baseUnits(s: unknown): bigint | null {
  if (typeof s !== "string") return null;
  const m = /^(\d{1,78})(?:\.0+)?$/.exec(s);
  return m ? BigInt(m[1] as string) : null;
}

/** A deposit memo: absent, null and "" all mean "no memo"; any other value is compared exactly. */
const memoOf = (m: string | null | undefined): string | null => (m === undefined || m === null || m === "" ? null : m);

/** Same deposit address: the chain's normal form when it has one (EVM and bech32 case), else exact. */
function sameAddress(chain: string | null, a: string, b: string): boolean {
  if (a === b) return true;
  if (chain === null) return false;
  try {
    return normalizeAddress(chain, a) === normalizeAddress(chain, b);
  } catch {
    return false;
  }
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

/**
 * R5 re-read (ADR-0028): is `recipient` one of these registry rows' addresses, whatever its asset, type or
 * mode? Used only to tell a stale view or a merchant's own wallet from a recipient NearPay never had.
 */
export function recipientIsListed(rows: readonly RegistryRow[], recipient: string): boolean {
  return rows.some((r) => {
    if (r.address_norm === recipient.toLowerCase()) return true;
    if (r.type !== "chain_address") return false;
    try {
      return normalizeAddress(r.chain, recipient) === r.address_norm;
    } catch {
      return false;
    }
  });
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
  /**
   * The co-signer's verdict on a recipient R5 found nowhere in the registry, after re-reading it (ADR-0028):
   * `stale` (identity's view may lag: the account's payout wallets changed recently, or the recipient is one
   * of its own wallets for another asset) or `unavailable` (the view is behind or unreadable). Absent: R5's
   * own `security`.
   */
  readonly recipientUnknownAs?: { readonly class: "stale" | "unavailable"; readonly reason: string };
}

type RouteOutcome = { ok: true; row: RegistryRow } | ({ ok: false } & CheckFailure);

/**
 * R2–R7 on a provider status response (R1 — the lookup itself — happens before). Values are compared as what
 * they mean (instants, integers, memo absence, the chain's address normal form), never as strings, so a
 * provider changing its formatting cannot look like tampering. A provider value sentinel cannot read, or a
 * missing NearPay configuration, is `unavailable` (refused, retried, paged), not `security`. A signature that
 * does not verify while every other check passes is `unavailable` with `drift: "R2"` (SENTINEL-1): R2 together
 * with any other failure — pipeline, request, an unreadable value, a missing treasury, an R5 miss — stays a
 * `security` breach. Precedence: pipeline security > request security > unavailable > R5 stale/ambiguous > R7.
 */
export function checkRouteQuote(i: RouteQuoteInput): RouteOutcome {
  const q = i.status.quoteResponse;
  const pipeline: string[] = [];
  const request: string[] = [];
  const unavailable: string[] = [];
  if (!i.signatureValid) pipeline.push("R2 provider signature does not verify");
  if (q.quoteRequest.referral !== i.referral) pipeline.push("R3 referral is not NearPay's");
  // the chain checkout names must be the one the deposit address lives on (an EVM address is valid on
  // every EVM chain, so a wrong chain would send funds where nobody watches): Intents deposits are on
  // NEAR; otherwise the origin asset's own chain, whenever its id says so
  const depositChain = q.quoteRequest.depositType === "INTENTS" ? NEAR : assetChain(q.quoteRequest.originAsset);
  // address and memo are bound by the ticket and are what sentinel asked the provider about: a different
  // answer comes from the provider, not from the caller
  if (!sameAddress(depositChain, q.quote.depositAddress ?? "", i.deposit.address))
    pipeline.push("R4 deposit address differs");
  if (memoOf(q.quote.depositMemo) !== memoOf(i.deposit.memo)) pipeline.push("R4 deposit memo differs");
  if (q.quoteRequest.originAsset !== i.deposit.origin_asset_id) request.push("R4 origin asset differs");
  const signedIn = baseUnits(q.quote.amountIn);
  if (signedIn === null) unavailable.push("R4 the provider's amountIn is not a base-unit integer");
  else if (signedIn !== baseUnits(i.deposit.amount_in)) request.push("R4 amount differs");
  if (depositChain !== null && i.deposit.chain !== depositChain) request.push("R4 deposit chain differs");
  // Solana / Bitcoin (§16): the provider's deposit address must also be a valid address of that chain
  if (depositChain !== null && attestedChain(depositChain)?.depositAddressShape) {
    const v = validateAddress(depositChain, q.quote.depositAddress ?? "");
    if (!v.ok) pipeline.push(`R4 deposit address is not a valid ${depositChain} address (${v.reason})`);
  }
  // The payer-facing deadline is when 1Click starts refunding: quoteRequest.deadline. It is NOT covered by the
  // quote signature (the SDK hashes {...request, ...quote}, so quote.deadline overwrites it); it is trusted
  // because sentinel reads it from 1Click itself over TLS (R1), never from rails or checkout. Live 1Click's
  // quote.deadline is when the deposit address goes inactive (3 days later on mainnet, 2026-11-07; the sandbox
  // sets both equal), so it must not end before refunds begin.
  const qd = instantNs(q.quoteRequest.deadline);
  if (qd === null) unavailable.push("R4 the provider's deadline is not an ISO 8601 instant");
  else if (qd !== instantNs(i.deposit.deadline)) request.push("R4 deadline differs");
  const inactive = instantNs(q.quote.deadline);
  if (inactive === null) unavailable.push("R4 the provider's deposit-address deadline is missing or unreadable");
  else if (qd !== null && inactive < qd) pipeline.push("R4 deposit address goes inactive before the deadline");
  if (!i.treasury) unavailable.push("R6 no treasury configured for this mode");
  else pipeline.push(...appFeesFailures(q.quoteRequest.appFees, i.treasury, i.split).map((r) => `R6 ${r}`));
  const match = matchRegistry(i.registry, {
    recipient: q.quoteRequest.recipient,
    recipientType: q.quoteRequest.recipientType,
    destinationAsset: q.quoteRequest.destinationAsset,
    livemode: i.livemode,
  });
  const unknown = !match.ok && match.class === "security";
  if (unknown && !i.recipientUnknownAs) pipeline.push(`R5 ${match.reason}`);
  // R2 alone, with every other rule verified and passing: the funds go where NearPay's own configuration and
  // identity's registry say, so this is "cannot verify the provider's echo", not tampering (SENTINEL-1)
  if (pipeline.length === 1 && !i.signatureValid && request.length === 0 && unavailable.length === 0 && match.ok)
    return { ok: false, class: "unavailable", reasons: [R2_DRIFT_REASON], drift: "R2" };
  if (pipeline.length) {
    const onlyR5 = unknown && pipeline.length === 1;
    // a bad signature next to a rule that could not be verified stays a breach; the record says which rule, so
    // it is never mistaken for (or re-read as) an R2-only refusal
    const unverified =
      pipeline.length === 1 && !i.signatureValid
        ? [
            ...unavailable,
            ...(match.ok ? [] : [`R5 ${unknown && i.recipientUnknownAs ? i.recipientUnknownAs.reason : match.reason}`]),
          ]
        : [];
    return {
      ok: false,
      class: "security",
      evidence: "pipeline",
      reasons: [...pipeline, ...request, ...unverified],
      ...(onlyR5 ? { recipientUnknown: true as const } : {}),
      ...(match.ok ? { row: match.row } : {}),
    };
  }
  if (request.length)
    return {
      ok: false,
      class: "security",
      evidence: "request",
      reasons: request,
      ...(match.ok ? { row: match.row } : {}),
    };
  if (unavailable.length) return { ok: false, class: "unavailable", reasons: unavailable };
  if (unknown && i.recipientUnknownAs)
    return { ok: false, class: i.recipientUnknownAs.class, reasons: [`R5 ${i.recipientUnknownAs.reason}`] };
  if (!match.ok) return { ok: false, class: match.class, reasons: [`R5 ${match.reason}`] };
  if (!OPEN.has(i.status.status)) return { ok: false, class: "stale", reasons: [`R7 status ${i.status.status}`] };
  if ((qd as bigint) <= BigInt(i.nowMs + 60_000) * 1_000_000n)
    return { ok: false, class: "stale", reasons: ["R7 deadline within 60 s"] };
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
  // every field of the requirement comes from the caller: a refusal is `request` evidence (ADR-0028)
  const security: string[] = [];
  if (!i.treasury) return { ok: false, class: "unavailable", reasons: ["no treasury configured for this mode"] };
  if (r.fee_to !== i.treasury) security.push("fee recipient is not the treasury");
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
  if (security.length) return { ok: false, class: "security", evidence: "request", reasons: security };
  if (!match.ok) return { ok: false, class: match.class, reasons: [match.reason] };
  const deadline = instantNs(r.deadline);
  if (deadline === null || deadline <= BigInt(i.nowMs + 30_000) * 1_000_000n)
    return { ok: false, class: "stale", reasons: ["deadline within 30 s"] };
  return { ok: true, row: match.row };
}
