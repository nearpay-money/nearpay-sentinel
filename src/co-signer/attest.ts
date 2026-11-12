/**
 * `POST /v1/attestations/deposit_instructions` (lld/sentinel.md §5): ticket gate → cache → provider
 * re-read (route_quote) or requirement checks (intents_transfer) → registry match (R5 re-read when the
 * recipient is unknown) → quarantine gate → sign. Fail-closed: every refusal means checkout shows no
 * address. A `security` failure never stops the platform by itself (ADR-0028, owner directive
 * 2026-11-12): on an address rails confirms NearPay issued it is recorded and, with pipeline evidence,
 * quarantines the account; the global switch engages only on corroborated breaches across accounts
 * (kill-switch/containment.ts). Spoofs are refused, counted and rate-limited.
 */

import { sql } from "@nearpay-internal/db";
import { isId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError, type RouteBodyOut } from "@nearpay-internal/service";
import type { createDepositInstructionsAttestation } from "@nearpay-money/spec";
import { routeQuoteDepositKey, type SignedAttestation } from "@nearpay-money/spec";
import { attestedAsset } from "../address-integrity/assets.js";
import {
  type CheckFailure,
  checkIntents,
  checkRouteQuote,
  type RegistryRow,
  type RouteQuoteInput,
  recipientIsListed,
} from "../address-integrity/checks.js";
import { rulesOf } from "../address-integrity/containment.js";
import type { Sentinel } from "../app/context.js";
import { TokensUnavailable } from "../infra/clients/tokens.js";
import { activeQuarantine, containBreach, type DepositLookup } from "../kill-switch/containment.js";
import { buildAttestation } from "./attestation.js";
import { signAttestation, verifyTicket } from "./crypto.js";

export type AttestBody = RouteBodyOut<typeof createDepositInstructionsAttestation>;

/** Spoof refusals per client IP: 5 in 10 minutes, then 429 for the rest of the window. */
const SPOOF_LIMIT = 5;
const SPOOF_WINDOW_MS = 10 * 60_000;
const spoofs = new Map<string, number[]>();

function spoofed(ip: string, now: number): number {
  const recent = (spoofs.get(ip) ?? []).filter((t) => now - t < SPOOF_WINDOW_MS);
  recent.push(now);
  spoofs.set(ip, recent);
  if (spoofs.size > 10_000) spoofs.delete(spoofs.keys().next().value as string);
  return recent.length;
}

function limited(ip: string, now: number): number | null {
  const recent = (spoofs.get(ip) ?? []).filter((t) => now - t < SPOOF_WINDOW_MS);
  if (recent.length < SPOOF_LIMIT) return null;
  return Math.ceil(((recent[0] as number) + SPOOF_WINDOW_MS - now) / 1000);
}

/** identity's registry view could not be read (§9: read-only role, 300 ms): the request is unavailable. */
class RegistryUnavailable extends Error {
  override readonly name = "RegistryUnavailable";
}

async function fromRegistry<T>(q: () => Promise<T>): Promise<T> {
  try {
    return await q();
  } catch (e) {
    throw new RegistryUnavailable(e instanceof Error ? e.message : String(e));
  }
}

async function registryRows(s: Sentinel, livemode: boolean, assetId: string): Promise<RegistryRow[]> {
  return fromRegistry(() =>
    s.registry
      .selectFrom("sentinel_destination_registry")
      .selectAll()
      .where("livemode", "=", livemode)
      .where("asset_id", "=", assetId)
      .where("status", "in", ["active", "disabled"])
      .execute(),
  );
}

async function record(
  s: Sentinel,
  b: AttestBody,
  depositKey: string,
  o: {
    result: "signed" | "rejected" | "unavailable";
    cls?: string;
    reasons?: readonly string[];
    row?: RegistryRow;
    response?: SignedAttestation;
    ip: string;
  },
): Promise<void> {
  await s.db
    .insertInto("attestations")
    .values({
      id: uuidv7(),
      livemode: b.livemode,
      kind: b.kind,
      deposit_key: depositKey,
      attempt_id: b.attempt_id,
      account_id: o.row?.account_id ?? null,
      destination_id: o.row?.id ?? null,
      result: o.result,
      class: o.cls ?? null,
      reasons: [...(o.reasons ?? [])],
      response: o.response ? JSON.stringify(o.response) : null,
      client_ip: o.ip.slice(0, 64),
      expires_at: o.response ? new Date(o.response.attestation.expires_at) : null,
    })
    .execute();
}

/** Cache value (`att:<deposit_key>`): the signed response and the destination it vouches for. */
interface CacheEntry {
  destination_id: string;
  response: SignedAttestation;
}

async function cachedAttestation(
  s: Sentinel,
  depositKey: string,
  attemptId: string,
): Promise<SignedAttestation | null> {
  const raw = await s.cache.get(depositKey);
  if (!raw) return null;
  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw) as CacheEntry;
  } catch {
    return null;
  }
  const a = entry.response?.attestation;
  if (!a || a.attempt_id !== attemptId || Date.parse(a.expires_at) <= s.now()) return null;
  const active = await fromRegistry(() =>
    s.registry
      .selectFrom("sentinel_destination_registry")
      .select(["id", "account_id", "livemode"])
      .where("id", "=", entry.destination_id)
      .where("status", "=", "active")
      .executeTakeFirst(),
  );
  if (!active) {
    await s.cache.del([depositKey]);
    return null;
  }
  // a quarantined account is never re-served: the full path refuses it before signing
  if (await activeQuarantine(s, active.account_id, active.livemode)) return null;
  return entry.response;
}

export async function attest(s: Sentinel, b: AttestBody, ip: string): Promise<SignedAttestation> {
  const started = s.now();
  const done = (result: string, reason: string) =>
    s.metrics.attestation(b.kind, result, reason, (s.now() - started) / 1000);
  const retry = limited(ip, s.now());
  if (retry !== null) {
    done("rejected", "rate_limited");
    throw new ApiError("rate_limited", { params: { retry_after: retry }, headers: { "Retry-After": String(retry) } });
  }

  // 1. ticket gate (before any provider call)
  const depositKey =
    b.kind === "route_quote" && b.deposit
      ? routeQuoteDepositKey(b.livemode ? "oneclick" : "sandbox", b.deposit.address, b.deposit.memo)
      : (b.requirement?.binding as string);
  const t = verifyTicket(b.attestation_ticket, s.ticketKey, Math.floor(s.now() / 1000));
  if (
    !t.ok ||
    t.payload.attempt_id !== b.attempt_id ||
    t.payload.livemode !== b.livemode ||
    t.payload.deposit_key !== depositKey
  ) {
    done("rejected", "ticket");
    throw new ApiError("ticket_invalid");
  }

  try {
    return await checked(s, b, depositKey, ip, done);
  } catch (e) {
    if (!(e instanceof RegistryUnavailable)) throw e;
    await record(s, b, depositKey, {
      result: "unavailable",
      cls: "unavailable",
      reasons: [`registry: ${e.message}`.slice(0, 500)],
      ip,
    });
    done("unavailable", "registry");
    s.log.error({ err: e }, "identity registry view unreachable");
    throw new ApiError("attestation_unavailable");
  }
}

async function checked(
  s: Sentinel,
  b: AttestBody,
  depositKey: string,
  ip: string,
  done: (result: string, reason: string) => void,
): Promise<SignedAttestation> {
  // 2. cache: a signed attestation is re-served until it expires (idempotent for the SPA's retries),
  //    while its destination is still active (a disabled destination is never re-attested, even when an
  //    api replica missed the eviction while Valkey was down)
  const cached = await cachedAttestation(s, depositKey, b.attempt_id);
  if (cached) {
    done("signed", "cached");
    return cached;
  }

  // 3. checks
  const treasury = b.livemode ? s.treasury : s.testTreasury;
  let outcome: { ok: true; row: RegistryRow } | ({ ok: false } & CheckFailure);
  // rails' answer about the deposit address, asked at most once per request (R5 re-read, containment)
  let asked: Promise<DepositLookup | null> | undefined;
  const lookup = (): Promise<DepositLookup | null> => {
    if (!b.deposit) return Promise.resolve(null);
    const d = b.deposit;
    asked ??= s.rails.exists(d.address, d.memo).catch(() => null);
    return asked;
  };
  let signedAmount: { amountIn: string; amountInFormatted: string } | undefined;
  if (b.kind === "route_quote" && b.deposit) {
    const provider = b.livemode ? s.live : s.test;
    if (!provider) {
      await record(s, b, depositKey, {
        result: "unavailable",
        cls: "unavailable",
        reasons: ["provider not configured"],
        ip,
      });
      done("unavailable", "provider");
      throw new ApiError("attestation_unavailable");
    }
    const st = await provider.status(b.deposit.address, b.deposit.memo);
    if (!st.ok) {
      await record(s, b, depositKey, { result: "unavailable", cls: "unavailable", reasons: [`R1 ${st.detail}`], ip });
      done("unavailable", "R1");
      throw new ApiError("attestation_unavailable");
    }
    const q = st.status.quoteResponse;
    signedAmount = { amountIn: q.quote.amountIn, amountInFormatted: q.quote.amountInFormatted };
    const input: RouteQuoteInput = {
      livemode: b.livemode,
      deposit: b.deposit,
      status: st.status,
      signatureValid: provider.verifySignature(q),
      registry: await registryRows(s, b.livemode, q.quoteRequest.destinationAsset),
      treasury,
      referral: s.referral,
      split: s.split,
      nowMs: s.now(),
    };
    outcome = checkRouteQuote(input);
    if (!outcome.ok && outcome.recipientUnknown) outcome = await recheckRecipient(s, input, lookup);
  } else {
    const r = b.requirement;
    if (!r) throw ApiError.invalid("requirement is required", "requirement");
    outcome = checkIntents({
      livemode: b.livemode,
      requirement: r,
      registry: await registryRows(s, b.livemode, r.token),
      treasury,
      nowMs: s.now(),
    });
  }

  if (!outcome.ok) {
    if (outcome.class === "unavailable") {
      // NearPay's configuration or a provider value sentinel cannot read: refuse, retry, page — never security
      await record(s, b, depositKey, { result: "unavailable", cls: "unavailable", reasons: outcome.reasons, ip });
      done("unavailable", "checks");
      s.log.error(
        { reasons: outcome.reasons, livemode: b.livemode, attempt: b.attempt_id },
        "ALERT attestation unavailable: configuration or provider response cannot be verified",
      );
      throw new ApiError("attestation_unavailable");
    }
    await record(s, b, depositKey, {
      result: "rejected",
      cls: outcome.class,
      reasons: outcome.reasons,
      ...(outcome.row ? { row: outcome.row } : {}),
      ip,
    });
    done("rejected", outcome.class);
    if (outcome.class === "stale") throw new ApiError("attestation_stale");
    if (outcome.class === "security") await onSecurity(s, b, outcome, ip, lookup);
    throw new ApiError("attestation_refused");
  }

  // quarantine gate (ADR-0028): an account under quarantine gets no signature until it expires or ops clear it
  const held = await activeQuarantine(s, outcome.row.account_id, b.livemode);
  if (held) {
    await record(s, b, depositKey, {
      result: "unavailable",
      cls: "quarantined",
      reasons: [`quarantined until ${held.expires_at.toISOString()}: ${held.reason}`.slice(0, 500)],
      row: outcome.row,
      ip,
    });
    done("unavailable", "quarantined");
    s.log.warn(
      { account: outcome.row.account_id, until: held.expires_at.toISOString(), attempt: b.attempt_id },
      "deposit instructions refused: the account is quarantined",
    );
    throw new ApiError("attestation_unavailable");
  }

  // 4. the asset the payer sends: display data from sentinel's own read of the provider's token registry,
  //    consistent with the signed quote (CR-15-07); never from the request
  const assetId = b.kind === "route_quote" ? (b.deposit?.origin_asset_id as string) : (b.requirement?.token as string);
  const tokens = b.livemode ? s.liveTokens : s.testTokens;
  let display: Awaited<ReturnType<NonNullable<typeof tokens>["asset"]>> = null;
  let why: string | null = tokens ? null : "token registry not configured";
  if (tokens) {
    try {
      display = await tokens.asset(assetId);
    } catch (e) {
      if (!(e instanceof TokensUnavailable)) throw e;
      why = e.message;
    }
  }
  const asset = why === null ? attestedAsset(assetId, display, signedAmount) : { ok: false as const, reason: why };
  if (!asset.ok) {
    await record(s, b, depositKey, {
      result: "unavailable",
      cls: "unavailable",
      reasons: [`asset: ${asset.reason}`.slice(0, 500)],
      row: outcome.row,
      ip,
    });
    done("unavailable", "asset");
    s.log.error({ asset: assetId, reason: asset.reason, livemode: b.livemode }, "attested asset unavailable");
    throw new ApiError("attestation_unavailable");
  }

  // 5. sign
  const signed = signAttestation(buildAttestation(b, outcome.row, asset.asset, s.now()), s.signingKey);
  await record(s, b, depositKey, { result: "signed", row: outcome.row, response: signed, ip });
  const entry: CacheEntry = { destination_id: outcome.row.id, response: signed };
  await s.cache.set(depositKey, JSON.stringify(entry), Date.parse(signed.attestation.expires_at));
  done("signed", "ok");
  return signed;
}

/**
 * R5 found no destination for the recipient (ADR-0028): before calling it a breach, re-read identity's
 * registry (after a short pause); then a replica that is behind is `unavailable`, and a recipient that is
 * one of the account's own wallets (another asset, type or mode) or an account whose payout wallets changed
 * recently (instant activation, ADR-0027) is `stale` — both still refused, neither a breach. Only a recipient
 * NearPay never had, read from a current view, stays `security`.
 */
async function recheckRecipient(
  s: Sentinel,
  input: RouteQuoteInput,
  lookup: () => Promise<DepositLookup | null>,
): Promise<ReturnType<typeof checkRouteQuote>> {
  const p = s.containment;
  const q = input.status.quoteResponse.quoteRequest;
  if (p.rereadMs > 0) await new Promise((r) => setTimeout(r, p.rereadMs));
  const registry = await registryRows(s, input.livemode, q.destinationAsset);
  const again = checkRouteQuote({ ...input, registry });
  if (again.ok || !again.recipientUnknown) return again;
  const as = (cls: "stale" | "unavailable", reason: string) => {
    s.log.warn(
      { recipient: q.recipient, reason },
      `R5 recipient not in identity's registry view: ${cls}, not security`,
    );
    return checkRouteQuote({ ...input, registry, recipientUnknownAs: { class: cls, reason } });
  };
  const lag = await fromRegistry(() =>
    sql<{ replica: boolean; lag_s: number | null }>`
      select pg_is_in_recovery() as replica,
             extract(epoch from (now() - pg_last_xact_replay_timestamp()))::float8 as lag_s`.execute(s.registry),
  );
  const r = lag.rows[0];
  if (r?.replica && (r.lag_s === null || r.lag_s * 1000 > p.registryMaxLagMs))
    return as("unavailable", `recipient not found and identity's registry view is ${r.lag_s ?? "?"} s behind`);
  const known = await lookup();
  if (known?.exists && known.account_id && isId("acct", known.account_id)) {
    const own = await fromRegistry(() =>
      s.registry
        .selectFrom("sentinel_destination_registry")
        .selectAll()
        .where("account_id", "=", toUuid(known.account_id as string, "acct"))
        .where("livemode", "=", input.livemode)
        .execute(),
    );
    if (recipientIsListed(own, q.recipient))
      return as("stale", "the recipient is one of the account's payout wallets, for another asset or type");
    const since = input.nowMs - p.registryRecentMs;
    const recent = own.some(
      (d) => (d.active_at && d.active_at.getTime() >= since) || (d.disabled_at && d.disabled_at.getTime() >= since),
    );
    if (recent)
      return as(
        "stale",
        `recipient not found; the account's payout wallets changed in the last ${Math.round(p.registryRecentMs / 60_000)} min (identity's view may lag) — retry`,
      );
  }
  return again;
}

/**
 * A security-class refusal (ADR-0028, amending L-SN-01). An address rails does not know is a spoof → refuse
 * and count. Rails unreachable → refuse and page. A genuine NearPay address → recorded; with pipeline
 * evidence an audit finding, a scoped quarantine (live) and the corroboration rule (containBreach); with
 * request evidence (fields only the caller supplied) recorded and counted per IP, nothing stopped.
 */
async function onSecurity(
  s: Sentinel,
  b: AttestBody,
  outcome: CheckFailure,
  ip: string,
  lookup: () => Promise<DepositLookup | null>,
): Promise<void> {
  const reasons = outcome.reasons;
  const evidence = outcome.evidence ?? "request";
  const rules = rulesOf(reasons);
  const count = (address: string) => {
    for (const rule of rules) s.metrics.integrityRefusal(b.livemode, evidence, rule, address);
  };
  if (b.kind !== "route_quote" || !b.deposit) {
    count("unchecked");
    s.log.warn({ reasons, ip, attempt: b.attempt_id }, "intents requirement refused (security)");
    spoofed(ip, s.now());
    return;
  }
  const known = await lookup();
  if (known === null) {
    count("unverified");
    s.log.error(
      { reasons, deposit: b.deposit.address },
      "ALERT attestation refused (security) and rails is unreachable",
    );
    return;
  }
  if (!known.exists) {
    count("spoof");
    const n = spoofed(ip, s.now());
    s.log.warn({ reasons, ip, deposit: b.deposit.address, count: n }, "spoofed deposit instructions refused");
    return;
  }
  count("genuine");
  if (evidence === "request") spoofed(ip, s.now());
  // the refusal stands whatever happens here; a recording failure pages instead of failing the request
  await containBreach(s, {
    livemode: b.livemode,
    evidence,
    reasons,
    attemptId: b.attempt_id,
    depositAddress: b.deposit.address,
    depositMemo: b.deposit.memo,
    lookup: known,
    destinationAccount: outcome.row?.account_id ?? null,
    ip,
  }).catch((e) =>
    s.log.error(
      { err: e, reasons, deposit: b.deposit?.address },
      "ALERT quote integrity breach on a NearPay deposit address could not be recorded or contained",
    ),
  );
}

/** For tests: forget spoof counters. */
export function resetSpoofCounters(): void {
  spoofs.clear();
}
