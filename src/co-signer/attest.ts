/**
 * `POST /v1/attestations/deposit_instructions` (lld/sentinel.md §5): ticket gate → cache → provider
 * re-read (route_quote) or requirement checks (intents_transfer) → registry match → sign. Fail-closed:
 * every refusal means checkout shows no address. Only a `security` failure on an address rails confirms
 * NearPay issued engages the kill switch (L-SN-01); spoofs are refused, counted and rate-limited.
 */

import type { createDepositInstructionsAttestation } from "@nearpay/spec";
import { type Attestation, routeQuoteDepositKey, type SignedAttestation } from "@nearpay/spec";
import { destinationFingerprint } from "@nearpay-internal/chains";
import { uuidv7 } from "@nearpay-internal/ids";
import { ApiError, type RouteBodyOut } from "@nearpay-internal/service";
import { type CheckFailure, checkIntents, checkRouteQuote, type RegistryRow } from "../address-integrity/checks.js";
import type { Sentinel } from "../app/context.js";
import { setKillSwitch } from "../kill-switch/kill-switch.js";
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

function attestation(s: Sentinel, b: AttestBody, row: RegistryRow, expiresAt: string): Attestation {
  const issued = new Date(Math.floor(s.now() / 1000) * 1000).toISOString();
  return {
    v: 1,
    kind: b.kind,
    attempt_id: b.attempt_id,
    livemode: b.livemode,
    ...(b.kind === "route_quote" && b.deposit ? { deposit: { ...b.deposit } } : {}),
    ...(b.kind === "intents_transfer" && b.requirement
      ? { requirement: { ...b.requirement } as Attestation["requirement"] }
      : {}),
    merchant: { name: row.merchant_name, kyb_verified: row.kyb_verified },
    destination: {
      asset_id: row.asset_id,
      chain: row.chain,
      fingerprint: destinationFingerprint(row.chain, row.address_norm, row.asset_id),
    },
    issued_at: issued,
    expires_at: new Date(expiresAt).toISOString(),
  };
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
      .select("id")
      .where("id", "=", entry.destination_id)
      .where("status", "=", "active")
      .executeTakeFirst(),
  );
  if (!active) {
    await s.cache.del([depositKey]);
    return null;
  }
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
    outcome = checkRouteQuote({
      livemode: b.livemode,
      deposit: b.deposit,
      status: st.status,
      signatureValid: provider.verifySignature(q),
      registry: await registryRows(s, b.livemode, q.quoteRequest.destinationAsset),
      treasury,
      referral: s.referral,
      split: s.split,
      nowMs: s.now(),
    });
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
    await record(s, b, depositKey, { result: "rejected", cls: outcome.class, reasons: outcome.reasons, ip });
    done("rejected", outcome.class);
    if (outcome.class === "stale") throw new ApiError("attestation_stale");
    if (outcome.class === "security") await onSecurity(s, b, outcome.reasons, ip);
    throw new ApiError("attestation_refused");
  }

  // 4. sign
  const expires = b.kind === "route_quote" ? (b.deposit?.deadline as string) : (b.requirement?.deadline as string);
  const signed = signAttestation(attestation(s, b, outcome.row, expires), s.signingKey);
  await record(s, b, depositKey, { result: "signed", row: outcome.row, response: signed, ip });
  const entry: CacheEntry = { destination_id: outcome.row.id, response: signed };
  await s.cache.set(depositKey, JSON.stringify(entry), Date.parse(signed.attestation.expires_at));
  done("signed", "ok");
  return signed;
}

/**
 * A security-class refusal (L-SN-01): a genuine NearPay deposit address with a bad quote is an
 * integrity breach → kill switch (live only; a test-mode breach cannot stop live payments). An address
 * rails does not know is a spoof → refuse and count. Rails unreachable → refuse and page.
 */
async function onSecurity(s: Sentinel, b: AttestBody, reasons: readonly string[], ip: string): Promise<void> {
  if (b.kind !== "route_quote" || !b.deposit) {
    s.log.warn({ reasons, ip, attempt: b.attempt_id }, "intents requirement refused (security)");
    spoofed(ip, s.now());
    return;
  }
  const known = await s.rails.exists(b.deposit.address, b.deposit.memo).catch(() => null);
  if (known === null) {
    s.log.error(
      { reasons, deposit: b.deposit.address },
      "ALERT attestation refused (security) and rails is unreachable",
    );
    return;
  }
  if (!known.exists) {
    const n = spoofed(ip, s.now());
    s.log.warn({ reasons, ip, deposit: b.deposit.address, count: n }, "spoofed deposit instructions refused");
    return;
  }
  s.log.error(
    { reasons, deposit: b.deposit.address, livemode: known.livemode },
    "ALERT quote integrity breach on a NearPay deposit address",
  );
  if (b.livemode && known.livemode === true) {
    await setKillSwitch(
      s,
      true,
      `integrity breach on ${b.deposit.address}: ${reasons.join("; ")}`.slice(0, 500),
      "sentinel",
    );
  }
}

/** For tests: forget spoof counters. */
export function resetSpoofCounters(): void {
  spoofs.clear();
}
