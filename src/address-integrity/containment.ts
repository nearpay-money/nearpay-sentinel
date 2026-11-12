/**
 * Containment of integrity refusals (ADR-0028, lld/sentinel.md §5 "Containment"), pure.
 *
 * Owner directive 2026-11-12: "the service should never stop". An integrity failure on one payment never
 * stops the platform. A `security` refusal with `pipeline` evidence on a live deposit address rails confirms
 * NearPay issued quarantines the account(s) involved for a bounded time; the global kill switch is engaged
 * automatically only on corroborated, systemic evidence — at least `refusals` such refusals across at least
 * `accounts` distinct accounts within `windowMs`. A compromised provider key, referral, treasury or rails
 * shows up across merchants; registry lag, one merchant's configuration or a single odd quote does not.
 */

/** Containment settings (`NP_INTEGRITY_*`, `NP_QUARANTINE_TTL_S`, `NP_REGISTRY_*`; §10). */
export interface ContainmentPolicy {
  /** Pipeline refusals on genuine live addresses within the window that engage the global switch (≥ 2). */
  readonly systemicRefusals: number;
  /** …across at least this many distinct accounts (≥ 2: one account's signal is never global). */
  readonly systemicAccounts: number;
  readonly systemicWindowMs: number;
  /** How long a quarantine holds unless ops extend or clear it. */
  readonly quarantineTtlMs: number;
  /** R5 re-read: pause before reading identity's registry again. */
  readonly rereadMs: number;
  /** R5: a registry replica further behind than this is `unavailable`. */
  readonly registryMaxLagMs: number;
  /** R5: an account whose payout wallets changed this recently gets `stale` (the view may lag). */
  readonly registryRecentMs: number;
}

export const DEFAULT_CONTAINMENT: ContainmentPolicy = {
  systemicRefusals: 3,
  systemicAccounts: 2,
  systemicWindowMs: 15 * 60_000,
  quarantineTtlMs: 30 * 60_000,
  rereadMs: 250,
  registryMaxLagMs: 5_000,
  registryRecentMs: 15 * 60_000,
};

/** A recorded pipeline refusal on a genuine live address: when, and which account(s) it concerned. */
export interface Breach {
  readonly atMs: number;
  /** The account the execution belongs to (rails) or the quote pays (registry); null: unknown. */
  readonly account: string | null;
  /** Unique id (used as the account key when the account is unknown, so it counts on its own). */
  readonly id: string;
}

export interface SystemicVerdict {
  readonly engage: boolean;
  readonly refusals: number;
  readonly accounts: number;
}

/**
 * The corroboration rule. Breaches outside `[now − window, now]` are ignored. An unknown account counts as
 * a distinct one (fail towards detection: rails confirmed the address but could not name its account).
 */
export function systemicVerdict(breaches: readonly Breach[], p: ContainmentPolicy, nowMs: number): SystemicVerdict {
  const recent = breaches.filter((b) => b.atMs <= nowMs && nowMs - b.atMs <= p.systemicWindowMs);
  const accounts = new Set(recent.map((b) => b.account ?? `unknown:${b.id}`)).size;
  const refusals = recent.length;
  return {
    engage: refusals >= Math.max(2, p.systemicRefusals) && accounts >= Math.max(2, p.systemicAccounts),
    refusals,
    accounts,
  };
}

/** The rule ids (R2 … R6, `intents`) of refusal reasons, for metrics and records; sorted, unique. */
export function rulesOf(reasons: readonly string[]): string[] {
  const out = new Set<string>();
  for (const r of reasons) {
    const m = /^R([1-7])\b/.exec(r);
    out.add(m ? `R${m[1]}` : "intents");
  }
  return [...out].sort();
}

/** A quarantine row's state at `nowMs`. */
export function quarantineState(
  q: { status: string; expires_at: Date },
  nowMs: number,
): "active" | "expired" | "cleared" {
  if (q.status === "cleared") return "cleared";
  return q.expires_at.getTime() > nowMs ? "active" : "expired";
}

/**
 * New expiry when a breach (re)quarantines an account: `now + ttl`, never shortening an expiry ops set
 * further out.
 */
export function quarantineExpiry(current: Date | null, ttlMs: number, nowMs: number): Date {
  const next = nowMs + ttlMs;
  return new Date(current && current.getTime() > next ? current.getTime() : next);
}
