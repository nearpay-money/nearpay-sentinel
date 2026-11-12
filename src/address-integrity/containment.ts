/**
 * Containment of integrity refusals (ADR-0028, lld/sentinel.md §5 "Containment"), pure.
 *
 * Owner directive 2026-11-12: "the service should never stop". An integrity failure on one payment never
 * stops the platform. A `security` refusal with `pipeline` evidence on a live deposit address rails confirms
 * NearPay issued quarantines the account(s) involved for a bounded time; the global kill switch is engaged
 * automatically only on corroborated, systemic evidence — at least `refusals` such refusals across at least
 * `accounts` distinct accounts within `windowMs`. A compromised provider key, referral, treasury or rails
 * shows up across merchants; registry lag, one merchant's configuration or a single odd quote does not.
 *
 * Provider-wide drift (SENTINEL-1, ADR-0028 amendment 2026-11-12) also shows up across merchants, with the
 * same refusal on every one. A refusal whose every reason is a *format/semantics* reason that cannot redirect
 * a payment by itself ({@link driftSignature}: R4 "address goes inactive before the deadline", R6 entry
 * count, R6 non-integer fee, R6 treasury share below the split) and that repeats identically on at least
 * `accounts` distinct known accounts within the window is classified as drift: it is still refused and
 * recorded, it pages (`ALERT integrity_drift_suspected`), but it quarantines nobody and never counts toward
 * the systemic rule. Everything that can redirect funds — R2 together with anything else, R3, R4 deposit
 * address/memo/shape, R5, R6 fees not paying the treasury exactly once or above 500 bps — keeps its full
 * weight, however uniform.
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
  readonly id: string;
  /** The refusal's reasons (drift classification, uniform-rules flag); absent: never drift. */
  readonly reasons?: readonly string[];
}

export interface SystemicVerdict {
  readonly engage: boolean;
  /** Counted refusals (drift-classified ones excluded). */
  readonly refusals: number;
  /** Distinct known accounts among the counted refusals (an unknown account never counts, SENTINEL-7). */
  readonly accounts: number;
  /** Drift signatures in the window: refused and recorded, never counted, never quarantined (sorted). */
  readonly drift: readonly string[];
  /**
   * Every counted refusal has the same rule set, across ≥ 2 accounts: likely a provider format change or a
   * rails/sentinel configuration skew (the rule ids, e.g. "R2+R3"); null otherwise. Informational: the switch
   * still engages on it, with `IntegrityDriftSuspected` next to `KillSwitchEngaged`.
   */
  readonly uniformRules: string | null;
}

/**
 * Refusal reasons that describe a provider format or semantics change and cannot redirect a payment by
 * themselves: the address/memo match the ticket, the referral is NearPay's, the treasury is paid exactly once
 * and the total stays within 500 bps (otherwise another reason is present).
 */
const DRIFT_ELIGIBLE: readonly RegExp[] = [
  /^R4 deposit address goes inactive before the deadline$/,
  /^R6 appFees has \d+ entries$/,
  /^R6 appFees has a non-integer or negative fee$/,
  /^R6 treasury appFee \S+ bps of \S+ is below its share$/,
];

/**
 * The drift signature of a refusal: its reasons with numbers blanked, sorted — when every reason is
 * drift-eligible; null when any reason is not (that refusal is never drift).
 */
export function driftSignature(reasons: readonly string[]): string | null {
  if (reasons.length === 0 || !reasons.every((r) => DRIFT_ELIGIBLE.some((re) => re.test(r)))) return null;
  return [...new Set(reasons.map((r) => r.replace(/ \d+(?:\.\d+)?/g, " #")))].sort().join(" | ");
}

const inWindow = (breaches: readonly Breach[], p: ContainmentPolicy, nowMs: number) =>
  breaches.filter((b) => b.atMs <= nowMs && nowMs - b.atMs <= p.systemicWindowMs);

/**
 * Drift signatures within the window: a drift-eligible signature seen on at least `max(2, accounts)` distinct
 * known accounts. Identical on every merchant → the provider (or a configuration) changed, not one payment.
 */
export function driftSignatures(breaches: readonly Breach[], p: ContainmentPolicy, nowMs: number): Set<string> {
  const by = new Map<string, Set<string>>();
  for (const b of inWindow(breaches, p, nowMs)) {
    const sig = b.reasons ? driftSignature(b.reasons) : null;
    if (sig === null || b.account === null) continue;
    by.set(sig, (by.get(sig) ?? new Set()).add(b.account));
  }
  const need = Math.max(2, p.systemicAccounts);
  return new Set([...by].filter(([, accounts]) => accounts.size >= need).map(([sig]) => sig));
}

/** Is this breach drift-classified, given the window's drift signatures? */
export function isDrift(b: Pick<Breach, "reasons">, drift: ReadonlySet<string>): boolean {
  const sig = b.reasons ? driftSignature(b.reasons) : null;
  return sig !== null && drift.has(sig);
}

/**
 * The corroboration rule. Breaches outside `[now − window, now]` are ignored, and so are drift-classified
 * ones (SENTINEL-1: the systemic switch can never engage on drift). A breach whose account is unknown counts
 * as a refusal but not as an account (SENTINEL-7: rails always names the account of an address it issued, so
 * a null account is noise, not a second merchant).
 */
export function systemicVerdict(breaches: readonly Breach[], p: ContainmentPolicy, nowMs: number): SystemicVerdict {
  const recent = inWindow(breaches, p, nowMs);
  const drift = driftSignatures(recent, p, nowMs);
  const counted = recent.filter((b) => !isDrift(b, drift));
  const accounts = new Set(counted.map((b) => b.account).filter((a): a is string => a !== null)).size;
  const refusals = counted.length;
  const ruleSets = new Set(counted.map((b) => (b.reasons ? rulesOf(b.reasons).join("+") : `?${b.id}`)));
  const only = ruleSets.size === 1 ? ([...ruleSets][0] as string) : null;
  return {
    engage: refusals >= Math.max(2, p.systemicRefusals) && accounts >= Math.max(2, p.systemicAccounts),
    refusals,
    accounts,
    drift: [...drift].sort(),
    uniformRules: only !== null && !only.startsWith("?") && accounts >= 2 ? only : null,
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

/**
 * Releasing the global switch clears the quarantines sentinel created during the engagement (SENTINEL-2):
 * those created since this instant. A switch sentinel engaged covers the corroboration window before it (the
 * breaches that engaged it); an operator's engagement starts when they engaged it.
 */
export function engagementQuarantineSince(
  engaged: { readonly actor: string; readonly atMs: number },
  p: Pick<ContainmentPolicy, "systemicWindowMs">,
): number {
  return engaged.actor === "sentinel" ? engaged.atMs - p.systemicWindowMs : engaged.atMs;
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
 * Expiry when a breach quarantines an account that has no quarantine in force: `now + ttl`, never shortening an
 * expiry ops set further out. A quarantine in force is never extended by a further breach (SENTINEL-2: payers
 * retrying the same broken quote must not keep a merchant blocked); it runs out, is cleared, or is
 * re-armed by the next breach after it ended.
 */
export function quarantineExpiry(current: Date | null, ttlMs: number, nowMs: number): Date {
  const next = nowMs + ttlMs;
  return new Date(current && current.getTime() > next ? current.getTime() : next);
}

/**
 * Is a recorded pipeline breach still a pipeline breach under the current rules? Recorded before SENTINEL-1, a
 * refusal whose only reason was the provider signature (R2) on a quote whose recipient matched a destination
 * (`destinationMatched`) is now `unavailable` (provider echo drift), never a breach. Everything else stands.
 */
export function stillPipelineBreach(b: { reasons: readonly string[]; destinationMatched: boolean }): boolean {
  return !(b.destinationMatched && b.reasons.length === 1 && /^R2 /.test(b.reasons[0] as string));
}

/** The engagement of the global switch as recorded on its row. */
export interface Engagement {
  readonly actor: string;
  readonly reason: string;
  readonly atMs: number;
}

export const SYSTEMIC_REASON_PREFIX = "systemic integrity breach";

/**
 * Diagnostic for the operator (ops CLI `kill-switch-release-status`): would this engagement still engage the
 * switch under the current rules? It only informs the person deciding on the release; it never releases
 * anything. `breaches` are the recorded pipeline breaches on genuine live addresses up to the engagement
 * (already filtered with {@link stillPipelineBreach}).
 *
 * - An operator's engagement is never stale (people decide; only they release it).
 * - A sentinel engagement that is not a systemic one is a single payment's check (the rule before ADR-0028,
 *   e.g. the 2026-11-11 "integrity breach on 0x11D2…: R4 deposit chain differs"): stale.
 * - A systemic engagement is re-evaluated on its window: still corroborated (drift excluded) → kept; no
 *   longer → stale. When no breach of its window is on record it cannot be re-evaluated → kept (fail closed).
 */
export function staleAutomaticStop(
  e: Engagement,
  breaches: readonly Breach[],
  p: ContainmentPolicy,
): { readonly stale: boolean; readonly why: string } {
  if (e.actor !== "sentinel") return { stale: false, why: "an operator engaged it" };
  if (!e.reason.startsWith(SYSTEMIC_REASON_PREFIX))
    return { stale: true, why: "it was engaged by a single payment's check, which never stops the platform now" };
  // the engaging breach is written in the same transaction a few ms before the switch row: 1 s of slack
  const at = e.atMs + 1_000;
  const window = breaches.filter((b) => b.atMs <= at && at - b.atMs <= p.systemicWindowMs + 1_000);
  if (window.length === 0) return { stale: false, why: "its breaches are not on record, so it cannot be re-checked" };
  const v = systemicVerdict(window, { ...p, systemicWindowMs: p.systemicWindowMs + 1_000 }, at);
  return v.engage
    ? { stale: false, why: `still corroborated: ${v.refusals} refusals across ${v.accounts} merchants` }
    : {
        stale: true,
        why:
          v.drift.length > 0
            ? "its refusals were the same provider-format change on every merchant, not tampering"
            : "its refusals are no longer corroborated across merchants under the current rules",
      };
}
