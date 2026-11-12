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
 * The reason sentinel wrote when one payment's check engaged the switch (before ADR-0028; the 2026-11-11
 * incident "integrity breach on 0x11D2…5036: R4 deposit chain differs"): the deposit address, then the
 * refusal's reasons joined with "; ". Sentinel has never written any other non-systemic reason.
 */
const SINGLE_CHECK_REASON = /^integrity breach on (\S+): (.+)$/s;

/** Caller-supplied fields (ADR-0028 decision 2: request evidence, never a stop). */
const REQUEST_REASONS: ReadonlySet<string> = new Set([
  "R4 origin asset differs",
  "R4 amount differs",
  "R4 deposit chain differs",
  "R4 deadline differs",
]);

/**
 * Why a stale automatic stop would not happen under the current rules (label `reason_class` of
 * `kill_switch_auto_released_total`):
 * - `omdep_misparse`: one payment's "R4 deposit chain differs" (the 2026-11-11 incident: the old parser read a
 *   `.omdep.near` asset id as a NEAR token; spec 0.5.2 fixed it, and the chain is caller-supplied anyway);
 * - `request_evidence`: one payment's caller-supplied fields only;
 * - `drift`: provider-format drift (one payment's drift-eligible reasons, or a systemic window whose refusals
 *   are drift-classified or R2-only echo drift);
 * - `single_breach`: any other single payment's check (one payment never stops the platform now);
 * - `null_account`: a systemic window that reached the account threshold only by counting unknown accounts;
 * - `uncorroborated`: a systemic window that is not corroborated across merchants under the current rules.
 */
export type StaleClass =
  | "omdep_misparse"
  | "request_evidence"
  | "drift"
  | "single_breach"
  | "null_account"
  | "uncorroborated";

export const STALE_CLASSES: readonly StaleClass[] = [
  "omdep_misparse",
  "request_evidence",
  "drift",
  "single_breach",
  "null_account",
  "uncorroborated",
];

/** Why a stop is kept: an operator's, still corroborated, or not judgeable (fail closed). */
export type KeepReason = "operator" | "corroborated" | "unjudgeable";

export type StopVerdict =
  | { readonly stale: true; readonly why: string; readonly class: StaleClass }
  | { readonly stale: false; readonly why: string; readonly keep: KeepReason };

/** Recorded rows of an engagement's window that the current rules no longer read as pipeline breaches. */
export interface Reclassified {
  /** R2-only refusals on a matched recipient recorded before SENTINEL-1 (provider echo drift). */
  readonly r2Only?: number;
  /** Request-evidence (caller-supplied) refusals. */
  readonly request?: number;
}

function singleCheckClass(reasons: readonly string[]): StaleClass {
  if (reasons.length > 0 && reasons.every((r) => r === "R4 deposit chain differs")) return "omdep_misparse";
  if (reasons.length > 0 && reasons.every((r) => REQUEST_REASONS.has(r))) return "request_evidence";
  if (driftSignature(reasons) !== null) return "drift";
  return "single_breach";
}

/** The engagement's own window: breaches up to it (1 s of slack: the engaging breach is written a few ms first). */
function engagementWindow(e: Engagement, breaches: readonly Breach[], p: ContainmentPolicy) {
  const at = e.atMs + 1_000;
  const wp = { ...p, systemicWindowMs: p.systemicWindowMs + 1_000 };
  const window = breaches.filter((b) => b.atMs <= at && at - b.atMs <= wp.systemicWindowMs);
  return { at, wp, window };
}

/**
 * Would this engagement still engage the switch under the current rules (ADR-0028 and its amendment)?
 * `breaches` are the recorded pipeline breaches on genuine live addresses around the engagement (already
 * filtered with {@link stillPipelineBreach}); `reclassified` counts the window's recorded rows the current rules
 * no longer read as pipeline breaches. Used by the automatic release ({@link autoReleaseDecision}) and by the ops
 * CLI `kill-switch-release-status`.
 *
 * - An operator's engagement is never stale (people decide; only they release it).
 * - A sentinel engagement must carry a reason sentinel writes; any other reason cannot be judged → kept.
 * - One payment's check (the rule before ADR-0028): stale, unless breaches on record in its window are
 *   corroborated under the current rules (then kept).
 * - A systemic engagement is re-evaluated on its window: still corroborated (drift excluded) → kept; no longer →
 *   stale. When nothing of its window is on record it cannot be re-evaluated → kept (fail closed).
 */
export function staleAutomaticStop(
  e: Engagement,
  breaches: readonly Breach[],
  p: ContainmentPolicy,
  reclassified: Reclassified = {},
): StopVerdict {
  if (e.actor !== "sentinel") return { stale: false, keep: "operator", why: "an operator engaged it" };
  const { at, wp, window } = engagementWindow(e, breaches, p);
  const v = window.length > 0 ? systemicVerdict(window, wp, at) : null;
  const corroborated = (n: SystemicVerdict) =>
    ({
      stale: false,
      keep: "corroborated",
      why: `still corroborated: ${n.refusals} refusals across ${n.accounts} merchants`,
    }) as const;

  if (!e.reason.startsWith(SYSTEMIC_REASON_PREFIX)) {
    const m = SINGLE_CHECK_REASON.exec(e.reason);
    if (!m)
      return {
        stale: false,
        keep: "unjudgeable",
        why: "its reason is not one sentinel writes, so it cannot be checked against the current rules",
      };
    if (v?.engage) return corroborated(v);
    return {
      stale: true,
      class: singleCheckClass((m[2] as string).split("; ")),
      why: "it was engaged by a single payment's check, which never stops the platform now",
    };
  }

  if (v === null) {
    const r2 = reclassified.r2Only ?? 0;
    const req = reclassified.request ?? 0;
    if (r2 + req === 0)
      return { stale: false, keep: "unjudgeable", why: "its breaches are not on record, so it cannot be re-checked" };
    return {
      stale: true,
      class: r2 > 0 ? "drift" : "request_evidence",
      why:
        r2 > 0
          ? "its refusals were the provider's signature echo changing, which is not tampering under the current rules"
          : "its refusals were about fields the payer's browser sent, which never stop the platform now",
    };
  }
  if (v.engage) return corroborated(v);
  if (v.drift.length > 0)
    return {
      stale: true,
      class: "drift",
      why: "its refusals were the same provider-format change on every merchant, not tampering",
    };
  const unknown = window.some((b) => b.account === null);
  if (unknown && v.refusals >= Math.max(2, p.systemicRefusals))
    return {
      stale: true,
      class: "null_account",
      why: "it counted refusals whose merchant is unknown as extra merchants; under the current rules they are not",
    };
  return {
    stale: true,
    class: "uncorroborated",
    why: "its refusals are no longer corroborated across merchants under the current rules",
  };
}

// ------------------------------------------------------------------------- automatic release (2026-11-13)

/**
 * Automatic release of stale automatic stops (owner decision 2026-11-13; ADR-0028 amendment 2026-11-13):
 * `NP_KILL_SWITCH_AUTO_RELEASE_TICK_S`, `NP_KILL_SWITCH_AUTO_RELEASE_MAX_REENGAGEMENTS`.
 */
export interface AutoReleasePolicy {
  /** How often sentinel-auditor checks the switch (also once at boot). */
  readonly tickMs: number;
  /** Flap guard: auto-release → re-engagement cycles tolerated within `flapWindowMs`; more → no auto-release. */
  readonly maxReengagements: number;
  readonly flapWindowMs: number;
}

export const DEFAULT_AUTO_RELEASE: AutoReleasePolicy = {
  tickMs: 60_000,
  maxReengagements: 3,
  flapWindowMs: 60 * 60_000,
};

export const AUTO_RELEASE_PREFIX = "auto-released: ";
export const AUTO_RELEASE_SUFFIX = " — no longer platform evidence under ADR-0028";
const REASON_MAX = 500;

/** The `kill_switch_log` reason of an automatic release, within the 500-character column (old reason shortened). */
export function autoReleaseReason(old: string): string {
  const room = REASON_MAX - AUTO_RELEASE_PREFIX.length - AUTO_RELEASE_SUFFIX.length;
  const kept = old.length > room ? `${old.slice(0, room - 1)}…` : old;
  return `${AUTO_RELEASE_PREFIX}${kept}${AUTO_RELEASE_SUFFIX}`;
}

/** A `kill_switch_log` row, as the flap guard reads it. */
export interface SwitchLogEntry {
  readonly version: number;
  readonly engaged: boolean;
  readonly actor: string;
  readonly reason: string;
  readonly atMs: number;
}

const isAutoRelease = (r: SwitchLogEntry) =>
  !r.engaged && r.actor === "sentinel" && r.reason.startsWith(AUTO_RELEASE_PREFIX);

/**
 * Flap guard input: how many times sentinel engaged the switch again right after one of its automatic releases,
 * with the re-engagement inside `[now − windowMs, now]`.
 */
export function reengagementsAfterAutoRelease(log: readonly SwitchLogEntry[], nowMs: number, windowMs: number): number {
  const rows = [...log].sort((x, y) => x.version - y.version);
  let n = 0;
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i] as SwitchLogEntry;
    const prev = rows[i - 1] as SwitchLogEntry;
    if (r.engaged && r.actor === "sentinel" && isAutoRelease(prev) && r.atMs <= nowMs && nowMs - r.atMs <= windowMs)
      n++;
  }
  return n;
}

export type AutoReleaseDecision =
  | { readonly release: true; readonly class: StaleClass; readonly why: string }
  | {
      readonly release: false;
      readonly keep: KeepReason | "new_evidence" | "flapping";
      readonly why: string;
    };

/**
 * Should sentinel release the engaged global switch by itself? Only a stale automatic stop
 * ({@link staleAutomaticStop}: engaged by sentinel, and its recorded reason and evidence would not engage the
 * switch under the current rules), and only when:
 * - no corroborated systemic evidence arrived after it (each later breach re-evaluates the window ending there:
 *   the systemic rule cannot engage an engaged switch again, so such evidence would otherwise be lost);
 * - the flap guard holds: sentinel re-engaged after its automatic releases at most `maxReengagements` times
 *   within `flapWindowMs`.
 * Never: an operator's stop, a still-corroborated systemic stop, or a stop whose evidence cannot be judged.
 * `breaches` cover `[engagement − window − 1 s, now]`.
 */
export function autoReleaseDecision(i: {
  readonly engagement: Engagement;
  readonly breaches: readonly Breach[];
  readonly reclassified?: Reclassified;
  readonly log: readonly SwitchLogEntry[];
  readonly containment: ContainmentPolicy;
  readonly policy: AutoReleasePolicy;
  readonly nowMs: number;
}): AutoReleaseDecision {
  const v = staleAutomaticStop(i.engagement, i.breaches, i.containment, i.reclassified);
  if (!v.stale) return { release: false, keep: v.keep, why: v.why };
  const since = i.engagement.atMs + 1_000;
  for (const b of i.breaches) {
    if (b.atMs <= since || b.atMs > i.nowMs) continue;
    const later = systemicVerdict(i.breaches, i.containment, b.atMs);
    if (later.engage)
      return {
        release: false,
        keep: "new_evidence",
        why: `new corroborated evidence arrived during the stop: ${later.refusals} refusals across ${later.accounts} merchants`,
      };
  }
  const flaps = reengagementsAfterAutoRelease(i.log, i.nowMs, i.policy.flapWindowMs);
  if (flaps > i.policy.maxReengagements)
    return {
      release: false,
      keep: "flapping",
      why: `the switch was engaged again ${flaps} times within ${Math.round(i.policy.flapWindowMs / 60_000)} min after automatic releases (more than ${i.policy.maxReengagements}), so automatic release is paused`,
    };
  return { release: true, class: v.class, why: v.why };
}
