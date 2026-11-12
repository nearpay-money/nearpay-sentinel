/** Dependencies shared by sentinel use cases. */

import type { KeyObject } from "node:crypto";
import type { Kysely, Transaction } from "@nearpay-internal/db";
import type { Logger, ServiceMetrics } from "@nearpay-internal/service";
import { Redis } from "ioredis";
import type { ProviderSplit } from "../address-integrity/checks.js";
import { type AutoReleasePolicy, type ContainmentPolicy, STALE_CLASSES } from "../address-integrity/containment.js";
import type { ClientIpRule } from "../api/client-ip.js";
import type { SigningKey } from "../co-signer/crypto.js";
import type { EsploraReader, EvmReader, NearReader, SolanaReader } from "../infra/clients/chains.js";
import type { SandboxStatus, StatusProvider } from "../infra/clients/providers.js";
import type { TokenRegistry } from "../infra/clients/tokens.js";
import type { DB, RegistryDB } from "../infra/db/schema.js";
import type { SingleOperatorPolicy } from "../kill-switch/two-person.js";

export type Tx = Transaction<DB>;

export interface SentinelMetrics {
  attestation(kind: string, result: string, reason: string, seconds: number): void;
  finding(result: string): void;
  killSwitch(engaged: boolean): void;
  /** An audit on a Stage 4 chain had no sentinel reader configured (§16 `audit_coverage_missing{chain}`). */
  coverageMissing(chain: string): void;
  /** `nearpay_ops_single_operator_actions_total{action}` (app/single-operator-metrics.ts). */
  singleOperatorAction(action: string): void;
  /**
   * A `security` refusal (ADR-0028), once per rule: `evidence` pipeline|request, `rule` R2…R6|intents,
   * `address` genuine (rails confirmed NearPay issued it) | spoof | unverified (rails unreachable).
   */
  integrityRefusal(livemode: boolean, evidence: string, rule: string, address: string): void;
  /** The corroboration rule engaged the global kill switch. */
  systemicEngaged(): void;
  /**
   * Provider-wide drift suspected (SENTINEL-1, `integrity_drift_total{source,rules}`): `r2_only` an R2-only
   * refusal (unavailable), `pattern` a drift-classified breach (not contained), `engaged` the systemic rule
   * engaged on refusals that all share one rule set.
   */
  integrityDrift(source: "r2_only" | "pattern" | "engaged", rules: string): void;
  /** Quarantines lifted in bulk (`quarantines_cleared_total{by}`): `release`, `drift`, `ops_all`. */
  quarantinesCleared(by: "release" | "drift" | "ops_all", n: number): void;
  /** Sentinel released a stale automatic stop by itself (`kill_switch_auto_released_total{reason_class}`, 2026-11-13). */
  killSwitchAutoReleased(reasonClass: string): void;
}

/** Attestation outcomes pre-created at zero so `increase()` sees the first failure (SENTINEL-3). */
export const ATTESTATION_OUTCOMES: readonly (readonly [result: string, reason: string])[] = [
  ["signed", "ok"],
  ["signed", "cached"],
  ["unavailable", "R1"],
  ["unavailable", "provider"],
  ["unavailable", "registry"],
  ["unavailable", "checks"],
  ["unavailable", "integrity_drift"],
  ["unavailable", "quarantined"],
  ["unavailable", "asset"],
  ["rejected", "security"],
  ["rejected", "stale"],
  ["rejected", "ambiguous"],
  ["rejected", "ticket"],
  ["rejected", "rate_limited"],
];

/** Scrape-time readers for the containment gauges (database state shared by every replica). */
export interface ContainmentGauges {
  quarantinesActive(): Promise<number>;
  systemicWindow(): Promise<{ refusals: number; accounts: number; drift?: number }>;
}

/** Static facts exported as gauges at boot (SENTINEL-1 config hash, SENTINEL-3 1Click key expiry). */
export interface StaticGauges {
  /** `fee_config_info{hash}` = 1 (address-integrity/config-hash.ts). */
  readonly feeConfigHash?: string;
  /** `oneclick_key_expiry_seconds{mode}`: the `exp` (unix seconds) of sentinel's 1Click key when it is a JWT. */
  readonly oneClickKeyExpiry?: Readonly<Record<string, number | null>>;
}

export const noMetrics: SentinelMetrics = {
  attestation() {},
  finding() {},
  killSwitch() {},
  coverageMissing() {},
  singleOperatorAction() {},
  integrityRefusal() {},
  systemicEngaged() {},
  integrityDrift() {},
  quarantinesCleared() {},
  killSwitchAutoReleased() {},
};

/** Service metrics (§12). The kill-switch gauge is read from the database on every scrape. */
export function sentinelMetrics(
  m: ServiceMetrics,
  engaged?: () => Promise<boolean>,
  singleOperatorAction: (action: string) => void = () => {},
  containment?: ContainmentGauges,
  statics: StaticGauges = {},
): SentinelMetrics {
  const att = m.counter("attestations_total", "Co-signing requests by outcome.", ["kind", "result", "reason"]);
  for (const kind of ["route_quote", "intents_transfer"])
    for (const [result, reason] of ATTESTATION_OUTCOMES) att.inc({ kind, result, reason }, 0);
  const dur = m.histogram(
    "attestation_duration_seconds",
    "Co-signing latency.",
    ["result"],
    [0.01, 0.05, 0.1, 0.25, 0.5, 1, 1.5, 3],
  );
  const findings = m.counter("audit_findings_total", "Independent re-verification results.", ["result"]);
  const coverage = m.counter(
    "audit_coverage_missing",
    "Audits that found no sentinel chain reader configured for the settlement chain (alert).",
    ["chain"],
  );
  const ks = m.gauge(
    "kill_switch_engaged",
    "1 while live quoting is stopped.",
    [],
    engaged
      ? async (g) => {
          g.set((await engaged()) ? 1 : 0);
        }
      : undefined,
  );
  const refusals = m.counter(
    "integrity_refusals_total",
    "Security refusals of deposit instructions by evidence, rule and whether rails confirmed the address (ADR-0028).",
    ["livemode", "evidence", "rule", "address"],
  );
  const systemic = m.counter(
    "integrity_systemic_engaged_total",
    "Times corroborated integrity breaches across accounts engaged the global kill switch.",
  );
  m.gauge(
    "quarantines_active",
    "Accounts whose deposit instructions sentinel does not sign right now (live and test).",
    [],
    containment
      ? async (g) => {
          g.set(await containment.quarantinesActive());
        }
      : undefined,
  );
  m.gauge(
    "integrity_systemic_window",
    "Pipeline breaches on genuine live addresses in the current corroboration window (refusals, distinct accounts).",
    ["measure"],
    containment
      ? async (g) => {
          const w = await containment.systemicWindow();
          g.set({ measure: "refusals" }, w.refusals);
          g.set({ measure: "accounts" }, w.accounts);
          g.set({ measure: "drift" }, w.drift ?? 0);
        }
      : undefined,
  );
  const drift = m.counter(
    "integrity_drift_total",
    "Provider-wide drift suspected (SENTINEL-1): R2-only refusals, drift-classified breaches, uniform systemic engagements.",
    ["source", "rules"],
  );
  for (const [source, rules] of [
    ["r2_only", "R2"],
    ["pattern", "R4"],
    ["pattern", "R6"],
    ["pattern", "R4+R6"],
  ] as const)
    drift.inc({ source, rules }, 0);
  const cleared = m.counter(
    "quarantines_cleared_total",
    "Quarantines lifted in bulk: on a kill-switch release, on drift classification, by ops quarantine-clear-all.",
    ["by"],
  );
  const autoReleased = m.counter(
    "kill_switch_auto_released_total",
    "Stale automatic stops sentinel released by itself (owner decision 2026-11-13), by why the current rules would not engage them.",
    ["reason_class"],
  );
  for (const reason_class of STALE_CLASSES) autoReleased.inc({ reason_class }, 0);
  const feeConfig = m.gauge(
    "fee_config_info",
    "1 for the fingerprint of sentinel's treasury/referral/provider-split configuration (rails exposes the same; alert on more than one).",
    ["hash"],
  );
  if (statics.feeConfigHash) feeConfig.set({ hash: statics.feeConfigHash }, 1);
  const keyExpiry = m.gauge(
    "oneclick_key_expiry_seconds",
    "Expiry (unix seconds, the JWT exp) of sentinel's 1Click API key per mode; absent when the key is not a JWT.",
    ["mode"],
  );
  for (const [mode, exp] of Object.entries(statics.oneClickKeyExpiry ?? {}))
    if (exp !== null) keyExpiry.set({ mode }, exp);
  return {
    integrityDrift: (source, rules) => drift.inc({ source, rules }),
    quarantinesCleared: (by, n) => cleared.inc({ by }, n),
    killSwitchAutoReleased: (reason_class) => autoReleased.inc({ reason_class }),
    integrityRefusal: (livemode, evidence, rule, address) =>
      refusals.inc({ livemode: String(livemode), evidence, rule, address }),
    systemicEngaged: () => systemic.inc(),
    attestation: (kind, result, reason, s) => {
      att.inc({ kind, result, reason });
      dur.observe({ result }, s);
    },
    finding: (result) => findings.inc({ result }),
    killSwitch: (on) => ks.set(on ? 1 : 0),
    coverageMissing: (chain) => coverage.inc({ chain }),
    singleOperatorAction,
  };
}

/** Cache of signed attestations (`att:<deposit_key>`, until `expires_at`). Valkey, or in-process. */
export interface AttestationCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, untilMs: number): Promise<void>;
  del(keys: readonly string[]): Promise<void>;
  close(): Promise<void>;
}

export function attestationCache(valkeyUrl: string | undefined, now: () => number = Date.now): AttestationCache {
  const local = new Map<string, { v: string; until: number }>();
  const redis = valkeyUrl
    ? new Redis(valkeyUrl, {
        lazyConnect: false,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 0,
        connectTimeout: 1_000,
        commandTimeout: 250,
      })
    : null;
  redis?.on("error", () => {});
  const up = () => redis?.status === "ready";
  return {
    async get(key) {
      if (up()) {
        try {
          return await (redis as Redis).get(`att:${key}`);
        } catch {}
      }
      const hit = local.get(key);
      if (!hit || hit.until <= now()) return null;
      return hit.v;
    },
    async set(key, value, untilMs) {
      const ttl = untilMs - now();
      if (ttl <= 0) return;
      local.set(key, { v: value, until: untilMs });
      if (local.size > 50_000) local.delete(local.keys().next().value as string);
      if (up()) await (redis as Redis).set(`att:${key}`, value, "PX", ttl).catch(() => {});
    },
    async del(keys) {
      for (const k of keys) local.delete(k);
      if (keys.length && up()) await (redis as Redis).del(...keys.map((k) => `att:${k}`)).catch(() => {});
    },
    async close() {
      redis?.disconnect();
    },
  };
}

/**
 * Rails' internal API with sentinel's service credentials (`rails.read`). Never a source of truth for
 * a verdict: `exists` only decides whether a security refusal is contained (quarantine, corroboration —
 * §5, ADR-0028) or counted as a spoof, and `asset` only feeds audit sampling (§7).
 */
export interface RailsClient {
  /**
   * Did NearPay issue this deposit address? null = rails unreachable. The execution and account only scope a
   * quarantine and an audit finding (ADR-0028); they never decide a verdict.
   */
  exists(
    address: string,
    memo: string | null,
  ): Promise<{
    exists: boolean;
    livemode: boolean | null;
    execution_id?: string | null;
    account_id?: string | null;
  } | null>;
  /** Decimals and USD price of an asset; null when rails does not know it or is unreachable. */
  asset(assetId: string, livemode: boolean): Promise<{ decimals: number; price_usd: string | null } | null>;
}

export interface Sentinel {
  readonly env: string;
  /** Where the client IP comes from (NP_CLIENT_IP_HEADER, NP_TRUSTED_PROXIES); default: by NP_ENV. */
  readonly clientIp?: ClientIpRule;
  readonly db: Kysely<DB>;
  readonly registry: Kysely<RegistryDB>;
  log: Logger;
  metrics: SentinelMetrics;
  readonly signingKey: SigningKey;
  readonly ticketKey: KeyObject;
  readonly live: StatusProvider | null;
  readonly test: SandboxStatus | null;
  /** The provider's token registry per mode (attested asset display data, CR-15-07); null: not configured. */
  readonly liveTokens: TokenRegistry | null;
  readonly testTokens: TokenRegistry | null;
  readonly rails: RailsClient;
  readonly cache: AttestationCache;
  readonly treasury: string | null;
  readonly testTreasury: string;
  readonly referral: string;
  readonly split: ProviderSplit;
  readonly intentsContract: string;
  readonly near: NearReader | null;
  readonly evm: ReadonlyMap<string, EvmReader>;
  /** Stage 4 (§16): sentinel's own Solana / Bitcoin readers; null = not configured (audits unverifiable). */
  readonly solana: SolanaReader | null;
  readonly bitcoin: EsploraReader | null;
  readonly auditSampleRate: number;
  readonly auditAlwaysUsdMicros: bigint;
  /** Adaptive two-person rule: wait before a single operator completes their own request (`NP_OPS_SINGLE_OPERATOR_DELAY_S`). */
  readonly singleOperator: SingleOperatorPolicy;
  /** Integrity containment: quarantine TTL, corroboration thresholds, R5 re-read (ADR-0028). */
  readonly containment: ContainmentPolicy;
  /** Automatic release of stale automatic stops (2026-11-13): tick and flap guard; default `DEFAULT_AUTO_RELEASE`. */
  readonly autoRelease?: AutoReleasePolicy;
  readonly random: () => number;
  readonly now: () => number;
}
