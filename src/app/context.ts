/** Dependencies shared by sentinel use cases. */

import type { KeyObject } from "node:crypto";
import type { Kysely, Transaction } from "@nearpay-internal/db";
import type { Logger, ServiceMetrics } from "@nearpay-internal/service";
import { Redis } from "ioredis";
import type { ProviderSplit } from "../address-integrity/checks.js";
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
}

export const noMetrics: SentinelMetrics = {
  attestation() {},
  finding() {},
  killSwitch() {},
  coverageMissing() {},
  singleOperatorAction() {},
};

/** Service metrics (§12). The kill-switch gauge is read from the database on every scrape. */
export function sentinelMetrics(
  m: ServiceMetrics,
  engaged?: () => Promise<boolean>,
  singleOperatorAction: (action: string) => void = () => {},
): SentinelMetrics {
  const att = m.counter("attestations_total", "Co-signing requests by outcome.", ["kind", "result", "reason"]);
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
  return {
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
 * a verdict: `exists` only decides whether a security refusal engages the kill switch (§5), and `asset`
 * only feeds audit sampling (§7).
 */
export interface RailsClient {
  /** Did NearPay issue this deposit address? null = rails unreachable. */
  exists(address: string, memo: string | null): Promise<{ exists: boolean; livemode: boolean | null } | null>;
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
  readonly random: () => number;
  readonly now: () => number;
}
