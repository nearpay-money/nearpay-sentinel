/**
 * Process wiring (lld/sentinel.md §2):
 * - `api`     co-signing (`POST /v1/attestations/deposit_instructions`), keys, ops kill switch
 * - `worker`  (`sentinel-auditor`) consumers (settled → audit job; destination disabled → cache
 *             eviction), jobs, outbox relay (kill-switch and finding events), automatic release of stale
 *             automatic stops (kill-switch/auto-release.ts)
 */

import { hostname } from "node:os";
import type { KeySource } from "@nearpay-internal/auth";
import { serviceTokenClient } from "@nearpay-internal/auth";
import {
  type Bus,
  busReady,
  connectBus,
  consumerLag,
  domainConsumersTask,
  durablesOf,
  ensureStreams,
  publish,
} from "@nearpay-internal/bus";
import {
  createDb,
  type Database,
  deadLettersOpen,
  jobsDue,
  jobWorkerTask,
  migrationStatus,
  outboxLagSeconds,
  outboxRelayTask,
  recurringJobsTask,
  sql,
} from "@nearpay-internal/db";
import { createService, type Service } from "@nearpay-internal/service";
import { STREAMS, type Subject } from "@nearpay-internal/spec";
import { feeConfigHash } from "../address-integrity/config-hash.js";
import { clientIpRule } from "../api/client-ip.js";
import { type KeyInfo, sentinelRoutes } from "../api/routes.js";
import { ed25519PublicKey, loadSigningKey } from "../co-signer/crypto.js";
import {
  type ApiConfig,
  autoReleasePolicy,
  bitcoinEsploraUrls,
  containmentPolicy,
  evmRpcUrls,
  nearRpcUrls,
  type SharedConfig,
  solanaRpcUrls,
  type WorkerConfig,
} from "../config.js";
import { deadLetters, sentinelHandlers } from "../consumers/handlers.js";
import {
  type EsploraReader,
  type EvmReader,
  esploraReader,
  evmReader,
  type NearReader,
  nearReader,
  type SolanaReader,
  solanaReader,
} from "../infra/clients/chains.js";
import { jwtExpiry } from "../infra/clients/oneclick-auth.js";
import { oneClickStatus, type SandboxStatus, type StatusProvider, sandboxStatus } from "../infra/clients/providers.js";
import { railsClient } from "../infra/clients/rails.js";
import { oneClickTokens, sandboxTokenRegistry, type TokenRegistry } from "../infra/clients/tokens.js";
import { MIGRATIONS_DIR } from "../infra/db/migrations.js";
import type { DB, RegistryDB } from "../infra/db/schema.js";
import { dbTokenListStore } from "../infra/db/token-store.js";
import { autoReleaseTask } from "../kill-switch/auto-release.js";
import { quarantinesActive, systemicWindow } from "../kill-switch/containment.js";
import { killSwitchState } from "../kill-switch/kill-switch.js";
import { jobHandlers, RECURRING } from "../workers/jobs.js";
import {
  type AttestationCache,
  attestationCache,
  noMetrics,
  type RailsClient,
  type Sentinel,
  type StaticGauges,
  sentinelMetrics,
} from "./context.js";
import { logSingleOperatorPolicy, registerSingleOperatorCounter } from "./single-operator-metrics.js";

/** Boot line: how integrity refusals are contained (ADR-0028). */
function logContainmentPolicy(log: Service["log"], p: Sentinel["containment"]): void {
  log.info(
    {
      quarantine_ttl_s: p.quarantineTtlMs / 1000,
      systemic_refusals: p.systemicRefusals,
      systemic_accounts: p.systemicAccounts,
      systemic_window_s: p.systemicWindowMs / 1000,
    },
    "integrity containment: a breach quarantines one account; the global switch engages only on corroborated breaches across accounts",
  );
}

/** Boot lines: the fee-config fingerprint (compare with rails) and the 1Click key expiry when it is a JWT. */
function logStatics(log: Service["log"], st: StaticGauges, nowMs: number): void {
  log.info({ fee_config_hash: st.feeConfigHash }, "fee configuration fingerprint (rails must show the same)");
  const exp = st.oneClickKeyExpiry?.live ?? null;
  if (exp === null) return;
  const days = (exp * 1000 - nowMs) / 86_400_000;
  if (days < 7)
    log.error(
      { alert: "oneclick_key_expiring", expires_at: new Date(exp * 1000).toISOString() },
      `ALERT sentinel's 1Click key expires in ${Math.max(0, Math.floor(days))} day(s): payments cannot be checked after that. Put a new key in NP_ONECLICK_API_KEY_FILE`,
    );
  else log.info({ expires_at: new Date(exp * 1000).toISOString() }, "1Click key expiry");
}

/** `GET /v1/attestations/keys` when no retirement is scheduled. */
export const NO_RETIREMENT = "9999-12-31T23:59:59.000Z";

export interface ServiceDeps {
  database?: Database<DB>;
  registry?: Database<RegistryDB>;
  keys?: KeySource;
  serviceToken?: () => Promise<string>;
  live?: StatusProvider | null;
  test?: SandboxStatus | null;
  liveTokens?: TokenRegistry | null;
  testTokens?: TokenRegistry | null;
  rails?: RailsClient;
  cache?: AttestationCache;
  near?: NearReader | null;
  evm?: ReadonlyMap<string, EvmReader>;
  solana?: SolanaReader | null;
  bitcoin?: EsploraReader | null;
  fetch?: typeof fetch;
  random?: () => number;
  now?: () => number;
}

interface Built {
  sentinel: Sentinel;
  database: Database<DB>;
  registry: Database<RegistryDB>;
  /** Exported once at boot (fee-config fingerprint, 1Click key expiry). */
  statics: StaticGauges;
}

/** Connection-acquire timeout of the registry pool (SENTINEL-5). */
export const REGISTRY_CONNECT_TIMEOUT_MS = 1_000;

function build(config: SharedConfig, deps: ServiceDeps, app: string): Built {
  const f = deps.fetch ? { fetch: deps.fetch } : {};
  const database = deps.database ?? createDb<DB>({ url: config.dbUrl, applicationName: `sentinel-${app}` });
  // read-only role on identity's registry view, 300 ms statements (§9); 8 connections and a 1 s
  // connection-acquire timeout so concurrent checkouts never queue without bound (SENTINEL-5; kit 0.3.1's
  // createDb has no option for it yet — KIT-5 — so the pool option is set on the pool it built)
  const registry =
    deps.registry ??
    (() => {
      const r = createDb<RegistryDB>({
        url: config.registryDbUrl,
        applicationName: `sentinel-${app}`,
        max: 8,
        statementTimeoutMs: 300,
      });
      r.pool.options.connectionTimeoutMillis = REGISTRY_CONNECT_TIMEOUT_MS;
      return r;
    })();
  const serviceToken =
    deps.serviceToken ??
    (() => {
      const c = serviceTokenClient({
        identityUrl: config.identityUrl,
        clientId: "sentinel",
        secret: config.serviceClientSecret,
        ...f,
      });
      return () => c.getToken();
    })();
  const evm =
    deps.evm ??
    new Map(
      Object.entries(evmRpcUrls(config))
        .filter(([, urls]) => urls.length > 0)
        .map(([chain, urls]) => [chain, evmReader({ urls, ...f })] as const),
    );
  const sentinel: Sentinel = {
    env: config.env,
    clientIp: clientIpRule(config.env, { header: config.clientIpHeader, trustedProxies: config.trustedProxies }),
    db: database.db,
    registry: registry.db,
    log: undefined as unknown as Sentinel["log"],
    metrics: noMetrics,
    signingKey: loadSigningKey(config.sentinelSigningKey, config.signingKeyPath),
    ticketKey: ed25519PublicKey(config.paymentsTicketPubkey),
    live:
      deps.live !== undefined
        ? deps.live
        : oneClickStatus({ baseUrl: config.oneclickBaseUrl, apiKey: config.oneclickApiKey, ...f }),
    test:
      deps.test !== undefined
        ? deps.test
        : config.sandboxBaseUrl && config.sandboxSigningPubkey
          ? sandboxStatus({
              baseUrl: config.sandboxBaseUrl,
              signingPubkey: config.sandboxSigningPubkey,
              serviceToken,
              ...f,
            })
          : null,
    liveTokens:
      deps.liveTokens !== undefined
        ? deps.liveTokens
        : oneClickTokens({
            baseUrl: config.oneclickBaseUrl,
            apiKey: config.oneclickApiKey,
            store: dbTokenListStore(database.db, "live"),
            ...f,
          }),
    testTokens:
      deps.testTokens !== undefined
        ? deps.testTokens
        : config.sandboxBaseUrl
          ? sandboxTokenRegistry({
              baseUrl: config.sandboxBaseUrl,
              serviceToken,
              store: dbTokenListStore(database.db, "test"),
              ...f,
            })
          : null,
    rails: deps.rails ?? railsClient({ baseUrl: config.railsUrl, serviceToken, ...f }),
    cache: deps.cache ?? attestationCache(config.valkeyUrl),
    treasury: config.treasuryAccount ?? null,
    testTreasury: config.testTreasuryAccount,
    referral: config.referral,
    split: {
      shareBps: config.providerSplit.share_bps,
      floorBps: config.providerSplit.floor_bps,
      stableFloorBps: config.providerSplit.stable_floor_bps,
    },
    intentsContract: config.intentsContract,
    near:
      deps.near !== undefined
        ? deps.near
        : nearReader({ urls: nearRpcUrls(config), senderHint: config.intentsContract, ...f }),
    evm,
    solana:
      deps.solana !== undefined
        ? deps.solana
        : solanaRpcUrls(config).length
          ? solanaReader({ urls: solanaRpcUrls(config), ...f })
          : null,
    bitcoin:
      deps.bitcoin !== undefined
        ? deps.bitcoin
        : bitcoinEsploraUrls(config).length
          ? esploraReader({ urls: bitcoinEsploraUrls(config), ...f })
          : null,
    auditSampleRate: config.auditSampleRate,
    auditAlwaysUsdMicros: BigInt(Math.round(config.auditAlwaysUsd * 1_000_000)),
    singleOperator: { delayMs: (config.opsSingleOperatorDelayS ?? 300) * 1000 },
    containment: containmentPolicy(config),
    autoRelease: autoReleasePolicy(config),
    random: deps.random ?? Math.random,
    now: deps.now ?? Date.now,
  };
  const statics: StaticGauges = {
    feeConfigHash: feeConfigHash(sentinel),
    oneClickKeyExpiry: { live: jwtExpiry(config.oneclickApiKey) },
  };
  return { sentinel, database, registry, statics };
}

function readiness(b: Built) {
  return {
    db: () => sql`select 1`.execute(b.database.db),
    migrations: async () => {
      const s = await migrationStatus(b.database.db, MIGRATIONS_DIR);
      if (s.pending.length || s.drift.length)
        throw new Error(`pending ${s.pending.join(",") || "-"} drift ${s.drift.join(",") || "-"}`);
    },
    registry: () => sql`select 1 from sentinel_destination_registry limit 1`.execute(b.registry.db),
  };
}

function attach(b: Built, service: Service, deps: ServiceDeps) {
  b.sentinel.log = service.log;
  logSingleOperatorPolicy(service.log, b.sentinel.singleOperator.delayMs / 1000);
  b.sentinel.metrics = sentinelMetrics(
    service.metrics,
    async () => (await killSwitchState(b.sentinel)).engaged,
    registerSingleOperatorCounter(service.metrics),
    {
      quarantinesActive: () => quarantinesActive(b.sentinel),
      systemicWindow: () => systemicWindow(b.sentinel),
    },
    b.statics,
  );
  logContainmentPolicy(service.log, b.sentinel.containment);
  logStatics(service.log, b.statics, b.sentinel.now());
  service.onShutdown(async () => {
    if (!deps.cache) await b.sentinel.cache.close();
    if (!deps.registry) await b.registry.close();
    if (!deps.database) await b.database.close();
  });
}

/** The sentinel context for the ops CLI (no listener, no background tasks). */
export function createOpsContext(
  config: SharedConfig,
  log: Sentinel["log"],
  deps: ServiceDeps = {},
): { sentinel: Sentinel; close(): Promise<void> } {
  const b = build(config, deps, "ops");
  b.sentinel.log = log;
  return {
    sentinel: b.sentinel,
    async close() {
      if (!deps.cache) await b.sentinel.cache.close();
      if (!deps.registry) await b.registry.close();
      if (!deps.database) await b.database.close();
    },
  };
}

export function createApi(config: ApiConfig, deps: ServiceDeps = {}): { service: Service; sentinel: Sentinel } {
  const b = build(config, deps, "api");
  const keys: KeyInfo = {
    notAfter: config.sentinelKeyNotAfter ?? NO_RETIREMENT,
    announced: config.sentinelAnnouncedKeys,
  };
  const service = createService({
    name: "sentinel",
    config,
    ...(deps.keys ? { keys: deps.keys } : {}),
    routes: sentinelRoutes(b.sentinel, keys),
    readiness: readiness(b),
  });
  attach(b, service, deps);
  return { service, sentinel: b.sentinel };
}

export interface WorkerDeps extends ServiceDeps {
  bus?: Bus;
  tickMs?: number;
  /** Automatic-release check period override (tests); default `NP_KILL_SWITCH_AUTO_RELEASE_TICK_S`. */
  autoReleaseTickMs?: number;
}

export async function createWorker(
  config: WorkerConfig,
  deps: WorkerDeps = {},
): Promise<{ service: Service; sentinel: Sentinel }> {
  const b = build(config, deps, "worker");
  const s = b.sentinel;
  const service = createService({ name: "sentinel", config, readiness: readiness(b) });
  attach(b, service, deps);
  const db = b.database;

  const bus = deps.bus ?? (await connectBus({ url: config.natsUrl, name: `sentinel-worker@${hostname()}` }));
  await ensureStreams(bus, [STREAMS.sentinel]);
  service.addReadiness("bus", () => {
    if (!busReady(bus)) throw new Error("NATS connection is closed");
  });
  const handlers = sentinelHandlers(db.db, s.cache);
  const durables = durablesOf("sentinel", Object.keys(handlers) as Subject[]);
  service.metrics.collectConsumerLag(async () =>
    Object.fromEntries(
      await Promise.all(durables.map(async (d) => [d.durable, await consumerLag(bus, d.stream, d.durable)])),
    ),
  );
  service.metrics.collectOutboxLag(() => outboxLagSeconds(db.db));
  service.metrics.collectJobsDue(() => jobsDue(db.db));
  service.metrics.collectDeadLettersOpen(() => deadLettersOpen(db.db));

  const onError = (e: unknown) => service.log.error({ err: e }, "background error");
  service.addBackground(
    outboxRelayTask({
      db: db.db,
      pool: db.pool,
      publish: (sub, e, mid) => publish(bus, sub, e, mid).then(() => {}),
      onError,
    }),
  );
  service.addBackground(
    domainConsumersTask({ bus, consumer: "sentinel", handlers, onDeadLetter: deadLetters(db.db), onError }),
  );
  service.addBackground(
    jobWorkerTask({
      db: db.db,
      workerId: `sentinel-worker@${hostname()}:${process.pid}`,
      handlers: jobHandlers(s),
      onError: (e, job) => service.log.warn({ err: e instanceof Error ? e.message : String(e), job }, "job failed"),
      onDeadLetter: (j) => service.log.error({ job: j }, "ALERT job dead-lettered"),
      ...(deps.tickMs ? { pollMs: deps.tickMs } : {}),
    }),
  );
  service.addBackground(
    recurringJobsTask({
      db: db.db,
      pool: db.pool,
      name: "sentinel:recurring-jobs",
      jobs: RECURRING,
      onError,
      ...(deps.tickMs ? { tickMs: deps.tickMs } : {}),
    }),
  );
  // stale automatic stops release themselves (owner decision 2026-11-13): once at boot, then every tick
  service.addBackground(autoReleaseTask(s, deps.autoReleaseTickMs ? { tickMs: deps.autoReleaseTickMs } : {}));
  if (!deps.bus) service.onShutdown(() => bus.close());
  return { service, sentinel: s };
}
