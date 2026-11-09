/**
 * Process wiring (lld/sentinel.md §2):
 * - `api`     co-signing (`POST /v1/attestations/deposit_instructions`), keys, ops kill switch
 * - `worker`  (`sentinel-auditor`) consumers (settled → audit job; destination disabled → cache
 *             eviction), jobs, outbox relay (kill-switch and finding events)
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
import { clientIpRule } from "../api/client-ip.js";
import { type KeyInfo, sentinelRoutes } from "../api/routes.js";
import { ed25519PublicKey, loadSigningKey } from "../co-signer/crypto.js";
import {
  type ApiConfig,
  bitcoinEsploraUrls,
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
import { oneClickStatus, type SandboxStatus, type StatusProvider, sandboxStatus } from "../infra/clients/providers.js";
import { railsClient } from "../infra/clients/rails.js";
import { oneClickTokens, sandboxTokenRegistry, type TokenRegistry } from "../infra/clients/tokens.js";
import { MIGRATIONS_DIR } from "../infra/db/migrations.js";
import type { DB, RegistryDB } from "../infra/db/schema.js";
import { killSwitchState } from "../kill-switch/kill-switch.js";
import { jobHandlers, RECURRING } from "../workers/jobs.js";
import {
  type AttestationCache,
  attestationCache,
  noMetrics,
  type RailsClient,
  type Sentinel,
  sentinelMetrics,
} from "./context.js";

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
}

function build(config: SharedConfig, deps: ServiceDeps, app: string): Built {
  const f = deps.fetch ? { fetch: deps.fetch } : {};
  const database = deps.database ?? createDb<DB>({ url: config.dbUrl, applicationName: `sentinel-${app}` });
  // read-only role on identity's registry view, 300 ms (§9)
  const registry =
    deps.registry ??
    createDb<RegistryDB>({
      url: config.registryDbUrl,
      applicationName: `sentinel-${app}`,
      max: 4,
      statementTimeoutMs: 300,
    });
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
        : oneClickTokens({ baseUrl: config.oneclickBaseUrl, apiKey: config.oneclickApiKey, ...f }),
    testTokens:
      deps.testTokens !== undefined
        ? deps.testTokens
        : config.sandboxBaseUrl
          ? sandboxTokenRegistry({ baseUrl: config.sandboxBaseUrl, serviceToken, ...f })
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
    random: deps.random ?? Math.random,
    now: deps.now ?? Date.now,
  };
  return { sentinel, database, registry };
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
  b.sentinel.metrics = sentinelMetrics(service.metrics, async () => (await killSwitchState(b.sentinel)).engaged);
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
  if (!deps.bus) service.onShutdown(() => bus.close());
  return { service, sentinel: s };
}
