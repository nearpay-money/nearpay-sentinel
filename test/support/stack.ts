/**
 * Integration harness: Postgres provisioned like nearpay-deploy's `postgres-init` (migrator owns the
 * database, the app role has DML only); identity's registry view emulated in an `identity` database
 * with the exact column list identity's contract test pins, read through a `sentinel_ro` role that can
 * only SELECT the view; the real `api` and `worker` processes from the factories `main.ts` uses; the
 * real **nearpay-sandbox image** for test mode; rails mocked from the spec; NATS for events; Valkey for
 * the shared cache.
 */
import { createServer as createHttpServer } from "node:http";
import { type AddressInfo, createServer } from "node:net";
import { publicJwk } from "@nearpay-internal/auth";
import { type Bus, connectBus, type Envelope, publish } from "@nearpay-internal/bus";
import { createDb, type Database, migrate, sql } from "@nearpay-internal/db";
import { newId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import type { Service } from "@nearpay-internal/service";
import { getInternalAsset, INTERNAL_ROUTES, lookupExecutionByDeposit } from "@nearpay-internal/spec";
import {
  type EventProbe,
  eventProbe,
  type MockPeer,
  mintOpsToken,
  mintServiceToken,
  mockPeer,
  provisionServiceDatabase,
  type Started,
  startNats,
  startPostgres,
  startValkey,
  testKeySource,
  testServiceToken,
  testSigningKey,
} from "@nearpay-internal/testing";
import { GenericContainer, type StartedTestContainer, Wait } from "testcontainers";
import { attestationCache, type Sentinel } from "../../src/app/context.js";
import { createApi, createWorker, type ServiceDeps, type WorkerDeps } from "../../src/app/services.js";
import type { WorkerConfig } from "../../src/config.js";
import { oneClickStatus, sandboxStatus } from "../../src/infra/clients/providers.js";
import { railsClient } from "../../src/infra/clients/rails.js";
import { MIGRATIONS_DIR } from "../../src/infra/db/migrations.js";
import type { DB, RegistryDB } from "../../src/infra/db/schema.js";
import type { FakeOneClick } from "./fakes.js";
import { mintTicket, newKeyPair } from "./keys.js";

export const SANDBOX_IMAGE = process.env.NP_SANDBOX_IMAGE ?? "nearpay/sandbox:local";
export const TREASURY = "treasury.nearpay.near";
export const LIVE_TREASURY = "intents.near"; // the recorded quote's appFee recipient
export const KID = "sent-it-1";
/** Operator of `opsToken()` (a console operator calling `POST /internal/kill-switch`). */
export const OPS_CLI_OPERATOR = "usr_01m6vree6ye928jvj2vxkyyz08";

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

async function waitHttp(url: string, ms = 60_000): Promise<void> {
  const until = Date.now() + ms;
  for (;;) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (r.ok) return;
    } catch {}
    if (Date.now() > until) throw new Error(`${url} did not become ready`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

export interface Sandbox {
  readonly url: string;
  readonly signingPubkey: string;
  readonly containers: StartedTestContainer[];
  /** Calls the sandbox as rails would (quotes, simulated deposits). */
  call(method: "GET" | "POST", path: string, body?: unknown): Promise<{ status: number; body: unknown }>;
}

async function startSandbox(pgUrl: string, jwksUrl: string): Promise<Sandbox> {
  const { migratorUrl, appUrl } = await provisionServiceDatabase(pgUrl, "sandbox");
  const k = newKeyPair();
  const port = await freePort();
  const metricsPort = await freePort();
  const base = (dbUrl: string) =>
    new GenericContainer(SANDBOX_IMAGE)
      .withNetworkMode("host")
      .withCopyContentToContainer([
        { content: dbUrl, target: "/run/secrets/db_url", mode: 0o444 },
        { content: k.pem, target: "/run/secrets/key", mode: 0o444 },
      ])
      .withEnvironment({
        NP_ENV: "local",
        NP_LOG_LEVEL: "warn",
        NP_PORT: String(port),
        NP_METRICS_PORT: String(metricsPort),
        NP_HOST: "127.0.0.1",
        NP_DB_URL_FILE: "/run/secrets/db_url",
        NP_SANDBOX_SIGNING_KEY_FILE: "/run/secrets/key",
        NP_JWKS_URL: jwksUrl,
        NP_SANDBOX_TIME_SCALE: "0.02",
        NP_SANDBOX_TICK_MS: "25",
      });
  const migrator = await base(migratorUrl)
    .withCommand(["dist/main.js", "migrate"])
    .withWaitStrategy(Wait.forOneShotStartup())
    .start();
  const api = await base(appUrl).withCommand(["dist/main.js", "api"]).start();
  const url = `http://127.0.0.1:${port}`;
  await waitHttp(`${url}/readyz`);
  return {
    url,
    signingPubkey: k.publicRaw,
    containers: [migrator, api],
    async call(method, path, body) {
      const r = await fetch(`${url}${path}`, {
        method,
        headers: {
          "x-nearpay-token": await mintServiceToken("rails"),
          ...(body ? { "content-type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      return { status: r.status, body: text ? JSON.parse(text) : undefined };
    },
  };
}

/** identity's `sentinel_destination_registry`, emulated: same columns, same filter, read-only role. */
async function startRegistry(pgUrl: string) {
  const reg = await provisionServiceDatabase(pgUrl, "identity", { roles: ["sentinel_ro"] });
  const owner = createDb<Record<string, never>>({ url: reg.migratorUrl });
  await sql`
    create table settlement_destinations (
      id uuid primary key, account_id uuid not null, livemode boolean not null, asset_id text not null,
      type text not null, chain text not null, address_norm text not null, status text not null,
      active_at timestamptz, merchant_name text not null, kyb_verified boolean not null,
      verification text not null, disabled_at timestamptz)`.execute(owner.db);
  await sql`
    create view sentinel_destination_registry as
      select id, account_id, livemode, asset_id, type, chain, address_norm, status, active_at, merchant_name,
             kyb_verified, verification, disabled_at
      from settlement_destinations where status = 'active' or (status = 'disabled' and active_at is not null)`.execute(
    owner.db,
  );
  await sql`grant select on sentinel_destination_registry to sentinel_ro`.execute(owner.db);
  // like nearpay-deploy's postgres-init (roles.sh): CONNECT on identity and USAGE on its schema only
  const su = createDb<Record<string, never>>({ url: reg.adminUrl });
  await sql`grant connect on database identity to sentinel_ro`.execute(su.db);
  await sql`grant usage on schema public to sentinel_ro`.execute(su.db);
  await su.close();
  return { reg, owner };
}

export interface Destination {
  id?: string;
  account_id?: string;
  livemode?: boolean;
  asset_id: string;
  type: "chain_address" | "intents_account";
  chain: string;
  address_norm: string;
  status?: string;
  active_at?: Date | null;
  merchant_name?: string;
  kyb_verified?: boolean;
  verification?: string;
  disabled_at?: Date | null;
}

export interface Stack {
  readonly pg: Started;
  readonly admin: Database<DB>;
  readonly api: Service;
  readonly sentinel: Sentinel;
  readonly apiUrl: string;
  readonly rails: MockPeer;
  /** Deposit addresses rails "issued" (lookupExecutionByDeposit answers exists for these). */
  readonly issued: Map<string, { livemode: boolean }>;
  readonly sandbox: Sandbox | null;
  readonly nats: (Started & { monitorUrl: string }) | null;
  readonly valkey: Started | null;
  readonly bus: Bus | null;
  readonly worker: { service: Service; sentinel: Sentinel } | null;
  readonly signingPublicRaw: string;
  readonly account: `acct_${string}`;
  /** Owner (migrator) connection of the emulated identity registry. */
  readonly registryOwner: Database<Record<string, never>>;
  /** Restores the default rails mock (after a test reset it). */
  mockRails(): void;
  /** Inserts a registry row (identity's side) and returns its uuid. */
  destination(d: Destination): Promise<string>;
  setDestinationStatus(id: string, status: string, disabledAt?: Date | null): Promise<void>;
  ticket(attemptId: string, livemode: boolean, depositKey: string, expS?: number): string;
  call(
    method: "GET" | "POST",
    path: string,
    o?: { body?: unknown; token?: string | null; headers?: Record<string, string> },
  ): Promise<{ status: number; body: unknown; headers: Headers }>;
  opsToken(scopes?: string[]): Promise<string>;
  /** A console operator token (`ptype=ops`, `sub` = `usr_…`, `ops_role`; step-up fresh unless `stepUp: false`). */
  operatorToken(o: {
    sub: string;
    role?: "ops" | "ops_admin";
    stepUp?: boolean;
    stepUpUntil?: number;
    scopes?: string[];
  }): Promise<string>;
  /** Another api process on the same databases with a config override (e.g. `env: "server"`). */
  extraApi(over: Partial<WorkerConfig>): Promise<{ call: Stack["call"]; stop(): Promise<void> }>;
  publishEvent(e: Envelope): Promise<void>;
  probe(filter?: string): Promise<EventProbe>;
  stop(): Promise<void>;
}

export interface StackOptions {
  sandbox?: boolean;
  worker?: boolean | WorkerDeps;
  oneclick?: FakeOneClick;
  valkey?: boolean;
  config?: Partial<WorkerConfig>;
  deps?: Partial<ServiceDeps>;
}

export async function startStack(o: StackOptions = {}): Promise<Stack> {
  const [pg, nats, valkey] = await Promise.all([
    startPostgres({ database: "postgres" }),
    o.worker ? startNats() : null,
    o.valkey ? startValkey() : null,
  ]);
  const { migratorUrl, appUrl } = await provisionServiceDatabase(pg.url, "sentinel");
  const migrator = createDb<DB>({ url: migratorUrl });
  await migrate(migrator.db, MIGRATIONS_DIR);
  await migrator.close();
  const admin = createDb<DB>({ url: appUrl, applicationName: "sentinel-test" });
  const { reg, owner } = await startRegistry(pg.url);

  const jwk = await publicJwk(testSigningKey());
  const jwks = createHttpServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [{ ...jwk, alg: "EdDSA", use: "sig" }] }));
  });
  await new Promise<void>((r) => jwks.listen(0, "127.0.0.1", r));
  const jwksUrl = `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/internal/jwks`;
  const sandbox = o.sandbox ? await startSandbox(pg.url, jwksUrl) : null;

  const issued = new Map<string, { livemode: boolean }>();
  const rails = await mockPeer({ service: "rails", routes: INTERNAL_ROUTES });
  const mockRails = () => {
    rails.on(lookupExecutionByDeposit, async (ctx) => {
      const hit = issued.get(ctx.query.deposit_address);
      return hit
        ? { exists: true, execution_id: newId("ex"), account_id: newId("acct"), livemode: hit.livemode }
        : { exists: false, execution_id: null, account_id: null, livemode: null };
    });
    rails.on(getInternalAsset, async (ctx) => ({
      asset_id: ctx.params.asset_id,
      chain: "near:mainnet",
      blockchain: "near",
      symbol: "USDC",
      decimals: 6,
      family: "USDC",
      is_usd_stable: true,
      price_usd: "1",
      price_ok: true,
      as_of: new Date().toISOString(),
    }));
  };
  mockRails();

  const ticketKey = newKeyPair();
  const signing = newKeyPair();
  const serviceToken = testServiceToken("sentinel");
  const config: WorkerConfig = {
    env: "test",
    logLevel: "silent",
    host: "127.0.0.1",
    port: 0,
    metricsPort: 0,
    dbUrl: appUrl,
    registryDbUrl: reg.roleUrl("sentinel_ro"),
    identityUrl: "http://127.0.0.1:9",
    serviceClientSecret: "unused",
    railsUrl: rails.url,
    sentinelSigningKey: signing.pem,
    sentinelAnnouncedKeys: [],
    paymentsTicketPubkey: ticketKey.publicRaw,
    treasuryAccount: LIVE_TREASURY,
    testTreasuryAccount: TREASURY,
    intentsContract: "intents.near",
    referral: "nearpay",
    providerSplit: { share_bps: 5000, floor_bps: 20, stable_floor_bps: 1 },
    oneclickBaseUrl: o.oneclick?.url ?? "http://127.0.0.1:9",
    auditSampleRate: 1,
    auditAlwaysUsd: 10_000,
    nearRpcUrls: ["http://127.0.0.1:9"],
    evmRpcUrls_1: [],
    evmRpcUrls_8453: [],
    evmRpcUrls_42161: [],
    natsUrl: nats?.url ?? "nats://127.0.0.1:9",
    signingKeyPath: `/run/secrets/sentinel-${KID}.pem`,
    ...(valkey ? { valkeyUrl: valkey.url } : {}),
    ...(sandbox ? { sandboxBaseUrl: sandbox.url, sandboxSigningPubkey: sandbox.signingPubkey } : {}),
    ...(o.config as object),
  } as WorkerConfig;
  const deps: ServiceDeps = {
    keys: testKeySource(),
    serviceToken,
    live: o.oneclick
      ? oneClickStatus({ baseUrl: o.oneclick.url, managerPublicKey: o.oneclick.managerPublicKey })
      : null,
    test: sandbox ? sandboxStatus({ baseUrl: sandbox.url, signingPubkey: sandbox.signingPubkey, serviceToken }) : null,
    rails: railsClient({ baseUrl: rails.url, serviceToken }),
    near: null,
    evm: new Map(),
    ...o.deps,
  };

  const { service: api, sentinel } = createApi(config, {
    ...deps,
    database: createDb<DB>({ url: appUrl, applicationName: "sentinel-api-test" }),
    registry: createDb<RegistryDB>({
      url: config.registryDbUrl,
      applicationName: "sentinel-api-test",
      statementTimeoutMs: 300,
    }),
    cache: attestationCache(config.valkeyUrl),
  });
  const { port } = await api.start();

  let worker: Stack["worker"] = null;
  let bus: Bus | null = null;
  if (o.worker && nats) {
    bus = await connectBus({ url: nats.url, name: "sentinel-test-publisher" });
    const w = await createWorker(config, {
      ...deps,
      database: createDb<DB>({ url: appUrl, applicationName: "sentinel-worker-test" }),
      registry: createDb<RegistryDB>({
        url: config.registryDbUrl,
        applicationName: "sentinel-worker-test",
        statementTimeoutMs: 300,
      }),
      cache: attestationCache(config.valkeyUrl),
      tickMs: 50,
      ...(typeof o.worker === "object" ? o.worker : {}),
    });
    await w.service.start();
    worker = w;
  }
  const account = newId("acct");
  const apiUrl = `http://127.0.0.1:${port}`;
  return {
    pg,
    admin,
    api,
    sentinel,
    apiUrl,
    rails,
    issued,
    sandbox,
    nats,
    valkey,
    bus,
    worker,
    signingPublicRaw: signing.publicRaw,
    account,
    registryOwner: owner,
    mockRails,
    async destination(d) {
      const id = d.id ?? uuidv7();
      await sql`
        insert into settlement_destinations (id, account_id, livemode, asset_id, type, chain, address_norm, status,
          active_at, merchant_name, kyb_verified, verification, disabled_at)
        values (${id}, ${d.account_id ?? toUuid(account, "acct")}, ${d.livemode ?? false},
          ${d.asset_id}, ${d.type}, ${d.chain}, ${d.address_norm}, ${d.status ?? "active"},
          ${d.active_at === undefined ? new Date(Date.now() - 86_400_000) : d.active_at}, ${d.merchant_name ?? "Acme GmbH"},
          ${d.kyb_verified ?? true}, ${d.verification ?? "test"}, ${d.disabled_at ?? null})`.execute(owner.db);
      return id;
    },
    async setDestinationStatus(id, status, disabledAt = null) {
      await sql`update settlement_destinations set status = ${status}, disabled_at = ${disabledAt} where id = ${id}`.execute(
        owner.db,
      );
    },
    ticket(attemptId, livemode, depositKey, expS = Math.floor(Date.now() / 1000) + 900) {
      return mintTicket(ticketKey.privateKey, { attempt_id: attemptId, livemode, deposit_key: depositKey, exp: expS });
    },
    async call(method, path, c = {}) {
      const res = await fetch(`${apiUrl}${path}`, {
        method,
        headers: {
          ...(c.token ? { "x-nearpay-token": c.token } : {}),
          ...(c.body !== undefined ? { "content-type": "application/json" } : {}),
          ...c.headers,
        },
        body: c.body === undefined ? undefined : JSON.stringify(c.body),
      });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : undefined, headers: res.headers };
    },
    opsToken: (scopes = ["sentinel.killswitch"]) => mintOpsToken({ sub: OPS_CLI_OPERATOR, role: "ops", scopes }),
    operatorToken: (t) =>
      mintOpsToken({
        sub: t.sub,
        role: t.role ?? "ops",
        ...(t.scopes ? { scopes: t.scopes } : {}),
        stepUp: t.stepUp === false ? false : t.stepUpUntil ? t.stepUpUntil - Math.floor(Date.now() / 1000) : true,
      }),
    async extraApi(over) {
      const { service } = createApi({ ...config, ...over } as WorkerConfig, {
        ...deps,
        database: createDb<DB>({ url: appUrl, applicationName: "sentinel-api-extra" }),
        registry: createDb<RegistryDB>({ url: config.registryDbUrl, applicationName: "sentinel-api-extra" }),
        cache: attestationCache(undefined),
      });
      const { port: p } = await service.start();
      const base = `http://127.0.0.1:${p}`;
      return {
        async call(method, path, c = {}) {
          const res = await fetch(`${base}${path}`, {
            method,
            headers: {
              ...(c.token ? { "x-nearpay-token": c.token } : {}),
              ...(c.body !== undefined ? { "content-type": "application/json" } : {}),
              ...c.headers,
            },
            body: c.body === undefined ? undefined : JSON.stringify(c.body),
          });
          const text = await res.text();
          return { status: res.status, body: text ? JSON.parse(text) : undefined, headers: res.headers };
        },
        stop: () => service.stop(),
      };
    },
    async publishEvent(e) {
      if (!bus) throw new Error("no bus (start the stack with a worker)");
      await publish(bus, e.subject, e, e.id);
    },
    async probe(filter = "evt.sentinel.>") {
      if (!nats) throw new Error("no NATS");
      return eventProbe(nats.url, filter);
    },
    async stop() {
      await worker?.service.stop().catch(() => {});
      await api.stop().catch(() => {});
      await bus?.close().catch(() => {});
      await rails.stop().catch(() => {});
      for (const c of sandbox?.containers ?? []) await c.stop().catch(() => {});
      await new Promise<void>((r) => jwks.close(() => r()));
      await admin.close();
      await owner.close();
      await valkey?.stop().catch(() => {});
      await nats?.stop().catch(() => {});
      await pg.stop().catch(() => {});
    },
  };
}
