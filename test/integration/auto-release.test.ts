/**
 * Automatic release of stale automatic stops (owner decision 2026-11-13; ADR-0028 amendment 2026-11-13) on real
 * Postgres and NATS: the live incident (actor sentinel, "integrity breach on 0x11D2…5036: R4 deposit chain
 * differs", 2026-11-11T18:58:29Z) is released by sentinel-auditor on boot and on its tick through the normal
 * release path (version + 1, kill_switch_log, outbox `released`, quarantine cleanup) and the next attestation
 * signs. An operator's stop, a corroborated systemic stop and unjudgeable evidence are never released; the flap
 * guard stops automatic release after more than 3 re-engagements within an hour.
 */
import { createDb, sql } from "@nearpay-internal/db";
import { newId, toUuid } from "@nearpay-internal/ids";
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import { routeQuoteDepositKey } from "@nearpay-money/spec";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { resetSpoofCounters } from "../../src/co-signer/attest.js";
import type { DB } from "../../src/infra/db/schema.js";
import { AUTO_RELEASED_MESSAGE, autoReleaseStaleStop, autoReleaseTask } from "../../src/kill-switch/auto-release.js";
import { quarantinesActive } from "../../src/kill-switch/containment.js";
import { killSwitchState, setKillSwitch } from "../../src/kill-switch/kill-switch.js";
import { runOps } from "../../src/ops/cli.js";
import { type FakeOneClick, fakeOneClick, PROVIDER_FEE_ACCOUNT } from "../support/fakes.js";
import { LIVE_TREASURY, type Stack, startStack } from "../support/stack.js";

const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const PATH = "/v1/attestations/deposit_instructions";
const MERCHANTS = ["a", "b", "c"] as const;
type M = (typeof MERCHANTS)[number];

const INCIDENT_REASON = "integrity breach on 0x11D278921A31AB448c7e27F33c2313C130B05036: R4 deposit chain differs";
const INCIDENT_AT = "2026-11-11T18:58:29Z";
const AUTO_REASON = `auto-released: ${INCIDENT_REASON} — no longer platform evidence under ADR-0028`;

let s: Stack;
let oc: FakeOneClick;
const acct = {} as Record<M, `acct_${string}`>;
const recipient = (m: M) => `merchant-${m}.near`;

beforeAll(async () => {
  oc = await fakeOneClick();
  // the stack's own worker checks once at boot (nothing engaged) and then not again during the tests
  s = await startStack({ oneclick: oc, worker: { autoReleaseTickMs: 3_600_000 } });
  for (const m of MERCHANTS) {
    acct[m] = m === "a" ? s.account : newId("acct");
    await s.destination({
      account_id: toUuid(acct[m], "acct"),
      livemode: true,
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: recipient(m),
      verification: "signature",
    });
  }
});
afterAll(async () => {
  await s?.stop();
  await oc?.stop();
});
beforeEach(async () => {
  resetSpoofCounters();
  s.issued.clear();
  await s.resetContainment();
  await sql`update kill_switch set engaged = false where id = 1`.execute(s.admin.db);
  await s.resetKillSwitchLog();
});

const fees = [
  { recipient: LIVE_TREASURY, fee: 25 },
  { recipient: PROVIDER_FEE_ACCOUNT, fee: 25 },
];

function quote(m: M, o: { tamper?: boolean } = {}): OneClickQuoteResponse {
  const q = oc.quote({
    request: { appFees: fees, recipient: recipient(m) },
    ...(o.tamper ? { afterSign: (x: OneClickQuoteResponse) => (x.quoteRequest.referral = "attacker") } : {}),
  });
  s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
  return q;
}

function body(q: OneClickQuoteResponse) {
  const attempt = newId("pa");
  const address = q.quote.depositAddress as string;
  return {
    livemode: true,
    kind: "route_quote",
    attempt_id: attempt,
    attestation_ticket: s.ticket(attempt, true, routeQuoteDepositKey("oneclick", address, null)),
    deposit: {
      address,
      memo: null,
      chain: "eip155:8453",
      origin_asset_id: USDC_BASE,
      amount_in: q.quote.amountIn,
      deadline: q.quote.deadline,
    },
  };
}

const attest = (b: unknown) =>
  s.call("POST", PATH, { body: b, headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" } });

async function ops(...argv: string[]) {
  const out: string[] = [];
  const code = await runOps(argv, s.sentinel, { actor: "cli@test", out: (l) => out.push(l), err: () => {} });
  return { code, json: out.length ? JSON.parse(out.join("\n")) : null };
}

/** The live incident as its row read on 2026-11-12 (engaged by sentinel's old single-payment check). */
async function engageIncident(): Promise<number> {
  const r = await sql<{ version: number }>`update kill_switch set engaged = true, actor = 'sentinel',
    reason = ${INCIDENT_REASON}, updated_at = ${new Date(INCIDENT_AT)}, version = version + 1
    where id = 1 returning version`.execute(s.admin.db);
  return (r.rows[0] as { version: number }).version;
}

async function until(cond: () => Promise<boolean>, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("timed out");
}

type Line = { level: string; obj: Record<string, unknown>; msg: string };
/** The sentinel with a logger that records every line. */
function capturing(base: Sentinel = s.sentinel): { sentinel: Sentinel; lines: Line[] } {
  const lines: Line[] = [];
  const at =
    (level: string) =>
    (obj: unknown, msg?: string): void => {
      lines.push(
        typeof obj === "string"
          ? { level, obj: {}, msg: obj }
          : { level, obj: obj as Record<string, unknown>, msg: msg ?? "" },
      );
    };
  const log = {
    info: at("info"),
    warn: at("warn"),
    error: at("error"),
    debug: at("debug"),
    trace: at("trace"),
    fatal: at("fatal"),
  };
  return { sentinel: { ...base, log: log as unknown as Sentinel["log"] }, lines };
}

async function expectIncidentReleased(version: number) {
  const st = await killSwitchState(s.sentinel);
  expect(st).toMatchObject({ engaged: false, actor: "sentinel", reason: AUTO_REASON, version: version + 1 });
  const log = await s.admin.db
    .selectFrom("kill_switch_log")
    .selectAll()
    .orderBy("version", "desc")
    .executeTakeFirstOrThrow();
  expect(log).toMatchObject({ engaged: false, actor: "sentinel", reason: AUTO_REASON, version: version + 1 });
  const out = await s.admin.db
    .selectFrom("outbox")
    .selectAll()
    .where("subject", "=", "evt.sentinel.kill_switch.released")
    .orderBy("created_at", "desc")
    .executeTakeFirstOrThrow();
  expect(out.aggregate_version).toBe(version + 1);
}

describe("the live incident is released automatically", () => {
  it("on boot: sentinel-auditor releases it, clears the stop's quarantines, and the next attestation signs", async () => {
    // a merchant paused by sentinel during the stop
    expect((await attest(body(quote("a", { tamper: true })))).status).toBe(409);
    expect(await quarantinesActive(s.sentinel)).toBe(1);
    expect((await attest(body(quote("a")))).status).toBe(503);
    const version = await engageIncident();

    const status = await ops("kill-switch-release-status");
    expect(status.json).toMatchObject({
      engaged: true,
      would_engage_under_current_rules: false,
      automatic_release: { expected: true, why: expect.stringMatching(/single payment's check/) },
      merchants_switched_back_on_by_release: 1,
    });
    expect(Date.parse(status.json.automatic_release.expected_by)).toBeGreaterThan(Date.now());
    expect(status.json.assessment).toMatch(/switches payments back on by itself/);
    expect(status.json.steps[0]).toMatch(/^Nothing to do: sentinel switches payments back on by itself/);
    expect(status.json.steps[1]).toMatch(/Request release/);

    // a sentinel-auditor process starts: its boot check releases the stop (its tick is an hour away)
    const w = await s.startWorker({ autoReleaseTickMs: 3_600_000 });
    try {
      expect(w.service.liveness().loops).toHaveProperty("sentinel:kill-switch-auto-release");
      await until(async () => !(await killSwitchState(s.sentinel)).engaged);
    } finally {
      await w.service.stop();
    }
    await expectIncidentReleased(version);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    const cleared = await s.admin.db
      .selectFrom("quarantine_log")
      .select(["action", "actor", "reason"])
      .where("account_id", "=", toUuid(acct.a, "acct"))
      .orderBy("version", "desc")
      .executeTakeFirstOrThrow();
    expect(cleared).toEqual({ action: "cleared", actor: "sentinel", reason: `kill switch released: ${AUTO_REASON}` });
    // the next attestation signs
    expect((await attest(body(quote("a")))).status).toBe(200);
    expect((await ops("kill-switch-release-status")).json).toMatchObject({ engaged: false });
  });

  it("on tick: a running sentinel-auditor releases it within one period", async () => {
    const w = await s.startWorker({ autoReleaseTickMs: 300 });
    try {
      await new Promise((r) => setTimeout(r, 400)); // boot check done: nothing engaged
      expect((await attest(body(quote("b", { tamper: true })))).status).toBe(409);
      const version = await engageIncident();
      await until(async () => !(await killSwitchState(s.sentinel)).engaged, 5_000);
      await expectIncidentReleased(version);
      expect(await quarantinesActive(s.sentinel)).toBe(0);
      expect((await attest(body(quote("b")))).status).toBe(200);
    } finally {
      await w.service.stop();
    }
  });

  it("logs an INFO line and the plain-words ALERT line, and counts the metric by reason class", async () => {
    await engageIncident();
    const counted: string[] = [];
    const c = capturing();
    const r = await autoReleaseStaleStop({
      ...c.sentinel,
      metrics: { ...c.sentinel.metrics, killSwitchAutoReleased: (k: string) => counted.push(k) },
    });
    expect(r).toMatchObject({ action: "released", class: "omdep_misparse", previousReason: INCIDENT_REASON });
    expect(counted).toEqual(["omdep_misparse"]);
    expect(c.lines).toContainEqual(
      expect.objectContaining({ level: "info", msg: expect.stringMatching(/^kill switch auto-released/) }),
    );
    expect(c.lines).toContainEqual({
      level: "warn",
      obj: expect.objectContaining({ alert: "kill_switch_auto_released", reason_class: "omdep_misparse" }),
      msg: `ALERT ${AUTO_RELEASED_MESSAGE}`,
    });
    expect(AUTO_RELEASED_MESSAGE).toBe(
      "Payments were paused by an automatic check that turned out to be a false alarm. They have been switched back on automatically.",
    );
    // nothing left to do
    expect(await autoReleaseStaleStop(s.sentinel)).toEqual({ action: "none" });
  });
});

describe("stops that are never released automatically", () => {
  it("an operator's engagement is untouched", async () => {
    expect((await ops("kill-switch-engage", "investigating", "a", "report")).code).toBe(0);
    const before = await killSwitchState(s.sentinel);
    expect(await autoReleaseStaleStop(s.sentinel)).toMatchObject({ action: "kept", decision: { keep: "operator" } });
    expect(await killSwitchState(s.sentinel)).toEqual(before);
    const status = (await ops("kill-switch-release-status")).json;
    expect(status.automatic_release).toEqual({
      expected: false,
      expected_by: null,
      why: "Sentinel will not switch payments back on by itself: an operator engaged it.",
    });
    expect(status.steps[0]).toMatch(/Request release/);
  });

  it("corroborated systemic evidence is untouched (the operator release, wait unchanged)", async () => {
    for (const m of ["a", "b", "a"] as const) expect((await attest(body(quote(m, { tamper: true })))).status).toBe(409);
    const before = await killSwitchState(s.sentinel);
    expect(before).toMatchObject({ engaged: true, actor: "sentinel" });
    expect(await autoReleaseStaleStop(s.sentinel)).toMatchObject({
      action: "kept",
      decision: { keep: "corroborated", why: "still corroborated: 3 refusals across 2 merchants" },
    });
    expect(await killSwitchState(s.sentinel)).toEqual(before);
    expect(await quarantinesActive(s.sentinel)).toBe(2);
    expect((await ops("kill-switch-release-status")).json).toMatchObject({
      would_engage_under_current_rules: true,
      automatic_release: { expected: false },
    });
  });

  it("a stale stop with corroborated evidence that arrived during it is untouched", async () => {
    await engageIncident();
    for (const m of ["a", "b", "a"] as const) expect((await attest(body(quote(m, { tamper: true })))).status).toBe(409);
    expect(await autoReleaseStaleStop(s.sentinel)).toMatchObject({
      action: "kept",
      decision: { keep: "new_evidence" },
    });
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
  });

  it("unjudgeable evidence is untouched and pages: a systemic stop with nothing on record, an unknown reason", async () => {
    await sql`update kill_switch set engaged = true, actor = 'sentinel', updated_at = now(),
      reason = 'systemic integrity breach: 3 refusals on NearPay deposit addresses across 2 accounts within 15 min' where id = 1`.execute(
      s.admin.db,
    );
    const c = capturing();
    const task = autoReleaseTask(c.sentinel, { tickMs: 3_600_000 });
    const beats: number[] = [];
    const run = await task.start({ beat: () => beats.push(Date.now()), idle: () => {} });
    await until(async () => beats.length > 0);
    await run.stop();
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
    expect(c.lines).toContainEqual(
      expect.objectContaining({
        level: "error",
        obj: expect.objectContaining({ alert: "kill_switch_auto_release_held", keep: "unjudgeable" }),
        msg: expect.stringMatching(/^ALERT Payments stay paused/),
      }),
    );

    await sql`update kill_switch set reason = 'paused by an older sentinel' where id = 1`.execute(s.admin.db);
    expect(await autoReleaseStaleStop(s.sentinel)).toMatchObject({ action: "kept", decision: { keep: "unjudgeable" } });
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
  });

  it("evidence that cannot be loaded: the switch stays engaged and the check pages (fail safe)", async () => {
    await engageIncident();
    const broken = createDb<DB>({ url: "postgres://nobody:nothing@127.0.0.1:9/none", applicationName: "broken" });
    try {
      const c = capturing({ ...s.sentinel, db: broken.db });
      await expect(autoReleaseStaleStop(c.sentinel)).rejects.toThrow();
      const beats: number[] = [];
      const run = await autoReleaseTask(c.sentinel, { tickMs: 3_600_000 }).start({
        beat: () => beats.push(1),
        idle: () => {},
      });
      await until(async () => beats.length > 0);
      await run.stop();
      expect(c.lines).toContainEqual(
        expect.objectContaining({
          level: "error",
          obj: expect.objectContaining({ alert: "kill_switch_auto_release_failed" }),
        }),
      );
    } finally {
      await broken.close();
    }
    expect(await killSwitchState(s.sentinel)).toMatchObject({ engaged: true, reason: INCIDENT_REASON });
  });
});

describe("flap guard", () => {
  it("after more than 3 re-engagements within an hour sentinel stops releasing automatically and pages", async () => {
    const released: number[] = [];
    // engaged by sentinel, released automatically, engaged again by sentinel, … (the log rows the guard reads)
    await setKillSwitch(s.sentinel, true, INCIDENT_REASON, "sentinel");
    for (let i = 0; i < 4; i++) {
      const r = await autoReleaseStaleStop(s.sentinel);
      expect(r).toMatchObject({ action: "released" });
      released.push(i);
      await setKillSwitch(s.sentinel, true, INCIDENT_REASON, "sentinel");
    }
    expect(released).toHaveLength(4);
    const c = capturing();
    const run = await autoReleaseTask(c.sentinel, { tickMs: 3_600_000 }).start();
    await until(async () => c.lines.length > 0);
    await run.stop();
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
    expect(c.lines).toContainEqual(
      expect.objectContaining({
        level: "error",
        obj: expect.objectContaining({ alert: "kill_switch_auto_release_held", keep: "flapping" }),
      }),
    );
    const status = (await ops("kill-switch-release-status")).json;
    expect(status).toMatchObject({ would_engage_under_current_rules: false, automatic_release: { expected: false } });
    expect(status.automatic_release.why).toMatch(/engaged again 4 times within 60 min/);
    expect(status.assessment).toMatch(/Release it in the console/);
  });
});
