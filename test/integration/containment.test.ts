/**
 * Integrity containment over HTTP (ADR-0028, owner directive 2026-11-12 "the service should never stop"):
 * one breach quarantines one account and every other merchant keeps working; only corroborated breaches
 * across accounts engage the global switch (actor `sentinel`, released by ops only); quarantines expire and
 * ops clear them; caller-supplied mismatches never stop anything; R5 re-read (stale, not security) and a
 * missing treasury (unavailable, not security).
 */
import { sql } from "@nearpay-internal/db";
import { newId, toUuid } from "@nearpay-internal/ids";
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import { routeQuoteDepositKey } from "@nearpay-money/spec";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resetSpoofCounters } from "../../src/co-signer/attest.js";
import { quarantinesActive, systemicWindow } from "../../src/kill-switch/containment.js";
import { killSwitchState } from "../../src/kill-switch/kill-switch.js";
import { runOps } from "../../src/ops/cli.js";
import { type FakeOneClick, fakeOneClick, PROVIDER_FEE_ACCOUNT } from "../support/fakes.js";
import { LIVE_TREASURY, type Stack, startStack } from "../support/stack.js";

const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const PATH = "/v1/attestations/deposit_instructions";
const MERCHANTS = ["a", "b", "c"] as const;
type M = (typeof MERCHANTS)[number];

let s: Stack;
let oc: FakeOneClick;
const acct = {} as Record<M, `acct_${string}`>;
const recipient = (m: M) => `merchant-${m}.near`;

beforeAll(async () => {
  oc = await fakeOneClick();
  s = await startStack({ oneclick: oc });
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
});

const fees = [
  { recipient: LIVE_TREASURY, fee: 25 },
  { recipient: PROVIDER_FEE_ACCOUNT, fee: 25 },
];

/** A quote paying merchant `m`, issued by rails for `m` (unless `issued: false`). */
function quote(
  m: M,
  o: { tamper?: boolean; recipient?: string; issued?: boolean } = {},
): { q: OneClickQuoteResponse; m: M } {
  const q = oc.quote({
    request: { appFees: fees, recipient: o.recipient ?? recipient(m) },
    // changed after signing: R2 and R3 both fail (an R2-only failure is provider drift, never a breach)
    ...(o.tamper ? { afterSign: (x: OneClickQuoteResponse) => (x.quoteRequest.referral = "attacker") } : {}),
  });
  if (o.issued !== false) s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
  return { q, m };
}

function body(q: OneClickQuoteResponse, deposit: object = {}) {
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
      ...deposit,
    },
  };
}

const attest = (b: unknown, ip = "203.0.113.7") =>
  s.call("POST", PATH, { body: b, headers: { "x-forwarded-for": `${ip}, 10.0.0.1` } });
const breaches = () => s.admin.db.selectFrom("integrity_breaches").selectAll().orderBy("created_at").execute();
const lastRecord = (attempt: string) =>
  s.admin.db
    .selectFrom("attestations")
    .selectAll()
    .where("attempt_id", "=", attempt)
    .orderBy("created_at", "desc")
    .executeTakeFirstOrThrow();

async function ops(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runOps(argv, s.sentinel, { actor: "cli@test", out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, json: out.length ? JSON.parse(out.join("\n")) : null, err: err.join("\n") };
}

describe("a single breach never stops the platform", () => {
  it("refuses, records, quarantines that account only; other merchants keep attesting; ops clear it", async () => {
    const bad = body(quote("a", { tamper: true }).q);
    expect((await attest(bad)).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    const [breach] = await breaches();
    expect(breach).toMatchObject({
      evidence: "pipeline",
      rules: ["R2", "R3"],
      account_id: toUuid(acct.a, "acct"),
      destination_account_id: toUuid(acct.a, "acct"),
      quarantined: true,
      systemic: false,
    });

    // merchant a: a genuine quote is now held (503, recorded as quarantined)
    const held = body(quote("a").q);
    const r = await attest(held);
    expect(r.status).toBe(503);
    expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
    expect(await lastRecord(held.attempt_id)).toMatchObject({ result: "unavailable", class: "quarantined" });

    // merchants b and c are unaffected
    for (const m of ["b", "c"] as const) expect((await attest(body(quote(m).q))).status).toBe(200);
    expect(await quarantinesActive(s.sentinel)).toBe(1);

    const list = await ops("quarantines");
    expect(list.json).toEqual([expect.objectContaining({ account_id: acct.a, livemode: true, state: "active" })]);
    const cleared = await ops("quarantine-clear", acct.a, "false", "positive", "checked");
    expect(cleared.code).toBe(0);
    expect(cleared.json).toMatchObject({
      state: "cleared",
      cleared_by: "cli@test",
      clear_note: "false positive checked",
    });
    expect((await ops("quarantine-clear", acct.a, "again")).code).toBe(1);
    expect((await attest(body(quote("a").q))).status).toBe(200);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    const log = await s.admin.db
      .selectFrom("quarantine_log")
      .select(["action", "actor"])
      .orderBy("created_at")
      .execute();
    expect(log).toEqual([
      { action: "quarantined", actor: "sentinel" },
      { action: "cleared", actor: "cli@test" },
    ]);
  });

  it("a quarantine expires on its own (TTL); a cached attestation is never re-served meanwhile", async () => {
    const ok = body(quote("b").q);
    expect((await attest(ok)).status).toBe(200);
    expect((await attest(body(quote("b", { tamper: true }).q))).status).toBe(409);
    // the cached signed attestation of b is not re-served while b is quarantined
    expect((await attest(ok)).status).toBe(503);
    // time passes: the quarantine is past its expiry
    await sql`update quarantines set expires_at = now() - interval '1 second'`.execute(s.admin.db);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    expect((await attest(ok)).status).toBe(200);
    expect((await ops("quarantines", "--all")).json).toEqual([expect.objectContaining({ state: "expired" })]);
  });

  it("ops extend a quarantine by minutes from now, and a breach never shortens it", async () => {
    expect((await attest(body(quote("c", { tamper: true }).q))).status).toBe(409);
    const ext = await ops("quarantine-extend", acct.c, "240", "investigating");
    expect(ext.code).toBe(0);
    const until = Date.parse(ext.json.expires_at);
    expect(until).toBeGreaterThan(Date.now() + 239 * 60_000);
    expect((await attest(body(quote("c", { tamper: true }).q))).status).toBe(409);
    const [q] = (await ops("quarantines")).json;
    expect(Date.parse(q.expires_at)).toBe(until);
    expect((await ops("quarantine-extend", acct.c, "0", "x")).code).toBe(2);
  });

  it("many breaches on one account stay local", async () => {
    for (let i = 0; i < 5; i++) expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    expect(await systemicWindow(s.sentinel)).toEqual({ refusals: 5, accounts: 1, drift: 0 });
    expect((await attest(body(quote("b").q))).status).toBe(200);
  });
});

describe("corroborated breaches across accounts", () => {
  it("3 pipeline breaches across 2 accounts within the window engage the global switch (actor sentinel)", async () => {
    expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    expect((await attest(body(quote("b", { tamper: true }).q))).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    const st = await killSwitchState(s.sentinel);
    expect(st).toMatchObject({ engaged: true, actor: "sentinel" });
    expect(st.reason).toMatch(/^systemic integrity breach: 3 refusals on NearPay deposit addresses across 2 accounts/);
    expect(st.reason).toContain("until ops release it");
    expect((await breaches()).map((b) => b.systemic)).toEqual([false, false, true]);
    const out = await s.admin.db
      .selectFrom("outbox")
      .selectAll()
      .where("subject", "=", "evt.sentinel.kill_switch.engaged")
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect(out.aggregate_version).toBe(st.version);
  });

  it("spoofs, test-mode addresses and rails outages never count", async () => {
    for (const m of ["a", "b", "c"] as const) {
      expect(
        (await attest(body(quote(m, { tamper: true, issued: false }).q), `198.51.100.${m.charCodeAt(0)}`)).status,
      ).toBe(409);
      const t = quote(m, { tamper: true });
      s.issued.set(t.q.quote.depositAddress as string, { livemode: false, account_id: acct[m] });
      expect((await attest(body(t.q))).status).toBe(409);
    }
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    // the test-mode ones are recorded (not live, not quarantined)
    expect((await breaches()).map((b) => [b.livemode, b.quarantined])).toEqual([
      [false, false],
      [false, false],
      [false, false],
    ]);
  });
});

describe("caller-supplied mismatches (request evidence) never stop anything", () => {
  it("refused and recorded on a genuine address, across accounts — no quarantine, no global switch", async () => {
    for (const m of ["a", "b", "c", "a"] as const) {
      const { q } = quote(m);
      const r = await attest(body(q, { amount_in: "1" }), `192.0.2.${m.charCodeAt(0)}`);
      expect(r.status).toBe(409);
    }
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    const all = await breaches();
    expect(all).toHaveLength(4);
    expect(all.every((b) => b.evidence === "request" && !b.quarantined && !b.systemic)).toBe(true);
    // the merchants keep attesting
    expect((await attest(body(quote("a").q))).status).toBe(200);
  });
});

describe("R5 registry re-read (instant payout wallets, ADR-0027)", () => {
  it("an account whose payout wallets changed recently → 409 stale, not security (no breach, no quarantine)", async () => {
    const fresh = newId("acct");
    await s.destination({
      account_id: toUuid(fresh, "acct"),
      livemode: true,
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: "old-wallet.near",
      verification: "signature",
      active_at: new Date(Date.now() - 60_000),
    });
    // the quote pays a wallet identity's view does not list (yet)
    const q = oc.quote({ request: { appFees: fees, recipient: "new-wallet.near" } });
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: fresh });
    const b = body(q);
    const r = await attest(b);
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: { code: "attestation_stale" } });
    expect(await lastRecord(b.attempt_id)).toMatchObject({
      class: "stale",
      reasons: [expect.stringMatching(/^R5 recipient not found; the account's payout wallets changed/)],
    });
    expect(await breaches()).toEqual([]);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("the account's own wallet for another asset → stale", async () => {
    const q = oc.quote({ request: { appFees: fees, recipient: recipient("b"), destinationAsset: USDC_BASE } });
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct.b });
    const r = await attest(body(q));
    expect(r.body).toMatchObject({ error: { code: "attestation_stale" } });
    expect(await breaches()).toEqual([]);
  });

  it("a wallet activated during the re-read pause is found: signed", async () => {
    const late = newId("acct");
    const q = oc.quote({ request: { appFees: fees, recipient: "just-activated.near" } });
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: late });
    const b = body(q);
    const pending = attest(b);
    await s.destination({
      account_id: toUuid(late, "acct"),
      livemode: true,
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: "just-activated.near",
      verification: "signature",
      active_at: new Date(),
    });
    const r = await pending;
    // either the first read already saw it or the re-read did; never a breach
    expect([200]).toContain(r.status);
    expect(await breaches()).toEqual([]);
  });

  it("a recipient NearPay never had, with a current view and no recent change, stays a breach", async () => {
    const q = oc.quote({ request: { appFees: fees, recipient: "attacker.near" } });
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct.c });
    expect((await attest(body(q))).status).toBe(409);
    expect(await breaches()).toEqual([
      expect.objectContaining({ evidence: "pipeline", rules: ["R5"], quarantined: true }),
    ]);
  });
});

describe("configuration errors are unavailable, not security", () => {
  it("R6 no live treasury configured → 503 attestation_unavailable, ALERT, no breach, no switch", async () => {
    const api = await s.extraApi({ treasuryAccount: undefined });
    try {
      const { q } = quote("a");
      const b = body(q);
      const r = await api.call("POST", PATH, { body: b, headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" } });
      expect(r.status).toBe(503);
      expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
      expect(await lastRecord(b.attempt_id)).toMatchObject({
        result: "unavailable",
        class: "unavailable",
        reasons: ["R6 no treasury configured for this mode"],
      });
      expect(await breaches()).toEqual([]);
      expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    } finally {
      await api.stop();
    }
  });
});

// ------------------------------------------------------------------------------------------------
// 2026-11-12 resilience audit (SENTINEL-1, -2, -6)
// ------------------------------------------------------------------------------------------------

const quarantineRow = (m: M) =>
  s.admin.db
    .selectFrom("quarantines")
    .selectAll()
    .where("account_id", "=", toUuid(acct[m], "acct"))
    .where("livemode", "=", true)
    .executeTakeFirst();

describe("SENTINEL-1: provider-wide drift is not tampering", () => {
  it("R2 alone with every other check passing → 503 unavailable, recorded, no breach, no quarantine, no switch", async () => {
    for (const m of MERCHANTS) {
      const q = oc.quote({
        request: { appFees: fees, recipient: recipient(m) },
        afterSign: (x) => (x.quote.amountOut = "1"), // a signed field the checks do not compare
      });
      s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
      const b = body(q);
      const r = await attest(b);
      expect(r.status).toBe(503);
      expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
      expect(await lastRecord(b.attempt_id)).toMatchObject({
        result: "unavailable",
        class: "unavailable",
        reasons: [expect.stringMatching(/^R2 .*provider echo drift suspected/)],
      });
    }
    expect(await breaches()).toEqual([]);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    // every merchant still signs a genuine quote
    for (const m of MERCHANTS) expect((await attest(body(quote(m).q))).status).toBe(200);
  });

  it("the same R6 format change on every merchant: refused, recorded as drift, quarantines lifted, switch never engages", async () => {
    // 1Click starts adding a third fee entry (format change): treasury still paid once, total within 500 bps
    const drifted = [
      { recipient: LIVE_TREASURY, fee: 25 },
      { recipient: PROVIDER_FEE_ACCOUNT, fee: 20 },
      { recipient: "partner.near", fee: 5 },
    ];
    const driftQuote = (m: M) => {
      const q = oc.quote({ request: { appFees: drifted, recipient: recipient(m) } });
      s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
      return body(q);
    };
    // first merchant: nothing to compare with yet, so it is contained like any breach
    expect((await attest(driftQuote("a"))).status).toBe(409);
    expect(await quarantineRow("a")).toMatchObject({ status: "active" });
    // second merchant, same refusal: drift — a's quarantine is lifted, b is not quarantined
    expect((await attest(driftQuote("b"))).status).toBe(409);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    expect(await quarantineRow("a")).toMatchObject({ status: "cleared", cleared_by: "sentinel" });
    expect(await quarantineRow("b")).toBeUndefined();
    // more refusals on every merchant, well past the systemic threshold: still no switch
    for (const m of ["c", "a", "b", "c"] as const) expect((await attest(driftQuote(m))).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    expect(await quarantinesActive(s.sentinel)).toBe(0);
    const all = await breaches();
    expect(all.map((b) => [b.drift, b.quarantined, b.systemic])).toEqual([
      [false, true, false],
      [true, false, false],
      [true, false, false],
      [true, false, false],
      [true, false, false],
      [true, false, false],
    ]);
    expect(await systemicWindow(s.sentinel)).toEqual({ refusals: 0, accounts: 0, drift: 1 });
    // only the first (pre-pattern) refusal opened a per-merchant audit finding
    const findings = await s.admin.db
      .selectFrom("audit_findings")
      .select("id")
      .where("check_kind", "=", "attestation")
      .execute();
    expect(findings).toHaveLength(1);
    // the merchants keep signing genuine quotes
    for (const m of MERCHANTS) expect((await attest(body(quote(m).q))).status).toBe(200);
  });

  it("a breach that can redirect funds keeps its weight next to drift (R5 on two merchants still engages)", async () => {
    const drifted = [
      { recipient: LIVE_TREASURY, fee: 25 },
      { recipient: PROVIDER_FEE_ACCOUNT, fee: 20 },
      { recipient: "partner.near", fee: 5 },
    ];
    for (const m of ["a", "b"] as const) {
      const q = oc.quote({ request: { appFees: drifted, recipient: recipient(m) } });
      s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
      expect((await attest(body(q))).status).toBe(409);
    }
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    for (const m of ["a", "b", "a"] as const) {
      const q = oc.quote({ request: { appFees: fees, recipient: "attacker.near" } });
      s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: acct[m] });
      expect((await attest(body(q))).status).toBe(409);
    }
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
    expect(await systemicWindow(s.sentinel)).toEqual({ refusals: 3, accounts: 2, drift: 1 });
  });
});

describe("SENTINEL-2: quarantines after a release, and retries", () => {
  it("retries of a quarantined account do not extend the quarantine", async () => {
    expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    const first = await quarantineRow("a");
    for (let i = 0; i < 3; i++) expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    const after = await quarantineRow("a");
    expect(after?.expires_at.getTime()).toBe(first?.expires_at.getTime());
    expect(after?.version).toBe(first?.version);
    const log = await s.admin.db.selectFrom("quarantine_log").select("action").execute();
    expect(log).toEqual([{ action: "quarantined" }]);
  });

  it("systemic engage → release → sentinel's quarantines cleared (operator holds kept) → those merchants sign again", async () => {
    // an operator hold on c, created before the stop
    expect((await ops("quarantine-extend", acct.c, "60", "manual review")).code).toBe(0);
    for (const m of ["a", "b", "a"] as const)
      expect((await attest(body(quote(m, { tamper: true }).q))).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
    expect(await quarantinesActive(s.sentinel)).toBe(3);
    // the operator also extends b's sentinel quarantine during the stop: theirs now, kept
    expect((await ops("quarantine-extend", acct.b, "120", "looking at b")).code).toBe(0);

    const status = await ops("kill-switch-release-status");
    expect(status.json).toMatchObject({
      engaged: true,
      would_engage_under_current_rules: true,
      merchants_switched_back_on_by_release: 1, // a; b was changed by an operator, c is an operator's hold
      merchants_kept_paused_by_operators: 2, // b (changed by an operator) and c (an operator hold)
      pending_release: null,
    });
    expect(status.json.summary).toMatch(/^Payments are paused: an automatic check found/);

    const released = await ops("kill-switch-release", "fixed: rotated the provider key");
    expect(released.code).toBe(0);
    expect(released.json).toMatchObject({ engaged: false, quarantines_cleared: 1 });
    expect(await quarantineRow("a")).toMatchObject({ status: "cleared", cleared_by: "cli@test" });
    expect(await quarantineRow("b")).toMatchObject({ status: "active" });
    expect(await quarantineRow("c")).toMatchObject({ status: "active", created_by: "cli@test" });
    const log = await s.admin.db
      .selectFrom("quarantine_log")
      .select(["action", "actor", "reason"])
      .where("account_id", "=", toUuid(acct.a, "acct"))
      .orderBy("version")
      .execute();
    expect(log.at(-1)).toMatchObject({
      action: "cleared",
      actor: "cli@test",
      reason: "kill switch released: fixed: rotated the provider key",
    });
    // the next attestation for a signs
    expect((await attest(body(quote("a").q))).status).toBe(200);
  });

  it("ops quarantine-clear-all lifts sentinel's holds in a mode, keeps operator holds, and audit-logs each", async () => {
    expect((await attest(body(quote("a", { tamper: true }).q))).status).toBe(409);
    expect((await attest(body(quote("b", { tamper: true }).q))).status).toBe(409);
    expect((await ops("quarantine-extend", acct.c, "30", "hold c")).code).toBe(0);
    expect((await ops("quarantine-clear-all")).code).toBe(2);
    const r = await ops("quarantine-clear-all", "provider", "format", "fixed");
    expect(r.code).toBe(0);
    expect(r.json).toEqual({
      livemode: true,
      cleared: expect.arrayContaining([acct.a, acct.b]),
      kept: [{ account_id: acct.c, by: "cli@test" }],
    });
    expect(r.json.cleared).toHaveLength(2);
    expect(await quarantinesActive(s.sentinel)).toBe(1);
    const cleared = await s.admin.db
      .selectFrom("quarantine_log")
      .select(["actor", "reason"])
      .where("action", "=", "cleared")
      .execute();
    expect(cleared).toEqual([
      { actor: "cli@test", reason: "provider format fixed" },
      { actor: "cli@test", reason: "provider format fixed" },
    ]);
    // test mode has nothing to clear
    expect((await ops("quarantine-clear-all", "x", "--test")).json).toEqual({ livemode: false, cleared: [], kept: [] });
  });

  it("kill-switch-release-status: a stale single-breach stop (the 2026-11-11 incident) is reported as not platform evidence, released automatically", async () => {
    await sql`update kill_switch set engaged = true, actor = 'sentinel',
      reason = 'integrity breach on 0x11D2…5036: R4 deposit chain differs', updated_at = now() where id = 1`.execute(
      s.admin.db,
    );
    const r = await ops("kill-switch-release-status");
    expect(r.json).toMatchObject({
      engaged: true,
      would_engage_under_current_rules: false,
      summary: "Payments are paused: an automatic check refused a payment.",
    });
    expect(r.json.assessment).toMatch(/would not happen under the current rules/);
    expect(r.json.automatic_release).toMatchObject({ expected: true });
    expect(r.json.steps[0]).toMatch(/^Nothing to do: sentinel switches payments back on by itself/);
    expect(r.json.steps[1]).toMatch(/Request release/);
    // it informs only: nothing was released
    expect((await killSwitchState(s.sentinel)).engaged).toBe(true);
    await sql`update kill_switch set engaged = false where id = 1`.execute(s.admin.db);
    expect((await ops("kill-switch-release-status")).json).toMatchObject({ engaged: false });
  });
});

describe("SENTINEL-6: request-evidence refusals are limited per attempt, not per IP", () => {
  it("6 request-evidence refusals from one IP for different attempts: the 7th, valid, request is not 429", async () => {
    const ip = "100.64.0.9"; // carrier-grade NAT: many payers, one address
    for (let i = 0; i < 6; i++) {
      const { q } = quote(MERCHANTS[i % 3] as M);
      expect((await attest(body(q, { amount_in: "1" }), ip)).status).toBe(409);
    }
    expect((await attest(body(quote("b").q), ip)).status).toBe(200);
  });

  it("the same attempt repeating a request-evidence refusal is limited after 5", async () => {
    const ip = "100.64.0.10";
    const { q } = quote("c");
    const b = body(q, { amount_in: "1" });
    for (let i = 0; i < 5; i++) expect((await attest(b, ip)).status).toBe(409);
    const limited = await attest({ ...b, deposit: { ...b.deposit, amount_in: q.quote.amountIn } }, ip);
    expect(limited.status).toBe(429);
    // another attempt from the same IP is fine
    expect((await attest(body(quote("c").q), ip)).status).toBe(200);
  });
});
