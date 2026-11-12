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
    ...(o.tamper ? { afterSign: (x: OneClickQuoteResponse) => (x.quote.amountOut = "1") } : {}),
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
      rules: ["R2"],
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
    expect(await systemicWindow(s.sentinel)).toEqual({ refusals: 5, accounts: 1 });
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
