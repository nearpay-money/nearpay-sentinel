/**
 * Console routes over HTTP (lld/sentinel.md §6, spec OPS_ROUTES): kill-switch state and log, engage (one
 * operator, no step-up), the two-person release (request → approve by a different ops_admin, fresh
 * step-ups, 1 h expiry, one pending request, engage in between expires it), the single-person release
 * refused on the server stage, and findings list/get/acknowledge — with the outbox rows (switch events,
 * `release_requested`, `ops_action.recorded`) written in the same transaction as each change.
 */

import { sql } from "@nearpay-internal/db";
import { fromUuid, newId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { runOps } from "../../src/ops/cli.js";
import { type Stack, startStack } from "../support/stack.js";

let s: Stack;
let offsetMs = 0;
beforeAll(async () => {
  s = await startStack({ deps: { now: () => Date.now() + offsetMs } });
});
afterAll(async () => {
  await s?.stop();
});

const alice = newId("usr"); // ops
const bob = newId("usr"); // ops_admin
const carol = newId("usr"); // ops_admin
const dave = newId("usr"); // ops

const tok = (sub: string, role: "ops" | "ops_admin", stepUp = true) => s.operatorToken({ sub, role, stepUp });

async function outbox() {
  const rows = await s.admin.db
    .selectFrom("outbox")
    .select(["subject", "payload"])
    .orderBy("created_at")
    .orderBy("id")
    .execute();
  return rows.map((r) => ({
    subject: r.subject,
    payload: (typeof r.payload === "string" ? JSON.parse(r.payload) : r.payload) as {
      aggregate: { id: string; version: number };
      data: { object: Record<string, unknown> };
    },
  }));
}

async function engage(reason = "drill") {
  const r = await s.call("POST", "/ops/kill_switch/engage", { token: await tok(dave, "ops", false), body: { reason } });
  expect(r.status).toBe(200);
  return r.body as { version: number; engaged: boolean };
}

async function request(sub = alice, role: "ops" | "ops_admin" = "ops", reason = "root cause fixed") {
  return s.call("POST", "/ops/kill_switch/release_requests", { token: await tok(sub, role), body: { reason } });
}

async function resetSwitch() {
  offsetMs = 0;
  await s.admin.db.transaction().execute(async (t) => {
    await sql`update release_requests set status = 'expired' where status = 'pending'`.execute(t);
    await t
      .updateTable("kill_switch")
      .set({ engaged: false, reason: "reset", actor: "test" })
      .where("id", "=", 1)
      .execute();
    await t.deleteFrom("outbox").execute();
  });
}

beforeEach(resetSwitch);

describe("authorization (in-handler, independent of the service package)", () => {
  it("needs an ops principal with an operator id and an admitted ops_role", async () => {
    expect((await s.call("GET", "/ops/kill_switch")).status).toBe(401);
    const noRole = await s.opsToken(["sentinel.read"]); // sub is not usr_…, no ops_role
    expect((await s.call("GET", "/ops/kill_switch", { token: noRole })).status).toBe(403);
    const r = await s.call("GET", "/ops/kill_switch", { token: await tok(alice, "ops", false) });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ engaged: false, pending_release: null });
    expect(typeof (r.body as { version: number }).version).toBe("number");
  });

  it("refuses a request without step-up and an approval by plain ops", async () => {
    await engage();
    const noStep = await s.call("POST", "/ops/kill_switch/release_requests", {
      token: await tok(alice, "ops", false),
      body: { reason: "x" },
    });
    expect(noStep.status).toBe(401);
    expect((noStep.body as { error: { code: string } }).error.code).toBe("step_up_required");
    const req = await request();
    const opa = (req.body as { id: string }).id;
    const byOps = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
      token: await tok(dave, "ops"),
      body: {},
    });
    expect(byOps.status).toBe(403);
    expect((byOps.body as { error: { code: string } }).error.code).toBe("permission_denied");
  });
});

describe("engage", () => {
  it("one operator without step-up; engaging an engaged switch emits nothing", async () => {
    const before = await s.call("GET", "/ops/kill_switch", { token: await tok(alice, "ops", false) });
    const on = await engage("incident 42");
    expect(on).toMatchObject({ engaged: true, reason: "incident 42", actor: dave, pending_release: null });
    expect(on.version).toBe((before.body as { version: number }).version + 1);
    const ev = await outbox();
    expect(ev.map((e) => e.subject)).toEqual(["evt.sentinel.kill_switch.engaged", "evt.sentinel.ops_action.recorded"]);
    expect(ev[1]?.payload.data.object).toMatchObject({
      actor: { sub: dave, ops_role: "ops" },
      action: "kill_switch.engaged",
      target: { type: "kill_switch" },
      account_id: null,
      approval: null,
    });
    expect(ev[1]?.payload.aggregate.id).toMatch(/^aud_/);
    const again = await engage("again");
    expect(again.version).toBe(on.version);
    expect((await outbox()).length).toBe(2);
  });
});

describe("two-person release", () => {
  it("request → approve by a different ops_admin releases in one transaction", async () => {
    const on = await engage();
    const req = await request();
    expect(req.status).toBe(201);
    const a = req.body as {
      id: string;
      status: string;
      requested_by: { id: string; role: string };
      expires_at: number;
      requested_at: number;
    };
    expect(a).toMatchObject({
      object: "ops_approval",
      action: "kill_switch.release",
      status: "pending",
      requested_by: { id: alice, role: "ops" },
      decided_by: null,
    });
    expect(a.expires_at - a.requested_at).toBe(3600);
    const state = await s.call("GET", "/ops/kill_switch", { token: await tok(bob, "ops_admin", false) });
    expect((state.body as { pending_release: { id: string } }).pending_release.id).toBe(a.id);

    const ok = await s.call("POST", `/ops/kill_switch/release_requests/${a.id}/approve`, {
      token: await tok(bob, "ops_admin"),
      body: { note: "verified" },
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({
      engaged: false,
      actor: `${alice}+${bob}`,
      reason: "root cause fixed",
      version: on.version + 1,
      pending_release: null,
    });
    const log = await s.call("GET", "/ops/kill_switch/log?limit=1", { token: await tok(bob, "ops_admin", false) });
    expect((log.body as { data: unknown[] }).data[0]).toMatchObject({
      engaged: false,
      actor: `${alice}+${bob}`,
      version: on.version + 1,
    });
    const ev = await outbox();
    expect(ev.map((e) => e.subject)).toEqual([
      "evt.sentinel.kill_switch.engaged",
      "evt.sentinel.ops_action.recorded",
      "evt.sentinel.kill_switch.release_requested",
      "evt.sentinel.ops_action.recorded",
      "evt.sentinel.kill_switch.released",
      "evt.sentinel.ops_action.recorded",
    ]);
    expect(ev[2]?.payload.data.object).toMatchObject({ id: a.id, status: "pending" });
    expect(ev[2]?.payload.aggregate.id).toBe(a.id);
    expect(ev[4]?.payload.data.object).toMatchObject({ engaged: false, actor: `${alice}+${bob}` });
    expect(ev[4]?.payload.aggregate.version).toBe(on.version + 1);
    expect(ev[5]?.payload.data.object).toMatchObject({
      action: "kill_switch.release_approved",
      actor: { sub: bob, ops_role: "ops_admin" },
      approval: a.id,
    });

    // an idempotent retry by the approver; any other decision is a conflict
    const replay = await s.call("POST", `/ops/kill_switch/release_requests/${a.id}/approve`, {
      token: await tok(bob, "ops_admin"),
      body: {},
    });
    expect(replay.status).toBe(200);
    expect((await outbox()).length).toBe(6);
    const late = await s.call("POST", `/ops/kill_switch/release_requests/${a.id}/approve`, {
      token: await tok(carol, "ops_admin"),
      body: {},
    });
    expect(late.status).toBe(409);
  });

  it("the requester can never approve their own request (403 approver_conflict), even as ops_admin", async () => {
    await engage();
    const req = await request(bob, "ops_admin");
    const opa = (req.body as { id: string }).id;
    const self = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
      token: await tok(bob, "ops_admin"),
      body: {},
    });
    expect(self.status).toBe(403);
    expect((self.body as { error: { code: string } }).error.code).toBe("approver_conflict");
    const st = await s.call("GET", "/ops/kill_switch", { token: await tok(bob, "ops_admin", false) });
    expect(st.body).toMatchObject({ engaged: true });
  });

  it("the database refuses an approval by the requester and any change of a decided request", async () => {
    await engage();
    const opa = ((await request()).body as { id: string }).id;
    const id = toUuid(opa, "opa");
    await expect(
      sql`update release_requests set status = 'approved', decided_by = requested_by, decided_role = 'ops_admin',
          decided_at = now() where id = ${id}`.execute(s.admin.db),
    ).rejects.toThrow(/release_approver_differs/);
    await sql`update release_requests set status = 'rejected', decided_by = ${toUuid(bob, "usr")},
        decided_role = 'ops_admin', decided_at = now() where id = ${id}`.execute(s.admin.db);
    await expect(
      sql`update release_requests set status = 'pending' where id = ${id}`.execute(s.admin.db),
    ).rejects.toThrow(/already rejected/);
    await expect(sql`delete from release_requests where id = ${id}`.execute(s.admin.db)).rejects.toThrow(
      /never deleted/,
    );
  });

  it("one pending request at a time; the same operator's retry is a replay", async () => {
    await engage();
    const first = await request();
    expect(first.status).toBe(201);
    const replay = await request();
    expect(replay.status).toBe(201);
    expect((replay.body as { id: string }).id).toBe((first.body as { id: string }).id);
    expect((await request(alice, "ops", "another reason")).status).toBe(409);
    expect((await request(dave)).status).toBe(409);
    expect((await outbox()).filter((e) => e.subject === "evt.sentinel.kill_switch.release_requested").length).toBe(1);
  });

  it("only while engaged", async () => {
    const r = await request();
    expect(r.status).toBe(409);
    expect((r.body as { error: { code: string } }).error.code).toBe("state_conflict");
  });

  it("expires after one hour: approval refused, request recorded expired, a new request allowed", async () => {
    await engage();
    const opa = ((await request()).body as { id: string }).id;
    offsetMs = 60 * 60_000 + 1_000;
    const late = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
      // the step-up is fresh on the shifted clock: only the expiry refuses
      token: await s.operatorToken({ sub: bob, role: "ops_admin", stepUpUntil: Math.floor(Date.now() / 1000) + 7200 }),
      body: {},
    });
    expect(late.status).toBe(409);
    const row = await s.admin.db
      .selectFrom("release_requests")
      .selectAll()
      .where("id", "=", toUuid(opa, "opa"))
      .executeTakeFirstOrThrow();
    expect(row.status).toBe("expired");
    const st = await s.call("GET", "/ops/kill_switch", { token: await tok(bob, "ops_admin", false) });
    expect(st.body).toMatchObject({ engaged: true, pending_release: null });
    // step-up tokens are minted on the real clock: shift back for the new request
    offsetMs = 0;
    expect((await request(dave)).status).toBe(201);
  });

  it("an engage in between expires the pending request", async () => {
    await engage();
    const opa = ((await request()).body as { id: string }).id;
    await engage("new evidence");
    const r = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
      token: await tok(bob, "ops_admin"),
      body: {},
    });
    expect(r.status).toBe(409);
    expect((await outbox()).filter((e) => e.subject === "evt.sentinel.kill_switch.released")).toEqual([]);
  });

  it("reject (any ops_admin) or withdraw (the requester, as ops_admin) executes nothing", async () => {
    await engage();
    const opa = ((await request(carol, "ops_admin")).body as { id: string }).id;
    const byOps = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/reject`, {
      token: await tok(dave, "ops", false),
      body: { note: "no" },
    });
    expect(byOps.status).toBe(403);
    const withdraw = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/reject`, {
      token: await tok(carol, "ops_admin", false),
      body: { note: "too early" },
    });
    expect(withdraw.status).toBe(200);
    expect(withdraw.body).toMatchObject({
      status: "rejected",
      decided_by: { id: carol, role: "ops_admin" },
      decision_note: "too early",
    });
    const ev = await outbox();
    expect(ev.at(-1)?.payload.data.object).toMatchObject({ action: "kill_switch.release_withdrawn", approval: opa });
    const approve = await s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
      token: await tok(bob, "ops_admin"),
      body: {},
    });
    expect(approve.status).toBe(409);
    const missing = await s.call("POST", `/ops/kill_switch/release_requests/${fromUuid("opa", uuidv7())}/reject`, {
      token: await tok(bob, "ops_admin"),
      body: { note: "x" },
    });
    expect(missing.status).toBe(404);
  });

  it("concurrent requests: exactly one is created", async () => {
    await engage();
    const ops = Array.from({ length: 6 }, () => newId("usr"));
    const res = await Promise.all(ops.map((o) => request(o)));
    expect(res.filter((r) => r.status === 201).length).toBe(1);
    expect(res.filter((r) => r.status === 409).length).toBe(5);
    const pending = await s.admin.db
      .selectFrom("release_requests")
      .select("id")
      .where("status", "=", "pending")
      .execute();
    expect(pending.length).toBe(1);
  });

  it("concurrent approvals: the switch is released exactly once", async () => {
    const on = await engage();
    const opa = ((await request()).body as { id: string }).id;
    const admins = [bob, carol, newId("usr"), newId("usr")];
    const res = await Promise.all(
      admins.map(async (a) =>
        s.call("POST", `/ops/kill_switch/release_requests/${opa}/approve`, {
          token: await tok(a, "ops_admin"),
          body: {},
        }),
      ),
    );
    expect(res.filter((r) => r.status === 200).length).toBe(1);
    expect(res.filter((r) => r.status === 409).length).toBe(3);
    const released = (await outbox()).filter((e) => e.subject === "evt.sentinel.kill_switch.released");
    expect(released.length).toBe(1);
    expect(released[0]?.payload.aggregate.version).toBe(on.version + 1);
  });
});

describe("single-person release (POST /internal/kill-switch, ops CLI)", () => {
  it("is refused with 409 two_person_required on the server stage; engage still works", async () => {
    const server = await s.extraApi({ env: "server" });
    try {
      const token = await s.opsToken(["sentinel.killswitch"]);
      const on = await server.call("POST", "/internal/kill-switch", { token, body: { engaged: true, reason: "x" } });
      expect(on.status).toBe(200);
      const off = await server.call("POST", "/internal/kill-switch", { token, body: { engaged: false, reason: "y" } });
      expect(off.status).toBe(409);
      expect((off.body as { error: { code: string } }).error.code).toBe("two_person_required");
    } finally {
      await server.stop();
    }
    const err: string[] = [];
    const code = await runOps(
      ["kill-switch-release", "drill", "over"],
      { ...s.sentinel, env: "server" },
      {
        actor: "cli@test",
        out: () => {},
        err: (l) => err.push(l),
      },
    );
    expect(code).toBe(1);
    expect(err.join("")).toMatch(/two_person_required/);
    const st = await s.admin.db.selectFrom("kill_switch").select("engaged").executeTakeFirstOrThrow();
    expect(st.engaged).toBe(true);
  });

  it("stays available on local/test stacks and expires a pending console request", async () => {
    await engage();
    const opa = ((await request()).body as { id: string }).id;
    const r = await s.call("POST", "/internal/kill-switch", {
      token: await s.opsToken(["sentinel.killswitch"]),
      body: { engaged: false, reason: "testbed T7" },
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ engaged: false });
    const row = await s.admin.db
      .selectFrom("release_requests")
      .select("status")
      .where("id", "=", toUuid(opa, "opa"))
      .executeTakeFirstOrThrow();
    expect(row.status).toBe("expired");
  });
});

describe("kill-switch log", () => {
  it("newest first with a before_version cursor", async () => {
    await engage("a");
    await s.call("POST", "/internal/kill-switch", { token: await s.opsToken(), body: { engaged: false, reason: "b" } });
    await engage("c");
    const token = await tok(alice, "ops", false);
    const p1 = await s.call("GET", "/ops/kill_switch/log?limit=2", { token });
    const b1 = p1.body as { data: { version: number; reason: string }[]; has_more: boolean; url: string };
    expect(b1.data.map((d) => d.reason)).toEqual(["c", "b"]);
    expect(b1.has_more).toBe(true);
    expect(b1.url).toBe("/ops/kill_switch/log");
    const p2 = await s.call("GET", `/ops/kill_switch/log?limit=2&before_version=${b1.data[1]?.version}`, { token });
    const b2 = p2.body as { data: { version: number; reason: string }[] };
    expect(b2.data[0]?.reason).toBe("a");
    expect(b2.data[0]?.version).toBe((b1.data[1]?.version ?? 0) - 1);
  });
});

describe("findings", () => {
  async function finding(o: {
    result: "pass" | "mismatch" | "unverifiable";
    livemode?: boolean;
    account?: string;
    at?: Date;
  }) {
    const id = uuidv7();
    await s.admin.db
      .insertInto("audit_findings")
      .values({
        id,
        execution_id: newId("ex"),
        account_id: toUuid(o.account ?? s.account, "acct"),
        livemode: o.livemode ?? true,
        check_kind: "settlement",
        result: o.result,
        details: JSON.stringify({ reason: "test" }),
        tx_chain: "near:mainnet",
        tx_hash: "abc",
        ...(o.at ? { created_at: o.at } : {}),
      })
      .execute();
    return fromUuid("fnd", id);
  }

  it("lists open non-pass findings by default, filters, pages; gets one", async () => {
    await s.admin.db.deleteFrom("audit_findings").execute();
    const other = newId("acct");
    const t0 = Date.now() - 60_000;
    const m1 = await finding({ result: "mismatch", at: new Date(t0) });
    const u1 = await finding({ result: "unverifiable", livemode: false, at: new Date(t0 + 1_000) });
    const m2 = await finding({ result: "mismatch", account: other, at: new Date(t0 + 2_000) });
    const p1 = await finding({ result: "pass", at: new Date(t0 + 3_000) });
    const token = await tok(alice, "ops", false);
    const ids = async (q: string) =>
      ((await s.call("GET", `/ops/findings${q}`, { token })).body as { data: { id: string }[] }).data.map((d) => d.id);
    expect(await ids("")).toEqual([m2, u1, m1]);
    expect(await ids("?result=pass")).toEqual([p1]);
    expect(await ids("?result=mismatch")).toEqual([m2, m1]);
    expect(await ids(`?account=${other}`)).toEqual([m2]);
    expect(await ids("?livemode=false")).toEqual([u1]);
    expect(await ids(`?created[gte]=${Math.floor((t0 + 1_000) / 1000)}`)).toContain(m2);
    const page1 = (await s.call("GET", "/ops/findings?limit=2", { token })).body as {
      data: { id: string }[];
      has_more: boolean;
    };
    expect(page1.data.map((d) => d.id)).toEqual([m2, u1]);
    expect(page1.has_more).toBe(true);
    expect(await ids(`?limit=2&starting_after=${u1}`)).toEqual([m1]);
    expect(await ids(`?limit=1&ending_before=${m1}`)).toEqual([u1]);
    const got = await s.call("GET", `/ops/findings/${m1}`, { token });
    expect(got.body).toMatchObject({
      id: m1,
      object: "audit_finding",
      result: "mismatch",
      tx_chain: "near:mainnet",
      tx_hash: "abc",
      acknowledged_at: null,
      acknowledgement_note: null,
    });
    expect((await s.call("GET", `/ops/findings/${fromUuid("fnd", uuidv7())}`, { token })).status).toBe(404);
  });

  it("acknowledges with a note (operator action with the account), once", async () => {
    const f = await finding({ result: "mismatch" });
    const p = await finding({ result: "pass" });
    const ack = await s.call("POST", `/ops/findings/${f}/acknowledge`, {
      token: await tok(alice, "ops", false),
      body: { note: "checked on chain" },
    });
    expect(ack.status).toBe(200);
    expect(ack.body).toMatchObject({ id: f, acknowledged_by: alice, acknowledgement_note: "checked on chain" });
    const ev = await outbox();
    expect(ev.map((e) => e.subject)).toEqual(["evt.sentinel.ops_action.recorded"]);
    expect(ev[0]?.payload.data.object).toMatchObject({
      action: "finding.acknowledged",
      target: { type: "audit_finding", id: f },
      account_id: s.account,
    });
    const replay = await s.call("POST", `/ops/findings/${f}/acknowledge`, {
      token: await tok(alice, "ops", false),
      body: { note: "checked on chain" },
    });
    expect(replay.status).toBe(200);
    const again = await s.call("POST", `/ops/findings/${f}/acknowledge`, {
      token: await tok(dave, "ops", false),
      body: { note: "me too" },
    });
    expect(again.status).toBe(409);
    const pass = await s.call("POST", `/ops/findings/${p}/acknowledge`, {
      token: await tok(dave, "ops", false),
      body: { note: "?" },
    });
    expect(pass.status).toBe(409);
    expect((await outbox()).length).toBe(1);
  });
});
