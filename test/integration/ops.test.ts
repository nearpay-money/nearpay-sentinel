/** Stage 1 ops CLI (src/ops/cli.ts, §14) against the real database. */

import { fromUuid, newId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runOps } from "../../src/ops/cli.js";
import { type Stack, startStack } from "../support/stack.js";

let s: Stack;
beforeAll(async () => {
  s = await startStack();
});
afterAll(async () => {
  await s?.stop();
});

async function ops(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runOps(argv, s.sentinel, { actor: "cli@test", out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, json: out.length ? JSON.parse(out.join("\n")) : null, err: err.join("\n") };
}

async function finding(result: "pass" | "mismatch" | "unverifiable") {
  const id = uuidv7();
  const executionId = newId("ex");
  await s.admin.db
    .insertInto("audit_findings")
    .values({
      id,
      execution_id: executionId,
      account_id: toUuid(s.account, "acct"),
      livemode: true,
      check_kind: "settlement",
      result,
      details: JSON.stringify({ reason: "test" }),
    })
    .execute();
  return fromUuid("fnd", id);
}

describe("ops CLI", () => {
  it("engages, shows and releases the kill switch (one operator on local/test stacks); every change is logged and emitted", async () => {
    const on = await ops("kill-switch-engage", "integrity", "drill");
    expect(on.code).toBe(0);
    expect(on.json).toMatchObject({ engaged: true, reason: "integrity drill", actor: "cli@test" });
    const show = await ops("kill-switch");
    expect(show.json).toMatchObject({
      engaged: true,
      log: [expect.objectContaining({ engaged: true, actor: "cli@test" })],
    });
    const off = await ops("kill-switch-release", "drill", "over");
    expect(off.json).toMatchObject({ engaged: false, actor: "cli@test" });
    const events = await s.admin.db
      .selectFrom("outbox")
      .select(["subject", "aggregate_version"])
      .orderBy("created_at")
      .execute();
    expect(events.map((e) => e.subject)).toEqual([
      "evt.sentinel.kill_switch.engaged",
      "evt.sentinel.kill_switch.released",
    ]);
    expect(events[1]?.aggregate_version).toBe((events[0]?.aggregate_version ?? 0) + 1);
  });

  it("needs a reason to change the kill switch", async () => {
    const r = await ops("kill-switch-engage");
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/a reason is required/);
    expect((await ops("kill-switch-release", "x".repeat(501))).code).toBe(2);
  });

  it("lists open findings, acknowledges one, and lists all with --all", async () => {
    const open = await finding("mismatch");
    const passed = await finding("pass");
    const list = await ops("findings");
    expect(list.json.map((f: { id: string }) => f.id)).toContain(open);
    expect(list.json.map((f: { id: string }) => f.id)).not.toContain(passed);
    const ack = await ops("finding-ack", open, "checked", "on", "chain");
    expect(ack.json).toMatchObject({ id: open, acknowledged_by: "cli@test", acknowledgement_note: "checked on chain" });
    expect((await ops("findings")).json.map((f: { id: string }) => f.id)).not.toContain(open);
    expect((await ops("findings", "--all", "--limit", "10")).json.map((f: { id: string }) => f.id)).toEqual(
      expect.arrayContaining([open, passed]),
    );
    expect((await ops("finding-ack", passed, "nothing to do")).err).toMatch(/state_conflict/);
    const again = await ops("finding-ack", open, "again");
    expect(again.code).toBe(1);
    expect(again.err).toMatch(/state_conflict/);
    const missing = await ops("finding-ack", fromUuid("fnd", uuidv7()), "x");
    expect(missing.err).toMatch(/resource_missing|not found|No such/i);
  });

  it("shows attestation records by attempt, deposit key or deposit address", async () => {
    const attempt = newId("pa");
    await s.admin.db
      .insertInto("attestations")
      .values({
        id: uuidv7(),
        livemode: true,
        kind: "route_quote",
        deposit_key: "oneclick|0xabc_def|",
        attempt_id: attempt,
        result: "rejected",
        class: "security",
        reasons: ["R2 provider signature does not verify"],
      })
      .execute();
    for (const ref of [attempt, "oneclick|0xabc_def|", "0xabc_def"]) {
      const r = await ops("attestations", ref);
      expect(r.json).toEqual([expect.objectContaining({ attempt_id: attempt, class: "security" })]);
    }
    // `_` is not a wildcard: a near-miss address matches nothing
    expect((await ops("attestations", "0xabcxdef")).json).toEqual([]);
  });

  it("prints usage for unknown commands and options", async () => {
    expect((await ops()).code).toBe(2);
    expect((await ops("nope")).err).toMatch(/usage: ops.js/);
    expect((await ops("findings", "--bogus")).code).toBe(2);
    expect((await ops("findings", "--limit", "0")).code).toBe(2);
    expect((await ops("finding-ack", "ex_123", "x")).code).toBe(2);
  });
});
