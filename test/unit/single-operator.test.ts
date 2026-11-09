/**
 * Adaptive two-person rule (two-person.ts, lld/sentinel.md §6 "Single-operator platforms"): a second
 * operator only while two or more can approve; the single operator's guards; config and the counter.
 */
import { createMetrics, loadConfig } from "@nearpay-internal/service";
import { describe, expect, it } from "vitest";
import { registerSingleOperatorCounter, SINGLE_OPERATOR_METRIC } from "../../src/app/single-operator-metrics.js";
import { apiShape } from "../../src/config.js";
import {
  canApprove,
  madeBySingleOperator,
  type Operator,
  RELEASE_TTL_MS,
  type ReleaseRequest,
  SINGLE_OPERATOR_REASON_MIN,
  type SingleOperatorPolicy,
  singleOperatorAvailableAt,
} from "../../src/kill-switch/two-person.js";

const REQUESTED = 1_800_000_000_000;
const DELAY = 300_000;
const POLICY: SingleOperatorPolicy = { delayMs: DELAY };
const engaged = { engaged: true, version: 4 };
const REASON = "owner is the only operator; incident 42 closed";
const req = (o: Partial<ReleaseRequest> = {}): ReleaseRequest => ({
  id: "opa_1",
  reason: "root cause fixed",
  status: "pending",
  requestedBy: "usr_alice",
  requestedRole: "ops_admin",
  requestedAtMs: REQUESTED,
  requestedAdmins: 1,
  expiresAtMs: REQUESTED + RELEASE_TTL_MS,
  switchVersion: 4,
  decidedBy: null,
  ...o,
});
/** An operator verified at `authAtMs` (step-up fresh 10 min from then) with identity's count claim. */
const op = (
  authAtMs: number,
  activeAdmins: number | undefined = 1,
  id = "usr_alice",
  role: Operator["role"] = "ops_admin",
): Operator => ({
  id,
  role,
  stepUpUntil: Math.floor(authAtMs / 1000) + 600,
  activeAdmins,
  authAt: Math.floor(authAtMs / 1000),
});
const after = REQUESTED + DELAY + 1_000;

describe("adaptive two-person rule", () => {
  it("one approver when requested and now: the requester completes it after the wait, re-verified, with a reason", () => {
    expect(canApprove(op(after), req(), engaged, after + 1, POLICY, REASON)).toEqual({
      ok: true,
      replay: false,
      singleOperator: true,
    });
  });

  it("two or more approvers when requested: the requester is refused even if only one is left now", () => {
    for (const now of [2, 1, undefined])
      expect(
        canApprove(
          { ...op(after), activeAdmins: now },
          req({ requestedAdmins: 2 }),
          engaged,
          after + 1,
          POLICY,
          REASON,
        ),
      ).toMatchObject({ error: "approver_conflict", reason: "the approver must be a different operator" });
  });

  it("a second approver added after the request turns the rule back on", () => {
    expect(canApprove(op(after, 2), req(), engaged, after + 1, POLICY, REASON)).toMatchObject({
      error: "approver_conflict",
    });
  });

  it("an unknown count (no claim, or a request recorded without one) fails closed to two-person", () => {
    expect(
      canApprove({ ...op(after), activeAdmins: undefined }, req(), engaged, after + 1, POLICY, REASON),
    ).toMatchObject({
      error: "approver_conflict",
    });
    expect(canApprove(op(after), req({ requestedAdmins: null }), engaged, after + 1, POLICY, REASON)).toMatchObject({
      error: "approver_conflict",
    });
  });

  it("refused before the wait has passed, naming when", () => {
    const early = REQUESTED + DELAY - 1;
    const v = canApprove(op(early), req(), engaged, early, POLICY, REASON);
    expect(v).toMatchObject({ ok: false, error: "approver_conflict" });
    expect(v.ok ? "" : v.reason).toContain(new Date(REQUESTED + DELAY).toISOString());
  });

  it("a verification from before the wait ended does not count, even while its step-up is fresh", () => {
    expect(canApprove(op(REQUESTED + DELAY - 1_000), req(), engaged, after, POLICY, REASON)).toMatchObject({
      error: "step_up_required",
    });
    const noAuthAt: Operator = { ...op(after), authAt: undefined };
    expect(canApprove(noAuthAt, req(), engaged, after + 1, POLICY, REASON)).toMatchObject({
      error: "step_up_required",
    });
  });

  it("needs a written reason of at least the minimum length (trimmed)", () => {
    for (const note of [undefined, "", "   ", "x".repeat(SINGLE_OPERATOR_REASON_MIN - 1), `  ${"y".repeat(19)}  `])
      expect(canApprove(op(after), req(), engaged, after + 1, POLICY, note)).toMatchObject({
        error: "reason_required",
      });
  });

  it("a zero wait is refused for the kill-switch release", () => {
    expect(canApprove(op(REQUESTED + 1), req(), engaged, REQUESTED + 2, { delayMs: 0 }, REASON)).toMatchObject({
      error: "approver_conflict",
    });
  });

  it("still only an ops_admin, never after expiry or a switch change; replays stay replays", () => {
    expect(canApprove(op(after, 1, "usr_alice", "ops"), req(), engaged, after + 1, POLICY, REASON)).toMatchObject({
      error: "permission_denied",
    });
    const late = REQUESTED + RELEASE_TTL_MS;
    expect(canApprove(op(late), req(), engaged, late, POLICY, REASON)).toMatchObject({ expire: true });
    expect(canApprove(op(after), req({ status: "approved", decidedBy: "usr_alice" }), engaged, after + 1)).toEqual({
      ok: true,
      replay: true,
    });
  });

  it("a different operator approves through the two-person path (no wait, no reason)", () => {
    expect(canApprove(op(REQUESTED + 1, 2, "usr_bob"), req({ requestedAdmins: 2 }), engaged, REQUESTED + 2)).toEqual({
      ok: true,
      replay: false,
    });
  });

  it("availability is reported only for single-operator requests", () => {
    expect(singleOperatorAvailableAt(req(), POLICY)).toBe(REQUESTED + DELAY);
    expect(singleOperatorAvailableAt(req({ requestedAdmins: 2 }), POLICY)).toBeNull();
    expect(madeBySingleOperator(req({ requestedAdmins: 0 }))).toBe(true);
  });
});

const env = {
  NP_ENV: "server",
  NP_DB_URL_FILE: "/s/db",
  NP_REGISTRY_DB_URL_FILE: "/s/registry",
  NP_IDENTITY_URL: "http://identity-api:8080",
  NP_SERVICE_CLIENT_SECRET_FILE: "/s/client",
  NP_RAILS_URL: "http://rails-api:8080",
  NP_SENTINEL_SIGNING_KEY_FILE: "/s/key",
  NP_PAYMENTS_TICKET_PUBKEY: "ggCDFpCs8t32Qj9OwHEoAAuRDTWM1Y0iNdqH6VYDm9k",
};
const readFile = (p: string) => (p === "/s/db" || p === "/s/registry" ? "postgres://u:p@h:5432/d" : "x");

describe("config", () => {
  it("waits 300 s by default and reads NP_OPS_SINGLE_OPERATOR_DELAY_S", () => {
    expect(loadConfig(apiShape, { env, readFile }).opsSingleOperatorDelayS).toBe(300);
    expect(
      loadConfig(apiShape, { env: { ...env, NP_OPS_SINGLE_OPERATOR_DELAY_S: "120" }, readFile })
        .opsSingleOperatorDelayS,
    ).toBe(120);
  });

  it.each(["0", "3001", "-5"])("refuses NP_OPS_SINGLE_OPERATOR_DELAY_S=%s", (v) => {
    expect(() => loadConfig(apiShape, { env: { ...env, NP_OPS_SINGLE_OPERATOR_DELAY_S: v }, readFile })).toThrow();
  });
});

it("exports nearpay_ops_single_operator_actions_total{action} under its fixed name", async () => {
  const m = createMetrics("sentinel", { defaultMetrics: false });
  registerSingleOperatorCounter(m)("kill_switch.release");
  expect(SINGLE_OPERATOR_METRIC).toBe("nearpay_ops_single_operator_actions_total");
  expect(await m.render()).toContain('nearpay_ops_single_operator_actions_total{action="kill_switch.release"} 1');
});
