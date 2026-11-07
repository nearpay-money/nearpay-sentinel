/** Two-person release rules (src/kill-switch/two-person.ts, lld/sentinel.md §6). */
import { describe, expect, it } from "vitest";
import {
  canApprove,
  canReject,
  canRequest,
  effectiveStatus,
  type Operator,
  RELEASE_TTL_MS,
  type ReleaseRequest,
  releaseActor,
  staleReason,
  stepUpFresh,
} from "../../src/kill-switch/two-person.js";

const NOW = 1_800_000_000_000;
const fresh = Math.floor(NOW / 1000) + 300;
/** `stepUpUntil: null` → no step-up at all. */
const op = (id: string, role: Operator["role"] = "ops_admin", stepUpUntil: number | null = fresh): Operator => ({
  id,
  role,
  stepUpUntil: stepUpUntil ?? undefined,
});
const engaged = { engaged: true, version: 4 };
const req = (o: Partial<ReleaseRequest> = {}): ReleaseRequest => ({
  id: "opa_1",
  reason: "root cause fixed",
  status: "pending",
  requestedBy: "usr_alice",
  requestedRole: "ops",
  expiresAtMs: NOW + RELEASE_TTL_MS,
  switchVersion: 4,
  decidedBy: null,
  ...o,
});

describe("step-up", () => {
  it("is fresh only strictly before step_up_until", () => {
    expect(stepUpFresh(op("usr_a"), NOW)).toBe(true);
    expect(stepUpFresh(op("usr_a", "ops", Math.floor(NOW / 1000)), NOW)).toBe(false);
    expect(stepUpFresh(op("usr_a", "ops", null), NOW)).toBe(false);
  });
});

describe("staleness", () => {
  it("a pending request is valid until its expiry, for the engaged version it was made for", () => {
    expect(staleReason(req(), engaged, NOW)).toBeNull();
    expect(staleReason(req(), engaged, NOW + RELEASE_TTL_MS)).toMatch(/expired/);
    expect(staleReason(req(), { engaged: false, version: 5 }, NOW)).toMatch(/no longer engaged/);
    expect(staleReason(req(), { engaged: true, version: 6 }, NOW)).toMatch(/changed/);
    expect(staleReason(req({ status: "approved" }), engaged, NOW + RELEASE_TTL_MS)).toBeNull();
  });

  it("reads a stale pending request as expired and leaves decided ones alone", () => {
    expect(effectiveStatus(req(), engaged, NOW)).toBe("pending");
    expect(effectiveStatus(req(), engaged, NOW + RELEASE_TTL_MS)).toBe("expired");
    expect(effectiveStatus(req({ status: "rejected" }), engaged, NOW)).toBe("rejected");
  });
});

describe("request", () => {
  it("needs a fresh step-up, an engaged switch and no pending request", () => {
    expect(canRequest(op("usr_a", "ops"), engaged, null, "r", NOW)).toEqual({ ok: true, replay: false });
    expect(canRequest(op("usr_a", "ops", null), engaged, null, "r", NOW)).toMatchObject({
      error: "step_up_required",
    });
    expect(canRequest(op("usr_a"), { engaged: false, version: 5 }, null, "r", NOW)).toMatchObject({
      error: "state_conflict",
      expire: false,
    });
    expect(canRequest(op("usr_bob"), engaged, req(), "r", NOW)).toMatchObject({ error: "state_conflict" });
  });

  it("the same operator repeating the same request is a replay; a different reason is a conflict", () => {
    expect(canRequest(op("usr_alice", "ops"), engaged, req(), "root cause fixed", NOW)).toEqual({
      ok: true,
      replay: true,
    });
    expect(canRequest(op("usr_alice", "ops"), engaged, req(), "other", NOW)).toMatchObject({
      error: "state_conflict",
    });
  });

  it("a stale pending request does not block a new one", () => {
    expect(canRequest(op("usr_bob"), engaged, req({ expiresAtMs: NOW }), "r", NOW)).toEqual({
      ok: true,
      replay: false,
    });
  });
});

describe("approve", () => {
  it("a different ops_admin with a fresh step-up approves a valid request", () => {
    expect(canApprove(op("usr_bob"), req(), engaged, NOW)).toEqual({ ok: true, replay: false });
  });

  it("refuses the requester themself (approver_conflict), whatever their role", () => {
    expect(canApprove(op("usr_alice"), req({ requestedRole: "ops_admin" }), engaged, NOW)).toMatchObject({
      error: "approver_conflict",
    });
  });

  it("refuses ops (not admin) and a stale step-up", () => {
    expect(canApprove(op("usr_bob", "ops"), req(), engaged, NOW)).toMatchObject({ error: "permission_denied" });
    expect(canApprove(op("usr_bob", "ops_admin", fresh - 600), req(), engaged, NOW)).toMatchObject({
      error: "step_up_required",
    });
  });

  it("refuses decided requests; replays the same approver's approval", () => {
    expect(canApprove(op("usr_bob"), req({ status: "approved", decidedBy: "usr_bob" }), engaged, NOW)).toEqual({
      ok: true,
      replay: true,
    });
    expect(canApprove(op("usr_carol"), req({ status: "approved", decidedBy: "usr_bob" }), engaged, NOW)).toMatchObject({
      error: "state_conflict",
      expire: false,
    });
    expect(canApprove(op("usr_bob"), req({ status: "rejected", decidedBy: "usr_bob" }), engaged, NOW)).toMatchObject({
      error: "state_conflict",
    });
  });

  it("expires a request past its hour or for an older switch version", () => {
    const later = op("usr_bob", "ops_admin", Math.floor((NOW + RELEASE_TTL_MS) / 1000) + 60);
    expect(canApprove(later, req(), engaged, NOW + RELEASE_TTL_MS)).toMatchObject({
      error: "state_conflict",
      expire: true,
    });
    expect(canApprove(op("usr_bob"), req(), { engaged: true, version: 5 }, NOW)).toMatchObject({ expire: true });
  });
});

describe("reject", () => {
  it("any ops_admin, the requester included (withdraw), without step-up", () => {
    expect(canReject(op("usr_bob", "ops_admin", null), req(), engaged, NOW)).toEqual({ ok: true, replay: false });
    expect(canReject(op("usr_alice"), req(), engaged, NOW)).toEqual({ ok: true, replay: false });
    expect(canReject(op("usr_bob", "ops"), req(), engaged, NOW)).toMatchObject({ error: "permission_denied" });
  });

  it("replays, conflicts and expires like approve", () => {
    expect(canReject(op("usr_bob"), req({ status: "rejected", decidedBy: "usr_bob" }), engaged, NOW)).toEqual({
      ok: true,
      replay: true,
    });
    expect(canReject(op("usr_bob"), req({ status: "approved", decidedBy: "usr_carol" }), engaged, NOW)).toMatchObject({
      error: "state_conflict",
      expire: false,
    });
    expect(canReject(op("usr_bob"), req(), engaged, NOW + RELEASE_TTL_MS)).toMatchObject({ expire: true });
  });
});

it("names both operators in the release actor", () => {
  expect(releaseActor("usr_a", "usr_b")).toBe("usr_a+usr_b");
});
