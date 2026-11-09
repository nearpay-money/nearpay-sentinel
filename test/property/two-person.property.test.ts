/**
 * Property (lld/sentinel.md §6, two-person release): over any interleaving of engage / request / approve /
 * reject calls by any operators at any times, the switch is never released by one principal — every
 * release has a request and an approval by two different operators, the approver an `ops_admin`, both with
 * a fresh step-up, inside the hour, for the engaged version the request was made for; at most one request
 * is ever pending; an engage in between always invalidates a request; and stale requests always expire.
 *
 * The model applies the pure verdicts exactly like the use cases do (src/kill-switch/release.ts): each call
 * runs serialised (the switch row is locked), a stale pending request is expired first.
 */
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  canApprove,
  canReject,
  canRequest,
  type Operator,
  RELEASE_TTL_MS,
  type ReleaseRequest,
  staleReason,
} from "../../src/kill-switch/two-person.js";

interface Release {
  requester: string;
  approver: string;
  approverRole: string;
  approverStepUp: boolean;
  requesterStepUp: boolean;
  at: number;
  requestedAt: number;
  requestVersion: number;
  versionBefore: number;
}

interface World {
  engaged: boolean;
  version: number;
  requests: (ReleaseRequest & { requestedAt: number; requesterStepUp: boolean })[];
  releases: Release[];
}

const OPS = ["usr_a", "usr_b", "usr_c"] as const;

const operator = fc.record({
  id: fc.constantFrom(...OPS),
  role: fc.constantFrom("ops" as const, "ops_admin" as const),
  fresh: fc.boolean(),
});

type Call =
  | { kind: "engage"; dt: number }
  | { kind: "request"; dt: number; op: { id: string; role: "ops" | "ops_admin"; fresh: boolean }; reason: string }
  | {
      kind: "approve" | "reject";
      dt: number;
      op: { id: string; role: "ops" | "ops_admin"; fresh: boolean };
      pick: number;
    };

const dt = fc.integer({ min: 0, max: 40 * 60_000 }); // up to 40 min between calls: expiry happens often
const call: fc.Arbitrary<Call> = fc.oneof(
  fc.record({ kind: fc.constant("engage" as const), dt }),
  fc.record({ kind: fc.constant("request" as const), dt, op: operator, reason: fc.constantFrom("r1", "r2") }),
  fc.record({ kind: fc.constantFrom("approve" as const, "reject" as const), dt, op: operator, pick: fc.nat() }),
);

function opOf(o: { id: string; role: "ops" | "ops_admin"; fresh: boolean }, now: number): Operator {
  return { id: o.id, role: o.role, stepUpUntil: o.fresh ? Math.floor(now / 1000) + 600 : Math.floor(now / 1000) - 1 };
}

function run(calls: readonly Call[]): World {
  const w: World = { engaged: true, version: 1, requests: [], releases: [] };
  let now = 1_800_000_000_000;
  let n = 0;
  const pendings = () => w.requests.filter((r) => r.status === "pending");
  const setStatus = (id: string, status: ReleaseRequest["status"], decidedBy: string | null = null) => {
    const i = w.requests.findIndex((r) => r.id === id);
    const r = w.requests[i];
    if (!r) throw new Error("no request");
    if (r.status !== "pending") throw new Error(`transition from ${r.status}`); // the DB trigger
    w.requests[i] = { ...r, status, decidedBy };
  };
  for (const c of calls) {
    now += c.dt;
    expect(pendings().length).toBeLessThanOrEqual(1);
    if (c.kind === "engage") {
      for (const p of pendings()) setStatus(p.id, "expired");
      if (!w.engaged) {
        w.engaged = true;
        w.version += 1;
      }
      continue;
    }
    const op = opOf(c.op, now);
    const sw = { engaged: w.engaged, version: w.version };
    if (c.kind === "request") {
      let pending = pendings()[0] ?? null;
      if (pending && staleReason(pending, sw, now) !== null) {
        setStatus(pending.id, "expired");
        pending = null;
      }
      const v = canRequest(op, sw, pending, c.reason, now);
      if (!v.ok || v.replay) continue;
      w.requests.push({
        id: `opa_${n++}`,
        reason: c.reason,
        status: "pending",
        requestedBy: op.id,
        requestedRole: op.role,
        requestedAtMs: now,
        requestedAdmins: null,
        expiresAtMs: now + RELEASE_TTL_MS,
        switchVersion: w.version,
        decidedBy: null,
        requestedAt: now,
        requesterStepUp: c.op.fresh,
      });
      continue;
    }
    if (w.requests.length === 0) continue;
    const r = w.requests[c.pick % w.requests.length] as World["requests"][number];
    const v = c.kind === "approve" ? canApprove(op, r, sw, now) : canReject(op, r, sw, now);
    if (!v.ok) {
      if (v.error === "state_conflict" && v.expire) setStatus(r.id, "expired");
      continue;
    }
    if (v.replay) continue;
    if (c.kind === "reject") {
      setStatus(r.id, "rejected", op.id);
      continue;
    }
    setStatus(r.id, "approved", op.id);
    w.releases.push({
      requester: r.requestedBy,
      approver: op.id,
      approverRole: op.role,
      approverStepUp: c.op.fresh,
      requesterStepUp: r.requesterStepUp,
      at: now,
      requestedAt: r.requestedAt,
      requestVersion: r.switchVersion,
      versionBefore: w.version,
    });
    w.engaged = false;
    w.version += 1;
  }
  return w;
}

describe("two-person release (property)", () => {
  it("never releases with one principal; every release is a valid request + a different ops_admin's approval", () => {
    fc.assert(
      fc.property(fc.array(call, { maxLength: 60 }), (calls) => {
        const w = run(calls);
        for (const r of w.releases) {
          expect(r.approver).not.toBe(r.requester);
          expect(r.approverRole).toBe("ops_admin");
          expect(r.approverStepUp).toBe(true);
          expect(r.requesterStepUp).toBe(true);
          expect(r.at - r.requestedAt).toBeLessThan(RELEASE_TTL_MS);
          expect(r.requestVersion).toBe(r.versionBefore);
        }
        expect(w.requests.filter((q) => q.status === "approved").length).toBe(w.releases.length);
        expect(w.requests.filter((q) => q.status === "pending").length).toBeLessThanOrEqual(1);
      }),
      { numRuns: 1000 },
    );
  });

  it("one operator alone — whatever roles, step-ups, timings and retries — never releases", () => {
    fc.assert(
      fc.property(fc.constantFrom(...OPS), fc.array(call, { maxLength: 60 }), (who, calls) => {
        const solo = calls.map((c) => (c.kind === "engage" ? c : { ...c, op: { ...c.op, id: who } }));
        expect(run(solo).releases).toEqual([]);
      }),
      { numRuns: 500 },
    );
  });

  it("a request is never approvable from its expiry on, nor after the switch changed", () => {
    const req = (o: Partial<ReleaseRequest> = {}): ReleaseRequest => ({
      id: "opa_1",
      reason: "safe",
      status: "pending",
      requestedBy: "usr_a",
      requestedRole: "ops",
      requestedAtMs: 1_000_000,
      requestedAdmins: null,
      expiresAtMs: 1_000_000 + RELEASE_TTL_MS,
      switchVersion: 7,
      decidedBy: null,
      ...o,
    });
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 3 * RELEASE_TTL_MS }),
        fc.integer({ min: 0, max: 10 }),
        fc.boolean(),
        (elapsed, version, engaged) => {
          const now = 1_000_000 + elapsed;
          const admin: Operator = { id: "usr_b", role: "ops_admin", stepUpUntil: Math.floor(now / 1000) + 60 };
          const v = canApprove(admin, req(), { engaged, version }, now);
          const valid = elapsed < RELEASE_TTL_MS && engaged && version === 7;
          expect(v.ok).toBe(valid);
          if (!valid) expect(v).toMatchObject({ ok: false, error: "state_conflict", expire: true });
        },
      ),
    );
  });

  it("concurrent requests: serialised under the switch lock, exactly one is created", () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ id: fc.constantFrom(...OPS), reason: fc.constantFrom("x", "y") }), {
          minLength: 2,
          maxLength: 8,
        }),
        (racers) => {
          const now = 5_000_000;
          const sw = { engaged: true, version: 3 };
          let pending: ReleaseRequest | null = null;
          let created = 0;
          for (const r of racers) {
            const op: Operator = { id: r.id, role: "ops", stepUpUntil: Math.floor(now / 1000) + 60 };
            const v = canRequest(op, sw, pending, r.reason, now);
            if (!v.ok) {
              expect(v.error).toBe("state_conflict");
              continue;
            }
            if (v.replay) {
              expect(pending?.requestedBy).toBe(r.id);
              expect(pending?.reason).toBe(r.reason);
              continue;
            }
            created++;
            pending = {
              id: "opa_x",
              reason: r.reason,
              status: "pending",
              requestedBy: r.id,
              requestedRole: "ops",
              requestedAtMs: now,
              requestedAdmins: null,
              expiresAtMs: now + RELEASE_TTL_MS,
              switchVersion: 3,
              decidedBy: null,
            };
          }
          expect(created).toBe(1);
        },
      ),
    );
  });
});
