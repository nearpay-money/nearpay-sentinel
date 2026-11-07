/**
 * Two-person kill-switch release (lld/sentinel.md §6, spec `OpsApproval`), pure. Engaging needs one
 * operator; releasing needs a request by one operator and an approval by a **different** `ops_admin`,
 * both with a fresh step-up. Operator ids are always the `sub` of the verified ops token, never a client
 * field. A request is for one engaged switch version, expires after one hour, and at most one is pending.
 *
 * The database repeats the different-approver rule (`release_approver_differs`) and the single pending
 * request (`release_one_pending`); a trigger allows only `pending → approved | rejected | expired`.
 */

export const RELEASE_TTL_MS = 60 * 60_000;

export type OpsRole = "ops" | "ops_admin";
export type ReleaseStatus = "pending" | "approved" | "rejected" | "expired";

/** The verified ops principal. `id` is the operator user id (`usr_…`). */
export interface Operator {
  readonly id: string;
  readonly role: OpsRole;
  /** Unix seconds until which the step-up assertion is fresh (absent: none). */
  readonly stepUpUntil: number | undefined;
}

export interface SwitchView {
  readonly engaged: boolean;
  readonly version: number;
}

export interface ReleaseRequest {
  readonly id: string;
  readonly reason: string;
  readonly status: ReleaseStatus;
  readonly requestedBy: string;
  readonly requestedRole: OpsRole;
  readonly expiresAtMs: number;
  readonly switchVersion: number;
  readonly decidedBy: string | null;
}

export type Refusal =
  | { readonly ok: false; readonly error: "permission_denied" | "step_up_required"; readonly reason: string }
  | { readonly ok: false; readonly error: "approver_conflict"; readonly reason: string }
  /** `expire`: the request is pending but no longer valid; the caller records it as `expired`. */
  | { readonly ok: false; readonly error: "state_conflict"; readonly reason: string; readonly expire: boolean };

/** `replay`: the same operator repeated a call that already took effect (idempotent retry). */
export type Verdict = { readonly ok: true; readonly replay: boolean } | Refusal;

const deny = (error: "permission_denied" | "step_up_required", reason: string): Refusal => ({
  ok: false,
  error,
  reason,
});
const conflict = (reason: string, expire = false): Refusal => ({ ok: false, error: "state_conflict", reason, expire });

export function stepUpFresh(op: Operator, nowMs: number): boolean {
  return op.stepUpUntil !== undefined && op.stepUpUntil * 1000 > nowMs;
}

/**
 * Why a pending request can no longer be approved (null: still valid): it expired, or the switch it was
 * for changed (released, or engaged again — every change bumps the version).
 */
export function staleReason(r: ReleaseRequest, sw: SwitchView, nowMs: number): string | null {
  if (r.status !== "pending") return null;
  if (nowMs >= r.expiresAtMs) return "the release request has expired";
  if (!sw.engaged) return "the kill switch is no longer engaged";
  if (sw.version !== r.switchVersion) return "the kill switch changed since the request";
  return null;
}

/** The status a reader should see: a pending request past its validity reads as `expired`. */
export function effectiveStatus(r: ReleaseRequest, sw: SwitchView, nowMs: number): ReleaseStatus {
  return staleReason(r, sw, nowMs) === null ? r.status : "expired";
}

/**
 * Request a release. `pending` is the currently valid pending request, if any (stale ones are expired
 * first). The same operator repeating the same request is a replay.
 */
export function canRequest(
  op: Operator,
  sw: SwitchView,
  pending: ReleaseRequest | null,
  reason: string,
  nowMs: number,
): Verdict {
  if (!stepUpFresh(op, nowMs)) return deny("step_up_required", "requesting a release needs a fresh step-up");
  if (pending && staleReason(pending, sw, nowMs) === null) {
    if (pending.requestedBy === op.id && pending.reason === reason) return { ok: true, replay: true };
    return conflict("a release request is already pending");
  }
  if (!sw.engaged) return conflict("the kill switch is not engaged");
  return { ok: true, replay: false };
}

/** Approve (and so execute) a release: the second operator. */
export function canApprove(op: Operator, r: ReleaseRequest, sw: SwitchView, nowMs: number): Verdict {
  if (op.role !== "ops_admin") return deny("permission_denied", "only an ops_admin approves a release");
  if (!stepUpFresh(op, nowMs)) return deny("step_up_required", "approving a release needs a fresh step-up");
  if (op.id === r.requestedBy)
    return { ok: false, error: "approver_conflict", reason: "the approver must be a different operator" };
  if (r.status === "approved" && r.decidedBy === op.id) return { ok: true, replay: true };
  if (r.status !== "pending") return conflict(`the release request is ${r.status}`);
  const stale = staleReason(r, sw, nowMs);
  if (stale !== null) return conflict(stale, true);
  return { ok: true, replay: false };
}

/** Reject, or (as the requester) withdraw, a pending request. Executes nothing, so no step-up. */
export function canReject(op: Operator, r: ReleaseRequest, sw: SwitchView, nowMs: number): Verdict {
  if (op.role !== "ops_admin") return deny("permission_denied", "only an ops_admin rejects a release");
  if (r.status === "rejected" && r.decidedBy === op.id) return { ok: true, replay: true };
  if (r.status !== "pending") return conflict(`the release request is ${r.status}`);
  const stale = staleReason(r, sw, nowMs);
  if (stale !== null) return conflict(stale, true);
  return { ok: true, replay: false };
}

/** Kill-switch log / event actor of a two-person release: `<requester>+<approver>`. */
export function releaseActor(requester: string, approver: string): string {
  return `${requester}+${approver}`;
}
