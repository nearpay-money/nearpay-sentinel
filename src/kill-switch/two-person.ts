/**
 * Two-person kill-switch release (lld/sentinel.md §6, spec `OpsApproval`), pure. Engaging needs one
 * operator; releasing needs a request by one operator and an approval by a **different** `ops_admin`,
 * both with a fresh step-up — while two or more operators can approve (adaptive rule, below). Operator ids are always the `sub` of the verified ops token, never a client
 * field. A request is for one engaged switch version, expires after one hour, and at most one is pending.
 *
 * The database repeats the different-approver rule (`release_approver_differs`) and the single pending
 * request (`release_one_pending`); a trigger allows only `pending → approved | rejected | expired`.
 */

export const RELEASE_TTL_MS = 60 * 60_000;

/** The only `NP_ENV` values on which the single-person release (CLI, `POST /internal/kill-switch`) is allowed. */
export const SINGLE_PERSON_ENVS: ReadonlySet<string> = new Set(["local", "test"]);

/**
 * Allow-list, fail closed: `server`, an unknown stage, an empty or mistyped value all require two persons
 * (audit finding 2, stage 2).
 */
export function singlePersonAllowed(env: string): boolean {
  return SINGLE_PERSON_ENVS.has(env);
}

export type OpsRole = "ops" | "ops_admin";
export type ReleaseStatus = "pending" | "approved" | "rejected" | "expired";

/** The verified ops principal. `id` is the operator user id (`usr_…`). */
export interface Operator {
  readonly id: string;
  readonly role: OpsRole;
  /** Unix seconds until which the step-up assertion is fresh (absent: none). */
  readonly stepUpUntil: number | undefined;
  /**
   * Active operators who can approve (`ops_admin`) when identity minted the token (claim `ops_admins`).
   * Absent (an older identity): treated as two or more — the two-person rule applies (fail closed).
   */
  readonly activeAdmins?: number | undefined;
  /** Unix seconds of the operator's last user verification (claim `ops_auth_at`: passkey step-up or Access login). */
  readonly authAt?: number | undefined;
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
  /** When the first step was recorded. */
  readonly requestedAtMs: number;
  /** Active approvers (`ops_admin`) when the request was made; null: unknown (two-person applies). */
  readonly requestedAdmins: number | null;
  readonly expiresAtMs: number;
  readonly switchVersion: number;
  readonly decidedBy: string | null;
}

export type Refusal =
  | { readonly ok: false; readonly error: "permission_denied" | "step_up_required"; readonly reason: string }
  | { readonly ok: false; readonly error: "approver_conflict"; readonly reason: string }
  /** Single-operator completion without a written reason: `400` on `note`. */
  | { readonly ok: false; readonly error: "reason_required"; readonly reason: string }
  /** `expire`: the request is pending but no longer valid; the caller records it as `expired`. */
  | { readonly ok: false; readonly error: "state_conflict"; readonly reason: string; readonly expire: boolean };

/** `replay`: the same operator repeated a call that already took effect (idempotent retry). */
export type Verdict =
  | { readonly ok: true; readonly replay: boolean; readonly singleOperator?: boolean | undefined }
  | Refusal;

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

// ---------------------------------------------------------------------------------------------
// Adaptive two-person rule (lld/sentinel.md §6 "Single-operator platforms"). A second, different operator
// is required only while the platform has two or more active operators who can approve (`ops_admin`) —
// the same principle as the merchant two-approver rule. The count is the one identity signed into the
// token: recorded on the request when it was made, and checked again at completion, so revoking the other
// operator mid-action never turns a two-person request into a single-operator one (and adding a second
// operator turns the rule back on at once). With one active operator, the requester completes it alone
// with: a user verification performed after the wait (`NP_OPS_SINGLE_OPERATOR_DELAY_S`, > 0 here), a
// written reason, an audit event marked `single_operator` and `nearpay_ops_single_operator_actions_total`.
// ---------------------------------------------------------------------------------------------

/** Minimum length of the written reason of a single-operator completion (trimmed). */
export const SINGLE_OPERATOR_REASON_MIN = 20;

export interface SingleOperatorPolicy {
  /** Minimum wait after the request, ms (> 0 for the kill-switch release). */
  readonly delayMs: number;
}

export const DEFAULT_SINGLE_OPERATOR_POLICY: SingleOperatorPolicy = { delayMs: 300_000 };

const single = (n: number | null | undefined): boolean => n !== null && n !== undefined && n <= 1;

/** The request was made on a single-operator platform (so its requester may complete it alone). */
export function madeBySingleOperator(r: ReleaseRequest): boolean {
  return single(r.requestedAdmins);
}

/** When the requester may complete their own request (null: the two-person rule applies to it). */
export function singleOperatorAvailableAt(r: ReleaseRequest, policy: SingleOperatorPolicy): number | null {
  return madeBySingleOperator(r) ? r.requestedAtMs + policy.delayMs : null;
}

/** The single-operator guards (the requester completing their own request), or null when they hold. */
export function singleOperatorProblem(
  op: Operator,
  r: ReleaseRequest,
  policy: SingleOperatorPolicy,
  note: string | undefined,
  nowMs: number,
): Refusal | null {
  if (!madeBySingleOperator(r) || !single(op.activeAdmins) || policy.delayMs <= 0)
    return { ok: false, error: "approver_conflict", reason: "the approver must be a different operator" };
  const availableAt = r.requestedAtMs + policy.delayMs;
  if (nowMs < availableAt)
    return {
      ok: false,
      error: "approver_conflict",
      reason: `you are the only operator, so you can complete your own request from ${new Date(availableAt).toISOString()}`,
    };
  if (op.authAt === undefined || op.authAt * 1000 < availableAt)
    return deny("step_up_required", "completing your own request needs a new confirmation after the wait");
  if ((note ?? "").trim().length < SINGLE_OPERATOR_REASON_MIN)
    return {
      ok: false,
      error: "reason_required",
      reason: `completing your own request needs a written reason (at least ${SINGLE_OPERATOR_REASON_MIN} characters)`,
    };
  return null;
}

/**
 * Approve (and so execute) a release: the second operator — or, on a single-operator platform, the
 * requester under {@link singleOperatorProblem} (`singleOperator: true` tells the caller).
 */
export function canApprove(
  op: Operator,
  r: ReleaseRequest,
  sw: SwitchView,
  nowMs: number,
  policy: SingleOperatorPolicy = DEFAULT_SINGLE_OPERATOR_POLICY,
  note?: string,
): Verdict {
  if (op.role !== "ops_admin") return deny("permission_denied", "only an ops_admin approves a release");
  if (!stepUpFresh(op, nowMs)) return deny("step_up_required", "approving a release needs a fresh step-up");
  const self = op.id === r.requestedBy;
  if (self && !(madeBySingleOperator(r) && single(op.activeAdmins)))
    return { ok: false, error: "approver_conflict", reason: "the approver must be a different operator" };
  if (r.status === "approved" && r.decidedBy === op.id) return { ok: true, replay: true };
  if (r.status !== "pending") return conflict(`the release request is ${r.status}`);
  const stale = staleReason(r, sw, nowMs);
  if (stale !== null) return conflict(stale, true);
  if (self) {
    const problem = singleOperatorProblem(op, r, policy, note, nowMs);
    if (problem) return problem;
    return { ok: true, replay: false, singleOperator: true };
  }
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
