/** Kysely table types (migrations/0001_sentinel.sql, 0002_two_person_release.sql, 0003_account_names.sql, 0004_single_operator.sql, 0005_integrity_containment.sql) and identity's registry view (read-only role). */
import type { ColumnType, KitTables } from "@nearpay-internal/db";

type Timestamp = ColumnType<Date, Date | string | undefined, Date | string>;
type Opt<T> = ColumnType<T | null, T | null | undefined, T | null>;
type Json<T> = ColumnType<T, string, string>;
type OptJson<T> = ColumnType<T | null, string | null | undefined, string | null>;

export interface AttestationsTable {
  id: string;
  livemode: boolean;
  kind: "route_quote" | "intents_transfer";
  deposit_key: string;
  attempt_id: string;
  account_id: Opt<string>;
  destination_id: Opt<string>;
  result: "signed" | "rejected" | "unavailable";
  class: Opt<string>;
  reasons: ColumnType<string[], string[] | undefined, string[]>;
  response: OptJson<unknown>;
  client_ip: Opt<string>;
  expires_at: Opt<Date>;
  created_at: Timestamp;
}

export interface AuditFindingsTable {
  id: string;
  execution_id: string;
  account_id: string;
  livemode: boolean;
  /** `attestation` (migration 0005): a pipeline integrity breach on a live NearPay deposit address. */
  check_kind: "destination" | "settlement" | "attestation";
  result: "pass" | "mismatch" | "unverifiable";
  details: Json<Record<string, unknown>>;
  tx_chain: Opt<string>;
  tx_hash: Opt<string>;
  recipient: Opt<string>;
  asset_id: Opt<string>;
  /** numeric(78,0): read as a decimal string. */
  amount: ColumnType<string | null, string | null | undefined, string | null>;
  created_at: Timestamp;
  acknowledged_at: Opt<Date>;
  acknowledged_by: Opt<string>;
  acknowledgement_note: Opt<string>;
}

export interface KillSwitchTable {
  id: number;
  engaged: boolean;
  reason: string;
  actor: string;
  version: number;
  updated_at: Timestamp;
}

export interface KillSwitchLogTable {
  id: string;
  engaged: boolean;
  reason: string;
  actor: string;
  version: number;
  created_at: Timestamp;
}

/** A two-person release request (`OpsApproval`, `opa_`); operator ids are `usr_` uuids. */
export interface ReleaseRequestsTable {
  id: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "expired";
  requested_by: string;
  requested_role: "ops" | "ops_admin";
  requested_at: Timestamp;
  decided_by: Opt<string>;
  decided_role: Opt<"ops" | "ops_admin">;
  decided_at: Opt<Date>;
  decision_note: Opt<string>;
  expires_at: ColumnType<Date, Date | string, Date | string>;
  switch_version: number;
  /** Migration 0004: active `ops_admin` operators when requested (null: unknown → two-person). */
  requested_admins: Opt<number>;
  /** Migration 0004: approved by its requester on a single-operator platform. */
  single_operator: ColumnType<boolean, boolean | undefined, boolean>;
}

/** Display names of accounts (spec 0.2.1), from `evt.identity.account.*`; stale versions are ignored. */
export interface AccountNamesTable {
  account_id: string;
  display_name: string;
  version: number;
  updated_at: Timestamp;
}

/** A `security` refusal on a deposit address rails confirmed NearPay issued (migration 0005, append-only). */
export interface IntegrityBreachesTable {
  id: string;
  livemode: boolean;
  evidence: "pipeline" | "request";
  rules: ColumnType<string[], string[], string[]>;
  reasons: ColumnType<string[], string[], string[]>;
  attempt_id: string;
  deposit_address: Opt<string>;
  deposit_memo: Opt<string>;
  execution_id: Opt<string>;
  account_id: Opt<string>;
  destination_account_id: Opt<string>;
  client_ip: Opt<string>;
  quarantined: ColumnType<boolean, boolean | undefined, boolean>;
  systemic: ColumnType<boolean, boolean | undefined, boolean>;
  created_at: Timestamp;
}

/** One quarantine per (account, mode) (migration 0005). */
export interface QuarantinesTable {
  account_id: string;
  livemode: boolean;
  status: "active" | "cleared";
  reason: string;
  breach_id: Opt<string>;
  created_by: string;
  created_at: Timestamp;
  expires_at: ColumnType<Date, Date | string, Date | string>;
  cleared_at: Opt<Date>;
  cleared_by: Opt<string>;
  clear_note: Opt<string>;
  version: ColumnType<number, number | undefined, number>;
  updated_at: Timestamp;
}

export interface QuarantineLogTable {
  id: string;
  account_id: string;
  livemode: boolean;
  action: "quarantined" | "extended" | "cleared";
  reason: string;
  actor: string;
  expires_at: Opt<Date>;
  version: number;
  created_at: Timestamp;
}

export interface SentinelTables {
  account_names: AccountNamesTable;
  integrity_breaches: IntegrityBreachesTable;
  quarantines: QuarantinesTable;
  quarantine_log: QuarantineLogTable;
  attestations: AttestationsTable;
  audit_findings: AuditFindingsTable;
  kill_switch: KillSwitchTable;
  kill_switch_log: KillSwitchLogTable;
  release_requests: ReleaseRequestsTable;
}

export type DB = SentinelTables & KitTables;

/** identity's `sentinel_destination_registry` view (identity migrations 0001 + 0002): active destinations and once-active disabled ones. */
export interface RegistryDB {
  sentinel_destination_registry: {
    id: string;
    account_id: string;
    livemode: boolean;
    asset_id: string;
    type: string;
    chain: string;
    address_norm: string;
    status: string;
    active_at: Date | null;
    merchant_name: string;
    kyb_verified: boolean;
    verification: string;
    disabled_at: Date | null;
  };
}
