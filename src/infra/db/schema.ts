/** Kysely table types (migrations/0001_sentinel.sql, 0002_two_person_release.sql, 0003_account_names.sql) and identity's registry view (read-only role). */
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
  check_kind: "destination" | "settlement";
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
}

/** Display names of accounts (spec 0.2.1), from `evt.identity.account.*`; stale versions are ignored. */
export interface AccountNamesTable {
  account_id: string;
  display_name: string;
  version: number;
  updated_at: Timestamp;
}

export interface SentinelTables {
  account_names: AccountNamesTable;
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
