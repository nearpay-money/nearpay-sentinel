/** Configuration (lld/sentinel.md §10, foundations §13). */
import { NearAccountId } from "@nearpay/spec";
import { baseConfigShape, list, loadConfig, secret, url } from "@nearpay-internal/service";
import { z } from "zod";

const json = <T extends z.ZodType>(schema: T, fallback: string) =>
  z
    .string()
    .default(fallback)
    .transform((s, ctx) => {
      try {
        const r = schema.safeParse(JSON.parse(s));
        if (r.success) return r.data as z.output<T>;
        ctx.addIssue({ code: "custom", message: r.error.message });
      } catch {
        ctx.addIssue({ code: "custom", message: "expected JSON" });
      }
      return z.NEVER;
    });

const bps = z.int().min(0).max(10_000);
const nearAccount = z.string().refine((s) => NearAccountId.safeParse(s).success, "must be a NEAR account id");
const rpcList = () => list(url(["https:", "http:"]));
/** Sentinel's own RPC provider accounts (URLs carry API keys): a fresh schema, since `secret()` marks the one it wraps. */
const ownRpcList = () => secret(rpcList()).optional();
const rawEd25519 = z
  .string()
  .refine(
    (s) => /^[A-Za-z0-9_-]{43}$/.test(s) && Buffer.from(s, "base64url").length === 32,
    "a raw 32-byte Ed25519 key, base64url",
  );
const timestamp = z.string().refine((s) => Number.isFinite(Date.parse(s)), "an ISO 8601 timestamp");

const shared = {
  ...baseConfigShape,
  dbUrl: secret(url(["postgres:", "postgresql:"])),
  /** identity's database as `sentinel_ro` (SELECT on `sentinel_destination_registry` only). */
  registryDbUrl: secret(url(["postgres:", "postgresql:"])),
  /** Attestation cache shared by the api replicas (optional: in-process cache per replica without it). */
  valkeyUrl: url(["redis:", "rediss:"]).optional(),
  identityUrl: url(["http:", "https:"]),
  serviceClientSecret: secret(),
  railsUrl: url(["http:", "https:"]),
  /** Ed25519 PKCS#8 PEM; the kid is the file name `sentinel-<kid>.pem` (§10). */
  sentinelSigningKey: secret(),
  /** Retirement time of the signing key published by `GET /v1/attestations/keys` (unset: none scheduled). */
  sentinelKeyNotAfter: timestamp.optional(),
  /** Keys announced next to the signing key during a rotation (§11): `[{kid, public_key, not_after}]`. */
  sentinelAnnouncedKeys: json(
    z.array(z.object({ kid: z.string().regex(/^[a-z0-9-]{1,64}$/), public_key: rawEd25519, not_after: timestamp })),
    "[]",
  ),
  /** Payments' attestation-ticket public key (raw Ed25519, base64url). */
  paymentsTicketPubkey: rawEd25519,
  /** Live appFees / Intents fee recipient (owner-provided). Unset: live requests are refused (R6). */
  treasuryAccount: nearAccount.optional(),
  testTreasuryAccount: nearAccount.default("treasury.nearpay.near"),
  intentsContract: nearAccount.default("intents.near"),
  referral: z.string().min(1).max(64).default("nearpay"),
  /** 1Click appFees split (R6 amended): provider share and floors, bps. */
  providerSplit: json(
    z.object({ share_bps: bps, floor_bps: bps, stable_floor_bps: bps }),
    '{"share_bps":5000,"floor_bps":20,"stable_floor_bps":1}',
  ),
  oneclickBaseUrl: url(["https:", "http:"]).default("https://1click.chaindefuser.com"),
  /** Sentinel's own 1Click key (separate from rails'). */
  oneclickApiKey: secret().optional(),
  /** Test mode (nearpay-sandbox); without it test-mode requests are unavailable. */
  sandboxBaseUrl: url(["http:", "https:"]).optional(),
  sandboxSigningPubkey: z.string().min(32).optional(),
  /** Fraction of settled executions audited (1.0 in Stages 1–2). */
  auditSampleRate: z.coerce.number().min(0).max(1).default(1),
  /** Executions at or above this many USD are always audited. */
  auditAlwaysUsd: z.coerce.number().min(0).default(10_000),
  /** Shared public RPC pools; sentinel's own provider accounts (`*_FILE` secrets) take precedence. */
  nearRpcUrls: rpcList().default(["https://free.rpc.fastnear.com", "https://rpc.mainnet.near.org"]),
  evmRpcUrls_1: rpcList().default(["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"]),
  evmRpcUrls_8453: rpcList().default(["https://mainnet.base.org", "https://base-rpc.publicnode.com"]),
  evmRpcUrls_42161: rpcList().default(["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"]),
  sentinelNearRpcUrls: ownRpcList(),
  sentinelEvmRpcUrls_1: ownRpcList(),
  sentinelEvmRpcUrls_8453: ownRpcList(),
  sentinelEvmRpcUrls_42161: ownRpcList(),
};

export const apiShape = { ...shared };
export const workerShape = { ...shared, natsUrl: url(["nats:", "tls:"]) };
export const opsShape = { ...shared };
export const migrateShape = { ...baseConfigShape, dbUrl: secret(url(["postgres:", "postgresql:"])) };

type WithPath<T> = T & { /** Path of the signing key file (its name carries the kid). */ signingKeyPath?: string };
export type SharedConfig = WithPath<z.output<z.ZodObject<typeof shared>>>;
export type ApiConfig = WithPath<z.output<z.ZodObject<typeof apiShape>>>;
export type WorkerConfig = WithPath<z.output<z.ZodObject<typeof workerShape>>>;

const withPath = <T extends object>(c: T): WithPath<T> => {
  const p = process.env.NP_SENTINEL_SIGNING_KEY_FILE;
  return p ? { ...c, signingKeyPath: p } : c;
};

export const readApiConfig = (): ApiConfig => withPath(loadConfig(apiShape));
export const readWorkerConfig = (): WorkerConfig => withPath(loadConfig(workerShape));
export const readOpsConfig = (): SharedConfig => withPath(loadConfig(opsShape));

/** Sentinel's NEAR RPC pool. */
export function nearRpcUrls(c: SharedConfig): readonly string[] {
  return c.sentinelNearRpcUrls?.length ? c.sentinelNearRpcUrls : c.nearRpcUrls;
}

/** Sentinel's EVM RPC pools by chain. */
export function evmRpcUrls(c: SharedConfig): Record<string, readonly string[]> {
  const pick = (own: readonly string[] | undefined, shared: readonly string[]) => (own?.length ? own : shared);
  return {
    "eip155:1": pick(c.sentinelEvmRpcUrls_1, c.evmRpcUrls_1),
    "eip155:8453": pick(c.sentinelEvmRpcUrls_8453, c.evmRpcUrls_8453),
    "eip155:42161": pick(c.sentinelEvmRpcUrls_42161, c.evmRpcUrls_42161),
  };
}
