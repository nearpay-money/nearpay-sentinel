/** Configuration (§10): secrets only from files, defaults, the signing-key path and RPC precedence. */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "@nearpay-internal/service";
import { describe, expect, it } from "vitest";
import {
  apiShape,
  bitcoinEsploraUrls,
  evmRpcUrls,
  nearRpcUrls,
  readApiConfig,
  solanaRpcUrls,
  workerShape,
} from "../../src/config.js";

const files: Record<string, string> = {
  "/s/db": "postgres://sentinel_app:x@postgres:5432/sentinel",
  "/s/registry": "postgres://sentinel_ro:x@postgres:5432/identity",
  "/s/client": "secret",
  "/s/key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
  "/s/near": "https://near.example/key1, https://near2.example/key2",
  "/s/solana": "https://sol.example/key1",
  "/s/esplora": "https://esplora.example/key1/api",
};
const env = {
  NP_ENV: "test",
  NP_DB_URL_FILE: "/s/db",
  NP_REGISTRY_DB_URL_FILE: "/s/registry",
  NP_IDENTITY_URL: "http://identity-api:8080",
  NP_SERVICE_CLIENT_SECRET_FILE: "/s/client",
  NP_RAILS_URL: "http://rails-api:8080",
  NP_SENTINEL_SIGNING_KEY_FILE: "/s/key",
  NP_PAYMENTS_TICKET_PUBKEY: "ggCDFpCs8t32Qj9OwHEoAAuRDTWM1Y0iNdqH6VYDm9k",
};
const read = (p: string) => {
  const v = files[p];
  if (v === undefined) throw new Error(`no file ${p}`);
  return v;
};

describe("config", () => {
  it("reads the Compose wiring with the LLD defaults", () => {
    const c = loadConfig(apiShape, { env, readFile: read });
    expect(c).toMatchObject({
      dbUrl: files["/s/db"],
      registryDbUrl: files["/s/registry"],
      sentinelSigningKey: files["/s/key"],
      auditSampleRate: 1,
      auditAlwaysUsd: 10_000,
      referral: "nearpay",
      intentsContract: "intents.near",
      testTreasuryAccount: "treasury.nearpay.near",
      providerSplit: { share_bps: 5000, floor_bps: 20, stable_floor_bps: 1 },
      sentinelAnnouncedKeys: [],
    });
    expect(c.treasuryAccount).toBeUndefined();
    expect(nearRpcUrls(c)).toEqual(["https://free.rpc.fastnear.com", "https://rpc.mainnet.near.org"]);
    expect(Object.keys(evmRpcUrls(c))).toEqual(["eip155:1", "eip155:8453", "eip155:42161"]);
  });

  it("refuses secrets from plain variables", () => {
    expect(() => loadConfig(apiShape, { env: { ...env, NP_SENTINEL_SIGNING_KEY: "pem" }, readFile: read })).toThrow(
      /_FILE/,
    );
  });

  it("reads the shared public pools from plain variables (as Compose sets them)", () => {
    const c = loadConfig(apiShape, {
      env: {
        ...env,
        NP_NEAR_RPC_URLS: "https://rpc.mainnet.near.org",
        NP_EVM_RPC_URLS_8453: "https://mainnet.base.org",
      },
      readFile: read,
    });
    expect(nearRpcUrls(c)).toEqual(["https://rpc.mainnet.near.org"]);
    expect(evmRpcUrls(c)["eip155:8453"]).toEqual(["https://mainnet.base.org"]);
  });

  it("refuses sentinel's own RPC accounts from plain variables (their URLs carry keys)", () => {
    expect(() =>
      loadConfig(apiShape, { env: { ...env, NP_SENTINEL_NEAR_RPC_URLS: "https://k.example" }, readFile: read }),
    ).toThrow(/NP_SENTINEL_NEAR_RPC_URLS_FILE/);
  });

  it("prefers sentinel's own RPC accounts (secret files) over the shared pools", () => {
    const c = loadConfig(apiShape, { env: { ...env, NP_SENTINEL_NEAR_RPC_URLS_FILE: "/s/near" }, readFile: read });
    expect(nearRpcUrls(c)).toEqual(["https://near.example/key1", "https://near2.example/key2"]);
  });

  it("Stage 4: Solana / Bitcoin readers have no public default; own accounts take precedence over rails' pools", () => {
    const none = loadConfig(apiShape, { env, readFile: read });
    expect([solanaRpcUrls(none), bitcoinEsploraUrls(none)]).toEqual([[], []]);
    const shared = loadConfig(apiShape, {
      env: { ...env, NP_SOLANA_RPC_URLS: "https://sol.shared", NP_BITCOIN_ESPLORA_URLS: "https://esplora.shared/api" },
      readFile: read,
    });
    expect([solanaRpcUrls(shared), bitcoinEsploraUrls(shared)]).toEqual([
      ["https://sol.shared"],
      ["https://esplora.shared/api"],
    ]);
    const own = loadConfig(apiShape, {
      env: {
        ...env,
        NP_SOLANA_RPC_URLS: "https://sol.shared",
        NP_BITCOIN_ESPLORA_URLS: "https://esplora.shared/api",
        NP_SENTINEL_SOLANA_RPC_URLS_FILE: "/s/solana",
        NP_SENTINEL_BITCOIN_ESPLORA_URLS_FILE: "/s/esplora",
      },
      readFile: read,
    });
    expect([solanaRpcUrls(own), bitcoinEsploraUrls(own)]).toEqual([
      ["https://sol.example/key1"],
      ["https://esplora.example/key1/api"],
    ]);
  });

  it.each([
    ["a ticket key of the wrong length", { NP_PAYMENTS_TICKET_PUBKEY: "AAAA" }],
    ["a sample rate above 1", { NP_AUDIT_SAMPLE_RATE: "1.5" }],
    ["a treasury that is not a NEAR account", { NP_TREASURY_ACCOUNT: "Not An Account" }],
    ["a malformed key announcement", { NP_SENTINEL_ANNOUNCED_KEYS: '[{"kid":"X"}]' }],
    ["a malformed retirement time", { NP_SENTINEL_KEY_NOT_AFTER: "soon" }],
  ])("refuses %s", (_n, extra) => {
    expect(() => loadConfig(apiShape, { env: { ...env, ...extra }, readFile: read })).toThrow();
  });

  it("the worker also needs NATS", () => {
    expect(() => loadConfig(workerShape, { env, readFile: read })).toThrow(/NATS/);
    expect(loadConfig(workerShape, { env: { ...env, NP_NATS_URL: "nats://nats:4222" }, readFile: read }).natsUrl).toBe(
      "nats://nats:4222",
    );
  });

  it("keeps the signing key's path (its file name carries the kid)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-config-"));
    const saved = { ...process.env };
    try {
      for (const [k, v] of Object.entries(env)) {
        if (!k.endsWith("_FILE")) process.env[k] = v;
        else {
          const name = k === "NP_SENTINEL_SIGNING_KEY_FILE" ? "sentinel-sent-2026-11.pem" : k.toLowerCase();
          writeFileSync(join(dir, name), read(v));
          process.env[k] = join(dir, name);
        }
      }
      const c = readApiConfig();
      expect(c.signingKeyPath).toBe(join(dir, "sentinel-sent-2026-11.pem"));
      expect(c.sentinelSigningKey).toBe(files["/s/key"]);
    } finally {
      process.env = saved;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
