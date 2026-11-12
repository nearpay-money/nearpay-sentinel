/**
 * Co-signing over HTTP (§5–§6, live mode against a signed 1Click double): the ticket gate, R1–R7 with
 * their classes and status codes, caching and its destination re-check, the security reactions
 * (spoof counting and rate limit, kill switch only for a live address rails confirms, page when rails is
 * unreachable), the registry outage path, keys and the ops kill switch.
 */

import { destinationFingerprint } from "@nearpay-internal/chains";
import { sql } from "@nearpay-internal/db";
import { newId, toUuid } from "@nearpay-internal/ids";
import type { OneClickQuoteResponse } from "@nearpay-internal/spec";
import { routeQuoteDepositKey, SignedAttestation } from "@nearpay-money/spec";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { NO_RETIREMENT } from "../../src/app/services.js";
import { attest as attestDirect, resetSpoofCounters } from "../../src/co-signer/attest.js";
import { verifyAttestation } from "../../src/co-signer/crypto.js";
import { killSwitchState } from "../../src/kill-switch/kill-switch.js";
import { FAKE_TOKENS, type FakeOneClick, fakeOneClick, PROVIDER_FEE_ACCOUNT } from "../support/fakes.js";
import { KID, LIVE_TREASURY, OPS_CLI_OPERATOR, type Stack, startStack } from "../support/stack.js";

const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
const RECIPIENT = "0x52908400098527886e0f7030069857d2e4169ee7"; // the recorded quote's Intents recipient
const PATH = "/v1/attestations/deposit_instructions";

let s: Stack;
let oc: FakeOneClick;
let dest: string;
beforeAll(async () => {
  oc = await fakeOneClick();
  s = await startStack({ oneclick: oc });
  dest = await s.destination({
    livemode: true,
    asset_id: USDC_NEAR,
    type: "intents_account",
    chain: "near:mainnet",
    address_norm: RECIPIENT,
    verification: "signature",
  });
});
afterAll(async () => {
  await s?.stop();
  await oc?.stop();
});
beforeEach(async () => {
  resetSpoofCounters();
  s.issued.clear();
  await s.resetContainment();
  if ((await killSwitchState(s.sentinel)).engaged)
    await sql`update kill_switch set engaged = false where id = 1`.execute(s.admin.db);
});

const fees = (treasury = LIVE_TREASURY) => [
  { recipient: treasury, fee: 25 },
  { recipient: PROVIDER_FEE_ACCOUNT, fee: 25 },
];

function body(
  q: OneClickQuoteResponse,
  o: { attempt?: string; ticketAttempt?: string; expS?: number; deposit?: object } = {},
) {
  const attempt = o.attempt ?? newId("pa");
  const address = q.quote.depositAddress as string;
  return {
    livemode: true,
    kind: "route_quote",
    attempt_id: attempt,
    attestation_ticket: s.ticket(
      o.ticketAttempt ?? attempt,
      true,
      routeQuoteDepositKey("oneclick", address, null),
      o.expS,
    ),
    deposit: {
      address,
      memo: null,
      chain: "eip155:8453",
      origin_asset_id: USDC_BASE,
      amount_in: q.quote.amountIn,
      deadline: q.quote.deadline,
      ...o.deposit,
    },
  };
}

const attest = (b: unknown, ip = "203.0.113.7") =>
  s.call("POST", PATH, { body: b, headers: { "x-forwarded-for": `${ip}, 10.0.0.1` } });
const statusCalls = () => oc.requests.filter((r) => r.path === "/v0/status").length;
const rows = (attempt: string) =>
  s.admin.db.selectFrom("attestations").selectAll().where("attempt_id", "=", attempt).orderBy("created_at").execute();

describe("signing", () => {
  it("co-signs a genuine quote: Ed25519 over JCS with the configured kid, matched destination, deadline expiry", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    const b = body(q);
    const r = await attest(b);
    expect(r.status).toBe(200);
    const signed = SignedAttestation.parse(r.body);
    expect(signed.kid).toBe(KID);
    expect(verifyAttestation(signed, s.signingPublicRaw)).toBe(true);
    expect(signed.attestation).toMatchObject({
      v: 1,
      kind: "route_quote",
      attempt_id: b.attempt_id,
      livemode: true,
      deposit: b.deposit,
      merchant: { name: "Acme GmbH", kyb_verified: true },
      destination: {
        asset_id: USDC_NEAR,
        chain: "near:mainnet",
        fingerprint: destinationFingerprint("near:mainnet", RECIPIENT, USDC_NEAR),
      },
      // CR-15-07: the origin asset, display data from sentinel's own read of 1Click's token registry
      asset: {
        asset_id: USDC_BASE,
        symbol: "USDC",
        decimals: 6,
        // spec 0.2.1: the token contract from the same registry read, inside the signed object
        token: { standard: "erc20", address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" },
      },
      expires_at: q.quote.deadline,
    });
    expect(Date.parse(signed.attestation.issued_at) % 1000).toBe(0);
    const [rec] = await rows(b.attempt_id);
    expect(rec).toMatchObject({ result: "signed", destination_id: dest, client_ip: "203.0.113.7", reasons: [] });
    // a forged leftmost X-Forwarded-For hop does not change the recorded IP (the gateway appends the real peer)
    expect(rec?.account_id).toBe(toUuid(s.account, "acct"));
    const fb = body(oc.quote({ request: { appFees: fees() } }));
    const forged = await s.call("POST", PATH, {
      body: fb,
      headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.8, 10.0.0.1" },
    });
    expect(forged.status).toBe(200);
    expect((await rows(fb.attempt_id))[0]).toMatchObject({ client_ip: "203.0.113.8" });
  });

  it("signs an omdep origin asset on BNB Smart Chain (the 2026-11-11 incident quote shape): no breach, no switch", async () => {
    const USDT_BSC = "nep141:bnb-0x55d398326f99059ff775485246999027b3197955.omdep.near";
    const q = oc.quote({
      request: { appFees: fees(), originAsset: USDT_BSC },
      quote: { amountIn: "2014321000000000000", amountInFormatted: "2.014321" },
    });
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: s.account });
    const b = body(q, { deposit: { chain: "eip155:56", origin_asset_id: USDT_BSC } });
    const r = await attest(b);
    expect(r.status).toBe(200);
    expect(SignedAttestation.parse(r.body).attestation).toMatchObject({
      deposit: { chain: "eip155:56", origin_asset_id: USDT_BSC },
      asset: {
        asset_id: USDT_BSC,
        symbol: "USDT",
        decimals: 18,
        token: { standard: "erc20", address: "0x55d398326f99059ff775485246999027b3197955" },
      },
    });
    expect(await s.admin.db.selectFrom("integrity_breaches").selectAll().execute()).toEqual([]);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("re-serves the cached attestation without asking the provider again (idempotent retries)", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    const b = body(q);
    const first = await attest(b);
    const calls = statusCalls();
    const again = await attest(b);
    expect(again.status).toBe(200);
    expect(again.body).toEqual(first.body);
    expect(statusCalls()).toBe(calls);
  });

  it("never re-serves a cached attestation once its destination is disabled", async () => {
    const d = await s.destination({
      livemode: true,
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address_norm: "shop.near",
    });
    const q = oc.quote({ request: { appFees: fees(), recipient: "shop.near" } });
    const b = body(q);
    expect((await attest(b)).status).toBe(200);
    s.issued.set(q.quote.depositAddress as string, { livemode: true });
    await s.setDestinationStatus(d, "disabled", new Date());
    const r = await attest(b);
    // a disabled destination is stale, never a breach: the kill switch stays released
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: { code: "attestation_stale" } });
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("signs a fee-free quote", async () => {
    const q = oc.quote({ request: { appFees: [] } });
    expect((await attest(body(q))).status).toBe(200);
  });
});

describe("ticket gate (before any provider call)", () => {
  it.each([
    ["another attempt's ticket", { ticketAttempt: newId("pa") }],
    ["an expired ticket", { expS: Math.floor(Date.now() / 1000) - 1 }],
  ])("refuses %s with 401 ticket_invalid", async (_n, o) => {
    const q = oc.quote({ request: { appFees: fees() } });
    const calls = statusCalls();
    const r = await attest(body(q, o));
    expect(r.status).toBe(401);
    expect(r.body).toMatchObject({ error: { code: "ticket_invalid" } });
    expect(statusCalls()).toBe(calls);
  });

  it("refuses a ticket for another deposit address and one for the other mode", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    const b = body(q);
    const other = { ...b, deposit: { ...b.deposit, address: "0x0000000000000000000000000000000000000bad" } };
    expect((await attest(other)).status).toBe(401);
    const testTicket = s.ticket(b.attempt_id, false, routeQuoteDepositKey("oneclick", b.deposit.address, null));
    expect((await attest({ ...b, attestation_ticket: testTicket })).status).toBe(401);
  });

  it("validates the request against the spec", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    const { deposit: _d, ...noDeposit } = body(q);
    const r = await attest(noDeposit);
    expect(r.status).toBe(400);
    expect(r.body).toMatchObject({ error: { code: "invalid_request" } });
  });
});

describe("attested asset (CR-15-07)", () => {
  const USDC_ARB = "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near";
  const quoteFor = (asset: string) => oc.quote({ request: { appFees: fees(), originAsset: asset } });

  it("refuses (503, never the kill switch) when the registry's decimals do not explain the signed amountInFormatted", async () => {
    oc.tokens = [...FAKE_TOKENS, { ...FAKE_TOKENS[0], assetId: USDC_ARB, blockchain: "arb", decimals: 18 }];
    const q = quoteFor(USDC_ARB);
    s.issued.set(q.quote.depositAddress as string, { livemode: true });
    const b = body(q, { deposit: { origin_asset_id: USDC_ARB, chain: "eip155:42161" } });
    const r = await attest(b);
    expect(r.status).toBe(503);
    expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
    expect((await rows(b.attempt_id))[0]?.reasons[0]).toMatch(/^asset: registry decimals 18 do not explain/);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("refuses an asset the registry does not list", async () => {
    const other = "nep141:arb-0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9.omft.near";
    const q = quoteFor(other);
    const b = body(q, { deposit: { origin_asset_id: other, chain: "eip155:42161" } });
    const r = await attest(b);
    expect(r.status).toBe(503);
    expect((await rows(b.attempt_id))[0]?.reasons[0]).toMatch(/not in the provider's token registry/);
  });

  it("refuses when the token registry cannot be read and nothing is cached", async () => {
    oc.tokens = null;
    // nothing persisted either (SENTINEL-4 keeps the last good list in the database)
    await s.admin.db.deleteFrom("token_lists").execute();
    const fresh = await s.extraApi({}); // a new process: empty token cache
    try {
      const q = oc.quote({ request: { appFees: fees() } });
      const r = await fresh.call("POST", PATH, { body: body(q) });
      expect(r.status).toBe(503);
      expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
    } finally {
      oc.tokens = FAKE_TOKENS;
      await fresh.stop();
    }
  });
});

describe("R1 provider lookup", () => {
  it("503 attestation_unavailable when 1Click is down (2 s, 1 retry)", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    oc.failNext = 2;
    const b = body(q);
    const r = await attest(b);
    expect(r.status).toBe(503);
    expect(r.body).toMatchObject({ error: { code: "attestation_unavailable" } });
    expect((await rows(b.attempt_id))[0]).toMatchObject({ result: "unavailable", class: "unavailable" });
    // the retry hides one failure
    oc.failNext = 1;
    expect((await attest(body(q))).status).toBe(200);
  });

  it("503 when 1Click does not know the deposit address", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    oc.statuses.delete(q.quote.depositAddress as string);
    expect((await attest(body(q))).status).toBe(503);
  });
});

describe("security refusals", () => {
  // a quote changed after 1Click signed it: signature and referral both fail (an R2-only failure is drift, SENTINEL-1)
  const tampered = () =>
    oc.quote({ request: { appFees: fees() }, afterSign: (q) => (q.quoteRequest.referral = "attacker") });

  it("a spoof (rails never issued the address) is refused, counted and rate-limited per IP — never the kill switch", async () => {
    for (let i = 0; i < 5; i++) {
      const r = await attest(body(tampered()), "198.51.100.9");
      expect(r.status).toBe(409);
      expect(r.body).toMatchObject({ error: { code: "attestation_refused" } });
    }
    const limited = await attest(body(oc.quote({ request: { appFees: fees() } })), "198.51.100.9");
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ error: { code: "rate_limited" } });
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(500);
    // another IP is unaffected
    expect((await attest(body(oc.quote({ request: { appFees: fees() } })), "198.51.100.10")).status).toBe(200);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("a breach on a live address rails confirms is contained: refused, recorded, account quarantined — never the global switch (ADR-0028)", async () => {
    const q = tampered();
    s.issued.set(q.quote.depositAddress as string, { livemode: true, account_id: s.account });
    const b = body(q);
    const r = await attest(b);
    expect(r.status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    const breach = await s.admin.db.selectFrom("integrity_breaches").selectAll().executeTakeFirstOrThrow();
    expect(breach).toMatchObject({ evidence: "pipeline", rules: ["R2", "R3"], quarantined: true, systemic: false });
    const out = await s.admin.db
      .selectFrom("outbox")
      .selectAll()
      .where("subject", "=", "evt.sentinel.audit_finding.created")
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect((out.payload as { data: { object: unknown } }).data.object).toMatchObject({
      account_id: s.account,
      check_kind: "attestation",
      result: "mismatch",
    });
    expect((await rows(b.attempt_id))[0]).toMatchObject({ result: "rejected", class: "security" });
  });

  it("a breach on an address rails says is test mode never stops live quoting", async () => {
    const q = tampered();
    s.issued.set(q.quote.depositAddress as string, { livemode: false });
    expect((await attest(body(q))).status).toBe(409);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("rails unreachable: refuse and page, no automatic switch", async () => {
    const q = tampered();
    s.issued.set(q.quote.depositAddress as string, { livemode: true });
    s.rails.reset(); // every rails route now answers 500
    try {
      expect((await attest(body(q))).status).toBe(409);
      expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
    } finally {
      s.mockRails();
    }
  });

  it.each([
    ["R3 referral", { request: { appFees: fees(), referral: "someone-else" } }],
    ["R6 attacker fee", { request: { appFees: [{ recipient: "attacker.near", fee: 50 }] } }],
    ["R5 unknown recipient", { request: { appFees: fees(), recipient: "attacker.near" } }],
  ])("%s → 409 attestation_refused (security)", async (_n, o) => {
    const b = body(oc.quote(o));
    const r = await attest(b);
    expect(r.status).toBe(409);
    expect((await rows(b.attempt_id))[0]).toMatchObject({ class: "security" });
  });

  it("R4: deposit instructions that differ from the provider's are refused", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    const r = await attest(body(q, { deposit: { amount_in: "1" } }));
    expect(r.status).toBe(409);
    const c = await attest(body(oc.quote({ request: { appFees: fees() } }), { deposit: { chain: "eip155:1" } }));
    expect(c.status).toBe(409);
  });
});

describe("ambiguous and stale", () => {
  it("ambiguous registry → 409 refused, never the kill switch even for an issued address", async () => {
    for (const _ of [1, 2])
      await s.destination({
        livemode: true,
        asset_id: USDC_NEAR,
        type: "intents_account",
        chain: "near:mainnet",
        address_norm: "twice.near",
        verification: "unverified",
      });
    const q = oc.quote({ request: { appFees: fees(), recipient: "twice.near" } });
    s.issued.set(q.quote.depositAddress as string, { livemode: true });
    const b = body(q);
    const r = await attest(b);
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: { code: "attestation_refused" } });
    expect((await rows(b.attempt_id))[0]).toMatchObject({ class: "ambiguous" });
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });

  it("settled deposit → 409 attestation_stale", async () => {
    const q = oc.quote({ request: { appFees: fees() }, status: { status: "SUCCESS" } });
    const r = await attest(body(q));
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: { code: "attestation_stale" } });
  });

  it("deadline within 60 s → 409 attestation_stale", async () => {
    const soon = new Date(Date.now() + 30_000);
    soon.setUTCMilliseconds(0);
    const q = oc.quote({
      request: { appFees: fees(), deadline: soon.toISOString() },
      quote: { deadline: soon.toISOString() },
    });
    expect((await attest(body(q))).body).toMatchObject({ error: { code: "attestation_stale" } });
  });
});

describe("registry outage", () => {
  it("503 attestation_unavailable when identity's view cannot be read", async () => {
    const q = oc.quote({ request: { appFees: fees() } });
    await sql`revoke select on sentinel_destination_registry from sentinel_ro`.execute(s.registryOwner.db);
    try {
      const b = body(q);
      const r = await attest(b);
      expect(r.status).toBe(503);
      expect((await rows(b.attempt_id))[0]).toMatchObject({
        result: "unavailable",
        reasons: [expect.stringMatching(/^registry: /)],
      });
    } finally {
      await sql`grant select on sentinel_destination_registry to sentinel_ro`.execute(s.registryOwner.db);
    }
  });
});

describe("keys and the ops kill switch", () => {
  it("lists the signing key (informational)", async () => {
    const r = await s.call("GET", "/v1/attestations/keys");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({
      object: "list",
      keys: [{ kid: KID, public_key: s.signingPublicRaw, not_after: NO_RETIREMENT }],
    });
  });

  it("engages and releases with the ops scope; each change is logged with the operator", async () => {
    const token = await s.opsToken();
    const on = await s.call("POST", "/internal/kill-switch", { token, body: { engaged: true, reason: "drill" } });
    expect(on.status).toBe(200);
    expect(on.body).toMatchObject({ engaged: true, reason: "drill", actor: `ops:${OPS_CLI_OPERATOR}` });
    const v = (await killSwitchState(s.sentinel)).version;
    // idempotent: already engaged → no new version
    expect(
      (await s.call("POST", "/internal/kill-switch", { token, body: { engaged: true, reason: "again" } })).body,
    ).toMatchObject({
      engaged: true,
      reason: "drill",
    });
    expect((await killSwitchState(s.sentinel)).version).toBe(v);
    const off = await s.call("POST", "/internal/kill-switch", {
      token: await s.opsToken(),
      body: { engaged: false, reason: "drill over" },
    });
    expect(off.body).toMatchObject({ engaged: false, actor: `ops:${OPS_CLI_OPERATOR}` });
    const log = await s.admin.db
      .selectFrom("kill_switch_log")
      .selectAll()
      .orderBy("version", "desc")
      .limit(2)
      .execute();
    expect(log.map((l) => [l.engaged, l.actor])).toEqual([
      [false, `ops:${OPS_CLI_OPERATOR}`],
      [true, `ops:${OPS_CLI_OPERATOR}`],
    ]);
    await expect(sql`delete from kill_switch_log`.execute(s.admin.db)).rejects.toThrow(/append-only/);
  });

  it("refuses callers without the ops scope", async () => {
    expect((await s.call("POST", "/internal/kill-switch", { body: { engaged: true, reason: "x" } })).status).toBe(401);
    const wrong = await s.opsToken(["rails.read"]);
    expect(
      (await s.call("POST", "/internal/kill-switch", { token: wrong, body: { engaged: true, reason: "x" } })).status,
    ).toBe(403);
    expect((await killSwitchState(s.sentinel)).engaged).toBe(false);
  });
});

describe("resilience (2026-11-12 audit)", () => {
  it("SENTINEL-5: a registry read that times out once and then answers still signs", async () => {
    let failures = 1;
    const flaky = s.sentinel.registry.withPlugin({
      transformQuery(args) {
        if (failures > 0) {
          failures--;
          throw Object.assign(new Error("canceling statement due to statement timeout"), { code: "57014" });
        }
        return args.node;
      },
      async transformResult(args) {
        return args.result;
      },
    });
    const ctx = { ...s.sentinel, registry: flaky };
    const q = oc.quote({ request: { appFees: fees() } });
    const signed = await attestDirect(ctx, body(q) as never, "203.0.113.50");
    expect(verifyAttestation(SignedAttestation.parse(signed), s.signingPublicRaw)).toBe(true);
    expect(failures).toBe(0);
    // a permanent error is not retried: unavailable
    let calls = 0;
    const broken = s.sentinel.registry.withPlugin({
      transformQuery() {
        calls++;
        throw new Error("permission denied for view sentinel_destination_registry");
      },
      async transformResult(args) {
        return args.result;
      },
    });
    await expect(
      attestDirect(
        { ...s.sentinel, registry: broken },
        body(oc.quote({ request: { appFees: fees() } })) as never,
        "203.0.113.50",
      ),
    ).rejects.toMatchObject({
      code: "attestation_unavailable",
    });
    expect(calls).toBe(1);
  });

  it("SENTINEL-4: the last good token list is persisted and serves a fresh process while 1Click /v0/tokens is down", async () => {
    const headers = { "x-forwarded-for": "203.0.113.7, 10.0.0.1" };
    await s.admin.db.deleteFrom("token_lists").execute();
    // a process that reads 1Click's list persists it
    const first = await s.extraApi({});
    try {
      const r = await first.call("POST", PATH, { body: body(oc.quote({ request: { appFees: fees() } })), headers });
      expect(r.status).toBe(200);
    } finally {
      await first.stop();
    }
    const saved = await s.admin.db
      .selectFrom("token_lists")
      .selectAll()
      .where("registry", "=", "live")
      .executeTakeFirst();
    expect(saved?.body).toEqual(expect.arrayContaining(FAKE_TOKENS));
    // a restart while /v0/tokens is down signs from it
    oc.tokens = null;
    const second = await s.extraApi({});
    try {
      const r = await second.call("POST", PATH, { body: body(oc.quote({ request: { appFees: fees() } })), headers });
      expect(r.status).toBe(200);
    } finally {
      oc.tokens = FAKE_TOKENS;
      await second.stop();
    }
  });
});
