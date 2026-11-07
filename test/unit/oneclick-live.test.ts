import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { oneClickAuthHeaders } from "../../src/infra/clients/oneclick-normalize.js";
import { oneClickStatus } from "../../src/infra/clients/providers.js";

/** A real mainnet `GET /v0/status` body (PENDING_DEPOSIT, 2026-11-07), quoted by rails with quoteWaitingTimeMs 3000. */
const live = readFileSync(new URL("../fixtures/oneclick-status-pending-live.json", import.meta.url), "utf8");

function fakeFetch(body: string, seen: Request[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push(new Request(input, init));
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

describe("live 1Click status (sentinel R1/R2)", () => {
  it("accepts the real status body (nulls, nested correlationId missing) and sends a JWT key as a bearer token", async () => {
    const seen: Request[] = [];
    const p = oneClickStatus({ baseUrl: "https://1click.test", apiKey: "aaa.bbb.ccc", fetch: fakeFetch(live, seen) });
    const st = await p.status("0x77B262Cb4dB1Ca5021F773388F244F05b66bE8F2", null);
    expect(st.ok).toBe(true);
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer aaa.bbb.ccc");
    expect(seen[0]?.headers.get("x-api-key")).toBeNull();
  });

  it("verifies the real 1Click signature (status echo omits quoteWaitingTimeMs; rails' 3000 is put back)", async () => {
    const p = oneClickStatus({ baseUrl: "https://1click.test", fetch: fakeFetch(live) });
    const st = await p.status("0x77B262Cb4dB1Ca5021F773388F244F05b66bE8F2", null);
    if (!st.ok) throw new Error("status");
    expect(p.verifySignature(st.status.quoteResponse)).toBe(true);
  });

  it("still refuses a tampered quote, a different waiting time, and a different recipient", async () => {
    const p = oneClickStatus({ baseUrl: "https://1click.test", fetch: fakeFetch(live) });
    const st = await p.status("0x77B262Cb4dB1Ca5021F773388F244F05b66bE8F2", null);
    if (!st.ok) throw new Error("status");
    const q = st.status.quoteResponse;
    expect(p.verifySignature({ ...q, quote: { ...q.quote, amountOut: "9999999" } })).toBe(false);
    expect(p.verifySignature({ ...q, quoteRequest: { ...q.quoteRequest, recipient: "attacker.near" } })).toBe(false);
    expect(p.verifySignature({ ...q, quoteRequest: { ...q.quoteRequest, quoteWaitingTimeMs: 2000 } })).toBe(false);
    const other = oneClickStatus({ baseUrl: "https://1click.test", fetch: fakeFetch(live), quoteWaitingTimeMs: 1000 });
    expect(other.verifySignature(q)).toBe(false);
  });

  it("auth headers: JWT → bearer, other keys → X-API-Key, none → nothing", () => {
    expect(oneClickAuthHeaders("x.y.z")).toEqual({ authorization: "Bearer x.y.z" });
    expect(oneClickAuthHeaders("k")).toEqual({ "x-api-key": "k" });
    expect(oneClickAuthHeaders(undefined)).toEqual({});
  });
});
