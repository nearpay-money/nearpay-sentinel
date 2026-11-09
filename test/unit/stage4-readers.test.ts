/**
 * Sentinel's own Solana JSON-RPC and Bitcoin Esplora readers (lld/sentinel.md §16 "Integrations": Solana
 * 3 s, Esplora 5 s, one retry), driven by a scripted `fetch`: the exact request, the retry/fallback rules
 * and that every unreadable answer is `ChainUnavailable` (the audit retries), never a pass.
 */
import { describe, expect, it } from "vitest";
import { ChainUnavailable, esploraReader, solanaReader } from "../../src/infra/clients/chains.js";

type Call = { url: string; init: RequestInit | undefined };
type Answer = Response | Error;

/** A `fetch` that records each call and answers from the script in order. */
function scripted(answers: Answer[]): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    const a = answers.shift();
    if (!a) throw new Error("unexpected call");
    if (a instanceof Error) throw a;
    return a;
  }) as typeof fetch;
  return { fetch: f, calls };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const text = (body: string, status = 200) => new Response(body, { status });

const SIG = "5h6xBEauJ3PK6SWCZ1PGjBvj8vDdWG3KpwATGy1ARAXFSDwt8GFXM7W5Ncn16wmqokgpiKRLuS83KUxyZyv2sUYv";
const TXID = "a".repeat(64);

describe("solanaReader", () => {
  it("asks getTransaction at finalized, jsonParsed, max version 0, and returns the result", async () => {
    const { fetch, calls } = scripted([json({ jsonrpc: "2.0", id: "sentinel", result: { slot: 1 } })]);
    await expect(solanaReader({ urls: ["https://sol.example"], fetch }).transaction(SIG)).resolves.toEqual({
      slot: 1,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://sol.example");
    expect(JSON.parse(String(calls[0]?.init?.body))).toMatchObject({
      method: "getTransaction",
      params: [SIG, { commitment: "finalized", maxSupportedTransactionVersion: 0, encoding: "jsonParsed" }],
    });
    expect(calls[0]?.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("null result (unknown or not finalized yet) is null", async () => {
    const { fetch } = scripted([json({ jsonrpc: "2.0", id: "sentinel", result: null })]);
    await expect(solanaReader({ urls: ["https://sol.example"], fetch }).transaction(SIG)).resolves.toBeNull();
  });

  it("a single-URL pool is retried once; then ChainUnavailable", async () => {
    const ok = scripted([text("busy", 503), json({ result: { slot: 2 } })]);
    await expect(solanaReader({ urls: ["https://a"], fetch: ok.fetch }).transaction(SIG)).resolves.toEqual({
      slot: 2,
    });
    expect(ok.calls.map((c) => c.url)).toEqual(["https://a", "https://a"]);
    const down = scripted([new Error("timeout"), text("busy", 503)]);
    await expect(solanaReader({ urls: ["https://a"], fetch: down.fetch }).transaction(SIG)).rejects.toBeInstanceOf(
      ChainUnavailable,
    );
    expect(down.calls).toHaveLength(2);
  });

  it("a longer pool tries each URL once, in order", async () => {
    const { fetch, calls } = scripted([new Error("reset"), json({ result: { slot: 3 } })]);
    await expect(solanaReader({ urls: ["https://a", "https://b"], fetch }).transaction(SIG)).resolves.toEqual({
      slot: 3,
    });
    expect(calls.map((c) => c.url)).toEqual(["https://a", "https://b"]);
  });

  it("a JSON-RPC error is ChainUnavailable, not 'not found'", async () => {
    const { fetch } = scripted([
      json({ error: { code: -32015, message: "Transaction version (1) is not supported" } }),
    ]);
    await expect(solanaReader({ urls: ["https://a"], fetch }).transaction(SIG)).rejects.toThrow(/Transaction version/);
  });
});

describe("esploraReader", () => {
  it("reads /tx/{txid} and the tip height from the same server", async () => {
    const tx = { txid: TXID, vout: [] };
    const { fetch, calls } = scripted([json(tx), text("900000\n")]);
    await expect(esploraReader({ urls: ["https://esplora.example/api/"], fetch }).tx(TXID)).resolves.toEqual({
      tx,
      tipHeight: 900_000,
    });
    expect(calls.map((c) => c.url)).toEqual([
      `https://esplora.example/api/tx/${TXID}`,
      "https://esplora.example/api/blocks/tip/height",
    ]);
  });

  it("404 is null (not found yet); a txid that is not 64 lower-case hex is never requested", async () => {
    const { fetch, calls } = scripted([text("Transaction not found", 404)]);
    const r = esploraReader({ urls: ["https://e"], fetch });
    await expect(r.tx(TXID)).resolves.toBeNull();
    await expect(r.tx("A".repeat(64))).resolves.toBeNull();
    await expect(r.tx("../blocks/tip")).resolves.toBeNull();
    expect(calls).toHaveLength(1);
  });

  it("an unreadable tip moves to the next server; a single server is tried twice, then ChainUnavailable", async () => {
    const tx = { txid: TXID, vout: [] };
    const next = scripted([json(tx), text("not a number"), json(tx), text("12")]);
    await expect(esploraReader({ urls: ["https://a", "https://b"], fetch: next.fetch }).tx(TXID)).resolves.toEqual({
      tx,
      tipHeight: 12,
    });
    expect(next.calls.map((c) => c.url)).toEqual([
      `https://a/tx/${TXID}`,
      "https://a/blocks/tip/height",
      `https://b/tx/${TXID}`,
      "https://b/blocks/tip/height",
    ]);
    const down = scripted([text("busy", 503), new Error("timeout")]);
    await expect(esploraReader({ urls: ["https://a"], fetch: down.fetch }).tx(TXID)).rejects.toBeInstanceOf(
      ChainUnavailable,
    );
    expect(down.calls).toHaveLength(2);
    const tipDown = scripted([json(tx), text("busy", 503), json(tx), text("busy", 503)]);
    await expect(esploraReader({ urls: ["https://a"], fetch: tipDown.fetch }).tx(TXID)).rejects.toThrow(
      /tip height unreadable/,
    );
  });
});
