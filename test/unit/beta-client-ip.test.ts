/** Public beta (Cloudflare → cloudflared → Traefik): the payer IP the spoof counter keys on. */
import { describe, expect, it } from "vitest";
import { clientIpRule, trustedProxies } from "../../src/api/client-ip.js";
import { clientIp } from "../../src/api/routes.js";

const req = (headers: Record<string, string>, peer?: string) => ({
  headers,
  ...(peer ? { socket: { remoteAddress: peer } } : {}),
});

describe("sentinel payer IP", () => {
  it("server: CF-Connecting-IP from a trusted proxy peer; a client-written X-Forwarded-For never counts", () => {
    const rule = clientIpRule("server");
    expect(clientIp(req({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "6.6.6.6" }, "172.18.0.4"), rule)).toBe(
      "203.0.113.7",
    );
    expect(clientIp(req({ "x-forwarded-for": "6.6.6.6" }, "172.18.0.4"), rule)).toBe("unknown");
  });
  it("an untrusted peer is the client itself", () => {
    expect(clientIp(req({ "cf-connecting-ip": "1.2.3.4" }, "::ffff:198.51.100.3"), clientIpRule("server"))).toBe(
      "198.51.100.3",
    );
  });
  it("local: the rightmost untrusted X-Forwarded-For hop, never the forged leftmost one", () => {
    const rule = clientIpRule("local");
    expect(clientIp(req({ "x-forwarded-for": "6.6.6.6, 203.0.113.7, 10.0.0.1" }, "127.0.0.1"), rule)).toBe(
      "203.0.113.7",
    );
    expect(clientIp(req({}), rule)).toBe("unknown");
    expect(() => trustedProxies(["300.0.0.0/8"])).toThrow(/NP_TRUSTED_PROXIES/);
  });
});
