import { describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { runOps } from "../../src/ops/cli.js";

describe("ops CLI: dead-letters / outbox (kit 0.6.0 runKitOps)", () => {
  it("routes to the kit and prints its usage on a bad sub-command", async () => {
    const errs: string[] = [];
    const s = { db: {}, cache: {} } as unknown as Sentinel;
    const deps = { actor: "test", err: (l: string) => errs.push(l), out: () => {} };
    expect(await runOps(["dead-letters", "drop", "x"], s, deps)).toBe(2);
    expect(await runOps(["outbox"], s, deps)).toBe(2);
    expect(errs.join("\n")).toContain("dead-letters list");
  });
});
