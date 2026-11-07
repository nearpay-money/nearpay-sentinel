/**
 * Audit finding 2 (stage 2): the single-person kill-switch release is a local/test convenience. Any other
 * `NP_ENV` value — `server`, an unknown stage, an empty or mistyped value — must require two persons.
 */
import { ApiError } from "@nearpay-internal/service";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { Sentinel } from "../../src/app/context.js";
import { setKillSwitchSinglePerson } from "../../src/kill-switch/kill-switch.js";
import { singlePersonAllowed } from "../../src/kill-switch/two-person.js";

class Reached extends Error {}

/** A sentinel whose DB throws `Reached`: getting there means the single-person path was allowed. */
function fake(env: string) {
  const warn = () => {};
  return {
    env,
    db: {
      transaction: () => {
        throw new Reached();
      },
    },
    log: { warn, error: warn, info: warn },
    metrics: { killSwitch: () => {} },
  } as unknown as Pick<Sentinel, "db" | "log" | "metrics" | "env">;
}

async function outcome(env: string, engaged: boolean): Promise<"allowed" | "two_person_required"> {
  try {
    await setKillSwitchSinglePerson(fake(env), engaged, "r", "cli@test");
  } catch (e) {
    if (e instanceof Reached) return "allowed";
    if (e instanceof ApiError && e.code === "two_person_required") return "two_person_required";
    throw e;
  }
  throw new Error("unreachable");
}

describe("single-person kill-switch release by NP_ENV", () => {
  it("is allowed only on local and test", async () => {
    expect(await outcome("local", false)).toBe("allowed");
    expect(await outcome("test", false)).toBe("allowed");
  });

  it("requires two persons on server, unknown stages and malformed values", async () => {
    for (const env of ["server", "staging", "production", "prod", "", "Local", "TEST", " local", "dev"]) {
      expect(await outcome(env, false), env).toBe("two_person_required");
    }
  });

  it("engaging stays single-person everywhere", async () => {
    for (const env of ["local", "test", "server", "staging", ""]) expect(await outcome(env, true)).toBe("allowed");
  });

  it("property: any value other than local/test refuses", () => {
    fc.assert(
      fc.property(fc.string(), (env) => {
        expect(singlePersonAllowed(env)).toBe(env === "local" || env === "test");
      }),
    );
  });
});
