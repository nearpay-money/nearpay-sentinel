/** The last good provider token list in sentinel's own database (`token_lists`, SENTINEL-4). */
import type { Kysely } from "@nearpay-internal/db";
import type { TokenListStore } from "../clients/tokens.js";
import type { DB } from "./schema.js";

export function dbTokenListStore(db: Kysely<DB>, registry: "live" | "test"): TokenListStore {
  return {
    async load() {
      const r = await db
        .selectFrom("token_lists")
        .select(["body", "fetched_at"])
        .where("registry", "=", registry)
        .executeTakeFirst();
      return r ? { body: r.body, atMs: r.fetched_at.getTime() } : null;
    },
    async save(body, atMs) {
      const json = JSON.stringify(body);
      const at = new Date(atMs);
      await db
        .insertInto("token_lists")
        .values({ registry, body: json, fetched_at: at })
        .onConflict((oc) => oc.column("registry").doUpdateSet({ body: json, fetched_at: at, updated_at: new Date() }))
        .execute();
    },
  };
}
