import { sql } from "drizzle-orm";

import type { IdentityDb } from "./db/client";

export async function consumeRateLimit(input: {
  db: IdentityDb;
  key: string;
  limit: number;
  now?: number;
  windowMs: number;
}): Promise<boolean> {
  const now = input.now ?? Date.now();
  const windowStart = now - input.windowMs;
  const result = await input.db.execute<{ count: number }>(sql`
    INSERT INTO "rate_limit" ("id", "key", "count", "last_request")
    VALUES (${crypto.randomUUID()}, ${`identity-v1:${input.key}`}, 1, ${now})
    ON CONFLICT ("key") DO UPDATE SET
      "count" = CASE
        WHEN "rate_limit"."last_request" < ${windowStart} THEN 1
        ELSE "rate_limit"."count" + 1
      END,
      "last_request" = CASE
        WHEN "rate_limit"."last_request" < ${windowStart} THEN ${now}
        ELSE "rate_limit"."last_request"
      END
    RETURNING "count"
  `);
  return (result[0]?.count ?? input.limit + 1) <= input.limit;
}
