import { lt, sql } from "drizzle-orm";

import type { IdentityDb } from "./db/client";
import { rateLimit } from "./db/schema";

export const MAX_RATE_LIMIT_WINDOW_MS = 5 * 60 * 1_000;

export async function consumeRateLimit(input: {
  db: IdentityDb;
  key: string;
  limit: number;
  now?: number;
  windowMs: number;
}): Promise<boolean> {
  if (input.windowMs > MAX_RATE_LIMIT_WINDOW_MS) {
    throw new RangeError(
      `Rate-limit windows cannot exceed ${MAX_RATE_LIMIT_WINDOW_MS}ms`,
    );
  }
  const now = input.now ?? Date.now();
  const windowStart = now - input.windowMs;
  return input.db.transaction(async (transaction) => {
    await transaction
      .delete(rateLimit)
      .where(lt(rateLimit.lastRequest, now - MAX_RATE_LIMIT_WINDOW_MS));
    const result = await transaction.execute<{ count: number }>(sql`
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
  });
}
