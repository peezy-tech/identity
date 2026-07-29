import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema";

export type IdentityDb = PostgresJsDatabase<typeof schema>;

export type IdentityDbClient = {
  close(): Promise<void>;
  db: IdentityDb;
  sql: ReturnType<typeof postgres>;
};

export function createDbClient(databaseUrl: string): IdentityDbClient {
  const sql = postgres(databaseUrl, {
    max: 10,
    onnotice: () => undefined,
  });
  return {
    close: async () => {
      await sql.end({ timeout: 5 });
    },
    db: drizzle(sql, { schema }),
    sql,
  };
}
