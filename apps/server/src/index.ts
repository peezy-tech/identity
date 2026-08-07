import { resolve } from "node:path";

import { migrate } from "drizzle-orm/postgres-js/migrator";

import { createIdentityApp } from "./app";
import { createIdentityAuth, createIdentityProofAuth } from "./auth";
import { seedConfiguredClients } from "./clients";
import { loadConfig } from "./config";
import { createDbClient } from "./db/client";
import { createPrivyGateway } from "./privy-migration";

const config = loadConfig();
const database = createDbClient(config.databaseUrl);
const { db } = database;
const migrationsFolder = resolve(import.meta.dir, "../drizzle");

await migrate(db, { migrationsFolder });
await seedConfiguredClients(db, config);

const { auth, socialProviderNames } = createIdentityAuth(config, db);
const proofAuth = createIdentityProofAuth(config, db);
const app = createIdentityApp({
  auth,
  config,
  db,
  ...(config.privyMigration === undefined
    ? {}
    : { privyGateway: createPrivyGateway(config.privyMigration) }),
  proofAuth,
  socialProviderNames,
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void database.close().finally(() => process.exit(0));
  });
}

export default {
  fetch: app.fetch,
  port: config.port,
};
