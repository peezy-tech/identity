import { randomUUID } from "node:crypto";

import postgres from "postgres";

type LegacyUser = {
  createdAt: Date;
  email: string;
  emailVerified: boolean;
  id: string;
  image: string | null;
  name: string;
  updatedAt: Date;
};

type LegacyAccount = {
  accountId: string;
  createdAt: Date;
  id: string;
  providerId: string;
  userId: string;
  updatedAt: Date;
};

type LegacyWallet = {
  address: string;
  chainId: number;
  createdAt: Date;
  id: string;
  isPrimary: boolean;
  userId: string;
};

type LegacyWalletOwner = {
  address: string;
  createdAt: Date;
  userId: string;
};

export type ImportData = {
  accounts: LegacyAccount[];
  users: LegacyUser[];
  walletOwners: LegacyWalletOwner[];
  wallets: LegacyWallet[];
};

export async function main(
  env: Record<string, string | undefined> = process.env,
  args: string[] = process.argv.slice(2),
): Promise<void> {
  const sourceUrl = requiredEnv("PLEDGE_DATABASE_URL", env);
  const targetUrl = requiredEnv("DATABASE_URL", env);
  const apply = args.includes("--apply");
  const json = args.includes("--json");

  if (sourceUrl === targetUrl) {
    throw new Error("PLEDGE_DATABASE_URL and DATABASE_URL must be different");
  }
  if (apply && env.CONFIRM_IDENTITY_IMPORT !== "pledge-cash") {
    throw new Error(
      "Set CONFIRM_IDENTITY_IMPORT=pledge-cash to run an applying import",
    );
  }

  const source = postgres(sourceUrl, {
    max: 3,
    onnotice: () => undefined,
  });
  const target = postgres(targetUrl, {
    max: 1,
    onnotice: () => undefined,
  });

  try {
    await assertDistinctDatabases(source, target);
    const data = await readLegacyIdentity(source);
    validateLegacyIdentity(data);
    await assertTargetSchema(target);

    const report = {
      mode: apply ? "apply" : "dry-run",
      source: {
        accounts: data.accounts.length,
        users: data.users.length,
        walletOwners: data.walletOwners.length,
        wallets: data.wallets.length,
      },
    };

    if (apply) {
      await importIdentity(target, data);
    }

    if (json) {
      console.log(JSON.stringify({ ...report, verified: apply }, null, 2));
    } else {
      console.log(
        `${apply ? "Imported and verified" : "Validated"} ${data.users.length} users, ` +
          `${data.walletOwners.length} EOA principals, ${data.accounts.length} provider accounts, ` +
          `and ${data.wallets.length} wallet observations.`,
      );
      if (!apply) {
        console.log(
          "No target rows were changed. Re-run with --apply and CONFIRM_IDENTITY_IMPORT=pledge-cash.",
        );
      }
    }
  } finally {
    await Promise.all([source.end({ timeout: 5 }), target.end({ timeout: 5 })]);
  }
}

if (import.meta.main) {
  await main();
}

export async function readLegacyIdentity(
  sql: postgres.Sql,
): Promise<ImportData> {
  const [users, accounts, wallets, walletOwners] = await Promise.all([
    sql<LegacyUser[]>`
      SELECT
        "id"::text AS "id",
        "name",
        "email",
        "email_verified" AS "emailVerified",
        "image",
        "created_at" AS "createdAt",
        "updated_at" AS "updatedAt"
      FROM "users"
      ORDER BY "id"
    `,
    sql<LegacyAccount[]>`
      SELECT
        "id"::text AS "id",
        "account_id" AS "accountId",
        "provider_id" AS "providerId",
        "user_id"::text AS "userId",
        "created_at" AS "createdAt",
        "updated_at" AS "updatedAt"
      FROM "auth_accounts"
      ORDER BY "id"
    `,
    sql<LegacyWallet[]>`
      SELECT
        "id"::text AS "id",
        "user_id"::text AS "userId",
        "address",
        "chain_id" AS "chainId",
        "is_primary" AS "isPrimary",
        "created_at" AS "createdAt"
      FROM "auth_wallets"
      ORDER BY "created_at", "id"
    `,
    sql<LegacyWalletOwner[]>`
      SELECT
        "address",
        "user_id"::text AS "userId",
        "created_at" AS "createdAt"
      FROM "wallet_owners"
      ORDER BY lower("address")
    `,
  ]);

  return {
    accounts: [...accounts],
    users: [...users],
    walletOwners: [...walletOwners],
    wallets: [...wallets],
  };
}

export function validateLegacyIdentity(data: ImportData): void {
  const userIds = uniqueMap(data.users, (row) => row.id, "user id");
  uniqueMap(data.users, (row) => row.email.toLowerCase(), "user email");
  uniqueMap(data.accounts, (row) => row.id, "provider account id");
  uniqueMap(
    data.accounts,
    (row) => `${row.providerId}\0${row.accountId}`,
    "provider account",
  );
  for (const account of data.accounts) {
    requireReference(userIds, account.userId, `account ${account.id}`);
  }

  const owners = uniqueMap(
    data.walletOwners,
    (row) => normalizedAddress(row.address),
    "normalized EOA owner",
  );
  for (const owner of data.walletOwners) {
    requireReference(userIds, owner.userId, `wallet owner ${owner.address}`);
  }
  uniqueMap(
    data.wallets,
    (row) => `${normalizedAddress(row.address)}\0${row.chainId}`,
    "wallet and chain",
  );
  uniqueMap(data.wallets, (row) => row.id, "wallet id");
  for (const wallet of data.wallets) {
    requireReference(userIds, wallet.userId, `wallet ${wallet.id}`);
    const owner = owners.get(normalizedAddress(wallet.address));
    if (owner === undefined) {
      throw new Error(`Wallet ${wallet.id} has no global wallet_owners row`);
    }
    if (owner.userId !== wallet.userId) {
      throw new Error(
        `Wallet ${wallet.id} and its global owner disagree on user id`,
      );
    }
  }
  for (const [address] of owners) {
    if (
      !data.wallets.some(
        (wallet) => normalizedAddress(wallet.address) === address,
      )
    ) {
      throw new Error(`Global wallet owner ${address} has no auth wallet`);
    }
  }

  const primaryCounts = new Map<string, number>();
  for (const wallet of data.wallets) {
    if (!wallet.isPrimary) continue;
    primaryCounts.set(
      wallet.userId,
      (primaryCounts.get(wallet.userId) ?? 0) + 1,
    );
  }
  for (const [userId, count] of primaryCounts) {
    if (count > 1) {
      throw new Error(`User ${userId} has ${count} primary auth wallets`);
    }
  }
}

export async function assertTargetSchema(sql: postgres.Sql): Promise<void> {
  const [result] = await sql<{ identityTable: string | null }[]>`
    SELECT to_regclass('public.user')::text AS "identityTable"
  `;
  if (result?.identityTable !== "user") {
    throw new Error(
      "Target identity schema is missing; start the provider migrations first",
    );
  }
}

export async function assertDistinctDatabases(
  source: postgres.Sql,
  target: postgres.Sql,
): Promise<void> {
  const [sourceIdentity, targetIdentity] = await Promise.all([
    readDatabaseIdentity(source),
    readDatabaseIdentity(target),
  ]);
  if (
    sourceIdentity.database === targetIdentity.database &&
    sourceIdentity.serverAddress === targetIdentity.serverAddress &&
    sourceIdentity.serverPort === targetIdentity.serverPort &&
    sourceIdentity.postmasterStartedAt === targetIdentity.postmasterStartedAt
  ) {
    throw new Error(
      "PLEDGE_DATABASE_URL and DATABASE_URL resolve to the same database",
    );
  }
}

export async function importIdentity(
  sql: postgres.Sql,
  data: ImportData,
): Promise<void> {
  const walletsByAddress = new Map<string, LegacyWallet[]>();
  for (const wallet of data.wallets) {
    const address = normalizedAddress(wallet.address);
    const existing = walletsByAddress.get(address) ?? [];
    existing.push(wallet);
    walletsByAddress.set(address, existing);
  }

  let stage = "users";
  try {
    await sql.begin(async (transaction) => {
      if (data.users.length > 0) {
        stage = "users";
        const rows = data.users.map((row) => ({
          created_at: row.createdAt.toISOString(),
          email: row.email,
          email_verified: row.emailVerified,
          id: row.id,
          image: row.image,
          name: row.name,
          status: "active",
          updated_at: row.updatedAt.toISOString(),
        }));
        await transaction`
        INSERT INTO "user" ${transaction(
          rows,
          "id",
          "name",
          "email",
          "email_verified",
          "image",
          "status",
          "created_at",
          "updated_at",
        )}
        ON CONFLICT ("id") DO NOTHING
      `;
      }
      if (data.walletOwners.length > 0) {
        stage = "wallet principals";
        const rows = data.walletOwners.map((owner) => {
          const address = normalizedAddress(owner.address);
          const firstWallet = walletsByAddress.get(address)?.[0];
          if (firstWallet === undefined) {
            throw new Error(
              `Wallet principal ${address} has no credential row`,
            );
          }
          return {
            account_kind: "eoa",
            address,
            chain_id: null,
            created_at: owner.createdAt.toISOString(),
            family: "evm",
            id: firstWallet.id,
            sign_in_enabled: true,
            updated_at: owner.createdAt.toISOString(),
            user_id: owner.userId,
          };
        });
        await transaction`
        INSERT INTO "wallet_principal" ${transaction(
          rows,
          "id",
          "user_id",
          "family",
          "account_kind",
          "address",
          "chain_id",
          "sign_in_enabled",
          "created_at",
          "updated_at",
        )}
        ON CONFLICT ("id") DO NOTHING
      `;
      }
      if (data.wallets.length > 0) {
        stage = "wallet credentials";
        const rows = data.wallets.map((row) => ({
          address: normalizedAddress(row.address),
          chain_id: row.chainId,
          created_at: row.createdAt.toISOString(),
          id: row.id,
          is_primary: row.isPrimary,
          user_id: row.userId,
        }));
        await transaction`
        INSERT INTO "wallet_address" ${transaction(
          rows,
          "id",
          "user_id",
          "address",
          "chain_id",
          "is_primary",
          "created_at",
        )}
        ON CONFLICT ("id") DO NOTHING
      `;
      }
      if (data.accounts.length > 0) {
        stage = "provider accounts";
        const rows = data.accounts.map((row) => ({
          account_id: row.accountId,
          created_at: row.createdAt.toISOString(),
          id: row.id,
          provider_id: row.providerId,
          updated_at: row.updatedAt.toISOString(),
          user_id: row.userId,
        }));
        await transaction`
        INSERT INTO "account" ${transaction(
          rows,
          "id",
          "account_id",
          "provider_id",
          "user_id",
          "created_at",
          "updated_at",
        )}
        ON CONFLICT ("id") DO NOTHING
      `;
      }
      stage = "verification";
      await verifyImport(transaction, data);
      stage = "audit event";
      await transaction`
      INSERT INTO "identity_audit_event" (
        "id", "kind", "metadata", "created_at"
      )
      VALUES (
        ${randomUUID()},
        'migration.pledge-cash-imported',
        ${JSON.stringify({
          accounts: data.accounts.length,
          users: data.users.length,
          walletPrincipals: data.walletOwners.length,
        })}::jsonb,
        now()
      )
    `;
    });
  } catch (error) {
    throw new Error(`PledgeCash identity import failed during ${stage}`, {
      cause: error,
    });
  }
}

async function readDatabaseIdentity(sql: postgres.Sql): Promise<{
  database: string;
  postmasterStartedAt: string;
  serverAddress: string | null;
  serverPort: number | null;
}> {
  const [identity] = await sql<
    {
      database: string;
      postmasterStartedAt: string;
      serverAddress: string | null;
      serverPort: number | null;
    }[]
  >`
    SELECT
      current_database() AS "database",
      pg_postmaster_start_time()::text AS "postmasterStartedAt",
      inet_server_addr()::text AS "serverAddress",
      inet_server_port() AS "serverPort"
  `;
  if (identity === undefined) {
    throw new Error("Database identity could not be read");
  }
  return identity;
}

export async function verifyImport(
  sql: postgres.Sql,
  data: ImportData,
): Promise<void> {
  const userIds = data.users.map((row) => row.id);
  const importedUsers =
    userIds.length === 0
      ? []
      : await sql<
          {
            email: string;
            emailVerified: boolean;
            id: string;
            image: string | null;
            name: string;
            status: string;
          }[]
        >`
          SELECT
            "id",
            "name",
            "email",
            "email_verified" AS "emailVerified",
            "image",
            "status"
          FROM "user"
          WHERE "id" = ANY(${userIds}::text[])
        `;
  const targetUsers = new Map(importedUsers.map((row) => [row.id, row]));
  for (const sourceUser of data.users) {
    const targetUser = targetUsers.get(sourceUser.id);
    if (
      targetUser === undefined ||
      targetUser.name !== sourceUser.name ||
      targetUser.email.toLowerCase() !== sourceUser.email.toLowerCase() ||
      targetUser.emailVerified !== sourceUser.emailVerified ||
      targetUser.image !== sourceUser.image ||
      targetUser.status !== "active"
    ) {
      throw new Error(`Target user verification failed for ${sourceUser.id}`);
    }
  }

  const ownerAddresses = data.walletOwners.map((row) =>
    normalizedAddress(row.address),
  );
  const importedOwners =
    ownerAddresses.length === 0
      ? []
      : await sql<
          {
            address: string;
            id: string;
            signInEnabled: boolean;
            userId: string;
          }[]
        >`
          SELECT
            "id",
            lower("address") AS "address",
            "sign_in_enabled" AS "signInEnabled",
            "user_id" AS "userId"
          FROM "wallet_principal"
          WHERE "family" = 'evm'
            AND "account_kind" = 'eoa'
            AND lower("address") = ANY(${ownerAddresses}::text[])
        `;
  const targetOwners = new Map(importedOwners.map((row) => [row.address, row]));
  for (const sourceOwner of data.walletOwners) {
    const address = normalizedAddress(sourceOwner.address);
    const targetOwner = targetOwners.get(address);
    const expectedPrincipalId = data.wallets.find(
      (wallet) => normalizedAddress(wallet.address) === address,
    )?.id;
    if (
      targetOwner === undefined ||
      targetOwner.id !== expectedPrincipalId ||
      targetOwner.userId !== sourceOwner.userId ||
      !targetOwner.signInEnabled
    ) {
      throw new Error(
        `Target wallet-owner verification failed for ${sourceOwner.address}`,
      );
    }
  }

  const accountUserIds =
    userIds.length === 0
      ? []
      : await sql<
          {
            accountId: string;
            id: string;
            providerId: string;
            userId: string;
          }[]
        >`
          SELECT
            "id",
            "account_id" AS "accountId",
            "provider_id" AS "providerId",
            "user_id" AS "userId"
          FROM "account"
          WHERE "user_id" = ANY(${userIds}::text[])
        `;
  const targetAccounts = new Map(
    accountUserIds.map((row) => [`${row.providerId}\0${row.accountId}`, row]),
  );
  for (const sourceAccount of data.accounts) {
    const targetAccount = targetAccounts.get(
      `${sourceAccount.providerId}\0${sourceAccount.accountId}`,
    );
    if (
      targetAccount === undefined ||
      targetAccount.id !== sourceAccount.id ||
      targetAccount.userId !== sourceAccount.userId
    ) {
      throw new Error(
        `Target provider-account verification failed for ${sourceAccount.id}`,
      );
    }
  }

  await verifyIdMappings(sql, "wallet_address", data.wallets, [
    ["user_id", (row) => row.userId],
    ["chain_id", (row) => String(row.chainId)],
    ["address", (row) => normalizedAddress(row.address)],
    ["is_primary", (row) => String(row.isPrimary)],
  ]);
}

async function verifyIdMappings<T extends { id: string }>(
  sql: postgres.Sql,
  table: "wallet_address",
  source: T[],
  fields: Array<[string, (row: T) => string]>,
): Promise<void> {
  if (source.length === 0) return;
  const fieldNames = fields.map(([field]) => field);
  const rows = await sql.unsafe<Record<string, unknown>[]>(
    `SELECT "id", ${fieldNames.map((field) => `"${field}"`).join(", ")}
     FROM "${table}"
     WHERE "id" = ANY($1::text[])`,
    [source.map((row) => row.id)],
  );
  const target = new Map(rows.map((row) => [String(row.id), row]));
  for (const sourceRow of source) {
    const targetRow = target.get(sourceRow.id);
    if (targetRow === undefined) {
      throw new Error(
        `Target ${table} verification failed for ${sourceRow.id}`,
      );
    }
    for (const [field, expected] of fields) {
      const actual =
        field === "address"
          ? String(targetRow[field]).toLowerCase()
          : String(targetRow[field]);
      if (actual !== expected(sourceRow)) {
        throw new Error(
          `Target ${table}.${field} verification failed for ${sourceRow.id}`,
        );
      }
    }
  }
}

function uniqueMap<T>(
  values: T[],
  key: (value: T) => string,
  description: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const value of values) {
    const identity = key(value);
    if (result.has(identity)) {
      throw new Error(`Duplicate ${description}: ${identity}`);
    }
    result.set(identity, value);
  }
  return result;
}

function requireReference<T>(
  values: Map<string, T>,
  id: string,
  description: string,
): void {
  if (!values.has(id)) {
    throw new Error(`${description} references missing identity ${id}`);
  }
}

function normalizedAddress(value: string): string {
  const address = value.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    throw new Error(`Invalid EVM wallet address: ${value}`);
  }
  return address;
}

function requiredEnv(
  name: string,
  env: Record<string, string | undefined>,
): string {
  const value = env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}
