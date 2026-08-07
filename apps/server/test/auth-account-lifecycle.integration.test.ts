import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { resolve } from "node:path";

import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

import { commitAccountMerge } from "../src/account-merge";
import { createIdentityAuth } from "../src/auth";
import type { IdentityConfig } from "../src/config";
import type { IdentityDb } from "../src/db/client";
import {
  account,
  identityAuditEvent,
  identitySubjectMerge,
  user,
} from "../src/db/schema";
import * as schema from "../src/db/schema";

const databaseUrl = process.env.TEST_DATABASE_URL;

if (databaseUrl === undefined) {
  test.skip("account credential lifecycle locking (TEST_DATABASE_URL is unset)", () => {
    // The integration suite is enabled in CI and by the documented local command.
  });
} else {
  describe("account credential lifecycle locking", () => {
    const databaseName = `auth_merge_race_${crypto
      .randomUUID()
      .replaceAll("-", "")}`;
    const applicationName = databaseName;
    const isolatedDatabaseUrl = new URL(databaseUrl);
    isolatedDatabaseUrl.pathname = `/${databaseName}`;
    const adminSql = postgres(databaseUrl, {
      max: 2,
      onnotice: () => undefined,
    });
    let databaseSql: ReturnType<typeof postgres>;
    let db: IdentityDb;
    const config: IdentityConfig = {
      appClients: [],
      baseUrl: "https://identity.test",
      databaseUrl: isolatedDatabaseUrl.toString(),
      oidcClients: [],
      port: 8790,
      secret: "identity-test-secret-01234567890123456789",
      socialProviders: {
        github: {
          clientId: "github-test-client",
          clientSecret: "github-test-secret",
        },
      },
      trustedOrigins: [],
      trustedProxies: [],
    };

    beforeAll(async () => {
      await adminSql`CREATE DATABASE ${adminSql(databaseName)}`;
      databaseSql = postgres(isolatedDatabaseUrl.toString(), {
        connection: { application_name: applicationName },
        max: 10,
        onnotice: () => undefined,
      });
      db = drizzle(databaseSql, { schema }) as IdentityDb;
      await migrate(db, {
        migrationsFolder: resolve(import.meta.dir, "../drizzle"),
      });
    });

    afterAll(async () => {
      await databaseSql.end({ timeout: 5 });
      await adminSql`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = ${databaseName}
          AND pid <> pg_backend_pid()
      `;
      await adminSql`DROP DATABASE IF EXISTS ${adminSql(databaseName)}`;
      await adminSql.end({ timeout: 5 });
    });

    test("moves a social credential when its lifecycle lock precedes account consolidation", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Social Link Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Social Link Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(identitySubjectMerge).values({
        actorUserId: targetUserId,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId,
        status: "prepared",
        targetUserId,
      });
      await databaseSql`
        CREATE FUNCTION delay_social_link_audit()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          PERFORM pg_sleep(1);
          RETURN NEW;
        END
        $$
      `;
      await databaseSql`
        CREATE TRIGGER delay_social_link_audit
        BEFORE INSERT ON identity_audit_event
        FOR EACH ROW
        WHEN (NEW.kind = 'social.linked')
        EXECUTE FUNCTION delay_social_link_audit()
      `;
      const { auth } = createIdentityAuth(config, db);
      const context = await auth.$context;

      try {
        const linkPromise = context.internalAdapter.linkAccount({
          accountId: `github-${sourceUserId}`,
          providerId: "github",
          userId: sourceUserId,
        });
        const linkPid = await waitForDatabaseWaitEvent({
          applicationName,
          event: "PgSleep",
          sqlClient: adminSql,
        });
        const mergePromise = commitAccountMerge({
          attemptId: mergeAttemptId,
          db,
          targetUserId,
        });
        await waitForBlockedBackend({
          applicationName,
          blockerPid: linkPid,
          sqlClient: adminSql,
        });
        const createdAccount = await linkPromise;
        await expect(mergePromise).resolves.toEqual({ merged: true });

        expect(createdAccount.userId).toBe(sourceUserId);
        expect(
          await db
            .select({ userId: account.userId })
            .from(account)
            .where(eq(account.id, createdAccount.id)),
        ).toEqual([{ userId: targetUserId }]);
        expect(
          await db
            .select({
              credentialId: identityAuditEvent.credentialId,
              kind: identityAuditEvent.kind,
              userId: identityAuditEvent.userId,
            })
            .from(identityAuditEvent)
            .where(eq(identityAuditEvent.credentialId, createdAccount.id)),
        ).toEqual([
          {
            credentialId: createdAccount.id,
            kind: "social.linked",
            userId: sourceUserId,
          },
        ]);
      } finally {
        await databaseSql`
          DROP TRIGGER IF EXISTS delay_social_link_audit
          ON identity_audit_event
        `;
        await databaseSql`DROP FUNCTION IF EXISTS delay_social_link_audit()`;
      }
    });

    test("rejects a social credential after account consolidation wins the lifecycle lock", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const existingAccountId = crypto.randomUUID();
      const racedProviderAccountId = `github-${crypto.randomUUID()}`;
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Social Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Social Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(account).values({
        accountId: sourceUserId,
        createdAt: now,
        id: existingAccountId,
        providerId: "credential",
        updatedAt: now,
        userId: sourceUserId,
      });
      await db.insert(identitySubjectMerge).values({
        actorUserId: targetUserId,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId,
        status: "prepared",
        targetUserId,
      });
      const { auth } = createIdentityAuth(config, db);
      const context = await auth.$context;
      await expect(
        commitAccountMerge({
          attemptId: mergeAttemptId,
          db,
          targetUserId,
        }),
      ).resolves.toEqual({ merged: true });

      await expect(
        context.internalAdapter.linkAccount({
          accountId: racedProviderAccountId,
          providerId: "github",
          userId: sourceUserId,
        }),
      ).rejects.toMatchObject({
        body: expect.objectContaining({ code: "ACCOUNT_UNAVAILABLE" }),
        status: "FORBIDDEN",
      });
      expect(
        await db
          .select({ id: account.id })
          .from(account)
          .where(eq(account.accountId, racedProviderAccountId)),
      ).toHaveLength(0);
      expect(
        await db
          .select({ id: identityAuditEvent.id })
          .from(identityAuditEvent)
          .where(eq(identityAuditEvent.userId, sourceUserId)),
      ).toHaveLength(0);
      expect(
        await db
          .select({ userId: account.userId })
          .from(account)
          .where(eq(account.id, existingAccountId)),
      ).toEqual([{ userId: targetUserId }]);
      expect(
        await db
          .select({ status: user.status })
          .from(user)
          .where(eq(user.id, sourceUserId)),
      ).toEqual([{ status: "merged" }]);
    });

    test("keeps HTTP credential unlink disabled after consolidation moves the account", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const credentialId = crypto.randomUUID();
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Delete Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Delete Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(account).values({
        accountId: `github-${sourceUserId}`,
        createdAt: now,
        id: credentialId,
        providerId: "github",
        updatedAt: now,
        userId: sourceUserId,
      });
      await db.insert(identitySubjectMerge).values({
        actorUserId: targetUserId,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId,
        status: "prepared",
        targetUserId,
      });
      const { auth } = createIdentityAuth(config, db);
      await expect(
        commitAccountMerge({
          attemptId: mergeAttemptId,
          db,
          targetUserId,
        }),
      ).resolves.toEqual({ merged: true });

      const response = await auth.handler(
        new Request("https://identity.test/api/auth/unlink-account", {
          body: JSON.stringify({
            accountId: `github-${sourceUserId}`,
            providerId: "github",
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        }),
      );
      expect(response.status).toBe(404);
      expect(
        await db
          .select({ userId: account.userId })
          .from(account)
          .where(eq(account.id, credentialId)),
      ).toEqual([{ userId: targetUserId }]);
    });

    test("completes a credential delete before consolidation when delete holds the lifecycle lock", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const credentialId = crypto.randomUUID();
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Delete First Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Delete First Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(account).values({
        accountId: `github-${sourceUserId}`,
        createdAt: now,
        id: credentialId,
        providerId: "github",
        updatedAt: now,
        userId: sourceUserId,
      });
      await db.insert(identitySubjectMerge).values({
        actorUserId: targetUserId,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId,
        status: "prepared",
        targetUserId,
      });
      await databaseSql`
        CREATE FUNCTION delay_account_delete_before_merge()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          PERFORM pg_sleep(1);
          RETURN OLD;
        END
        $$
      `;
      await databaseSql`
        CREATE TRIGGER delay_account_delete_before_merge
        BEFORE DELETE ON account
        FOR EACH ROW
        EXECUTE FUNCTION delay_account_delete_before_merge()
      `;

      try {
        const { auth } = createIdentityAuth(config, db);
        const context = await auth.$context;
        const deletePromise = context.adapter.delete({
          model: "account",
          where: [{ field: "id", value: credentialId }],
        });
        const deletePid = await waitForDatabaseWaitEvent({
          applicationName,
          event: "PgSleep",
          sqlClient: adminSql,
        });
        const mergePromise = commitAccountMerge({
          attemptId: mergeAttemptId,
          db,
          targetUserId,
        });
        await waitForBlockedBackend({
          applicationName,
          blockerPid: deletePid,
          sqlClient: adminSql,
        });

        await expect(deletePromise).resolves.toBeUndefined();
        await expect(mergePromise).resolves.toEqual({ merged: true });
        expect(
          await db
            .select({ id: account.id })
            .from(account)
            .where(eq(account.id, credentialId)),
        ).toHaveLength(0);
        expect(
          await db
            .select({ status: user.status })
            .from(user)
            .where(eq(user.id, sourceUserId)),
        ).toEqual([{ status: "merged" }]);
      } finally {
        await databaseSql`
          DROP TRIGGER IF EXISTS delay_account_delete_before_merge ON account
        `;
        await databaseSql`
          DROP FUNCTION IF EXISTS delay_account_delete_before_merge()
        `;
      }
    });

    test("keeps unmatched account mutations as no-ops", async () => {
      const { auth } = createIdentityAuth(config, db);
      const context = await auth.$context;
      const where = [{ field: "id", value: crypto.randomUUID() }];

      await expect(
        context.adapter.update({
          model: "account",
          update: { accessToken: "unused" },
          where,
        }),
      ).resolves.toBeNull();
      await expect(
        context.adapter.updateMany({
          model: "account",
          update: { accessToken: "unused" },
          where,
        }),
      ).resolves.toBe(0);
      await expect(
        context.adapter.delete({ model: "account", where }),
      ).resolves.toBeUndefined();
      await expect(
        context.adapter.deleteMany({ model: "account", where }),
      ).resolves.toBe(0);
    });
  });
}

async function waitForBlockedBackend(input: {
  applicationName: string;
  blockerPid: number;
  sqlClient: ReturnType<typeof postgres>;
}): Promise<number> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const [activity] = await input.sqlClient<{ pid: number }[]>`
      SELECT pid
      FROM pg_stat_activity
      WHERE pid <> pg_backend_pid()
        AND application_name = ${input.applicationName}
        AND wait_event_type = 'Lock'
        AND ${input.blockerPid} = ANY(pg_blocking_pids(pid))
      LIMIT 1
    `;
    if (activity !== undefined) return activity.pid;
    await Bun.sleep(5);
  }
  throw new Error(`No database backend waited for blocker ${input.blockerPid}`);
}

async function waitForDatabaseWaitEvent(input: {
  applicationName: string;
  event: string;
  sqlClient: ReturnType<typeof postgres>;
}): Promise<number> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const [activity] = await input.sqlClient<{ pid: number }[]>`
      SELECT pid
      FROM pg_stat_activity
      WHERE pid <> pg_backend_pid()
        AND application_name = ${input.applicationName}
        AND wait_event = ${input.event}
      LIMIT 1
    `;
    if (activity !== undefined) return activity.pid;
    await Bun.sleep(5);
  }
  throw new Error(`No database backend entered ${input.event}`);
}
