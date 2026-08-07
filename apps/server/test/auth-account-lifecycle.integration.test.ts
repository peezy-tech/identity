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
  oauthClient,
  oauthConsent,
  user,
  walletAddress,
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

    test("moves a Better Auth wallet row when wallet creation holds the lifecycle lock", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const targetWalletId = crypto.randomUUID();
      const sourceWalletAddress = "0x7100000000000000000000000000000000000001";
      const targetWalletAddress = "0x7100000000000000000000000000000000000002";
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Wallet Create Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Wallet Create Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(walletAddress).values({
        address: targetWalletAddress,
        chainId: 1,
        createdAt: now,
        id: targetWalletId,
        isPrimary: true,
        userId: targetUserId,
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
        CREATE FUNCTION delay_wallet_create_before_merge()
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
        CREATE TRIGGER delay_wallet_create_before_merge
        BEFORE INSERT ON wallet_address
        FOR EACH ROW
        EXECUTE FUNCTION delay_wallet_create_before_merge()
      `;

      try {
        const { auth } = createIdentityAuth(config, db);
        const context = await auth.$context;
        const walletPromise = context.adapter.create<
          {
            address: string;
            chainId: number;
            createdAt: Date;
            isPrimary: boolean;
            userId: string;
          },
          { id: string; userId: string }
        >({
          data: {
            address: sourceWalletAddress,
            chainId: 1,
            createdAt: now,
            isPrimary: true,
            userId: sourceUserId,
          },
          model: "walletAddress",
        });
        const walletPid = await waitForDatabaseWaitEvent({
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
          blockerPid: walletPid,
          sqlClient: adminSql,
        });

        const createdWallet = await walletPromise;
        await expect(mergePromise).resolves.toEqual({ merged: true });
        expect(createdWallet.userId).toBe(sourceUserId);
        expect(
          await db
            .select({
              address: walletAddress.address,
              isPrimary: walletAddress.isPrimary,
              userId: walletAddress.userId,
            })
            .from(walletAddress)
            .where(eq(walletAddress.id, createdWallet.id)),
        ).toEqual([
          {
            address: sourceWalletAddress,
            isPrimary: false,
            userId: targetUserId,
          },
        ]);
        expect(
          await db
            .select({ isPrimary: walletAddress.isPrimary })
            .from(walletAddress)
            .where(eq(walletAddress.id, targetWalletId)),
        ).toEqual([{ isPrimary: true }]);
      } finally {
        await databaseSql`
          DROP TRIGGER IF EXISTS delay_wallet_create_before_merge
          ON wallet_address
        `;
        await databaseSql`
          DROP FUNCTION IF EXISTS delay_wallet_create_before_merge()
        `;
      }
    });

    test("rejects a Better Auth wallet row after consolidation wins the lifecycle lock", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const racedWalletAddress = "0x7200000000000000000000000000000000000001";
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Wallet Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Wallet Merge Target",
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
        context.adapter.create({
          data: {
            address: racedWalletAddress,
            chainId: 1,
            createdAt: now,
            isPrimary: true,
            userId: sourceUserId,
          },
          model: "walletAddress",
        }),
      ).rejects.toMatchObject({
        body: expect.objectContaining({ code: "ACCOUNT_UNAVAILABLE" }),
        status: "FORBIDDEN",
      });
      expect(
        await db
          .select({ id: walletAddress.id })
          .from(walletAddress)
          .where(eq(walletAddress.address, racedWalletAddress)),
      ).toHaveLength(0);
    });

    test("deletes OAuth consent when consent creation holds the lifecycle lock before consolidation", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const clientId = `consent-client-${crypto.randomUUID()}`;
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Consent Create Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Consent Create Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(oauthClient).values({ clientId, redirectUris: [] });
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
        CREATE FUNCTION delay_consent_create_before_merge()
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
        CREATE TRIGGER delay_consent_create_before_merge
        BEFORE INSERT ON oauth_consent
        FOR EACH ROW
        EXECUTE FUNCTION delay_consent_create_before_merge()
      `;

      try {
        const { auth } = createIdentityAuth(config, db);
        const context = await auth.$context;
        const consentPromise = context.adapter.create<
          {
            clientId: string;
            createdAt: Date;
            scopes: string[];
            updatedAt: Date;
            userId: string;
          },
          { id: string; userId: string }
        >({
          data: {
            clientId,
            createdAt: now,
            scopes: ["openid"],
            updatedAt: now,
            userId: sourceUserId,
          },
          model: "oauthConsent",
        });
        const consentPid = await waitForDatabaseWaitEvent({
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
          blockerPid: consentPid,
          sqlClient: adminSql,
        });

        const createdConsent = await consentPromise;
        await expect(mergePromise).resolves.toEqual({ merged: true });
        expect(createdConsent.userId).toBe(sourceUserId);
        expect(
          await db
            .select({ id: oauthConsent.id })
            .from(oauthConsent)
            .where(eq(oauthConsent.id, createdConsent.id)),
        ).toHaveLength(0);
      } finally {
        await databaseSql`
          DROP TRIGGER IF EXISTS delay_consent_create_before_merge
          ON oauth_consent
        `;
        await databaseSql`
          DROP FUNCTION IF EXISTS delay_consent_create_before_merge()
        `;
      }
    });

    test("rejects OAuth consent after consolidation wins the lifecycle lock", async () => {
      const sourceUserId = crypto.randomUUID();
      const targetUserId = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const clientId = `consent-client-${crypto.randomUUID()}`;
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceUserId,
          name: "Consent Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetUserId}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetUserId,
          name: "Consent Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await db.insert(oauthClient).values({ clientId, redirectUris: [] });
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
        context.adapter.create({
          data: {
            clientId,
            createdAt: now,
            scopes: ["openid"],
            updatedAt: now,
            userId: sourceUserId,
          },
          model: "oauthConsent",
        }),
      ).rejects.toMatchObject({
        body: expect.objectContaining({ code: "ACCOUNT_UNAVAILABLE" }),
        status: "FORBIDDEN",
      });
      expect(
        await db
          .select({ id: oauthConsent.id })
          .from(oauthConsent)
          .where(eq(oauthConsent.userId, sourceUserId)),
      ).toHaveLength(0);
    });

    test("preserves nullable-owner OAuth consent mutations", async () => {
      const clientId = `consent-client-${crypto.randomUUID()}`;
      const now = new Date("2026-08-07T00:00:00.000Z");
      await db.insert(oauthClient).values({ clientId, redirectUris: [] });
      const { auth } = createIdentityAuth(config, db);
      const context = await auth.$context;

      const createdConsent = await context.adapter.create<
        {
          clientId: string;
          createdAt: Date;
          scopes: string[];
          updatedAt: Date;
          userId: null;
        },
        { id: string; userId: null }
      >({
        data: {
          clientId,
          createdAt: now,
          scopes: ["openid"],
          updatedAt: now,
          userId: null,
        },
        model: "oauthConsent",
      });
      expect(createdConsent.userId).toBeNull();
      await expect(
        context.adapter.update({
          model: "oauthConsent",
          update: { scopes: ["openid", "profile"] },
          where: [{ field: "id", value: createdConsent.id }],
        }),
      ).resolves.toMatchObject({
        id: createdConsent.id,
        scopes: ["openid", "profile"],
        userId: null,
      });
      await expect(
        context.adapter.delete({
          model: "oauthConsent",
          where: [{ field: "id", value: createdConsent.id }],
        }),
      ).resolves.toBeUndefined();
      expect(
        await db
          .select({ id: oauthConsent.id })
          .from(oauthConsent)
          .where(eq(oauthConsent.id, createdConsent.id)),
      ).toHaveLength(0);
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
