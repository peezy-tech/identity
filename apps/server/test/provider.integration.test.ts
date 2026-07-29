import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { resolve } from "node:path";

import {
  IdentityMeResponseSchema,
  WalletChallengeResponseSchema,
  WalletGrantExchangeResponseSchema,
  WalletGrantResponseSchema,
} from "@peezy.tech/identity";
import { eq } from "drizzle-orm";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { privateKeyToAccount } from "viem/accounts";

import {
  importIdentity,
  readLegacyIdentity,
  validateLegacyIdentity,
  verifyImport,
} from "../scripts/import-pledge-cash";
import { createIdentityApp } from "../src/app";
import { createIdentityAuth } from "../src/auth";
import { seedConfiguredClients } from "../src/clients";
import type { IdentityConfig } from "../src/config";
import { createDbClient, type IdentityDbClient } from "../src/db/client";
import { user, walletAddress } from "../src/db/schema";
import { identityMe } from "../src/identity";

const databaseUrl = process.env.TEST_DATABASE_URL;

if (databaseUrl === undefined) {
  test.skip("identity provider integration (TEST_DATABASE_URL is unset)", () => {
    // The integration suite is enabled in CI and by the documented local command.
  });
} else {
  describe("identity provider integration", () => {
    const origin = "https://pledge.test";
    const appSecret = "identity-test-app-secret-0123456789";
    const oidcSecret = "identity-test-oidc-secret-01234567";
    const subject = "9bb64f50-80eb-48e3-999e-c4712e752461";
    const otherSubject = "523ef58e-04a9-4b67-b863-c8004af31551";
    const wallet = privateKeyToAccount(
      "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    const config: IdentityConfig = {
      appClients: [
        {
          id: "pledge-cash",
          name: "PledgeCash",
          origins: [origin],
          secret: appSecret,
          siweStatement: "Sign in to PledgeCash.",
          walletLinkSiweStatement: "Link this wallet to PledgeCash.",
        },
      ],
      baseUrl: "https://identity.test",
      databaseUrl,
      oidcClients: [
        {
          audiences: ["pledge-cash"],
          clientId: "pledge-cash",
          clientSecret: oidcSecret,
          name: "PledgeCash",
          redirectUris: ["https://pledge.test/auth/callback/peezy"],
        },
      ],
      port: 8790,
      secret: "identity-test-secret-01234567890123456789",
      socialProviders: {
        github: {
          clientId: "github-test-client",
          clientSecret: "github-test-secret",
        },
      },
      trustedOrigins: [origin],
    };

    let database: IdentityDbClient;
    let app: ReturnType<typeof createIdentityApp>;

    beforeAll(async () => {
      database = createDbClient(databaseUrl);
      await database.sql.unsafe("DROP SCHEMA IF EXISTS drizzle CASCADE");
      await database.sql.unsafe("DROP SCHEMA IF EXISTS public CASCADE");
      await database.sql.unsafe("CREATE SCHEMA public");
      await migrate(database.db, {
        migrationsFolder: resolve(import.meta.dir, "../drizzle"),
      });
      await seedConfiguredClients(database.db, config);
      const { auth, socialProviderNames } = createIdentityAuth(
        config,
        database.db,
      );
      app = createIdentityApp({
        auth,
        config,
        db: database.db,
        socialProviderNames,
      });
    });

    afterAll(async () => {
      await database.close();
    });

    test("discovers the OIDC issuer and supports a walletless user", async () => {
      const metadataResponse = await app.request(
        "https://identity.test/api/auth/.well-known/openid-configuration",
      );
      expect(metadataResponse.status).toBe(200);
      const metadata = (await metadataResponse.json()) as {
        authorization_endpoint: string;
        issuer: string;
      };
      expect(metadata.issuer).toBe("https://identity.test/api/auth");
      expect(metadata.authorization_endpoint).toBe(
        "https://identity.test/api/auth/oauth2/authorize",
      );

      const now = new Date("2026-07-29T00:00:00.000Z");
      await database.db.insert(user).values({
        createdAt: now,
        email: "walletless@example.com",
        emailVerified: true,
        id: subject,
        name: "Walletless User",
        status: "active",
        updatedAt: now,
      });
      const identity = IdentityMeResponseSchema.parse(
        await identityMe(database.db, subject),
      );
      expect(identity.user.primaryEmail?.value).toBe("walletless@example.com");
      expect(
        identity.credentials.some((credential) => credential.kind === "wallet"),
      ).toBe(false);
    });

    test("links a wallet, exchanges its one-time grant, and preserves one global owner", async () => {
      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "pledge-cash",
            walletAddress: wallet.address,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        },
      );
      expect(challengeResponse.status).toBe(201);
      const challenge = WalletChallengeResponseSchema.parse(
        await challengeResponse.json(),
      );
      expect(challenge.statement).toBe("Sign in to PledgeCash.");
      const signature = await wallet.signMessage({
        message: challenge.message,
      });

      const issueResponse = await app.request(
        "https://identity.test/v1/wallet/grants/issue",
        {
          body: JSON.stringify({
            clientId: "pledge-cash",
            message: challenge.message,
            signature,
            subject,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        },
      );
      expect(issueResponse.status).toBe(201);
      const issued = WalletGrantResponseSchema.parse(
        await issueResponse.json(),
      );
      expect(issued.user.id).toBe(subject);

      const exchange = () =>
        app.request("https://identity.test/v1/wallet/grants/exchange", {
          body: JSON.stringify({
            clientId: "pledge-cash",
            grant: issued.grant,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        });
      const exchangeResponse = await exchange();
      expect(exchangeResponse.status).toBe(200);
      expect(
        WalletGrantExchangeResponseSchema.parse(await exchangeResponse.json())
          .subject,
      ).toBe(subject);
      expect((await exchange()).status).toBe(401);

      const linkedIdentity = await identityMe(database.db, subject);
      expect(
        linkedIdentity.credentials.find(
          (credential) => credential.kind === "wallet",
        ),
      ).toMatchObject({
        address: wallet.address.toLowerCase(),
        verifiedChainIds: [999],
      });

      const now = new Date("2026-07-29T00:01:00.000Z");
      await database.db.insert(user).values({
        createdAt: now,
        email: "other@example.com",
        emailVerified: true,
        id: otherSubject,
        name: "Other User",
        status: "active",
        updatedAt: now,
      });
      let conflict: unknown;
      try {
        await database.db.insert(walletAddress).values({
          address: wallet.address,
          chainId: 998,
          createdAt: now,
          id: crypto.randomUUID(),
          isPrimary: true,
          userId: otherSubject,
        });
      } catch (error) {
        conflict = error;
      }
      expect(
        (conflict as { cause?: { message?: string } } | undefined)?.cause
          ?.message,
      ).toContain("EVM wallet is already linked");

      const owners = await database.db
        .select({ id: user.id })
        .from(user)
        .where(eq(user.id, subject));
      expect(owners).toHaveLength(1);
    });

    test("hands an authenticated application subject into an explicit social-link flow once", async () => {
      const lookupResponse = await app.request(
        `https://identity.test/v1/users/${subject}`,
        {
          headers: { Authorization: basic("pledge-cash", appSecret) },
        },
      );
      expect(lookupResponse.status).toBe(200);
      expect(
        IdentityMeResponseSchema.parse(await lookupResponse.json()).user.id,
      ).toBe(subject);

      const handoffResponse = await app.request(
        "https://identity.test/v1/social-link-handoffs",
        {
          body: JSON.stringify({
            callbackUrl: `${origin}/settings/alerts`,
            clientId: "pledge-cash",
            provider: "github",
            subject,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        },
      );
      expect(handoffResponse.status).toBe(201);
      const handoff = (await handoffResponse.json()) as { url: string };
      const consumeResponse = await app.request(handoff.url);
      expect(consumeResponse.status).toBe(302);
      expect(consumeResponse.headers.get("set-cookie")).toContain(
        "peezy-identity.session_token",
      );
      expect(consumeResponse.headers.get("location")).toContain(
        "/link-social?",
      );
      expect((await app.request(handoff.url)).status).toBe(401);
    });

    test("imports identity rows without sessions, provider tokens, or product organizations", async () => {
      await database.sql.unsafe("DROP SCHEMA IF EXISTS legacy_pledge CASCADE");
      await database.sql.unsafe("CREATE SCHEMA legacy_pledge");
      await database.sql.unsafe(`
        CREATE TABLE legacy_pledge.users (
          id uuid PRIMARY KEY,
          name text NOT NULL,
          email text NOT NULL,
          email_verified boolean NOT NULL,
          image text,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.auth_accounts (
          id uuid PRIMARY KEY,
          account_id text NOT NULL,
          provider_id text NOT NULL,
          user_id uuid NOT NULL,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.auth_wallets (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL,
          address text NOT NULL,
          chain_id integer NOT NULL,
          is_primary boolean NOT NULL,
          created_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.wallet_owners (
          address text PRIMARY KEY,
          user_id uuid NOT NULL,
          created_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.organizations (
          id uuid PRIMARY KEY,
          name text NOT NULL,
          slug text NOT NULL,
          logo text,
          metadata text,
          created_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.organization_members (
          id uuid PRIMARY KEY,
          organization_id uuid NOT NULL,
          user_id uuid NOT NULL,
          role text NOT NULL,
          created_at timestamptz NOT NULL
        );
        CREATE TABLE legacy_pledge.organization_invitations (
          id uuid PRIMARY KEY,
          organization_id uuid NOT NULL,
          email text NOT NULL,
          role text,
          status text NOT NULL,
          expires_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL,
          inviter_id uuid NOT NULL
        );
      `);
      const legacy = postgres(databaseUrl, { max: 1 });
      try {
        await legacy`SELECT set_config('search_path', 'legacy_pledge', false)`;
        const importedSubject = "bc024a7f-bafe-480f-a614-a7b7226c4290";
        const walletId = "d2f9867a-fcb0-40f7-bcad-f14887205665";
        const organizationId = "16fcc520-3194-4499-a6ce-8f9d1600f3fd";
        const importedWallet = "0x1000000000000000000000000000000000000000";
        await legacy`
          INSERT INTO users VALUES (
            ${importedSubject}::uuid,
            'Imported User',
            'imported@example.com',
            true,
            NULL,
            '2026-07-01T00:00:00Z',
            '2026-07-02T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO auth_accounts VALUES (
            '43ae8f66-74e9-40fd-a4a4-038e1514db1c',
            'github-subject',
            'github',
            ${importedSubject}::uuid,
            '2026-07-01T00:00:00Z',
            '2026-07-02T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO auth_wallets VALUES (
            ${walletId}::uuid,
            ${importedSubject}::uuid,
            ${importedWallet},
            999,
            true,
            '2026-07-01T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO wallet_owners VALUES (
            ${importedWallet},
            ${importedSubject}::uuid,
            '2026-07-01T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO organizations VALUES (
            ${organizationId}::uuid,
            'Imported Org',
            'imported-org',
            NULL,
            NULL,
            '2026-07-01T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO organization_members VALUES (
            '2203a34f-2947-4335-9b8c-b3dbeacfe486',
            ${organizationId}::uuid,
            ${importedSubject}::uuid,
            'owner',
            '2026-07-01T00:00:00Z'
          )
        `;
        await legacy`
          INSERT INTO organization_invitations VALUES (
            '3f31e677-1698-42e5-9c30-6f0fd0b6d121',
            ${organizationId}::uuid,
            'invitee@example.com',
            'member',
            'pending',
            '2026-08-01T00:00:00Z',
            '2026-07-01T00:00:00Z',
            ${importedSubject}::uuid
          )
        `;

        const legacyIdentity = await readLegacyIdentity(legacy);
        validateLegacyIdentity(legacyIdentity);
        await importIdentity(database.sql, legacyIdentity);
        await verifyImport(database.sql, legacyIdentity);

        const imported = await identityMe(database.db, importedSubject);
        expect(imported.user.id).toBe(importedSubject);
        expect(imported.credentials).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              kind: "social",
              provider: "github",
            }),
            expect.objectContaining({
              address: importedWallet,
              kind: "wallet",
            }),
          ]),
        );
        const [copiedOrganization] = await database.sql<{ count: string }[]>`
          SELECT count(*)::text AS "count"
          FROM "organization"
          WHERE "id" = ${organizationId}
        `;
        expect(copiedOrganization?.count).toBe("0");
      } finally {
        await legacy.end({ timeout: 5 });
      }
    });
  });
}

function basic(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}
