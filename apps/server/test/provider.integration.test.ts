import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { resolve } from "node:path";

import {
  IdentityMeResponseSchema,
  PeezyHandleSchema,
  WalletChallengeResponseSchema,
  WalletGrantExchangeResponseSchema,
  WalletGrantResponseSchema,
} from "@peezy.tech/identity";
import bs58 from "bs58";
import { eq } from "drizzle-orm";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { decodeJwt } from "jose";
import postgres from "postgres";
import { privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";

import {
  assertDistinctDatabases,
  assertTargetSchema,
  importIdentity,
  readLegacyIdentity,
  validateLegacyIdentity,
  verifyImport,
} from "../scripts/import-pledge-cash";
import { commitAccountMerge } from "../src/account-merge";
import { createIdentityApp } from "../src/app";
import { createIdentityAuth, createIdentityProofAuth } from "../src/auth";
import { seedConfiguredClients } from "../src/clients";
import type { IdentityConfig } from "../src/config";
import { HOSTED_WALLET_STATEMENT } from "../src/constants";
import { createDbClient, type IdentityDbClient } from "../src/db/client";
import {
  account,
  accountWalletLinkChallenge,
  identitySubjectMerge,
  privyMigrationClaim,
  privyMigrationIdentity,
  rateLimit,
  session,
  user,
  walletAddress,
  walletChallenge,
  walletGrant,
  walletPrincipal,
} from "../src/db/schema";
import { identityMe } from "../src/identity";
import {
  claimPrivyMigration,
  createPrivyMigrationAttempt,
  PrivyMigrationError,
  type PrivyGateway,
} from "../src/privy-migration";
import { MAX_RATE_LIMIT_WINDOW_MS, consumeRateLimit } from "../src/rate-limit";
import { consumeSessionHandoff } from "../src/session-handoffs";
import { createWalletGrant } from "../src/wallet-grants";

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
    const hostedWallet = privateKeyToAccount(
      "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    );
    const migratingWallet = privateKeyToAccount(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const migratingSolanaWallet = createSolanaWallet();
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
          audiences: ["https://api.pledge.test", "https://admin.pledge.test"],
          clientId: "pledge-cash",
          clientSecret: oidcSecret,
          name: "PledgeCash",
          redirectUris: ["https://pledge.test/auth/callback/peezy"],
          requireHandle: false,
        },
      ],
      port: 8790,
      privyMigration: {
        appId: "legacy-lobby-app",
        appSecret: "legacy-lobby-secret",
      },
      secret: "identity-test-secret-01234567890123456789",
      socialProviders: {
        github: {
          clientId: "github-test-client",
          clientSecret: "github-test-secret",
        },
      },
      trustedProxies: [],
      trustedOrigins: [origin],
    };

    let database: IdentityDbClient;
    let app: ReturnType<typeof createIdentityApp>;
    let identityAuth: ReturnType<typeof createIdentityAuth>["auth"];
    let identityProofAuth: ReturnType<typeof createIdentityProofAuth>;
    const privyGateway: PrivyGateway = {
      async authenticateAccessToken(accessToken) {
        if (
          accessToken !== "valid-legacy-token" &&
          accessToken !== "wallet-bundle-token" &&
          accessToken !== "solana-wallet-bundle-token" &&
          accessToken !== "concurrent-token"
        ) {
          throw new PrivyMigrationError(
            401,
            "invalid_proof",
            "Privy authentication could not be verified",
          );
        }
        if (accessToken === "wallet-bundle-token") {
          return {
            createdAt: new Date("2025-01-02T00:00:00Z"),
            id: "did:privy:legacy-wallet-person",
            linkedAccounts: [
              {
                address: migratingWallet.address,
                chain_type: "ethereum",
                type: "embedded_wallet",
              },
            ],
          };
        }
        if (accessToken === "solana-wallet-bundle-token") {
          return {
            createdAt: new Date("2025-01-02T00:00:00Z"),
            id: "did:privy:legacy-solana-person",
            linkedAccounts: [
              {
                address: migratingSolanaWallet.address,
                chain_type: "solana",
                type: "embedded_wallet",
              },
            ],
          };
        }
        if (accessToken === "concurrent-token") {
          return {
            createdAt: new Date("2025-01-03T00:00:00Z"),
            id: "did:privy:concurrent-person",
            linkedAccounts: [],
          };
        }
        return {
          createdAt: new Date("2025-01-01T00:00:00Z"),
          id: "did:privy:legacy-person",
          linkedAccounts: [
            {
              subject: "github-legacy",
              type: "github_oauth",
              username: "legacy",
            },
            { subject: "discord-one", type: "discord_oauth" },
            { subject: "discord-two", type: "discord_oauth" },
            {
              address: "0x3000000000000000000000000000000000000000",
              chain_type: "ethereum",
              type: "wallet",
            },
            { fid: 42, type: "farcaster" },
          ],
        };
      },
    };

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
      identityAuth = auth;
      identityProofAuth = createIdentityProofAuth(config, database.db);
      app = createIdentityApp({
        auth,
        config,
        db: database.db,
        privyGateway,
        proofAuth: identityProofAuth,
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

    test("lands hosted sign-ins on a session-aware account route", async () => {
      const signedOutHome = await app.request("https://identity.test/");
      expect(signedOutHome.status).toBe(200);
      expect(await signedOutHome.text()).toContain("Sign in to peezy.tech");

      const signedOutPage = await app.request("https://identity.test/sign-in");
      expect(signedOutPage.status).toBe(200);
      const signedOutHtml = await signedOutPage.text();
      expect(signedOutHtml).toContain("These are peezy.tech sign-ins.");
      expect(signedOutHtml).toContain("Privy is not used here.");
      expect(signedOutHtml).toContain(
        'const callbackURL = location.origin + "/account"',
      );

      const routingWallet = privateKeyToAccount(
        `0x${randomBytes(32).toString("hex")}`,
      );
      const signedIn = await signInHostedWallet(app, config, routingWallet);
      const signedInHome = await app.request("https://identity.test/", {
        headers: { Cookie: signedIn.cookie },
      });
      expect(signedInHome.status).toBe(200);
      expect(await signedInHome.text()).toContain("Open account");

      const accountRedirect = await app.request(
        "https://identity.test/sign-in",
        { headers: { Cookie: signedIn.cookie } },
      );
      expect(accountRedirect.status).toBe(302);
      expect(accountRedirect.headers.get("location")).toBe("/account");

      const safeReturn = await app.request(
        "https://identity.test/sign-in?return_to=%2Faccount%3Ftab%3Dmethods",
        { headers: { Cookie: signedIn.cookie } },
      );
      expect(safeReturn.status).toBe(302);
      expect(safeReturn.headers.get("location")).toBe("/account?tab=methods");

      for (const returnTo of [
        "https%3A%2F%2Fevil.test%2Faccount",
        "%2F%2Fevil.test%2Faccount",
        "%2F..%2F%2Fevil.test%2Faccount",
        "%2Fx%2F..%2F%2Fevil.test%2Faccount",
        "%2F%252e%252e%2F%2Fevil.test%2Faccount",
      ]) {
        const rejectedReturn = await app.request(
          `https://identity.test/sign-in?return_to=${returnTo}`,
          { headers: { Cookie: signedIn.cookie } },
        );
        expect(rejectedReturn.status).toBe(302);
        expect(rejectedReturn.headers.get("location")).toBe("/account");
      }

      const oidcRedirect = await app.request(
        "https://identity.test/sign-in?client_id=pledge-cash&response_type=code&redirect_uri=https%3A%2F%2Fpledge.test%2Fauth%2Fcallback%2Fpeezy",
        { headers: { Cookie: signedIn.cookie } },
      );
      expect(oidcRedirect.status).toBe(302);
      expect(oidcRedirect.headers.get("location")).toBe(
        "/api/auth/oauth2/authorize?client_id=pledge-cash&response_type=code&redirect_uri=https%3A%2F%2Fpledge.test%2Fauth%2Fcallback%2Fpeezy",
      );
    });

    test("updates the account profile with same-origin session protection and signs out", async () => {
      const profileWallet = privateKeyToAccount(
        `0x${randomBytes(32).toString("hex")}`,
      );
      const signedIn = await signInHostedWallet(app, config, profileWallet);
      const update = (
        body: unknown,
        cookie = signedIn.cookie,
        origin = config.baseUrl,
      ) =>
        app.request("https://identity.test/v1/account/profile", {
          body: JSON.stringify(body),
          headers: {
            "Content-Type": "application/json",
            Cookie: cookie,
            Origin: origin,
          },
          method: "POST",
        });

      const response = await update({ displayName: "Peezy Operator" });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        user: { displayName: "Peezy Operator", id: signedIn.userId },
      });

      const me = await app.request("https://identity.test/v1/me", {
        headers: { Cookie: signedIn.cookie },
      });
      expect(me.status).toBe(200);
      expect(await me.json()).toMatchObject({
        user: { displayName: "Peezy Operator", id: signedIn.userId },
      });

      const claimed = await update({
        displayName: "Peezy Operator",
        handle: "peezy-operator",
      });
      expect(claimed.status).toBe(200);
      expect(await claimed.json()).toMatchObject({
        user: { handle: "peezy-operator", id: signedIn.userId },
      });
      expect(
        (
          await update({
            displayName: "Peezy Operator",
            handle: "different-handle",
          })
        ).status,
      ).toBe(409);

      const other = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`),
      );
      expect(
        (
          await update(
            { displayName: "Other", handle: "peezy-operator" },
            other.cookie,
          )
        ).status,
      ).toBe(409);
      expect(
        (await update({ displayName: "Other", handle: "admin" }, other.cookie))
          .status,
      ).toBe(409);

      expect((await update({ displayName: "" })).status).toBe(400);
      expect(
        (await update({ displayName: "Nope", unexpected: true })).status,
      ).toBe(400);
      expect(
        (
          await update(
            { displayName: "Cross origin" },
            signedIn.cookie,
            "https://evil.test",
          )
        ).status,
      ).toBe(403);
      expect((await update({ displayName: "No session" }, "")).status).toBe(
        401,
      );

      const signOutResponse = await app.request(
        "https://identity.test/api/auth/sign-out",
        {
          body: "{}",
          headers: {
            "Content-Type": "application/json",
            Cookie: signedIn.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(signOutResponse.status).toBe(200);
      const afterSignOut = await app.request("https://identity.test/account", {
        headers: { Cookie: signedIn.cookie },
      });
      expect(afterSignOut.status).toBe(302);
      expect(afterSignOut.headers.get("location")).toBe(
        "/sign-in?return_to=%2Faccount",
      );
    });

    test("emits a claimed global handle as preferred_username", async () => {
      const oidcWallet = privateKeyToAccount(
        `0x${randomBytes(32).toString("hex")}`,
      );
      const signedIn = await signInHostedWallet(app, config, oidcWallet);
      const handleRequiredApp = createIdentityApp({
        auth: identityAuth,
        config: {
          ...config,
          oidcClients: config.oidcClients.map((client) => ({
            ...client,
            requireHandle: true,
          })),
        },
        db: database.db,
        privyGateway,
        proofAuth: identityProofAuth,
        socialProviderNames: ["github"],
      });
      const gated = await handleRequiredApp.request(
        "https://identity.test/api/auth/oauth2/authorize?client_id=pledge-cash&response_type=code&redirect_uri=https%3A%2F%2Fpledge.test%2Fauth%2Fcallback%2Fpeezy",
        { headers: { Cookie: signedIn.cookie } },
      );
      expect(gated.status).toBe(302);
      expect(gated.headers.get("location")).toStartWith("/account?return_to=");
      await database.db
        .update(user)
        .set({ handle: "jojo-user", updatedAt: new Date() })
        .where(eq(user.id, signedIn.userId));
      expect(PeezyHandleSchema.parse("Jojo-User")).toBe("jojo-user");

      const authorization = await authorizeCode({
        app: handleRequiredApp,
        identityCookie: signedIn.cookie,
        resource: "https://api.pledge.test",
      });
      const tokenResponse = await exchangeAuthorizationCode({
        app: handleRequiredApp,
        code: authorization.code,
        codeVerifier: authorization.codeVerifier,
        oidcSecret,
        resource: "https://api.pledge.test",
      });
      expect(tokenResponse.status).toBe(200);
      const tokens = (await tokenResponse.json()) as {
        access_token: string;
        id_token: string;
      };
      expect(decodeJwt(tokens.id_token)).toMatchObject({
        preferred_username: "jojo-user",
        sub: signedIn.userId,
      });
      const userInfo = await handleRequiredApp.request(
        "https://identity.test/api/auth/oauth2/userinfo",
        { headers: { Authorization: `Bearer ${tokens.access_token}` } },
      );
      expect(userInfo.status).toBe(200);
      expect(await userInfo.json()).toMatchObject({
        preferred_username: "jojo-user",
        sub: signedIn.userId,
      });

      const metadata = (await (
        await handleRequiredApp.request(
          "https://identity.test/api/auth/.well-known/openid-configuration",
        )
      ).json()) as { claims_supported: string[] };
      expect(metadata.claims_supported).toContain("preferred_username");
    });

    test("uses the core social-link endpoint for Telegram", async () => {
      const telegramApp = createIdentityApp({
        auth: identityAuth,
        config,
        db: database.db,
        privyGateway,
        proofAuth: identityProofAuth,
        socialProviderNames: ["telegram"],
      });
      const response = await telegramApp.request(
        "https://identity.test/link-social?provider=telegram&callback_url=https%3A%2F%2Fidentity.test%2Faccount",
      );
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('fetch("/api/auth/link-social"');
      expect(html).toContain("JSON.stringify({ callbackURL, provider })");
      expect(html).not.toContain("/api/auth/oauth2/link");
    });

    test("keeps primary and proof SIWE nonces in separate namespaces", async () => {
      const nonceWallet = privateKeyToAccount(
        "0xabababababababababababababababababababababababababababababababab",
      );
      const chainId = 999;
      const requestNonce = async (basePath: string) => {
        const response = await app.request(
          `https://identity.test${basePath}/siwe/nonce`,
          {
            body: JSON.stringify({
              chainId,
              walletAddress: nonceWallet.address,
            }),
            headers: { "Content-Type": "application/json" },
            method: "POST",
          },
        );
        expect(response.status).toBe(200);
        return ((await response.json()) as { nonce: string }).nonce;
      };
      const signIn = async (basePath: string, nonce: string) => {
        const now = new Date();
        const message = createSiweMessage({
          address: nonceWallet.address,
          chainId,
          domain: "identity.test",
          expirationTime: new Date(now.getTime() + 10 * 60_000),
          issuedAt: now,
          nonce,
          statement: HOSTED_WALLET_STATEMENT,
          uri: config.baseUrl,
          version: "1",
        });
        return app.request(`https://identity.test${basePath}/siwe/verify`, {
          body: JSON.stringify({
            chainId,
            message,
            signature: await nonceWallet.signMessage({ message }),
            walletAddress: nonceWallet.address,
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        });
      };

      const primaryNonce = await requestNonce("/api/auth");
      const proofNonce = await requestNonce("/api/proof-auth");
      expect(proofNonce).not.toBe(primaryNonce);
      expect((await signIn("/api/auth", primaryNonce)).status).toBe(200);
      expect((await signIn("/api/proof-auth", proofNonce)).status).toBe(200);
    });

    test("rejects request bodies above the public API limit", async () => {
      const response = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({ padding: "x".repeat(20_000) }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        },
      );
      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({
        error: { message: "Request body is too large" },
      });

      const authResponse = await app.request(
        "https://identity.test/api/auth/siwe/nonce",
        {
          body: JSON.stringify({ padding: "x".repeat(100_000) }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      expect(authResponse.status).toBe(413);
    });

    test("claims a complete Privy bundle idempotently and never claims it for another subject", async () => {
      const first = privateKeyToAccount(
        "0x7777777777777777777777777777777777777777777777777777777777777777",
      );
      const second = privateKeyToAccount(
        "0x8888888888888888888888888888888888888888888888888888888888888888",
      );
      const firstSignIn = await signInHostedWallet(app, config, first);
      const secondSignIn = await signInHostedWallet(app, config, second);

      const claim = async (cookie: string, token = "valid-legacy-token") => {
        const attemptResponse = await app.request(
          "https://identity.test/v1/migrations/privy/attempts",
          {
            headers: { Cookie: cookie, Origin: config.baseUrl },
            method: "POST",
          },
        );
        expect(attemptResponse.status).toBe(201);
        const attempt = (await attemptResponse.json()) as {
          attemptId: string;
          csrfToken: string;
        };
        return app.request("https://identity.test/v1/migrations/privy/claims", {
          body: JSON.stringify(attempt),
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            Cookie: cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        });
      };

      const firstClaim = await claim(firstSignIn.cookie);
      expect(firstClaim.status).toBe(201);
      const firstBody = (await firstClaim.json()) as {
        identities: unknown[];
        privyUserId: string;
      };
      expect(firstBody.identities).toHaveLength(5);
      expect(firstBody.privyUserId).toBe("did:privy:legacy-person");
      expect((await claim(firstSignIn.cookie)).status).toBe(201);
      const claimedElsewhere = await claim(secondSignIn.cookie);
      expect(claimedElsewhere.status).toBe(409);
      expect(await claimedElsewhere.json()).toMatchObject({
        error: { code: "claimed_elsewhere" },
      });

      const [claimRow] = await database.db.select().from(privyMigrationClaim);
      expect(claimRow?.userId).toBe(firstSignIn.userId);
      const identityRows = await database.db
        .select()
        .from(privyMigrationIdentity);
      expect(identityRows).toHaveLength(5);

      const concurrentOne = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
      );
      const concurrentTwo = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
      );
      const outcomes = await Promise.all([
        claim(concurrentOne.cookie, "concurrent-token"),
        claim(concurrentTwo.cookie, "concurrent-token"),
      ]);
      expect(outcomes.map((response) => response.status).sort()).toEqual([
        201, 409,
      ]);
      expect(
        await database.db
          .select()
          .from(privyMigrationClaim)
          .where(
            eq(privyMigrationClaim.privyUserId, "did:privy:concurrent-person"),
          ),
      ).toHaveLength(1);
    });

    test("moves a Privy claim when the claim lifecycle lock precedes account consolidation", async () => {
      const sourceSubject = crypto.randomUUID();
      const targetSubject = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const privyUserId = `did:privy:${crypto.randomUUID()}`;
      const now = new Date("2026-08-07T00:00:00.000Z");
      await database.db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceSubject,
          name: "Privy Claim Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetSubject,
          name: "Privy Claim Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await database.db.insert(identitySubjectMerge).values({
        actorUserId: targetSubject,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId: sourceSubject,
        status: "prepared",
        targetUserId: targetSubject,
      });
      const migrationAttempt = await createPrivyMigrationAttempt(
        database.db,
        sourceSubject,
      );
      const raceGateway: PrivyGateway = {
        async authenticateAccessToken() {
          return {
            createdAt: now,
            id: privyUserId,
            linkedAccounts: [],
          };
        },
      };
      let signalClaimCommitted: () => void = () => undefined;
      const claimCommitted = new Promise<void>((resolve) => {
        signalClaimCommitted = resolve;
      });
      let releaseClaimResult: () => void = () => undefined;
      const claimResultReleased = new Promise<void>((resolve) => {
        releaseClaimResult = resolve;
      });
      const transaction = database.db.transaction.bind(
        database.db,
      ) as unknown as (...args: unknown[]) => Promise<unknown>;
      const claimDb = new Proxy(database.db, {
        get(target, property) {
          if (property === "transaction") {
            return async (...args: unknown[]) => {
              const outcome = await transaction(...args);
              signalClaimCommitted();
              await claimResultReleased;
              return outcome;
            };
          }
          const value = Reflect.get(target, property, target) as unknown;
          return typeof value === "function" ? value.bind(target) : value;
        },
      });

      await database.sql`
        CREATE FUNCTION test_delay_privy_attempt_consumption()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          PERFORM pg_sleep(0.5);
          RETURN NEW;
        END
        $$
      `;
      await database.sql`
        CREATE TRIGGER test_delay_privy_attempt_consumption
        BEFORE UPDATE ON privy_migration_attempt
        FOR EACH ROW
        EXECUTE FUNCTION test_delay_privy_attempt_consumption()
      `;
      try {
        const claimPromise = claimPrivyMigration({
          accessToken: "race-token",
          attemptId: migrationAttempt.attemptId,
          csrfToken: migrationAttempt.csrfToken,
          db: claimDb,
          gateway: raceGateway,
          userId: sourceSubject,
        });
        let mergePromise: ReturnType<typeof commitAccountMerge> | undefined;
        let synchronizationFailure: unknown;
        try {
          const claimPid = await waitForDatabaseWaitEvent({
            event: "PgSleep",
            sqlClient: database.sql,
          });
          mergePromise = commitAccountMerge({
            attemptId: mergeAttemptId,
            db: database.db,
            targetUserId: targetSubject,
          });
          await waitForBlockedBackend({
            blockerPid: claimPid,
            sqlClient: database.sql,
          });
        } catch (error) {
          synchronizationFailure = error;
        }
        if (synchronizationFailure !== undefined) {
          await Promise.allSettled([
            claimPromise,
            ...(mergePromise === undefined ? [] : [mergePromise]),
          ]);
          throw synchronizationFailure;
        }
        if (mergePromise === undefined) {
          throw new Error("Account consolidation was not started");
        }

        await claimCommitted;
        await expect(mergePromise).resolves.toEqual({ merged: true });
        releaseClaimResult();
        await expect(claimPromise).resolves.toMatchObject({
          privyUserHint: expect.any(String),
        });
        expect(
          await database.db
            .select({ userId: privyMigrationClaim.userId })
            .from(privyMigrationClaim)
            .where(eq(privyMigrationClaim.privyUserId, privyUserId)),
        ).toEqual([{ userId: targetSubject }]);
      } finally {
        await database.sql`
          DROP TRIGGER IF EXISTS test_delay_privy_attempt_consumption
          ON privy_migration_attempt
        `;
        await database.sql`
          DROP FUNCTION IF EXISTS test_delay_privy_attempt_consumption()
        `;
        releaseClaimResult();
      }
    });

    test("rejects a Privy claim when account consolidation holds the lifecycle lock first", async () => {
      const sourceSubject = crypto.randomUUID();
      const targetSubject = crypto.randomUUID();
      const mergeAttemptId = crypto.randomUUID();
      const principalId = crypto.randomUUID();
      const privyUserId = `did:privy:${crypto.randomUUID()}`;
      const mergeWallet = privateKeyToAccount(
        "0x1919191919191919191919191919191919191919191919191919191919191919",
      );
      const now = new Date("2026-08-07T00:00:00.000Z");
      await database.db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceSubject,
          name: "Privy Merge Claim Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetSubject,
          name: "Privy Merge Claim Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await database.db.insert(walletPrincipal).values({
        accountKind: "eoa",
        address: mergeWallet.address,
        createdAt: now,
        family: "evm",
        id: principalId,
        signInEnabled: true,
        updatedAt: now,
        userId: sourceSubject,
      });
      await database.db.insert(identitySubjectMerge).values({
        actorUserId: targetSubject,
        expiresAt: new Date(Date.now() + 60_000),
        id: mergeAttemptId,
        metadata: {},
        sourceUserId: sourceSubject,
        status: "prepared",
        targetUserId: targetSubject,
      });
      const migrationAttempt = await createPrivyMigrationAttempt(
        database.db,
        sourceSubject,
      );
      const raceGateway: PrivyGateway = {
        async authenticateAccessToken() {
          return {
            createdAt: now,
            id: privyUserId,
            linkedAccounts: [],
          };
        },
      };

      await database.sql`
        CREATE FUNCTION test_delay_privy_merge_principal_move()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          PERFORM pg_sleep(0.5);
          RETURN NEW;
        END
        $$
      `;
      await database.sql`
        CREATE TRIGGER test_delay_privy_merge_principal_move
        BEFORE UPDATE ON wallet_principal
        FOR EACH ROW
        EXECUTE FUNCTION test_delay_privy_merge_principal_move()
      `;
      try {
        const mergePromise = commitAccountMerge({
          attemptId: mergeAttemptId,
          db: database.db,
          targetUserId: targetSubject,
        });
        let claimPromise: ReturnType<typeof claimPrivyMigration> | undefined;
        let synchronizationFailure: unknown;
        try {
          const mergePid = await waitForDatabaseWaitEvent({
            event: "PgSleep",
            sqlClient: database.sql,
          });
          claimPromise = claimPrivyMigration({
            accessToken: "race-token",
            attemptId: migrationAttempt.attemptId,
            csrfToken: migrationAttempt.csrfToken,
            db: database.db,
            gateway: raceGateway,
            userId: sourceSubject,
          });
          await waitForBlockedBackend({
            blockerPid: mergePid,
            sqlClient: database.sql,
          });
        } catch (error) {
          synchronizationFailure = error;
        }
        if (synchronizationFailure !== undefined) {
          await Promise.allSettled([
            mergePromise,
            ...(claimPromise === undefined ? [] : [claimPromise]),
          ]);
          throw synchronizationFailure;
        }
        if (claimPromise === undefined) {
          throw new Error("Privy claim was not started");
        }

        await expect(mergePromise).resolves.toEqual({ merged: true });
        await expect(claimPromise).rejects.toMatchObject({
          code: "invalid_attempt",
          status: 403,
        });
        expect(
          await database.db
            .select({ id: privyMigrationClaim.id })
            .from(privyMigrationClaim)
            .where(eq(privyMigrationClaim.privyUserId, privyUserId)),
        ).toHaveLength(0);
        expect(
          await database.db
            .select({ status: user.status })
            .from(user)
            .where(eq(user.id, sourceSubject)),
        ).toEqual([{ status: "merged" }]);
      } finally {
        await database.sql`
          DROP TRIGGER IF EXISTS test_delay_privy_merge_principal_move
          ON wallet_principal
        `;
        await database.sql`
          DROP FUNCTION IF EXISTS test_delay_privy_merge_principal_move()
        `;
      }
    });

    test("consolidates a proof-authenticated subject transactionally and revokes sessions and provider tokens", async () => {
      const survivorWallet = privateKeyToAccount(
        "0x5555555555555555555555555555555555555555555555555555555555555555",
      );
      const sourceWallet = privateKeyToAccount(
        "0x6666666666666666666666666666666666666666666666666666666666666666",
      );
      const survivor = await signInHostedWallet(app, config, survivorWallet);
      const source = await signInHostedWallet(app, config, sourceWallet);
      const sourceEmail = "source-merge@example.com";
      await database.db
        .update(user)
        .set({ email: sourceEmail, emailVerified: true, updatedAt: new Date() })
        .where(eq(user.id, source.userId));
      await database.db.insert(account).values({
        accountId: "github-source-merge",
        accessToken: "source-access-token",
        accessTokenExpiresAt: new Date("2026-08-08T00:00:00.000Z"),
        id: crypto.randomUUID(),
        idToken: "source-id-token",
        providerId: "github",
        refreshToken: "source-refresh-token",
        refreshTokenExpiresAt: new Date("2026-09-08T00:00:00.000Z"),
        userId: source.userId,
      });
      const sourceAuthorization = await authorizeCode({
        app,
        identityCookie: source.cookie,
        resource: "https://api.pledge.test",
      });
      const sourceTokenResponse = await exchangeAuthorizationCode({
        app,
        code: sourceAuthorization.code,
        codeVerifier: sourceAuthorization.codeVerifier,
        oidcSecret,
        resource: "https://api.pledge.test",
      });
      expect(sourceTokenResponse.status).toBe(200);
      const sourceToken = (await sourceTokenResponse.json()) as {
        access_token: string;
      };
      const proof = await signInHostedWallet(
        app,
        config,
        sourceWallet,
        "/api/proof-auth",
        "peezy-proof.session_token",
      );
      const cookies = `${survivor.cookie}; ${proof.cookie}`;
      const previewResponse = await app.request(
        "https://identity.test/v1/account-merges/proofs",
        {
          headers: { Cookie: cookies, Origin: config.baseUrl },
          method: "POST",
        },
      );
      expect(previewResponse.status).toBe(201);
      const preview = (await previewResponse.json()) as { attemptId: string };
      expect(
        await database.db
          .select({ status: identitySubjectMerge.status })
          .from(identitySubjectMerge)
          .where(eq(identitySubjectMerge.id, preview.attemptId)),
      ).toEqual([{ status: "prepared" }]);
      const commitResponse = await app.request(
        "https://identity.test/v1/account-merges/commit",
        {
          body: JSON.stringify({ attemptId: preview.attemptId }),
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(commitResponse.status).toBe(200);
      expect(await commitResponse.json()).toEqual({ merged: true });
      expect(
        await database.db
          .select({ status: identitySubjectMerge.status })
          .from(identitySubjectMerge)
          .where(eq(identitySubjectMerge.id, preview.attemptId)),
      ).toEqual([{ status: "committed" }]);
      const [sourceRow] = await database.db
        .select({ status: user.status })
        .from(user)
        .where(eq(user.id, source.userId));
      expect(sourceRow?.status).toBe("merged");
      const [sourceEmailRow] = await database.db
        .select({ email: user.email })
        .from(user)
        .where(eq(user.id, source.userId));
      expect(sourceEmailRow?.email).toMatch(/\.invalid$/);
      const [mergedAccount] = await database.db
        .select({
          accessToken: account.accessToken,
          accessTokenExpiresAt: account.accessTokenExpiresAt,
          idToken: account.idToken,
          refreshToken: account.refreshToken,
          refreshTokenExpiresAt: account.refreshTokenExpiresAt,
        })
        .from(account)
        .where(eq(account.accountId, "github-source-merge"));
      expect(mergedAccount).toEqual({
        accessToken: null,
        accessTokenExpiresAt: null,
        idToken: null,
        refreshToken: null,
        refreshTokenExpiresAt: null,
      });
      expect(
        await database.db
          .select()
          .from(session)
          .where(eq(session.userId, survivor.userId)),
      ).toHaveLength(0);
      expect(
        await database.db
          .select()
          .from(session)
          .where(eq(session.userId, source.userId)),
      ).toHaveLength(0);
      const sourceIntrospection = await app.request(
        "https://identity.test/api/auth/oauth2/introspect",
        {
          body: new URLSearchParams({
            token: sourceToken.access_token,
            token_type_hint: "access_token",
          }),
          headers: {
            Authorization: basic("pledge-cash", oidcSecret),
            "Content-Type": "application/x-www-form-urlencoded",
          },
          method: "POST",
        },
      );
      expect(sourceIntrospection.status).toBe(200);
      expect(await sourceIntrospection.json()).toMatchObject({
        active: false,
      });
      expect(
        (await identityMe(database.db, survivor.userId)).credentials,
      ).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            address: sourceWallet.address.toLowerCase(),
            kind: "wallet",
          }),
          expect.objectContaining({
            kind: "email",
            value: sourceEmail,
            verified: true,
          }),
          expect.objectContaining({ kind: "social", provider: "github" }),
        ]),
      );
    });

    test("requires a recent proof-auth session before preparing consolidation", async () => {
      const survivor = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0x1717171717171717171717171717171717171717171717171717171717171717",
        ),
      );
      const source = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0x1818181818181818181818181818181818181818181818181818181818181818",
        ),
      );
      const proof = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0x1818181818181818181818181818181818181818181818181818181818181818",
        ),
        "/api/proof-auth",
        "peezy-proof.session_token",
      );
      await database.db
        .update(session)
        .set({ createdAt: new Date(Date.now() - 11 * 60_000) })
        .where(eq(session.userId, source.userId));

      const response = await app.request(
        "https://identity.test/v1/account-merges/proofs",
        {
          headers: {
            Cookie: `${survivor.cookie}; ${proof.cookie}`,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        error: { code: "reauth_required" },
      });
    });

    test("keeps a claimed parent while a wallet identity independently transitions to linked", async () => {
      const survivorWallet = privateKeyToAccount(
        "0x9999999999999999999999999999999999999999999999999999999999999999",
      );
      const survivor = await signInHostedWallet(app, config, survivorWallet);
      await database.db.insert(walletPrincipal).values({
        accountKind: "smart-account",
        address: migratingWallet.address,
        chainId: 1,
        family: "evm",
        id: crypto.randomUUID(),
        signInEnabled: true,
        userId: survivor.userId,
      });
      const accountResponse = await app.request(
        "https://identity.test/account",
        { headers: { Cookie: survivor.cookie } },
      );
      expect(accountResponse.status).toBe(200);
      expect(accountResponse.headers.get("content-security-policy")).toContain(
        "https://rpc.walletconnect.org",
      );
      const attemptResponse = await app.request(
        "https://identity.test/v1/migrations/privy/attempts",
        {
          headers: { Cookie: survivor.cookie, Origin: config.baseUrl },
          method: "POST",
        },
      );
      const attempt = (await attemptResponse.json()) as {
        attemptId: string;
        csrfToken: string;
      };
      const claimResponse = await app.request(
        "https://identity.test/v1/migrations/privy/claims",
        {
          body: JSON.stringify(attempt),
          headers: {
            Authorization: "Bearer wallet-bundle-token",
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(claimResponse.status).toBe(201);
      expect(await claimResponse.json()).toMatchObject({
        identities: [{ disposition: "needs_reverification" }],
      });

      const challengeResponse = await app.request(
        "https://identity.test/v1/account/wallet/challenges",
        {
          body: JSON.stringify({
            address: migratingWallet.address,
            chainId: 999,
          }),
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(challengeResponse.status).toBe(201);
      const challenge = (await challengeResponse.json()) as {
        challengeId: string;
        message: string;
      };
      const verifyResponse = await app.request(
        "https://identity.test/v1/account/wallet/verify",
        {
          body: JSON.stringify({
            ...challenge,
            signature: await migratingWallet.signMessage({
              message: challenge.message,
            }),
          }),
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(verifyResponse.status).toBe(200);
      const crossOriginClaimsResponse = await app.request(
        "https://identity.test/v1/migrations/privy/claims/current",
        {
          headers: {
            Cookie: survivor.cookie,
            Origin: "https://evil.test",
          },
        },
      );
      expect(crossOriginClaimsResponse.status).toBe(403);
      const [pendingWalletIdentity] = await database.db
        .select({ disposition: privyMigrationIdentity.disposition })
        .from(privyMigrationIdentity)
        .where(
          eq(
            privyMigrationIdentity.walletAddress,
            migratingWallet.address.toLowerCase(),
          ),
        )
        .limit(1);
      expect(pendingWalletIdentity?.disposition).toBe("needs_reverification");
      const claimsResponse = await app.request(
        "https://identity.test/v1/migrations/privy/claims/current",
        {
          headers: {
            Cookie: survivor.cookie,
            "Sec-Fetch-Site": "same-origin",
          },
        },
      );
      expect(await claimsResponse.json()).toMatchObject({
        claims: [
          {
            identities: [{ disposition: "linked" }],
            privyUserId: "did:privy:legacy-wallet-person",
          },
        ],
      });
      expect(
        await database.db
          .select()
          .from(privyMigrationClaim)
          .where(
            eq(
              privyMigrationClaim.privyUserId,
              "did:privy:legacy-wallet-person",
            ),
          ),
      ).toHaveLength(1);
    });

    test("links a claimed Privy Solana identity with a fresh SIWS proof", async () => {
      const survivor = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0x1212121212121212121212121212121212121212121212121212121212121212",
        ),
      );
      const attemptResponse = await app.request(
        "https://identity.test/v1/migrations/privy/attempts",
        {
          headers: { Cookie: survivor.cookie, Origin: config.baseUrl },
          method: "POST",
        },
      );
      const attempt = (await attemptResponse.json()) as {
        attemptId: string;
        csrfToken: string;
      };
      const claimResponse = await app.request(
        "https://identity.test/v1/migrations/privy/claims",
        {
          body: JSON.stringify(attempt),
          headers: {
            Authorization: "Bearer solana-wallet-bundle-token",
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(claimResponse.status).toBe(201);
      expect(await claimResponse.json()).toMatchObject({
        identities: [
          {
            chainType: "solana",
            disposition: "needs_reverification",
            walletAddress: migratingSolanaWallet.address,
          },
        ],
      });

      const challengeResponse = await app.request(
        "https://identity.test/v1/account/wallet/challenges",
        {
          body: JSON.stringify({
            address: migratingSolanaWallet.address,
            family: "solana",
          }),
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(challengeResponse.status).toBe(201);
      const challenge = (await challengeResponse.json()) as {
        challengeId: string;
        message: string;
      };
      const proofBody = JSON.stringify({
        ...challenge,
        signature: migratingSolanaWallet.sign(challenge.message),
      });
      const verifyResponse = await app.request(
        "https://identity.test/v1/account/wallet/verify",
        {
          body: proofBody,
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(verifyResponse.status).toBe(200);
      const replayResponse = await app.request(
        "https://identity.test/v1/account/wallet/verify",
        {
          body: proofBody,
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(replayResponse.status).toBe(403);
      expect(
        (await identityMe(database.db, survivor.userId)).credentials,
      ).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            address: migratingSolanaWallet.address,
            family: "solana",
            kind: "wallet",
          }),
        ]),
      );
      const claimsResponse = await app.request(
        "https://identity.test/v1/migrations/privy/claims/current",
        { headers: { Cookie: survivor.cookie, Origin: config.baseUrl } },
      );
      expect(await claimsResponse.json()).toMatchObject({
        claims: [{ identities: [{ disposition: "linked" }] }],
      });
    });

    test("invalidates and throttles failed account wallet proofs", async () => {
      const wallet = privateKeyToAccount(
        "0x1414141414141414141414141414141414141414141414141414141414141414",
      );
      const signedIn = await signInHostedWallet(app, config, wallet);
      const challengeResponse = await app.request(
        "https://identity.test/v1/account/wallet/challenges",
        {
          body: JSON.stringify({ address: wallet.address, chainId: 999 }),
          headers: {
            "Content-Type": "application/json",
            Cookie: signedIn.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(challengeResponse.status).toBe(201);
      const challenge = (await challengeResponse.json()) as {
        challengeId: string;
        message: string;
      };
      const verify = (signature: string) =>
        app.request("https://identity.test/v1/account/wallet/verify", {
          body: JSON.stringify({ ...challenge, signature }),
          headers: {
            "Content-Type": "application/json",
            Cookie: signedIn.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        });

      expect((await verify("0x00")).status).toBe(401);
      const [failedChallenge] = await database.db
        .select({ usedAt: accountWalletLinkChallenge.usedAt })
        .from(accountWalletLinkChallenge)
        .where(eq(accountWalletLinkChallenge.id, challenge.challengeId));
      expect(failedChallenge?.usedAt).toBeInstanceOf(Date);
      expect(
        (await verify(await wallet.signMessage({ message: challenge.message })))
          .status,
      ).toBe(403);

      const rateLimitKey = `identity-v1:account-wallet-verify:${signedIn.userId}`;
      await database.db
        .insert(rateLimit)
        .values({ count: 10, key: rateLimitKey, lastRequest: Date.now() })
        .onConflictDoUpdate({
          set: { count: 10, lastRequest: Date.now() },
          target: rateLimit.key,
        });
      expect((await verify("0x00")).status).toBe(429);
      await database.db
        .delete(rateLimit)
        .where(eq(rateLimit.key, rateLimitKey));
    });

    test("uses SIWS as an isolated proof and consolidates its Solana subject", async () => {
      const survivor = await signInHostedWallet(
        app,
        config,
        privateKeyToAccount(
          "0x1313131313131313131313131313131313131313131313131313131313131313",
        ),
      );
      const sourceWallet = createSolanaWallet();
      const source = await signInSolanaWallet(app, config, sourceWallet);
      const proof = await signInSolanaWallet(
        app,
        config,
        sourceWallet,
        "/api/proof-auth",
        "peezy-proof.session_token",
      );
      const previewResponse = await app.request(
        "https://identity.test/v1/account-merges/proofs",
        {
          headers: {
            Cookie: `${survivor.cookie}; ${proof.cookie}`,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(previewResponse.status).toBe(201);
      const preview = (await previewResponse.json()) as { attemptId: string };
      const commitResponse = await app.request(
        "https://identity.test/v1/account-merges/commit",
        {
          body: JSON.stringify({ attemptId: preview.attemptId }),
          headers: {
            "Content-Type": "application/json",
            Cookie: survivor.cookie,
            Origin: config.baseUrl,
          },
          method: "POST",
        },
      );
      expect(commitResponse.status).toBe(200);
      expect(
        await database.db
          .select({ userId: walletPrincipal.userId })
          .from(walletPrincipal)
          .where(eq(walletPrincipal.address, sourceWallet.address)),
      ).toEqual([{ userId: survivor.userId }]);
      expect(
        await database.db
          .select({ status: user.status })
          .from(user)
          .where(eq(user.id, source.userId)),
      ).toEqual([{ status: "merged" }]);
    });

    test("creates one hosted wallet identity and refuses it after disablement", async () => {
      const chainId = 999;
      const nonceResponse = await app.request(
        "https://identity.test/api/auth/siwe/nonce",
        {
          body: JSON.stringify({
            chainId,
            walletAddress: hostedWallet.address,
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      expect(nonceResponse.status).toBe(200);
      const { nonce } = (await nonceResponse.json()) as { nonce: string };
      const now = new Date();
      const message = createSiweMessage({
        address: hostedWallet.address,
        chainId,
        domain: "identity.test",
        expirationTime: new Date(now.getTime() + 10 * 60 * 1_000),
        issuedAt: now,
        nonce,
        statement: HOSTED_WALLET_STATEMENT,
        uri: config.baseUrl,
        version: "1",
      });
      const signature = await hostedWallet.signMessage({ message });
      const verifyResponse = await app.request(
        "https://identity.test/api/auth/siwe/verify",
        {
          body: JSON.stringify({
            chainId,
            message,
            signature,
            walletAddress: hostedWallet.address,
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      expect(verifyResponse.status).toBe(200);
      expect(verifyResponse.headers.get("set-cookie")).toContain(
        "peezy-identity.session_token",
      );
      expect(verifyResponse.headers.get("set-cookie")).toContain(
        "SameSite=None",
      );
      expect(verifyResponse.headers.get("set-cookie")).toContain("Secure");
      const identityCookie = responseCookie(
        verifyResponse,
        "peezy-identity.session_token",
      );
      const verified = (await verifyResponse.json()) as {
        user: { id: string };
      };
      const hostedIdentity = await identityMe(database.db, verified.user.id);
      expect(hostedIdentity.credentials).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            address: hostedWallet.address.toLowerCase(),
            kind: "wallet",
          }),
        ]),
      );

      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId,
            clientId: "pledge-cash",
            walletAddress: hostedWallet.address,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        },
      );
      const challenge = WalletChallengeResponseSchema.parse(
        await challengeResponse.json(),
      );
      const appSignature = await hostedWallet.signMessage({
        message: challenge.message,
      });
      const grantResponse = await app.request(
        "https://identity.test/v1/wallet/grants/issue",
        {
          body: JSON.stringify({
            clientId: "pledge-cash",
            message: challenge.message,
            signature: appSignature,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        },
      );
      expect(grantResponse.status).toBe(201);
      const grant = WalletGrantResponseSchema.parse(await grantResponse.json());
      expect(grant.user.id).toBe(verified.user.id);

      const authorizedResource = "https://api.pledge.test";
      const otherResource = "https://admin.pledge.test";
      const successfulAuthorization = await authorizeCode({
        app,
        identityCookie,
        resource: authorizedResource,
      });
      const successfulToken = await exchangeAuthorizationCode({
        app,
        code: successfulAuthorization.code,
        codeVerifier: successfulAuthorization.codeVerifier,
        oidcSecret,
        resource: authorizedResource,
      });
      expect(successfulToken.status).toBe(200);
      const tokenBody = (await successfulToken.json()) as {
        access_token: string;
        refresh_token: string;
      };
      const audience = decodeJwt(tokenBody.access_token).aud;
      expect(Array.isArray(audience) ? audience : [audience]).toContain(
        authorizedResource,
      );

      const narrowedAuthorization = await authorizeCode({
        app,
        identityCookie,
        resource: authorizedResource,
      });
      const widenedToken = await exchangeAuthorizationCode({
        app,
        code: narrowedAuthorization.code,
        codeVerifier: narrowedAuthorization.codeVerifier,
        oidcSecret,
        resource: otherResource,
      });
      expect(widenedToken.status).toBe(400);
      expect(await widenedToken.json()).toMatchObject({
        error: "invalid_target",
      });

      await database.db
        .update(user)
        .set({ status: "disabled" })
        .where(eq(user.id, verified.user.id));
      const disabledSessionResponse = await app.request(
        "https://identity.test/api/auth/get-session",
        {
          headers: { Cookie: identityCookie },
        },
      );
      expect(disabledSessionResponse.status).toBe(200);
      expect(await disabledSessionResponse.json()).toBeNull();
      const disabledRefreshResponse = await refreshAccessToken({
        app,
        oidcSecret,
        refreshToken: tokenBody.refresh_token,
      });
      expect(disabledRefreshResponse.status).toBe(400);
      expect(await disabledRefreshResponse.json()).toMatchObject({
        error: "invalid_request",
      });

      const disabledNonceResponse = await app.request(
        "https://identity.test/api/auth/siwe/nonce",
        {
          body: JSON.stringify({
            chainId,
            walletAddress: hostedWallet.address,
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      const disabledNonce = (await disabledNonceResponse.json()) as {
        nonce: string;
      };
      const disabledMessage = createSiweMessage({
        address: hostedWallet.address,
        chainId,
        domain: "identity.test",
        expirationTime: new Date(Date.now() + 10 * 60 * 1_000),
        issuedAt: new Date(),
        nonce: disabledNonce.nonce,
        statement: HOSTED_WALLET_STATEMENT,
        uri: config.baseUrl,
        version: "1",
      });
      const disabledResponse = await app.request(
        "https://identity.test/api/auth/siwe/verify",
        {
          body: JSON.stringify({
            chainId,
            message: disabledMessage,
            signature: await hostedWallet.signMessage({
              message: disabledMessage,
            }),
            walletAddress: hostedWallet.address,
          }),
          headers: { "Content-Type": "application/json" },
          method: "POST",
        },
      );
      expect(disabledResponse.status).toBe(401);
    });

    test("partitions wallet challenge limits after client and origin validation", async () => {
      const rateLimitedWallet = privateKeyToAccount(
        "0x1111111111111111111111111111111111111111111111111111111111111111",
      );
      const limitedIp = "198.51.100.10";
      const otherIp = "198.51.100.11";
      const [beforeInvalidRequest] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "rate_limit"
        WHERE "key" LIKE 'identity-v1:wallet-challenge:%'
      `;
      const invalidRequest = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "attacker-selected-client",
            walletAddress: rateLimitedWallet.address,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: "https://attacker.invalid",
          },
          method: "POST",
        },
        bunServer(limitedIp),
      );
      const [afterInvalidRequest] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "rate_limit"
        WHERE "key" LIKE 'identity-v1:wallet-challenge:%'
      `;
      expect(invalidRequest.status).toBe(404);
      expect(afterInvalidRequest?.count).toBe(beforeInvalidRequest?.count);

      const key = `identity-v1:wallet-challenge:pledge-cash:${origin}:${limitedIp}:${rateLimitedWallet.address.toLowerCase()}`;
      await database.db
        .insert(rateLimit)
        .values({
          count: 20,
          key,
          lastRequest: Date.now(),
        })
        .onConflictDoUpdate({
          set: { count: 20, lastRequest: Date.now() },
          target: rateLimit.key,
        });

      const requestChallenge = (walletAddress: string, clientIp: string) =>
        app.request(
          "https://identity.test/v1/wallet/challenges",
          {
            body: JSON.stringify({
              chainId: 999,
              clientId: "pledge-cash",
              walletAddress,
            }),
            headers: {
              "Content-Type": "application/json",
              Origin: origin,
            },
            method: "POST",
          },
          bunServer(clientIp),
        );

      const limitedResponse = await requestChallenge(
        rateLimitedWallet.address,
        limitedIp,
      );
      const rotatedAddressResponse = await requestChallenge(
        hostedWallet.address,
        limitedIp,
      );
      const rotatedIpResponse = await requestChallenge(
        rateLimitedWallet.address,
        otherIp,
      );
      await database.db.delete(rateLimit).where(eq(rateLimit.key, key));
      expect(limitedResponse.status).toBe(429);
      expect(rotatedAddressResponse.status).toBe(201);
      expect(rotatedIpResponse.status).toBe(201);
    });

    test("removes expired rate-limit keys while consuming a new key", async () => {
      const prefix = `rate-limit-cleanup:${randomBytes(8).toString("hex")}`;
      const now = Date.now();
      await database.db.insert(rateLimit).values([
        {
          count: 1,
          key: `identity-v1:${prefix}:stale-a`,
          lastRequest: now - MAX_RATE_LIMIT_WINDOW_MS - 1,
        },
        {
          count: 1,
          key: `identity-v1:${prefix}:stale-b`,
          lastRequest: now - MAX_RATE_LIMIT_WINDOW_MS - 1,
        },
      ]);

      expect(
        await consumeRateLimit({
          db: database.db,
          key: `${prefix}:fresh`,
          limit: 1,
          now,
          windowMs: MAX_RATE_LIMIT_WINDOW_MS,
        }),
      ).toBe(true);

      const [remaining] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "rate_limit"
        WHERE "key" LIKE ${`identity-v1:${prefix}:%`}
          AND "last_request" < ${now - MAX_RATE_LIMIT_WINDOW_MS}
      `;
      expect(remaining?.count).toBe("0");
    });

    test("rate limits wallet grants only after challenge validation", async () => {
      const grantWallet = privateKeyToAccount(
        "0x4444444444444444444444444444444444444444444444444444444444444444",
      );
      const limitedIp = "198.51.100.20";
      const otherIp = "198.51.100.21";
      const [beforeInvalidRequest] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "rate_limit"
        WHERE "key" LIKE 'identity-v1:wallet-grant:%'
      `;
      const invalidRequest = await app.request(
        "https://identity.test/v1/wallet/grants",
        {
          body: JSON.stringify({
            clientId: "attacker-selected-client",
            message: "not a SIWE message",
            signature: `0x${"00".repeat(65)}`,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: "https://attacker.invalid",
          },
          method: "POST",
        },
        bunServer(limitedIp),
      );
      const [afterInvalidRequest] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "rate_limit"
        WHERE "key" LIKE 'identity-v1:wallet-grant:%'
      `;
      expect(invalidRequest.status).toBe(400);
      expect(afterInvalidRequest?.count).toBe(beforeInvalidRequest?.count);

      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "pledge-cash",
            walletAddress: grantWallet.address,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        },
        bunServer(limitedIp),
      );
      const challenge = WalletChallengeResponseSchema.parse(
        await challengeResponse.json(),
      );
      const key = `identity-v1:wallet-grant:pledge-cash:${origin}:${limitedIp}:${grantWallet.address.toLowerCase()}`;
      await database.db
        .insert(rateLimit)
        .values({
          count: 30,
          key,
          lastRequest: Date.now(),
        })
        .onConflictDoUpdate({
          set: { count: 30, lastRequest: Date.now() },
          target: rateLimit.key,
        });

      const grantBody = JSON.stringify({
        clientId: "pledge-cash",
        message: challenge.message,
        signature: await grantWallet.signMessage({
          message: challenge.message,
        }),
      });
      const requestGrant = (clientIp: string) =>
        app.request(
          "https://identity.test/v1/wallet/grants",
          {
            body: grantBody,
            headers: {
              "Content-Type": "application/json",
              Origin: origin,
            },
            method: "POST",
          },
          bunServer(clientIp),
        );

      expect((await requestGrant(limitedIp)).status).toBe(429);
      expect((await requestGrant(otherIp)).status).toBe(201);
      await database.db.delete(rateLimit).where(eq(rateLimit.key, key));
    });

    test("rejects malformed wallet signatures without consuming the challenge", async () => {
      const malformedSignatureWallet = privateKeyToAccount(
        "0x5555555555555555555555555555555555555555555555555555555555555555",
      );
      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "pledge-cash",
            walletAddress: malformedSignatureWallet.address,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        },
      );
      const challenge = WalletChallengeResponseSchema.parse(
        await challengeResponse.json(),
      );
      const requestGrant = (signature: string) =>
        app.request("https://identity.test/v1/wallet/grants", {
          body: JSON.stringify({
            clientId: "pledge-cash",
            message: challenge.message,
            signature,
          }),
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        });

      expect((await requestGrant("0x00")).status).toBe(401);
      expect(
        (
          await requestGrant(
            await malformedSignatureWallet.signMessage({
              message: challenge.message,
            }),
          )
        ).status,
      ).toBe(201);
    });

    test("links a wallet, exchanges its one-time grant, and preserves one global owner", async () => {
      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "pledge-cash",
            purpose: "link",
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
      expect(challenge.statement).toBe("Link this wallet to PledgeCash.");
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

      await database.sql`
        UPDATE "wallet_principal"
        SET "sign_in_enabled" = false
        WHERE lower("address") = ${wallet.address.toLowerCase()}
      `;
      const disabledChallengeResponse = await app.request(
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
      const disabledChallenge = WalletChallengeResponseSchema.parse(
        await disabledChallengeResponse.json(),
      );
      const disabledIssueResponse = await app.request(
        "https://identity.test/v1/wallet/grants/issue",
        {
          body: JSON.stringify({
            clientId: "pledge-cash",
            message: disabledChallenge.message,
            signature: await wallet.signMessage({
              message: disabledChallenge.message,
            }),
            subject,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        },
      );
      expect(disabledIssueResponse.status).toBe(403);
    });

    test("serializes wallet grant issuance with account consolidation challenge revocation", async () => {
      const sourceSubject = crypto.randomUUID();
      const targetSubject = crypto.randomUUID();
      const attemptId = crypto.randomUUID();
      const principalId = crypto.randomUUID();
      const raceWallet = privateKeyToAccount(
        "0x1515151515151515151515151515151515151515151515151515151515151515",
      );
      const now = new Date("2026-08-07T00:00:00.000Z");
      await database.db.insert(user).values([
        {
          createdAt: now,
          email: `${sourceSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: sourceSubject,
          name: "Grant Merge Source",
          status: "active",
          updatedAt: now,
        },
        {
          createdAt: now,
          email: `${targetSubject}@identity.peezy.tech.invalid`,
          emailVerified: false,
          id: targetSubject,
          name: "Grant Merge Target",
          status: "active",
          updatedAt: now,
        },
      ]);
      await database.db.insert(walletPrincipal).values({
        accountKind: "eoa",
        address: raceWallet.address,
        createdAt: now,
        family: "evm",
        id: principalId,
        signInEnabled: true,
        updatedAt: now,
        userId: sourceSubject,
      });
      await database.db.insert(identitySubjectMerge).values({
        actorUserId: targetSubject,
        expiresAt: new Date(Date.now() + 60_000),
        id: attemptId,
        metadata: {},
        sourceUserId: sourceSubject,
        status: "prepared",
        targetUserId: targetSubject,
      });
      const challengeResponse = await app.request(
        "https://identity.test/v1/wallet/challenges",
        {
          body: JSON.stringify({
            chainId: 999,
            clientId: "pledge-cash",
            purpose: "link",
            walletAddress: raceWallet.address,
          }),
          headers: { "Content-Type": "application/json", Origin: origin },
          method: "POST",
        },
      );
      expect(challengeResponse.status).toBe(201);
      const challenge = WalletChallengeResponseSchema.parse(
        await challengeResponse.json(),
      );
      const signature = await raceWallet.signMessage({
        message: challenge.message,
      });

      await database.sql`
        CREATE FUNCTION test_delay_wallet_principal_update()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          PERFORM pg_sleep(0.5);
          RETURN NEW;
        END
        $$
      `;
      await database.sql`
        CREATE TRIGGER test_delay_wallet_principal_update
        BEFORE UPDATE ON wallet_principal
        FOR EACH ROW
        EXECUTE FUNCTION test_delay_wallet_principal_update()
      `;
      try {
        const mergePromise = commitAccountMerge({
          attemptId,
          db: database.db,
          targetUserId: targetSubject,
        });
        let issuePromise: ReturnType<typeof createWalletGrant> | undefined;
        let synchronizationFailure: unknown;
        try {
          const mergePid = await waitForDatabaseWaitEvent({
            event: "PgSleep",
            sqlClient: database.sql,
          });
          issuePromise = createWalletGrant({
            clientId: "pledge-cash",
            db: database.db,
            message: challenge.message,
            sessionSubject: sourceSubject,
            signature,
          });
          await waitForBlockedBackend({
            blockerPid: mergePid,
            sqlClient: database.sql,
          });
        } catch (error) {
          synchronizationFailure = error;
        }
        if (synchronizationFailure !== undefined) {
          await Promise.allSettled([
            mergePromise,
            ...(issuePromise === undefined ? [] : [issuePromise]),
          ]);
          throw synchronizationFailure;
        }
        if (issuePromise === undefined) {
          throw new Error("Wallet grant issuance was not started");
        }

        await expect(mergePromise).resolves.toEqual({ merged: true });
        await expect(issuePromise).rejects.toMatchObject({
          message: "Identity account is unavailable",
          status: 403,
        });
        expect(
          await database.db
            .select({ id: walletPrincipal.id, userId: walletPrincipal.userId })
            .from(walletPrincipal)
            .where(eq(walletPrincipal.id, principalId)),
        ).toEqual([{ id: principalId, userId: targetSubject }]);
        expect(
          await database.db
            .select({ nonce: walletChallenge.nonce })
            .from(walletChallenge)
            .where(eq(walletChallenge.nonce, challenge.nonce)),
        ).toHaveLength(0);
        expect(
          await database.db
            .select({ id: walletGrant.id })
            .from(walletGrant)
            .where(eq(walletGrant.userId, sourceSubject)),
        ).toHaveLength(0);
        expect(
          await database.db
            .select({ status: user.status })
            .from(user)
            .where(eq(user.id, sourceSubject)),
        ).toEqual([{ status: "merged" }]);
      } finally {
        await database.sql`
          DROP TRIGGER IF EXISTS test_delay_wallet_principal_update
          ON wallet_principal
        `;
        await database.sql`
          DROP FUNCTION IF EXISTS test_delay_wallet_principal_update()
        `;
      }
    });

    test("refuses to exchange a grant after its subject is disabled", async () => {
      const disabledSubject = crypto.randomUUID();
      const disabledWallet = privateKeyToAccount(
        "0x1616161616161616161616161616161616161616161616161616161616161616",
      );
      const now = new Date("2026-08-07T00:01:00.000Z");
      await database.db.insert(user).values({
        createdAt: now,
        email: "disabled-grant@example.com",
        emailVerified: true,
        id: disabledSubject,
        name: "Disabled Grant",
        status: "active",
        updatedAt: now,
      });
      const issueResponse = await issueWalletLinkGrant({
        app,
        appSecret,
        origin,
        subject: disabledSubject,
        wallet: disabledWallet,
      });
      expect(issueResponse.status).toBe(201);
      const issued = WalletGrantResponseSchema.parse(
        await issueResponse.json(),
      );

      await database.db
        .update(user)
        .set({ status: "disabled", updatedAt: new Date() })
        .where(eq(user.id, disabledSubject));
      const exchangeResponse = await app.request(
        "https://identity.test/v1/wallet/grants/exchange",
        {
          body: JSON.stringify({
            clientId: "pledge-cash",
            grant: issued.grant,
          }),
          headers: {
            Authorization: basic("pledge-cash", appSecret),
            "Content-Type": "application/json",
          },
          method: "POST",
        },
      );
      expect(exchangeResponse.status).toBe(401);
      expect(await exchangeResponse.json()).toMatchObject({
        error: { message: "Wallet grant is invalid or expired" },
      });
      expect(
        await database.db
          .select({ consumedAt: walletGrant.consumedAt })
          .from(walletGrant)
          .where(eq(walletGrant.userId, disabledSubject)),
      ).toEqual([{ consumedAt: null }]);
    });

    test("keeps ambient sign-in separate and requires an explicit authenticated link", async () => {
      const ambientSignInWallet = privateKeyToAccount(
        "0x2222222222222222222222222222222222222222222222222222222222222222",
      );
      const explicitLinkWallet = privateKeyToAccount(
        "0x3333333333333333333333333333333333333333333333333333333333333333",
      );
      const handoffResponse = await app.request(
        "https://identity.test/v1/social-link-handoffs",
        {
          body: JSON.stringify({
            callbackUrl: `${origin}/settings/wallets`,
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
      const handoff = (await handoffResponse.json()) as { url: string };
      const sessionResponse = await app.request(handoff.url);
      const identityCookie = responseCookie(
        sessionResponse,
        "peezy-identity.session_token",
      );

      const challenge = async (
        purpose: "link" | "sign-in",
        address: string,
      ) => {
        const response = await app.request(
          "https://identity.test/v1/wallet/challenges",
          {
            body: JSON.stringify({
              chainId: 999,
              clientId: "pledge-cash",
              purpose,
              walletAddress: address,
            }),
            headers: {
              "Content-Type": "application/json",
              Origin: origin,
            },
            method: "POST",
          },
        );
        expect(response.status).toBe(201);
        return WalletChallengeResponseSchema.parse(await response.json());
      };
      const grant = async (
        walletChallenge: Awaited<ReturnType<typeof challenge>>,
        signer: typeof ambientSignInWallet,
        cookie?: string,
      ) =>
        await app.request("https://identity.test/v1/wallet/grants", {
          body: JSON.stringify({
            clientId: "pledge-cash",
            message: walletChallenge.message,
            signature: await signer.signMessage({
              message: walletChallenge.message,
            }),
          }),
          headers: {
            ...(cookie === undefined ? {} : { Cookie: cookie }),
            "Content-Type": "application/json",
            Origin: origin,
          },
          method: "POST",
        });

      const signInChallenge = await challenge(
        "sign-in",
        ambientSignInWallet.address,
      );
      expect(signInChallenge.statement).toBe("Sign in to PledgeCash.");
      const signInResponse = await grant(
        signInChallenge,
        ambientSignInWallet,
        identityCookie,
      );
      expect(signInResponse.status).toBe(201);
      const signedIn = WalletGrantResponseSchema.parse(
        await signInResponse.json(),
      );
      expect(signedIn.user.id).not.toBe(subject);
      expect(
        (await identityMe(database.db, subject)).credentials.some(
          (credential) =>
            credential.kind === "wallet" &&
            credential.address === ambientSignInWallet.address.toLowerCase(),
        ),
      ).toBe(false);

      await database.sql`
        UPDATE "wallet_principal"
        SET "sign_in_enabled" = false
        WHERE lower("address") = ${ambientSignInWallet.address.toLowerCase()}
      `;
      const disabledSignInChallenge = await challenge(
        "sign-in",
        ambientSignInWallet.address,
      );
      expect(
        (
          await grant(
            disabledSignInChallenge,
            ambientSignInWallet,
            identityCookie,
          )
        ).status,
      ).toBe(403);

      const linkChallenge = await challenge("link", explicitLinkWallet.address);
      expect(linkChallenge.statement).toBe("Link this wallet to PledgeCash.");
      const unauthenticatedLink = await grant(
        linkChallenge,
        explicitLinkWallet,
      );
      expect(unauthenticatedLink.status).toBe(401);
      const linkedResponse = await grant(
        linkChallenge,
        explicitLinkWallet,
        identityCookie,
      );
      expect(linkedResponse.status).toBe(201);
      expect(
        WalletGrantResponseSchema.parse(await linkedResponse.json()).user.id,
      ).toBe(subject);
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
      const handoffToken = new URL(handoff.url).searchParams.get("token");
      if (handoffToken === null)
        throw new Error("Missing session handoff token");
      await expect(
        consumeSessionHandoff({
          createSession: async () => {
            throw new Error("transient session creation failure");
          },
          db: database.db,
          deleteSession: async () => undefined,
          token: handoffToken,
        }),
      ).rejects.toThrow("transient session creation failure");
      await expect(
        consumeSessionHandoff({
          createSession: async () => null,
          db: database.db,
          deleteSession: async () => undefined,
          token: handoffToken,
        }),
      ).rejects.toMatchObject({ status: "INTERNAL_SERVER_ERROR" });
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

    test("rejects a same-database migration and rolls back failed verification", async () => {
      await expect(assertTargetSchema(database.sql)).resolves.toBeUndefined();

      await expect(
        assertDistinctDatabases(database.sql, database.sql),
      ).rejects.toThrow(
        "PLEDGE_DATABASE_URL and DATABASE_URL resolve to the same database",
      );

      const now = new Date("2026-07-29T00:00:00.000Z");
      await expect(
        importIdentity(database.sql, {
          accounts: [
            {
              accountId: "must-roll-back",
              createdAt: now,
              id: "c18e4079-7448-40df-b4bc-a8527dd66424",
              providerId: "discord",
              updatedAt: now,
              userId: subject,
            },
          ],
          users: [
            {
              createdAt: now,
              email: "conflicting@example.com",
              emailVerified: true,
              id: subject,
              image: null,
              name: "Conflicting User",
              updatedAt: now,
            },
          ],
          walletOwners: [],
          wallets: [],
        }),
      ).rejects.toThrow(
        "PledgeCash identity import failed during verification",
      );

      const [accountCount] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "account"
        WHERE "id" = 'c18e4079-7448-40df-b4bc-a8527dd66424'
      `;
      const [auditCount] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "identity_audit_event"
        WHERE "kind" = 'migration.pledge-cash-imported'
      `;
      expect(accountCount?.count).toBe("0");
      expect(auditCount?.count).toBe("0");
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

    test("disables config-managed clients removed from deployment config", async () => {
      await seedConfiguredClients(database.db, {
        appClients: [],
        oidcClients: [],
      });
      const [configuredApp] = await database.sql<{ disabled: boolean }[]>`
        SELECT "disabled"
        FROM "app_client"
        WHERE "id" = 'pledge-cash'
      `;
      const [configuredOidc] = await database.sql<{ disabled: boolean }[]>`
        SELECT "disabled"
        FROM "oauth_client"
        WHERE "client_id" = 'pledge-cash'
      `;
      const [configuredResource] = await database.sql<{ disabled: boolean }[]>`
        SELECT "disabled"
        FROM "oauth_resource"
        WHERE "identifier" = 'https://api.pledge.test'
      `;
      const [configuredResourceLinks] = await database.sql<{ count: string }[]>`
        SELECT count(*)::text AS "count"
        FROM "oauth_client_resource"
        WHERE "client_id" = 'pledge-cash'
      `;
      expect(configuredApp?.disabled).toBe(true);
      expect(configuredOidc?.disabled).toBe(true);
      expect(configuredResource?.disabled).toBe(true);
      expect(configuredResourceLinks?.count).toBe("0");
    });
  });
}

function basic(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

function bunServer(address: string): {
  requestIP: () => { address: string; family: "IPv4"; port: number };
} {
  return {
    requestIP: () => ({
      address,
      family: "IPv4",
      port: 443,
    }),
  };
}

async function issueWalletLinkGrant(input: {
  app: ReturnType<typeof createIdentityApp>;
  appSecret: string;
  origin: string;
  subject: string;
  wallet: {
    address: `0x${string}`;
    signMessage(input: { message: string }): Promise<`0x${string}`>;
  };
}): Promise<Response> {
  const challengeResponse = await input.app.request(
    "https://identity.test/v1/wallet/challenges",
    {
      body: JSON.stringify({
        chainId: 999,
        clientId: "pledge-cash",
        purpose: "link",
        walletAddress: input.wallet.address,
      }),
      headers: {
        "Content-Type": "application/json",
        Origin: input.origin,
      },
      method: "POST",
    },
  );
  expect(challengeResponse.status).toBe(201);
  const challenge = WalletChallengeResponseSchema.parse(
    await challengeResponse.json(),
  );
  return input.app.request("https://identity.test/v1/wallet/grants/issue", {
    body: JSON.stringify({
      clientId: "pledge-cash",
      message: challenge.message,
      signature: await input.wallet.signMessage({
        message: challenge.message,
      }),
      subject: input.subject,
    }),
    headers: {
      Authorization: basic("pledge-cash", input.appSecret),
      "Content-Type": "application/json",
    },
    method: "POST",
  });
}

async function waitForBlockedBackend(input: {
  blockerPid: number;
  sqlClient: ReturnType<typeof postgres>;
}): Promise<number> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    const [activity] = await input.sqlClient<{ pid: number }[]>`
      SELECT pid
      FROM pg_stat_activity
      WHERE pid <> pg_backend_pid()
        AND datname = current_database()
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
  event: string;
  sqlClient: ReturnType<typeof postgres>;
}): Promise<number> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    const [activity] = await input.sqlClient<{ pid: number }[]>`
      SELECT pid
      FROM pg_stat_activity
      WHERE pid <> pg_backend_pid()
        AND datname = current_database()
        AND wait_event = ${input.event}
      LIMIT 1
    `;
    if (activity !== undefined) return activity.pid;
    await Bun.sleep(5);
  }
  throw new Error(`No database backend entered ${input.event}`);
}

async function authorizeCode(input: {
  app: ReturnType<typeof createIdentityApp>;
  identityCookie: string;
  resource: string;
}): Promise<{ code: string; codeVerifier: string }> {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authorizationUrl = new URL(
    "https://identity.test/api/auth/oauth2/authorize",
  );
  authorizationUrl.searchParams.set("client_id", "pledge-cash");
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set(
    "redirect_uri",
    "https://pledge.test/auth/callback/peezy",
  );
  authorizationUrl.searchParams.set("resource", input.resource);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set(
    "scope",
    "openid profile email offline_access",
  );
  authorizationUrl.searchParams.set("state", randomBytes(16).toString("hex"));

  const response = await input.app.request(authorizationUrl, {
    headers: { Cookie: input.identityCookie },
  });
  expect(response.status).toBe(302);
  const location = response.headers.get("location");
  if (location === null) throw new Error("OIDC authorization did not redirect");
  const code = new URL(location).searchParams.get("code");
  if (code === null) throw new Error("OIDC authorization returned no code");
  return { code, codeVerifier };
}

async function exchangeAuthorizationCode(input: {
  app: ReturnType<typeof createIdentityApp>;
  code: string;
  codeVerifier: string;
  oidcSecret: string;
  resource: string;
}): Promise<Response> {
  return await input.app.request(
    "https://identity.test/api/auth/oauth2/token",
    {
      body: new URLSearchParams({
        client_id: "pledge-cash",
        code: input.code,
        code_verifier: input.codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: "https://pledge.test/auth/callback/peezy",
        resource: input.resource,
      }),
      headers: {
        Authorization: basic("pledge-cash", input.oidcSecret),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    },
  );
}

async function refreshAccessToken(input: {
  app: ReturnType<typeof createIdentityApp>;
  oidcSecret: string;
  refreshToken: string;
}): Promise<Response> {
  return await input.app.request(
    "https://identity.test/api/auth/oauth2/token",
    {
      body: new URLSearchParams({
        client_id: "pledge-cash",
        grant_type: "refresh_token",
        refresh_token: input.refreshToken,
      }),
      headers: {
        Authorization: basic("pledge-cash", input.oidcSecret),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    },
  );
}

function responseCookie(response: Response, name: string): string {
  const values =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie")].filter(
          (value): value is string => value !== null,
        );
  for (const candidate of values) {
    const pair = candidate.split(";")[0] ?? "";
    const separator = pair.indexOf("=");
    if (separator < 1) continue;
    const cookieName = pair.slice(0, separator);
    if (
      cookieName === name ||
      cookieName === `__Secure-${name}` ||
      cookieName === `__Host-${name}`
    ) {
      return pair;
    }
  }
  throw new Error(`Expected ${name} cookie`);
}

async function signInHostedWallet(
  app: ReturnType<typeof createIdentityApp>,
  config: IdentityConfig,
  wallet: {
    address: `0x${string}`;
    signMessage(input: { message: string }): Promise<`0x${string}`>;
  },
  basePath = "/api/auth",
  cookieName = "peezy-identity.session_token",
): Promise<{ cookie: string; userId: string }> {
  const chainId = 999;
  const nonceResponse = await app.request(
    `${config.baseUrl}${basePath}/siwe/nonce`,
    {
      body: JSON.stringify({ chainId, walletAddress: wallet.address }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    },
  );
  expect(nonceResponse.status).toBe(200);
  const { nonce } = (await nonceResponse.json()) as { nonce: string };
  const now = new Date();
  const message = createSiweMessage({
    address: wallet.address,
    chainId,
    domain: new URL(config.baseUrl).host,
    expirationTime: new Date(now.getTime() + 10 * 60_000),
    issuedAt: now,
    nonce,
    statement: HOSTED_WALLET_STATEMENT,
    uri: config.baseUrl,
    version: "1",
  });
  const response = await app.request(
    `${config.baseUrl}${basePath}/siwe/verify`,
    {
      body: JSON.stringify({
        chainId,
        message,
        signature: await wallet.signMessage({ message }),
        walletAddress: wallet.address,
      }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    },
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as { user: { id: string } };
  return { cookie: responseCookie(response, cookieName), userId: body.user.id };
}

type TestSolanaWallet = ReturnType<typeof createSolanaWallet>;

function createSolanaWallet() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  return {
    address: bs58.encode(spki.subarray(-32)),
    sign: (message: string) =>
      sign(null, Buffer.from(message, "utf8"), privateKey).toString("base64"),
  };
}

async function signInSolanaWallet(
  app: ReturnType<typeof createIdentityApp>,
  config: IdentityConfig,
  wallet: TestSolanaWallet,
  basePath = "/api/auth",
  cookieName = "peezy-identity.session_token",
): Promise<{ cookie: string; userId: string }> {
  const challengeResponse = await app.request(
    `${config.baseUrl}${basePath}/siws/challenge`,
    {
      body: JSON.stringify({ address: wallet.address }),
      headers: { "Content-Type": "application/json", Origin: config.baseUrl },
      method: "POST",
    },
  );
  expect(challengeResponse.status).toBe(200);
  const challenge = (await challengeResponse.json()) as {
    challengeId: string;
    message: string;
  };
  const response = await app.request(
    `${config.baseUrl}${basePath}/siws/verify`,
    {
      body: JSON.stringify({
        ...challenge,
        signature: wallet.sign(challenge.message),
      }),
      headers: { "Content-Type": "application/json", Origin: config.baseUrl },
      method: "POST",
    },
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as { user: { id: string } };
  return { cookie: responseCookie(response, cookieName), userId: body.user.id };
}
