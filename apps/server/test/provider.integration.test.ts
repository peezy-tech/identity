import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";

import {
  IdentityMeResponseSchema,
  WalletChallengeResponseSchema,
  WalletGrantExchangeResponseSchema,
  WalletGrantResponseSchema,
} from "@peezy.tech/identity";
import { eq } from "drizzle-orm";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { decodeJwt } from "jose";
import postgres from "postgres";
import { privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";

import {
  assertDistinctDatabases,
  importIdentity,
  readLegacyIdentity,
  validateLegacyIdentity,
  verifyImport,
} from "../scripts/import-pledge-cash";
import { createIdentityApp } from "../src/app";
import { createIdentityAuth } from "../src/auth";
import { seedConfiguredClients } from "../src/clients";
import type { IdentityConfig } from "../src/config";
import { HOSTED_WALLET_STATEMENT } from "../src/constants";
import { createDbClient, type IdentityDbClient } from "../src/db/client";
import { rateLimit, user, walletAddress } from "../src/db/schema";
import { identityMe } from "../src/identity";
import { MAX_RATE_LIMIT_WINDOW_MS, consumeRateLimit } from "../src/rate-limit";
import { consumeSessionHandoff } from "../src/session-handoffs";

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
      trustedProxies: [],
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
