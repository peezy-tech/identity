import { createHash, randomBytes } from "node:crypto";

import { PeezyHandleSchema } from "@peezy.tech/identity";
import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import {
  oauthProvider,
  type OAuthProviderExtension,
} from "@better-auth/oauth-provider";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { APIError } from "better-auth/api";
import { genericOAuth, jwt, siwe } from "better-auth/plugins";
import { and, eq, inArray, sql } from "drizzle-orm";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { verifyMessage, type Address, type Hex } from "viem";
import { parseSiweMessage } from "viem/siwe";

import {
  HOSTED_WALLET_PROOF_TTL_MS,
  HOSTED_WALLET_STATEMENT,
} from "./constants";
import type { IdentityConfig, SocialProviderName } from "./config";
import type { IdentityDb } from "./db/client";
import * as schema from "./db/schema";
import { sessionHandoffPlugin } from "./session-handoffs";
import { solanaAuthPlugin } from "./solana-auth";

const TELEGRAM_ISSUER = "https://oauth.telegram.org";
const TELEGRAM_DISCOVERY_URL = `${TELEGRAM_ISSUER}/.well-known/openid-configuration`;
const TELEGRAM_JWKS = createRemoteJWKSet(
  new URL(`${TELEGRAM_ISSUER}/.well-known/jwks.json`),
);

type TelegramOAuthTokens = {
  idToken?: string | undefined;
};

type IdentityAuthMode = "primary" | "proof";

const configuredPublicClientCapability: OAuthProviderExtension = {
  clientDiscovery: {
    id: "configured-public-client-capability",
    matches: () => false,
    resolve: () => null,
  },
};

export function createIdentityAuth(config: IdentityConfig, db: IdentityDb) {
  return createConfiguredIdentityAuth(config, db, "primary");
}

export function createIdentityProofAuth(
  config: IdentityConfig,
  db: IdentityDb,
) {
  return createConfiguredIdentityAuth(config, db, "proof").auth;
}

function createConfiguredIdentityAuth(
  config: IdentityConfig,
  db: IdentityDb,
  mode: IdentityAuthMode,
) {
  const proofOnly = mode === "proof";
  const secureCookies = new URL(config.baseUrl).protocol === "https:";
  const socialProviderNames = configuredSocialProviders(config.socialProviders);
  const github = config.socialProviders.github;
  const apple = config.socialProviders.apple;
  const discord = config.socialProviders.discord;
  const telegram = config.socialProviders.telegram;
  const twitter = config.socialProviders.twitter;
  const telegramPlugins =
    telegram === undefined
      ? []
      : [
          genericOAuth({
            config: [
              {
                authentication: "basic",
                clientId: telegram.clientId,
                clientSecret: telegram.clientSecret,
                disableSignUp: proofOnly,
                discoveryUrl: TELEGRAM_DISCOVERY_URL,
                getUserInfo: (tokens) =>
                  telegramUserInfo(tokens, telegram.clientId),
                pkce: true,
                providerId: "telegram",
                scopes: ["openid", "profile"],
                tokenUrlParams: { client_id: telegram.clientId },
              },
            ],
          }),
        ];
  const resourceAudiences = [
    ...new Set(config.oidcClients.flatMap((client) => client.audiences)),
  ];
  const supportsPublicClients = config.oidcClients.some(
    (client) => client.type === "public-browser",
  );
  const providerPlugin = oauthProvider({
    accessTokenExpiresIn: 10 * 60,
    advertisedMetadata: {
      claims_supported: [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "sid",
        "scope",
        "azp",
        "name",
        "picture",
        "given_name",
        "family_name",
        "email",
        "email_verified",
        "preferred_username",
      ],
    },
    cachedResources: new Set(resourceAudiences),
    cachedTrustedClients: new Set(
      config.oidcClients.map((client) => client.clientId),
    ),
    clientPrivileges: () => false,
    codeExpiresIn: 5 * 60,
    consentPage: "/consent",
    customIdTokenClaims: ({ scopes, user }) => profileClaims(user, scopes),
    customUserInfoClaims: ({ scopes, user }) => profileClaims(user, scopes),
    enforcePerClientResources: true,
    // oauth-provider advertises `none` when a client-discovery capability is
    // present. This marker exposes pre-registered public rows without resolving
    // arbitrary clients or enabling dynamic client registration.
    extensions: supportsPublicClients ? [configuredPublicClientCapability] : [],
    idTokenExpiresIn: 10 * 60,
    loginPage: "/sign-in",
    refreshTokenExpiresIn: 30 * 24 * 60 * 60,
    resourcePrivileges: () => false,
    resources: resourceAudiences,
    scopes: ["openid", "profile", "email", "offline_access"],
    silenceWarnings: {
      oauthAuthServerConfig: true,
      openidConfig: true,
    },
  }) as unknown as BetterAuthPlugin;

  const auth = betterAuth({
    appName: "peezy.tech",
    basePath: proofOnly ? "/api/proof-auth" : "/api/auth",
    baseURL: config.baseUrl,
    secret: config.secret,
    trustedOrigins: [config.baseUrl, ...config.trustedOrigins],
    database: createIdentityDatabaseAdapter(db, proofOnly, socialProviderNames),
    disabledPaths: ["/unlink-account"],
    user: {
      additionalFields: {
        handle: {
          input: false,
          required: false,
          type: "string",
        },
        status: {
          defaultValue: "active",
          input: false,
          required: true,
          type: "string",
        },
      },
    },
    verification: {
      storeIdentifier: {
        hash: async (identifier) =>
          createHash("sha256")
            .update(`peezy-identity-verification:${mode}\0`)
            .update(identifier)
            .digest("hex"),
      },
    },
    account: {
      encryptOAuthTokens: true,
      storeStateStrategy: "database",
      accountLinking: {
        allowDifferentEmails: true,
        allowUnlinkingAll: false,
        disableImplicitLinking: true,
        enabled: true,
        trustedProviders: socialProviderNames,
        updateUserInfoOnLink: false,
      },
    },
    databaseHooks: {
      account: {
        create: {
          before: async (account) => ({ data: { ...account, idToken: null } }),
        },
        update: {
          before: async (account) => ({ data: { ...account, idToken: null } }),
        },
      },
      session: {
        create: {
          before: async (createdSession) =>
            isActiveIdentityUser(db, createdSession.userId),
        },
      },
    },
    socialProviders: {
      ...(discord === undefined
        ? {}
        : {
            discord: {
              ...discord,
              disableSignUp: proofOnly,
              disableDefaultScope: true,
              mapProfileToUser: (profile) => ({
                email: socialProviderEmail("discord", profile.id),
              }),
              scope: ["identify"],
            },
          }),
      ...(github === undefined
        ? {}
        : { github: { ...github, disableSignUp: proofOnly } }),
      ...(apple === undefined
        ? {}
        : {
            apple: {
              ...apple,
              disableSignUp: proofOnly,
              disableIdTokenSignIn: true,
            },
          }),
      ...(twitter === undefined
        ? {}
        : {
            twitter: {
              ...twitter,
              disableSignUp: proofOnly,
              disableDefaultScope: true,
              mapProfileToUser: (profile) => ({
                email: socialProviderEmail("twitter", profile.data.id),
              }),
              scope: ["users.read"],
            },
          }),
    },
    advanced: {
      cookiePrefix: proofOnly ? "peezy-proof" : "peezy-identity",
      database: { generateId: "uuid" },
      defaultCookieAttributes: {
        sameSite: secureCookies ? "none" : "lax",
      },
      ipAddress: {
        trustedProxies: config.trustedProxies,
      },
      useSecureCookies: secureCookies,
    },
    rateLimit: {
      enabled: true,
      storage: "database",
    },
    telemetry: { enabled: false },
    plugins: [
      ...(proofOnly
        ? []
        : [
            jwt({
              jwt: {
                issuer: `${config.baseUrl}/api/auth`,
              },
            }),
          ]),
      ...telegramPlugins,
      siwe({
        anonymous: true,
        domain: new URL(config.baseUrl).host,
        emailDomainName: "wallet.identity.peezy.tech.invalid",
        getNonce: async () => randomBytes(24).toString("hex"),
        verifyMessage: ({ address, message, signature }) =>
          verifyHostedWalletSignature(db, {
            address: address.toLowerCase() as Address,
            baseUrl: config.baseUrl,
            message,
            signature,
          }),
      }),
      solanaAuthPlugin(db, config, mode),
      ...(proofOnly ? [] : [sessionHandoffPlugin(db, config), providerPlugin]),
    ],
  });

  return { auth, socialProviderNames };
}

function profileClaims(
  user: Record<string, unknown>,
  scopes: readonly string[],
): Record<string, string> {
  if (!scopes.includes("profile")) return {};
  const claims: Record<string, string> = {};
  if (typeof user.name === "string" && user.name.length > 0) {
    claims.name = user.name;
  }
  if (typeof user.image === "string" && user.image.length > 0) {
    claims.picture = user.image;
  }
  const handle = PeezyHandleSchema.safeParse(user.handle);
  if (handle.success) claims.preferred_username = handle.data;
  return claims;
}

function createIdentityDatabaseAdapter(
  db: IdentityDb,
  proofOnly = false,
  socialProviderNames: readonly SocialProviderName[] = [],
) {
  const createRootAdapter = drizzleAdapter(db, {
    provider: "pg",
    schema,
  });

  return (...args: Parameters<typeof createRootAdapter>) => {
    type Adapter = ReturnType<typeof createRootAdapter>;
    type AdapterDb =
      | IdentityDb
      | Parameters<Parameters<IdentityDb["transaction"]>[0]>[0];
    type GuardedModel = "account" | "oauthConsent" | "walletAddress";
    type GuardedRow = { id: string; userId: string | null };

    const isGuardedModel = (model: string): model is GuardedModel =>
      model === "account" ||
      model === "oauthConsent" ||
      model === "walletAddress";
    const guardedUserIds = (rows: GuardedRow[]): string[] =>
      rows.flatMap((row) =>
        typeof row.userId === "string" ? [row.userId] : [],
      );

    const createAdapter = (adapterDb: AdapterDb): Adapter =>
      drizzleAdapter(adapterDb, {
        provider: "pg",
        schema,
      })(...args);

    // Account consolidation takes these same user locks before moving or
    // revoking credentials. Rechecking existing account ownership after the
    // lock makes the credential write linearizable with that lifecycle.
    const withActiveAccountUsers = async <Result>(input: {
      accountRows: GuardedRow[];
      adapterDb: AdapterDb;
      model: GuardedModel;
      operation: (adapter: Adapter, adapterDb: AdapterDb) => Promise<Result>;
      userIds: string[];
    }): Promise<Result> => {
      const userIds = [...new Set(input.userIds)].sort();
      if (userIds.length === 0) {
        return input.operation(createAdapter(input.adapterDb), input.adapterDb);
      }
      const lockedUsers = await input.adapterDb
        .select({ id: schema.user.id, status: schema.user.status })
        .from(schema.user)
        .where(inArray(schema.user.id, userIds))
        .orderBy(schema.user.id)
        .for("update");
      if (
        lockedUsers.length !== userIds.length ||
        lockedUsers.some((lockedUser) => lockedUser.status !== "active")
      ) {
        throw unavailableIdentityAccount();
      }

      const adapter = createAdapter(input.adapterDb);
      if (input.accountRows.length > 0) {
        const expectedOwners = new Map(
          input.accountRows.map((accountRow) => [
            accountRow.id,
            accountRow.userId,
          ]),
        );
        const accountRows = await adapter.findMany<{
          id: string;
          userId: string | null;
        }>({
          model: input.model,
          select: ["id", "userId"],
          where: [
            {
              field: "id",
              operator: "in",
              value: [...expectedOwners.keys()],
            },
          ],
        });
        if (
          accountRows.length !== expectedOwners.size ||
          accountRows.some(
            (accountRow) =>
              expectedOwners.get(accountRow.id) !== accountRow.userId,
          )
        ) {
          throw unavailableIdentityAccount();
        }
      }

      return input.operation(adapter, input.adapterDb);
    };

    const createWrappedAdapter = (
      adapterDb: AdapterDb,
      inTransaction: boolean,
    ): Adapter => {
      const adapter = createAdapter(adapterDb);
      const runGuarded = async <Result>(input: {
        accountRows: GuardedRow[];
        model: GuardedModel;
        operation: (adapter: Adapter, adapterDb: AdapterDb) => Promise<Result>;
        userIds: string[];
      }): Promise<Result> => {
        if (inTransaction) {
          return withActiveAccountUsers({ ...input, adapterDb });
        }
        return adapterDb.transaction((transaction) =>
          withActiveAccountUsers({ ...input, adapterDb: transaction }),
        );
      };

      const wrappedAdapter = {
        ...adapter,
        create: async (...createArgs: Parameters<typeof adapter.create>) => {
          const [input] = createArgs;
          if (proofOnly && input.model === "user") {
            throw new Error("Proof authentication cannot create an account");
          }
          if (!isGuardedModel(input.model)) {
            return adapter.create(...createArgs);
          }
          const userId = input.data.userId;
          if (typeof userId !== "string") {
            if (input.model === "oauthConsent") {
              return adapter.create(...createArgs);
            }
            throw unavailableIdentityAccount();
          }
          return runGuarded({
            accountRows: [],
            model: input.model,
            operation: async (transactionAdapter, transactionDb) => {
              const createdAccount = await transactionAdapter.create(
                ...createArgs,
              );
              if (
                input.model === "account" &&
                !proofOnly &&
                typeof createdAccount === "object" &&
                createdAccount !== null &&
                "id" in createdAccount &&
                typeof createdAccount.id === "string" &&
                "providerId" in createdAccount &&
                typeof createdAccount.providerId === "string" &&
                socialProviderNames.includes(
                  createdAccount.providerId as SocialProviderName,
                )
              ) {
                // Keep the immutable link audit in the credential transaction;
                // an after hook would run only after this lifecycle lock ends.
                await transactionDb.insert(schema.identityAuditEvent).values({
                  actorUserId: userId,
                  credentialId: createdAccount.id,
                  id: crypto.randomUUID(),
                  kind: "social.linked",
                  metadata: { provider: createdAccount.providerId },
                  userId,
                });
              }
              return createdAccount;
            },
            userIds: [userId],
          });
        },
        findOne: async (...findOneArgs: Parameters<typeof adapter.findOne>) => {
          const [input] = findOneArgs;
          const result = await adapter.findOne({
            ...input,
            ...(input.model === "walletAddress" && input.where !== undefined
              ? {
                  where: input.where.map((condition) =>
                    condition.field === "address"
                      ? { ...condition, mode: "insensitive" }
                      : condition,
                  ),
                }
              : {}),
          });
          if (
            (input.model === "user" && isDisabledIdentityUser(result)) ||
            (input.model === "session" &&
              isDisabledIdentityUser(
                (result as { user?: unknown } | null)?.user,
              ))
          ) {
            return null;
          }
          return result;
        },
        findMany: async (
          ...findManyArgs: Parameters<typeof adapter.findMany>
        ) => {
          const [input] = findManyArgs;
          const results = await adapter.findMany(input);
          return input.model === "session"
            ? results.filter(
                (result) =>
                  !isDisabledIdentityUser((result as { user?: unknown }).user),
              )
            : results;
        },
        delete: async (...deleteArgs: Parameters<typeof adapter.delete>) => {
          const [input] = deleteArgs;
          if (!isGuardedModel(input.model)) {
            return adapter.delete(...deleteArgs);
          }
          const accountRows = await adapter.findMany<{
            id: string;
            userId: string | null;
          }>({
            model: input.model,
            select: ["id", "userId"],
            where: input.where,
          });
          return runGuarded({
            accountRows,
            model: input.model,
            operation: (transactionAdapter) =>
              transactionAdapter.delete(...deleteArgs),
            userIds: guardedUserIds(accountRows),
          });
        },
        deleteMany: async (
          ...deleteManyArgs: Parameters<typeof adapter.deleteMany>
        ) => {
          const [input] = deleteManyArgs;
          if (!isGuardedModel(input.model)) {
            return adapter.deleteMany(...deleteManyArgs);
          }
          const accountRows = await adapter.findMany<{
            id: string;
            userId: string | null;
          }>({
            model: input.model,
            select: ["id", "userId"],
            where: input.where,
          });
          return runGuarded({
            accountRows,
            model: input.model,
            operation: (transactionAdapter) =>
              transactionAdapter.deleteMany(...deleteManyArgs),
            userIds: guardedUserIds(accountRows),
          });
        },
        update: async (...updateArgs: Parameters<typeof adapter.update>) => {
          const [input] = updateArgs;
          if (!isGuardedModel(input.model)) {
            return adapter.update(...updateArgs);
          }
          const accountRows = await adapter.findMany<{
            id: string;
            userId: string | null;
          }>({
            model: input.model,
            select: ["id", "userId"],
            where: input.where,
          });
          return runGuarded({
            accountRows,
            model: input.model,
            operation: (transactionAdapter) =>
              transactionAdapter.update(...updateArgs),
            userIds: guardedUserIds(accountRows),
          });
        },
        updateMany: async (
          ...updateManyArgs: Parameters<typeof adapter.updateMany>
        ) => {
          const [input] = updateManyArgs;
          if (!isGuardedModel(input.model)) {
            return adapter.updateMany(...updateManyArgs);
          }
          const accountRows = await adapter.findMany<{
            id: string;
            userId: string | null;
          }>({
            model: input.model,
            select: ["id", "userId"],
            where: input.where,
          });
          return runGuarded({
            accountRows,
            model: input.model,
            operation: (transactionAdapter) =>
              transactionAdapter.updateMany(...updateManyArgs),
            userIds: guardedUserIds(accountRows),
          });
        },
        transaction: (callback: Parameters<Adapter["transaction"]>[0]) =>
          adapterDb.transaction((transaction) =>
            callback(createWrappedAdapter(transaction, true)),
          ),
      };
      return wrappedAdapter as Adapter;
    };

    return createWrappedAdapter(db, false);
  };
}

function unavailableIdentityAccount(): APIError {
  return new APIError("FORBIDDEN", {
    code: "ACCOUNT_UNAVAILABLE",
    message: "Identity account is unavailable",
  });
}

function isDisabledIdentityUser(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    value.status !== "active"
  );
}

async function verifyHostedWalletSignature(
  db: IdentityDb,
  input: {
    address: Address;
    baseUrl: string;
    message: string;
    signature: string;
  },
): Promise<boolean> {
  let parsed: ReturnType<typeof parseSiweMessage>;
  try {
    parsed = parseSiweMessage(input.message);
    const expiresAt =
      parsed.expirationTime === undefined
        ? Number.NaN
        : parsed.expirationTime.getTime();
    if (
      parsed.statement !== HOSTED_WALLET_STATEMENT ||
      parsed.uri === undefined ||
      new URL(parsed.uri).origin !== new URL(input.baseUrl).origin ||
      parsed.version !== "1" ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= Date.now() ||
      expiresAt > Date.now() + HOSTED_WALLET_PROOF_TTL_MS + 60_000
    ) {
      return false;
    }
  } catch {
    return false;
  }

  const recovered = await verifyMessage({
    address: input.address,
    message: input.message,
    signature: input.signature as Hex,
  });
  if (!recovered) return false;

  const [owner] = await db
    .select({
      signInEnabled: schema.walletPrincipal.signInEnabled,
      status: schema.user.status,
      userId: schema.walletPrincipal.userId,
    })
    .from(schema.walletPrincipal)
    .innerJoin(schema.user, eq(schema.user.id, schema.walletPrincipal.userId))
    .where(
      and(
        eq(schema.walletPrincipal.accountKind, "eoa"),
        eq(schema.walletPrincipal.family, "evm"),
        sql`lower(${schema.walletPrincipal.address}) = lower(${input.address})`,
      ),
    )
    .limit(1);
  if (owner === undefined) return true;
  if (!owner.signInEnabled || owner.status !== "active") return false;

  const [credential] = await db
    .select({ id: schema.walletAddress.id })
    .from(schema.walletAddress)
    .where(
      and(
        eq(schema.walletAddress.userId, owner.userId),
        sql`lower(${schema.walletAddress.address}) = lower(${input.address})`,
      ),
    )
    .limit(1);
  return credential !== undefined;
}

async function isActiveIdentityUser(
  db: IdentityDb,
  subject: string,
): Promise<boolean> {
  const [identityUser] = await db
    .select({ status: schema.user.status })
    .from(schema.user)
    .where(eq(schema.user.id, subject))
    .limit(1);
  return identityUser?.status === "active";
}

export async function verifyTelegramIdToken(
  idToken: string,
  clientId: string,
  getKey: JWTVerifyGetKey = TELEGRAM_JWKS,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, getKey, {
    algorithms: ["RS256"],
    audience: clientId,
    issuer: TELEGRAM_ISSUER,
  });
  return payload;
}

export async function telegramUserInfo(
  tokens: TelegramOAuthTokens,
  clientId: string,
  getKey: JWTVerifyGetKey = TELEGRAM_JWKS,
): Promise<{
  email: string;
  emailVerified: false;
  id: string;
  image?: string;
  name: string;
  sub: string;
} | null> {
  if (tokens.idToken === undefined) return null;
  let payload: JWTPayload;
  try {
    payload = await verifyTelegramIdToken(tokens.idToken, clientId, getKey);
  } catch {
    return null;
  }

  const subject = typeof payload.sub === "string" ? payload.sub.trim() : "";
  const name = firstNonEmptyString(payload.name, payload.preferred_username);
  if (subject.length === 0 || name === undefined) return null;
  const image = firstNonEmptyString(payload.picture);
  return {
    email: socialProviderEmail("telegram", subject),
    emailVerified: false,
    id: subject,
    ...(image === undefined ? {} : { image }),
    name,
    sub: subject,
  };
}

export function configuredSocialProviders(
  providers: IdentityConfig["socialProviders"],
): SocialProviderName[] {
  return (
    ["apple", "discord", "github", "telegram", "twitter"] as const
  ).filter((provider) => providers[provider] !== undefined);
}

function socialProviderEmail(
  provider: SocialProviderName,
  accountId: string,
): string {
  const digest = createHash("sha256")
    .update(provider)
    .update("\0")
    .update(accountId)
    .digest("hex");
  return `${provider}-${digest}@social.identity.peezy.tech.invalid`;
}

function firstNonEmptyString(...values: unknown[]): string | undefined {
  return values
    .find(
      (value): value is string =>
        typeof value === "string" && value.trim().length > 0,
    )
    ?.trim();
}

export type IdentityAuth = ReturnType<typeof createIdentityAuth>["auth"];
export type IdentityProofAuth = ReturnType<typeof createIdentityProofAuth>;
