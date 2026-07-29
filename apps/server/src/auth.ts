import { createHash, randomBytes } from "node:crypto";

import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { genericOAuth, jwt, siwe } from "better-auth/plugins";
import { and, eq, sql } from "drizzle-orm";
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

const TELEGRAM_ISSUER = "https://oauth.telegram.org";
const TELEGRAM_DISCOVERY_URL = `${TELEGRAM_ISSUER}/.well-known/openid-configuration`;
const TELEGRAM_JWKS = createRemoteJWKSet(
  new URL(`${TELEGRAM_ISSUER}/.well-known/jwks.json`),
);

type TelegramOAuthTokens = {
  idToken?: string | undefined;
};

export function createIdentityAuth(config: IdentityConfig, db: IdentityDb) {
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
  const providerPlugin = oauthProvider({
    accessTokenExpiresIn: 10 * 60,
    cachedResources: new Set(resourceAudiences),
    cachedTrustedClients: new Set(
      config.oidcClients.map((client) => client.clientId),
    ),
    clientPrivileges: () => false,
    codeExpiresIn: 5 * 60,
    consentPage: "/consent",
    enforcePerClientResources: true,
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
    basePath: "/api/auth",
    baseURL: config.baseUrl,
    secret: config.secret,
    trustedOrigins: [config.baseUrl, ...config.trustedOrigins],
    database: createIdentityDatabaseAdapter(db),
    user: {
      additionalFields: {
        status: {
          defaultValue: "active",
          input: false,
          required: true,
          type: "string",
        },
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
          after: async (createdAccount) => {
            if (
              !socialProviderNames.includes(
                createdAccount.providerId as SocialProviderName,
              )
            ) {
              return;
            }
            await db.insert(schema.identityAuditEvent).values({
              actorUserId: createdAccount.userId,
              credentialId: createdAccount.id,
              id: crypto.randomUUID(),
              kind: "social.linked",
              metadata: { provider: createdAccount.providerId },
              userId: createdAccount.userId,
            });
          },
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
              disableDefaultScope: true,
              mapProfileToUser: (profile) => ({
                email: socialProviderEmail("discord", profile.id),
              }),
              scope: ["identify"],
            },
          }),
      ...(github === undefined ? {} : { github }),
      ...(apple === undefined
        ? {}
        : {
            apple: {
              ...apple,
              disableIdTokenSignIn: true,
            },
          }),
      ...(twitter === undefined
        ? {}
        : {
            twitter: {
              ...twitter,
              disableDefaultScope: true,
              mapProfileToUser: (profile) => ({
                email: socialProviderEmail("twitter", profile.data.id),
              }),
              scope: ["users.read"],
            },
          }),
    },
    advanced: {
      cookiePrefix: "peezy-identity",
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
      jwt({
        jwt: {
          issuer: `${config.baseUrl}/api/auth`,
        },
      }),
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
      sessionHandoffPlugin(db, config),
      providerPlugin,
    ],
  });

  return { auth, socialProviderNames };
}

function createIdentityDatabaseAdapter(db: IdentityDb) {
  const createAdapter = drizzleAdapter(db, {
    provider: "pg",
    schema,
  });

  return (...args: Parameters<typeof createAdapter>) => {
    const adapter = createAdapter(...args);
    return {
      ...adapter,
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
            isDisabledIdentityUser((result as { user?: unknown } | null)?.user))
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
    };
  };
}

function isDisabledIdentityUser(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    value.status === "disabled"
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
