import { createHash, randomBytes } from "node:crypto";

import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { genericOAuth, jwt, siwe } from "better-auth/plugins";
import { and, eq, sql } from "drizzle-orm";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { verifyMessage, type Address, type Hex } from "viem";

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
                issuer: TELEGRAM_ISSUER,
                pkce: true,
                providerId: "telegram",
                scopes: ["openid", "profile"],
                tokenUrlParams: { client_id: telegram.clientId },
              },
            ],
          }),
        ];

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
          before: async (account) => ({ data: { ...account, idToken: null } }),
        },
        update: {
          before: async (account) => ({ data: { ...account, idToken: null } }),
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
      useSecureCookies: new URL(config.baseUrl).protocol === "https:",
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
            message,
            signature,
          }),
      }),
      sessionHandoffPlugin(db, config),
      oauthProvider({
        accessTokenExpiresIn: 10 * 60,
        cachedTrustedClients: new Set(
          config.oidcClients.map((client) => client.clientId),
        ),
        clientPrivileges: () => false,
        codeExpiresIn: 5 * 60,
        consentPage: "/consent",
        idTokenExpiresIn: 10 * 60,
        loginPage: "/sign-in",
        refreshTokenExpiresIn: 30 * 24 * 60 * 60,
        scopes: ["openid", "profile", "email", "offline_access"],
        silenceWarnings: {
          oauthAuthServerConfig: true,
          openidConfig: true,
        },
        validAudiences: [
          config.baseUrl,
          ...config.oidcClients.flatMap((client) => client.audiences),
        ],
      }),
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
        return adapter.findOne({
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
      },
    };
  };
}

async function verifyHostedWalletSignature(
  db: IdentityDb,
  input: {
    address: Address;
    message: string;
    signature: string;
  },
): Promise<boolean> {
  const recovered = await verifyMessage({
    address: input.address,
    message: input.message,
    signature: input.signature as Hex,
  });
  if (!recovered) return false;

  const [owner] = await db
    .select({ userId: schema.walletPrincipal.userId })
    .from(schema.walletPrincipal)
    .where(
      and(
        eq(schema.walletPrincipal.accountKind, "eoa"),
        sql`lower(${schema.walletPrincipal.address}) = lower(${input.address})`,
      ),
    )
    .limit(1);
  if (owner === undefined) return true;

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
