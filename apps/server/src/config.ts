import { z } from "zod";

const optionalString = z.preprocess(
  (value) =>
    typeof value === "string" && value.trim().length === 0 ? undefined : value,
  z.string().trim().min(1).optional(),
);

const origin = z
  .string()
  .url()
  .transform((value, context) => {
    const url = new URL(value);
    if (url.pathname !== "/" || url.search || url.hash) {
      context.addIssue({
        code: "custom",
        message: "Expected an origin without a path, query, or fragment",
      });
      return z.NEVER;
    }
    return url.origin;
  });

const appClientSchema = z.object({
  id: z.string().trim().min(1).max(128),
  name: z.string().trim().min(1).max(128),
  origins: z.array(origin).min(1),
  secret: z.string().min(32),
  siweStatement: z.string().trim().min(1).max(256),
  walletLinkSiweStatement: z.string().trim().min(1).max(256).optional(),
});

const oidcClientSchema = z.object({
  audiences: z.array(z.string().trim().min(1)).default([]),
  clientId: z.string().trim().min(1).max(128),
  clientSecret: z.string().min(32),
  name: z.string().trim().min(1).max(128),
  redirectUris: z.array(z.string().url()).min(1),
});

function jsonEnv<T extends z.ZodType>(
  schema: T,
  fallback: z.input<T>,
): z.ZodPipe<z.ZodDefault<z.ZodString>, z.ZodTransform<z.output<T>, string>> {
  return z
    .string()
    .default(JSON.stringify(fallback))
    .transform((value, context) => {
      try {
        return schema.parse(JSON.parse(value));
      } catch (error) {
        context.addIssue({
          code: "custom",
          message: error instanceof Error ? error.message : "Invalid JSON",
        });
        return z.NEVER;
      }
    }) as z.ZodPipe<
    z.ZodDefault<z.ZodString>,
    z.ZodTransform<z.output<T>, string>
  >;
}

const envSchema = z.object({
  APPLE_CLIENT_ID: optionalString,
  APPLE_CLIENT_SECRET: optionalString,
  DATABASE_URL: z.string().url(),
  DISCORD_CLIENT_ID: optionalString,
  DISCORD_CLIENT_SECRET: optionalString,
  GITHUB_CLIENT_ID: optionalString,
  GITHUB_CLIENT_SECRET: optionalString,
  IDENTITY_APP_CLIENTS: jsonEnv(z.array(appClientSchema), []),
  IDENTITY_BASE_URL: origin,
  IDENTITY_OIDC_CLIENTS: jsonEnv(z.array(oidcClientSchema), []),
  IDENTITY_PORT: z.coerce.number().int().positive().default(8790),
  IDENTITY_SECRET: z.string().min(32),
  IDENTITY_TRUSTED_ORIGINS: z.string().default(""),
  TELEGRAM_OAUTH_CLIENT_ID: optionalString,
  TELEGRAM_OAUTH_CLIENT_SECRET: optionalString,
  TWITTER_CLIENT_ID: optionalString,
  TWITTER_CLIENT_SECRET: optionalString,
});

export type SocialProviderName =
  | "apple"
  | "discord"
  | "github"
  | "telegram"
  | "twitter";

export type SocialProviderConfig = {
  clientId: string;
  clientSecret: string;
};

export type AppClientConfig = z.infer<typeof appClientSchema>;
export type OidcClientConfig = z.infer<typeof oidcClientSchema>;

export type IdentityConfig = {
  appClients: AppClientConfig[];
  baseUrl: string;
  databaseUrl: string;
  oidcClients: OidcClientConfig[];
  port: number;
  secret: string;
  socialProviders: Partial<Record<SocialProviderName, SocialProviderConfig>>;
  trustedOrigins: string[];
};

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
): IdentityConfig {
  const parsed = envSchema.parse(env);
  const socialProviders: IdentityConfig["socialProviders"] = {};

  addSocialProvider(
    socialProviders,
    "apple",
    parsed.APPLE_CLIENT_ID,
    parsed.APPLE_CLIENT_SECRET,
  );
  addSocialProvider(
    socialProviders,
    "discord",
    parsed.DISCORD_CLIENT_ID,
    parsed.DISCORD_CLIENT_SECRET,
  );
  addSocialProvider(
    socialProviders,
    "github",
    parsed.GITHUB_CLIENT_ID,
    parsed.GITHUB_CLIENT_SECRET,
  );
  addSocialProvider(
    socialProviders,
    "telegram",
    parsed.TELEGRAM_OAUTH_CLIENT_ID,
    parsed.TELEGRAM_OAUTH_CLIENT_SECRET,
  );
  addSocialProvider(
    socialProviders,
    "twitter",
    parsed.TWITTER_CLIENT_ID,
    parsed.TWITTER_CLIENT_SECRET,
  );

  const configuredOrigins = parsed.IDENTITY_TRUSTED_ORIGINS.split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => origin.parse(value));
  const clientOrigins = parsed.IDENTITY_APP_CLIENTS.flatMap(
    (client) => client.origins,
  );

  return {
    appClients: uniqueBy(parsed.IDENTITY_APP_CLIENTS, (client) => client.id),
    baseUrl: parsed.IDENTITY_BASE_URL,
    databaseUrl: parsed.DATABASE_URL,
    oidcClients: uniqueBy(
      parsed.IDENTITY_OIDC_CLIENTS,
      (client) => client.clientId,
    ),
    port: parsed.IDENTITY_PORT,
    secret: parsed.IDENTITY_SECRET,
    socialProviders,
    trustedOrigins: [...new Set([...configuredOrigins, ...clientOrigins])],
  };
}

function addSocialProvider(
  target: IdentityConfig["socialProviders"],
  name: SocialProviderName,
  clientId: string | undefined,
  clientSecret: string | undefined,
): void {
  if ((clientId === undefined) !== (clientSecret === undefined)) {
    throw new Error(
      `${name.toUpperCase()}_CLIENT_ID and ${name.toUpperCase()}_CLIENT_SECRET must be configured together`,
    );
  }
  if (clientId !== undefined && clientSecret !== undefined) {
    target[name] = { clientId, clientSecret };
  }
}

function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  for (const value of values) {
    const identity = key(value);
    if (seen.has(identity)) {
      throw new Error(`Duplicate configured identity: ${identity}`);
    }
    seen.add(identity);
  }
  return values;
}
