import { describe, expect, test } from "bun:test";

import { loadConfig } from "../src/config";

const baseEnv = {
  DATABASE_URL: "postgres://postgres:postgres@127.0.0.1:5432/identity",
  IDENTITY_BASE_URL: "https://identity.peezy.tech",
  IDENTITY_SECRET: "identity-service-secret-at-least-32-characters",
};

const appClient = {
  id: "pledge-cash",
  name: "PledgeCash",
  origins: ["https://pledge.cash"],
  secret: "app-api-secret-at-least-32-characters",
  siweStatement: "Sign in to pledge.cash.",
};

const oidcClient = {
  audiences: ["https://api.pledge.cash"],
  clientId: "pledge-cash",
  clientSecret: "oidc-secret-that-is-distinct-and-at-least-32-characters",
  name: "PledgeCash",
  redirectUris: ["https://api.pledge.cash/auth/oauth2/callback/peezy"],
  requireHandle: true,
};

describe("Identity config", () => {
  test("keeps confidential app API and OIDC credentials distinct", () => {
    const config = loadConfig({
      ...baseEnv,
      IDENTITY_APP_CLIENTS: JSON.stringify([appClient]),
      IDENTITY_OIDC_CLIENTS: JSON.stringify([oidcClient]),
    });
    expect(config.appClients[0]?.secret).toBe(appClient.secret);
    expect(config.oidcClients[0]?.clientSecret).toBe(oidcClient.clientSecret);
    expect(config.oidcClients[0]?.requireHandle).toBe(true);

    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_APP_CLIENTS: JSON.stringify([appClient]),
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...oidcClient, clientSecret: appClient.secret },
        ]),
      }),
    ).toThrow(
      "Application pledge-cash must use distinct app API and OIDC client secrets",
    );
  });

  test("derives trusted browser origins from registered applications", () => {
    const config = loadConfig({
      ...baseEnv,
      IDENTITY_APP_CLIENTS: JSON.stringify([appClient]),
      IDENTITY_OIDC_CLIENTS: JSON.stringify([oidcClient]),
      IDENTITY_TRUSTED_ORIGINS: "https://admin.peezy.tech,https://pledge.cash",
    });

    expect(config.trustedOrigins).toEqual([
      "https://admin.peezy.tech",
      "https://pledge.cash",
    ]);
  });

  test("accepts only explicit trusted proxy addresses and CIDR ranges", () => {
    const config = loadConfig({
      ...baseEnv,
      IDENTITY_TRUSTED_PROXIES: "192.0.2.10,2001:db8::/48",
    });
    expect(config.trustedProxies).toEqual(["192.0.2.10", "2001:db8::/48"]);

    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_TRUSTED_PROXIES: "10.0.0.0/99",
      }),
    ).toThrow("Invalid trusted proxy address or CIDR: 10.0.0.0/99");
  });

  test("rejects insecure non-loopback application URLs", () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          {
            ...oidcClient,
            redirectUris: ["http://pledge.test/auth/callback/peezy"],
          },
        ]),
      }),
    ).toThrow("Expected HTTPS or a loopback HTTP URL without credentials");
  });

  test("normalizes duplicate resource audiences", () => {
    const config = loadConfig({
      ...baseEnv,
      IDENTITY_OIDC_CLIENTS: JSON.stringify([
        {
          ...oidcClient,
          audiences: ["https://api.pledge.cash", "https://api.pledge.cash"],
        },
      ]),
    });
    expect(config.oidcClients[0]?.audiences).toEqual([
      "https://api.pledge.cash",
    ]);
  });

  test("restricts application identifiers to URL-safe values", () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_APP_CLIENTS: JSON.stringify([
          { ...appClient, id: "pledge:cash" },
        ]),
      }),
    ).toThrow();
  });

  test("keeps Privy migration off unless explicitly enabled and configured", () => {
    expect(loadConfig(baseEnv).privyMigration).toBeUndefined();
    expect(() =>
      loadConfig({ ...baseEnv, PRIVY_MIGRATION_ENABLED: "true" }),
    ).toThrow(
      "PRIVY_MIGRATION_APP_ID and PRIVY_MIGRATION_APP_SECRET are required",
    );

    expect(
      loadConfig({
        ...baseEnv,
        PRIVY_MIGRATION_APP_ID: "legacy-lobby",
        PRIVY_MIGRATION_APP_SECRET: "privy-secret",
        PRIVY_MIGRATION_ENABLED: "true",
        PRIVY_MIGRATION_JWT_VERIFICATION_KEY: "verification-key",
      }).privyMigration,
    ).toEqual({
      appId: "legacy-lobby",
      appSecret: "privy-secret",
      jwtVerificationKey: "verification-key",
    });

    expect(
      loadConfig({
        ...baseEnv,
        PRIVY_APP_ID: "legacy-lobby-alias",
        PRIVY_APP_SECRET: "privy-secret-alias",
        PRIVY_MIGRATION_ENABLED: "true",
      }).privyMigration,
    ).toEqual({
      appId: "legacy-lobby-alias",
      appSecret: "privy-secret-alias",
    });
  });
});
