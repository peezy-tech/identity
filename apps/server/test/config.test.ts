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
  clientId: "pledge-cash",
  clientSecret: "oidc-secret-that-is-distinct-and-at-least-32-characters",
  name: "PledgeCash",
  redirectUris: ["https://api.pledge.cash/auth/oauth2/callback/peezy"],
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
});
