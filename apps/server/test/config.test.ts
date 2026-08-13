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
  type: "confidential" as const,
};

const publicBrowserClient = {
  audiences: [],
  clientId: "public-stream-theater",
  name: "Public Stream Theater",
  origins: ["https://stream-theater.tmp.peezy.tech", "http://localhost:5173"],
  redirectUris: [
    "https://stream-theater.tmp.peezy.tech/auth/callback",
    "http://localhost:5173/auth/callback",
  ],
  requireHandle: false,
  type: "public-browser" as const,
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

  test("parses a public browser client without broadening trusted origins", () => {
    const config = loadConfig({
      ...baseEnv,
      IDENTITY_OIDC_CLIENTS: JSON.stringify([publicBrowserClient]),
    });

    expect(config.oidcClients[0]).toEqual(publicBrowserClient);
    expect(config.trustedOrigins).toEqual([]);
  });

  test("requires an explicit client type and the matching secret policy", () => {
    const { clientSecret: _, ...withoutTypeOrSecret } = oidcClient;

    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([withoutTypeOrSecret]),
      }),
    ).toThrow();
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...withoutTypeOrSecret, type: "confidential" },
        ]),
      }),
    ).toThrow();
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...publicBrowserClient, clientSecret: oidcClient.clientSecret },
        ]),
      }),
    ).toThrow();
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...publicBrowserClient, origins: [] },
        ]),
      }),
    ).toThrow();
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...oidcClient, origins: ["https://pledge.cash"] },
        ]),
      }),
    ).toThrow();
  });

  test("validates and normalizes exact public browser origins", () => {
    const parseOrigins = (
      origins: string[],
      redirectUris = ["https://stream-theater.tmp.peezy.tech/auth/callback"],
    ) =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([
          { ...publicBrowserClient, origins, redirectUris },
        ]),
      });

    expect(() =>
      parseOrigins(["https://stream-theater.tmp.peezy.tech/app"]),
    ).toThrow("Expected an origin without a path, query, or fragment");
    expect(() =>
      parseOrigins(["https://user:pass@stream-theater.tmp.peezy.tech"]),
    ).toThrow("Expected HTTPS or a loopback HTTP URL without credentials");
    expect(() => parseOrigins(["https://*.tmp.peezy.tech"])).toThrow(
      "Wildcard hosts are not allowed",
    );
    expect(() =>
      parseOrigins(["http://stream-theater.tmp.peezy.tech"]),
    ).toThrow("Expected HTTPS or a loopback HTTP URL without credentials");
    expect(() =>
      parseOrigins([
        "https://stream-theater.tmp.peezy.tech",
        "https://stream-theater.tmp.peezy.tech:443",
      ]),
    ).toThrow("Duplicate browser origins are not allowed");
    expect(() =>
      parseOrigins(
        ["https://another.tmp.peezy.tech"],
        ["https://stream-theater.tmp.peezy.tech/auth/callback"],
      ),
    ).toThrow(
      "Redirect origin is not registered: https://stream-theater.tmp.peezy.tech",
    );

    expect(
      parseOrigins(
        ["http://127.0.0.1:5173"],
        ["http://127.0.0.1:5173/auth/callback"],
      ).oidcClients[0],
    ).toMatchObject({ origins: ["http://127.0.0.1:5173"] });
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

  test("rejects duplicate OIDC client IDs", () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        IDENTITY_OIDC_CLIENTS: JSON.stringify([oidcClient, oidcClient]),
      }),
    ).toThrow("Duplicate configured identity: pledge-cash");
  });
});
