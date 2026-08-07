import { describe, expect, test } from "bun:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import {
  bearerToken,
  createAccessTokenVerifier,
  exchangeWalletGrant,
  issueWalletGrant,
} from "../src";

describe("identity server helpers", () => {
  test("rejects a locally valid JWT after provider introspection revokes it", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const keyId = "identity-test-key";
    const subject = "9bb64f50-80eb-48e3-999e-c4712e752461";
    const audience = "https://api.identity.test";
    let revoked = false;
    const server = Bun.serve({
      fetch: async (request) => {
        const url = new URL(request.url);
        if (url.pathname === "/jwks") {
          return Response.json({
            keys: [
              {
                ...(await exportJWK(publicKey)),
                alg: "RS256",
                kid: keyId,
                use: "sig",
              },
            ],
          });
        }
        if (url.pathname === "/api/auth/oauth2/introspect") {
          expect(request.method).toBe("POST");
          expect(request.headers.get("authorization")).toBe(
            `Basic ${Buffer.from("identity-test:identity-secret").toString("base64")}`,
          );
          const body = new URLSearchParams(await request.text());
          expect(body.get("token_type_hint")).toBe("access_token");
          return Response.json({
            active: !revoked,
            sub: subject,
          });
        }
        return new Response(null, { status: 404 });
      },
      port: 0,
    });
    const issuer = `${server.url.origin}/api/auth`;
    const revokedToken = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setAudience(audience)
      .setExpirationTime("10 minutes")
      .setIssuer(issuer)
      .setSubject(subject)
      .setIssuedAt()
      .sign(privateKey);
    const verify = createAccessTokenVerifier({
      audience,
      issuer,
      introspection: {
        clientId: "identity-test",
        clientSecret: "identity-secret",
      },
      jwksUrl: `${server.url.origin}/jwks`,
    });

    try {
      await expect(verify(revokedToken)).resolves.toMatchObject({ subject });
      revoked = true;
      await expect(verify(revokedToken)).rejects.toThrow(
        "Identity access token is inactive",
      );
    } finally {
      server.stop(true);
    }
  });

  test("fails closed when access-token introspection exceeds its deadline", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const keyId = "identity-timeout-test-key";
    const subject = "9bb64f50-80eb-48e3-999e-c4712e752461";
    const audience = "https://api.identity.test";
    const server = Bun.serve({
      fetch: async () =>
        Response.json({
          keys: [
            {
              ...(await exportJWK(publicKey)),
              alg: "RS256",
              kid: keyId,
              use: "sig",
            },
          ],
        }),
      port: 0,
    });
    const issuer = `${server.url.origin}/api/auth`;
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setAudience(audience)
      .setExpirationTime("10 minutes")
      .setIssuer(issuer)
      .setSubject(subject)
      .setIssuedAt()
      .sign(privateKey);

    try {
      let requestAborted = false;
      const requestVerifier = createAccessTokenVerifier({
        audience,
        issuer,
        introspection: {
          clientId: "identity-test",
          clientSecret: "identity-secret",
          fetcher: async (_input, init) => {
            init?.signal?.addEventListener("abort", () => {
              requestAborted = true;
            });
            return await new Promise<Response>(() => {});
          },
          timeoutMs: 20,
        },
        jwksUrl: `${server.url.origin}/jwks`,
      });
      await expect(requestVerifier(token)).rejects.toThrow(
        "Identity access token introspection timed out",
      );
      expect(requestAborted).toBe(true);

      let bodyAborted = false;
      const bodyVerifier = createAccessTokenVerifier({
        audience,
        issuer,
        introspection: {
          clientId: "identity-test",
          clientSecret: "identity-secret",
          fetcher: async (_input, init) => {
            init?.signal?.addEventListener("abort", () => {
              bodyAborted = true;
            });
            return {
              ok: true,
              text: async () => await new Promise<string>(() => {}),
            } as Response;
          },
          timeoutMs: 20,
        },
        jwksUrl: `${server.url.origin}/jwks`,
      });
      await expect(bodyVerifier(token)).rejects.toThrow(
        "Identity access token introspection timed out",
      );
      expect(bodyAborted).toBe(true);
    } finally {
      server.stop(true);
    }
  });

  test("rejects introspection deadlines that overflow JavaScript timers", () => {
    const options = {
      audience: "https://api.identity.test",
      issuer: "https://identity.test/api/auth",
      introspection: {
        clientId: "identity-test",
        clientSecret: "identity-secret",
        timeoutMs: 2_147_483_647,
      },
    };

    expect(() => createAccessTokenVerifier(options)).not.toThrow();
    expect(() =>
      createAccessTokenVerifier({
        ...options,
        introspection: {
          ...options.introspection,
          timeoutMs: 2_147_483_648,
        },
      }),
    ).toThrow(
      "Identity introspection timeout must be positive and no greater than 2147483647 milliseconds",
    );
  });

  test("accepts exactly one bearer token", () => {
    expect(bearerToken("Bearer token-value")).toBe("token-value");
    expect(() => bearerToken("Basic value")).toThrow(
      "Authorization header must contain one bearer token",
    );
  });

  test("exchanges a wallet grant with confidential client credentials", async () => {
    const result = await exchangeWalletGrant({
      baseUrl: "https://id.peezy.tech/",
      clientId: "pledge-cash",
      clientSecret: "x".repeat(32),
      fetcher: async (input, init) => {
        expect(input).toBe("https://id.peezy.tech/v1/wallet/grants/exchange");
        expect(JSON.parse(String(init?.body))).toEqual({
          clientId: "pledge-cash",
          grant: "g".repeat(32),
        });
        expect(new Headers(init?.headers).get("Authorization")).toStartWith(
          "Basic ",
        );
        return Response.json({
          expiresAt: "2026-07-29T00:05:00.000Z",
          subject: "9bb64f50-80eb-48e3-999e-c4712e752461",
        });
      },
      grant: "g".repeat(32),
    });

    expect(result.subject).toBe("9bb64f50-80eb-48e3-999e-c4712e752461");
  });

  test("issues a wallet grant for an authenticated application subject", async () => {
    const subject = "9bb64f50-80eb-48e3-999e-c4712e752461";
    const result = await issueWalletGrant({
      baseUrl: "https://id.peezy.tech",
      clientId: "pledge-cash",
      clientSecret: "x".repeat(32),
      fetcher: async (input, init) => {
        expect(input).toBe("https://id.peezy.tech/v1/wallet/grants/issue");
        expect(JSON.parse(String(init?.body))).toEqual({
          clientId: "pledge-cash",
          message: "signed SIWE message",
          signature: `0x${"ab".repeat(65)}`,
          subject,
        });
        return Response.json({
          expiresAt: "2026-07-29T00:05:00.000Z",
          grant: "g".repeat(32),
          user: {
            createdAt: "2026-07-29T00:00:00.000Z",
            id: subject,
            status: "active",
          },
        });
      },
      message: "signed SIWE message",
      signature: `0x${"ab".repeat(65)}`,
      subject,
    });

    expect(result.user.id).toBe(subject);
  });
});
