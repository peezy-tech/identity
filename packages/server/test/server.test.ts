import { describe, expect, test } from "bun:test";

import { bearerToken, exchangeWalletGrant, issueWalletGrant } from "../src";

describe("identity server helpers", () => {
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
