import { describe, expect, test } from "bun:test";

import { createIdentityClient, type IdentityFetch } from "../src/client";

describe("identity browser client", () => {
  test("includes the active identity session when linking a wallet", async () => {
    let requestInit: RequestInit | undefined;
    const fetcher: IdentityFetch = async (_input, init) => {
      requestInit = init;
      return Response.json(
        {
          expiresAt: "2026-07-29T00:05:00.000Z",
          grant: "grant-token-with-at-least-thirty-two-characters",
          user: {
            createdAt: "2026-07-29T00:00:00.000Z",
            id: "9bb64f50-80eb-48e3-999e-c4712e752461",
            status: "active",
          },
        },
        { status: 201 },
      );
    };
    const client = createIdentityClient({
      baseUrl: "https://identity.peezy.tech",
      fetcher,
    });

    await client.createWalletGrant({
      clientId: "pledge-cash",
      message: "signed SIWE message",
      signature: `0x${"ab".repeat(65)}`,
    });

    expect(requestInit?.credentials).toBe("include");
  });
});
