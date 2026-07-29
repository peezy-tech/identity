import { describe, expect, test } from "bun:test";

import {
  IdentityMeResponseSchema,
  PeezyUserSchema,
  WalletCredentialSchema,
} from "../src/contracts";

const user = {
  createdAt: "2026-07-29T00:00:00.000Z",
  id: "9bb64f50-80eb-48e3-999e-c4712e752461",
  status: "active" as const,
};

describe("identity contracts", () => {
  test("allows a user with no wallet credential", () => {
    expect(
      IdentityMeResponseSchema.parse({
        credentials: [
          {
            id: "0e79b80e-c56b-42a7-b2da-ddb94d594f08",
            kind: "social",
            linkedAt: "2026-07-29T00:00:00.000Z",
            provider: "github",
          },
        ],
        user,
      }),
    ).toEqual({
      credentials: [
        {
          id: "0e79b80e-c56b-42a7-b2da-ddb94d594f08",
          kind: "social",
          linkedAt: "2026-07-29T00:00:00.000Z",
          provider: "github",
        },
      ],
      user,
    });
  });

  test("accepts only web URLs for public avatars", () => {
    expect(() =>
      PeezyUserSchema.parse({
        ...user,
        avatarUrl: "javascript:alert(1)",
      }),
    ).toThrow("Expected an HTTP or HTTPS URL");
  });

  test("normalizes EOA addresses and keeps them chain independent", () => {
    expect(
      WalletCredentialSchema.parse({
        accountKind: "eoa",
        address: "0xA00000000000000000000000000000000000000A",
        family: "evm",
        id: "715f5baa-cd86-4a98-a1fe-3dd930f5d5d4",
        kind: "wallet",
        linkedAt: "2026-07-29T00:00:00.000Z",
        signInEnabled: true,
        verifiedChainIds: [1, 8453],
      }).address,
    ).toBe("0xa00000000000000000000000000000000000000a");
  });

  test("requires smart accounts to be chain scoped", () => {
    expect(() =>
      WalletCredentialSchema.parse({
        accountKind: "smart-account",
        address: "0xa00000000000000000000000000000000000000a",
        family: "evm",
        id: "715f5baa-cd86-4a98-a1fe-3dd930f5d5d4",
        kind: "wallet",
        linkedAt: "2026-07-29T00:00:00.000Z",
        signInEnabled: false,
        verifiedChainIds: [1],
      }),
    ).toThrow("Smart-account credentials must be chain scoped");
  });
});
