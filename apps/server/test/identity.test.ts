import { describe, expect, test } from "bun:test";

import { PeezyUserSchema } from "@peezy.tech/identity";

import { toPeezyUser } from "../src/wallet-grants";

describe("identity user projection", () => {
  test("keeps the public user contract valid when provider profile text is malformed", () => {
    const projected = toPeezyUser({
      createdAt: new Date("2026-07-29T00:00:00.000Z"),
      email: "not-an-email",
      emailVerified: false,
      handle: null,
      id: "ca83177c-f524-4775-a82f-c86ede030b11",
      image: "not-a-url",
      name: `  ${"x".repeat(200)}  `,
      status: "active",
    });

    expect(PeezyUserSchema.parse(projected)).toEqual(projected);
    expect(projected.displayName).toHaveLength(128);
    expect(projected.avatarUrl).toBeUndefined();
    expect(projected.primaryEmail).toBeUndefined();
  });

  test("retains valid optional profile attributes", () => {
    expect(
      toPeezyUser({
        createdAt: new Date("2026-07-29T00:00:00.000Z"),
        email: "person@example.com",
        emailVerified: true,
        handle: "person",
        id: "cd08002b-2cd9-4eff-984c-c03accdf1580",
        image: "https://example.com/avatar.png",
        name: "Person",
        status: "active",
      }),
    ).toMatchObject({
      avatarUrl: "https://example.com/avatar.png",
      displayName: "Person",
      primaryEmail: {
        value: "person@example.com",
        verified: true,
      },
      handle: "person",
    });
  });
});
