import { describe, expect, test } from "bun:test";

import {
  isSignInCredential,
  linkedSocialProviders,
} from "../src/account-client-credentials";

describe("account credential presentation", () => {
  test("does not present email attributes as sign-in methods", () => {
    expect(isSignInCredential({ kind: "email" })).toBe(false);
    expect(isSignInCredential({ kind: "social" })).toBe(true);
    expect(isSignInCredential({ kind: "wallet" })).toBe(true);
    expect(isSignInCredential({ kind: "passkey" })).toBe(true);
  });

  test("tracks only the social providers already owned by this account", () => {
    expect([
      ...linkedSocialProviders([
        { kind: "social", provider: "twitter" },
        { kind: "email" },
        { kind: "social", provider: "twitter" },
        { kind: "wallet" },
        { kind: "social", provider: "github" },
      ]),
    ]).toEqual(["twitter", "github"]);
  });

  test("renders the filtered credential collection in the account UI", async () => {
    const source = await Bun.file(
      new URL("../src/account-client.tsx", import.meta.url),
    ).text();
    expect(source).toContain("signInCredentials.map");
    expect(source).not.toContain("identity.credentials.map");
  });

  test("disables consolidation proofs for linked social providers", async () => {
    const source = await Bun.file(
      new URL("../src/account-client.tsx", import.meta.url),
    ).text();
    expect(
      source.match(
        /disabled=\{busy !== null \|\| linkedProviders\.has\(provider\)\}/g,
      ),
    ).toHaveLength(2);
    expect(source).toContain("already linked`");
  });
});
