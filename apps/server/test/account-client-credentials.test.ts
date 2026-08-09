import { describe, expect, test } from "bun:test";

import { isSignInCredential } from "../src/account-client-credentials";

describe("account credential presentation", () => {
  test("does not present email attributes as sign-in methods", () => {
    expect(isSignInCredential({ kind: "email" })).toBe(false);
    expect(isSignInCredential({ kind: "social" })).toBe(true);
    expect(isSignInCredential({ kind: "wallet" })).toBe(true);
    expect(isSignInCredential({ kind: "passkey" })).toBe(true);
  });

  test("renders the filtered credential collection in the account UI", async () => {
    const source = await Bun.file(
      new URL("../src/account-client.tsx", import.meta.url),
    ).text();
    expect(source).toContain("signInCredentials.map");
    expect(source).not.toContain("identity.credentials.map");
  });
});
