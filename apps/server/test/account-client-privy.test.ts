import { describe, expect, test } from "bun:test";

describe("linked Privy account presentation", () => {
  test("shows the full Privy user ID for an existing claim", async () => {
    const source = await Bun.file(
      new URL("../src/account-client.tsx", import.meta.url),
    ).text();
    expect(source).toContain("<strong>Privy user ID</strong>");
    expect(source).toContain("<code>{claim.privyUserId}</code>");
    expect(source).not.toContain(
      "<strong>Privy {claim.privyUserHint}</strong>",
    );
  });
});
