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

  test("uses a durable login completion handoff and a distinct linked state", async () => {
    const source = await Bun.file(
      new URL("../src/account-client.tsx", import.meta.url),
    ).text();
    expect(source).toContain("useLogin({");
    expect(source).toContain(
      "writePendingPrivyMigrationAttempt(storage, next)",
    );
    expect(source).toContain("void submitPendingClaim()");
    expect(source).toContain("Lobby profile imported");
    expect(source).toContain("Refresh or import another Privy profile");
    expect(source).toContain("props.claims.length === 0");
  });
});
