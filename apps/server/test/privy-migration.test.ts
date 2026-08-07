import { describe, expect, test } from "bun:test";

import { normalizePrivyIdentities } from "../src/privy-migration";

const solanaAddress = "Vote111111111111111111111111111111111111111";

describe("Privy migration identity normalization", () => {
  test("captures every distinct linked identity, including repeated types and legacy-only entries", () => {
    const normalized = normalizePrivyIdentities([
      {
        email: "person@example.com",
        latest_verified_at: 1_750_000_000,
        subject: "google-subject",
        type: "google_oauth",
        username: "unsafe-display-name",
      },
      { subject: "discord-one", type: "discord_oauth", username: "one" },
      { subject: "discord-two", type: "discord_oauth", username: "two" },
      {
        address: "0x1000000000000000000000000000000000000000",
        chain_type: "ethereum",
        type: "wallet",
        wallet_client_type: "metamask",
      },
      {
        address: "0x2000000000000000000000000000000000000000",
        chain_type: "ethereum",
        embedded_wallet_type: "privy",
        type: "embedded_wallet",
      },
      {
        address: solanaAddress,
        chain_type: "solana",
        type: "embedded_wallet",
      },
    ]);

    expect(normalized).toHaveLength(6);
    expect(
      normalized.filter((item) => item.type === "discord_oauth"),
    ).toHaveLength(2);
    expect(
      normalized.find((item) => item.type === "google_oauth")?.provider,
    ).toBeUndefined();
    expect(
      normalized.find((item) => item.type === "discord_oauth")?.provider,
    ).toBe("discord");
    expect(normalized.filter((item) => item.walletAddress)).toHaveLength(3);
    expect(
      normalized.find((item) => item.chainType === "solana")?.walletAddress,
    ).toBe(solanaAddress);
    expect(JSON.stringify(normalized)).not.toContain("person@example.com");
    expect(
      normalized.find((item) => item.type === "google_oauth")?.sourceAccountId,
    ).toBe("google-subject");
  });

  test("deduplicates exact provider identities by stable subject without collapsing different subjects", () => {
    const normalized = normalizePrivyIdentities([
      { subject: "same-subject", type: "github_oauth", username: "old" },
      { subject: "same-subject", type: "github_oauth", username: "new" },
      { subject: "other-subject", type: "github_oauth", username: "other" },
    ]);
    expect(normalized).toHaveLength(2);
    expect(new Set(normalized.map((item) => item.sourceAccountId))).toEqual(
      new Set(["same-subject", "other-subject"]),
    );
  });

  test("keeps numeric-only identity identifiers distinct", () => {
    const normalized = normalizePrivyIdentities([
      { fid: 42, type: "farcaster" },
      { fid: 43, type: "farcaster" },
    ]);

    expect(normalized).toHaveLength(2);
    expect(new Set(normalized.map((item) => item.sourceAccountId))).toEqual(
      new Set(["42", "43"]),
    );
    expect(new Set(normalized.map((item) => item.metadata.fid))).toEqual(
      new Set([42, 43]),
    );
  });

  test("keeps smart wallets chain-unscoped and marks them as smart accounts", () => {
    const [identity] = normalizePrivyIdentities([
      {
        address: "0x4000000000000000000000000000000000000000",
        smart_wallet_type: "kernel",
        type: "smart_wallet",
      },
    ]);

    expect(identity).toMatchObject({
      type: "smart_wallet",
      walletAddress: "0x4000000000000000000000000000000000000000",
      walletType: "smart-account",
    });
    expect(identity?.chainType).toBeUndefined();
  });
});
