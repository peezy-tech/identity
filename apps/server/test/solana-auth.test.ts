import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";

import bs58 from "bs58";

import {
  createSiwsMessage,
  parseSolanaAddress,
  verifySiwsSignature,
} from "../src/solana-auth";

describe("Solana wallet authentication", () => {
  test("creates a nonce-bound SIWS message and verifies its Ed25519 signature", () => {
    const wallet = solanaWallet();
    const message = createSiwsMessage({
      address: wallet.address,
      baseUrl: "https://identity.peezy.tech",
      expirationTime: new Date("2026-08-06T12:10:00.000Z"),
      issuedAt: new Date("2026-08-06T12:00:00.000Z"),
      nonce: "0123456789abcdef",
    });
    expect(message).toContain(
      `identity.peezy.tech wants you to sign in with your Solana account:\n${wallet.address}`,
    );
    expect(message).toContain("Nonce: 0123456789abcdef");
    expect(
      verifySiwsSignature({
        address: wallet.address,
        message,
        signature: wallet.sign(message),
      }),
    ).toBe(true);
    expect(
      verifySiwsSignature({
        address: wallet.address,
        message: `${message} `,
        signature: wallet.sign(message),
      }),
    ).toBe(false);
  });

  test("rejects malformed addresses and non-canonical signatures", () => {
    expect(() => parseSolanaAddress("0OIl-not-base58")).toThrow(
      "Solana address is invalid",
    );
    expect(
      verifySiwsSignature({
        address: "11111111111111111111111111111111",
        message: "message",
        signature: "not base64",
      }),
    ).toBe(false);
  });
});

function solanaWallet() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const address = bs58.encode(spki.subarray(-32));
  return {
    address,
    sign: (message: string) =>
      sign(null, Buffer.from(message, "utf8"), privateKey).toString("base64"),
  };
}
