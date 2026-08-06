import { randomBytes, randomUUID } from "node:crypto";

import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { getAddress, verifyMessage, type Hex } from "viem";
import { createSiweMessage } from "viem/siwe";

import type { IdentityDb } from "./db/client";
import {
  account,
  accountWalletLinkChallenge,
  identityAuditEvent,
  user,
  walletAddress,
  walletPrincipal,
} from "./db/schema";
import {
  createSiwsMessage,
  parseSolanaAddress,
  verifySiwsSignature,
} from "./solana-auth";

const CHALLENGE_TTL_MS = 10 * 60_000;
const STATEMENT = "Link this wallet to your peezy.tech account.";

export class AccountWalletLinkError extends Error {
  readonly code: string;
  readonly status: 400 | 401 | 403 | 409;

  constructor(
    status: AccountWalletLinkError["status"],
    code: string,
    message: string,
  ) {
    super(message);
    this.name = "AccountWalletLinkError";
    this.status = status;
    this.code = code;
  }
}

export async function createAccountWalletLinkChallenge(input: {
  address: string;
  baseUrl: string;
  chainId?: number;
  db: IdentityDb;
  family: "evm" | "solana";
  userId: string;
}): Promise<{
  address: string;
  challengeId: string;
  expiresAt: string;
  message: string;
}> {
  if (
    input.family === "evm" &&
    (!Number.isSafeInteger(input.chainId) || (input.chainId ?? 0) <= 0)
  ) {
    throw new AccountWalletLinkError(
      400,
      "invalid_chain",
      "Wallet chain is invalid",
    );
  }
  let address: string;
  try {
    address =
      input.family === "evm"
        ? getAddress(input.address)
        : parseSolanaAddress(input.address);
  } catch {
    throw new AccountWalletLinkError(
      400,
      "invalid_wallet",
      "Wallet address is invalid",
    );
  }
  const origin = new URL(input.baseUrl).origin;
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + CHALLENGE_TTL_MS);
  const nonce = randomBytes(24).toString("hex");
  const message =
    input.family === "evm"
      ? createSiweMessage({
          address: address as `0x${string}`,
          chainId: input.chainId!,
          domain: new URL(origin).host,
          expirationTime: expiresAt,
          issuedAt,
          nonce,
          statement: STATEMENT,
          uri: origin,
          version: "1",
        })
      : createSiwsMessage({
          address,
          baseUrl: origin,
          expirationTime: expiresAt,
          issuedAt,
          nonce,
          statement: STATEMENT,
        });
  const challengeId = randomUUID();
  await input.db.insert(accountWalletLinkChallenge).values({
    address,
    ...(input.chainId === undefined ? {} : { chainId: input.chainId }),
    expiresAt,
    family: input.family,
    id: challengeId,
    message,
    nonce,
    userId: input.userId,
  });
  return { address, challengeId, expiresAt: expiresAt.toISOString(), message };
}

export async function verifyAccountWalletLink(input: {
  challengeId: string;
  db: IdentityDb;
  message: string;
  signature: string;
  userId: string;
}): Promise<{ address: string; credentialId: string; linked: true }> {
  const [challenge] = await input.db
    .select()
    .from(accountWalletLinkChallenge)
    .where(
      and(
        eq(accountWalletLinkChallenge.id, input.challengeId),
        eq(accountWalletLinkChallenge.userId, input.userId),
        isNull(accountWalletLinkChallenge.usedAt),
        gt(accountWalletLinkChallenge.expiresAt, new Date()),
      ),
    )
    .limit(1);
  if (challenge === undefined || challenge.message !== input.message) {
    throw new AccountWalletLinkError(
      403,
      "invalid_challenge",
      "Wallet challenge is invalid or expired",
    );
  }
  let valid =
    challenge.family === "solana"
      ? verifySiwsSignature({
          address: challenge.address,
          message: input.message,
          signature: input.signature,
        })
      : false;
  if (challenge.family === "evm") {
    try {
      valid = await verifyMessage({
        address: getAddress(challenge.address),
        message: input.message,
        signature: input.signature as Hex,
      });
    } catch {
      // Malformed signatures are failed proofs.
    }
  }
  if (!valid) {
    await input.db
      .update(accountWalletLinkChallenge)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(accountWalletLinkChallenge.id, challenge.id),
          isNull(accountWalletLinkChallenge.usedAt),
          gt(accountWalletLinkChallenge.expiresAt, new Date()),
        ),
      );
    throw new AccountWalletLinkError(
      401,
      "invalid_signature",
      "Wallet signature is invalid",
    );
  }

  return input.db.transaction(async (tx) => {
    const normalized =
      challenge.family === "evm"
        ? challenge.address.toLowerCase()
        : challenge.address;
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtext(${`wallet-principal:${challenge.family}:${normalized}`}))`,
    );
    const [consumed] = await tx
      .update(accountWalletLinkChallenge)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(accountWalletLinkChallenge.id, challenge.id),
          isNull(accountWalletLinkChallenge.usedAt),
          gt(accountWalletLinkChallenge.expiresAt, new Date()),
        ),
      )
      .returning({ id: accountWalletLinkChallenge.id });
    if (consumed === undefined) {
      throw new AccountWalletLinkError(
        409,
        "challenge_used",
        "Wallet challenge has already been used",
      );
    }
    const [identityUser] = await tx
      .select({ status: user.status })
      .from(user)
      .where(eq(user.id, input.userId))
      .for("update")
      .limit(1);
    if (identityUser?.status !== "active") {
      throw new AccountWalletLinkError(
        403,
        "account_unavailable",
        "Identity account is unavailable",
      );
    }
    const [principal] = await tx
      .select()
      .from(walletPrincipal)
      .where(
        and(
          eq(walletPrincipal.accountKind, "eoa"),
          eq(walletPrincipal.family, challenge.family),
          challenge.family === "evm"
            ? sql`lower(${walletPrincipal.address}) = ${normalized}`
            : eq(walletPrincipal.address, normalized),
        ),
      )
      .for("update")
      .limit(1);
    if (principal !== undefined && principal.userId !== input.userId) {
      throw new AccountWalletLinkError(
        409,
        "wallet_conflict",
        "Wallet is already linked to another account",
      );
    }
    const credentialId = principal?.id ?? randomUUID();
    if (principal === undefined) {
      await tx.insert(walletPrincipal).values({
        accountKind: "eoa",
        address:
          challenge.family === "evm"
            ? getAddress(challenge.address)
            : challenge.address,
        family: challenge.family,
        id: credentialId,
        signInEnabled: true,
        userId: input.userId,
      });
    }
    if (challenge.family === "evm" && challenge.chainId !== null) {
      const [firstWallet] = await tx
        .select({ id: walletAddress.id })
        .from(walletAddress)
        .where(eq(walletAddress.userId, input.userId))
        .limit(1);
      await tx
        .insert(walletAddress)
        .values({
          address: getAddress(challenge.address),
          chainId: challenge.chainId,
          createdAt: new Date(),
          id: randomUUID(),
          isPrimary: firstWallet === undefined,
          userId: input.userId,
        })
        .onConflictDoNothing();
    }
    await tx
      .insert(account)
      .values({
        accountId:
          challenge.family === "evm"
            ? `${getAddress(challenge.address)}:${challenge.chainId}`
            : challenge.address,
        id: randomUUID(),
        providerId: challenge.family === "evm" ? "siwe" : "siws",
        userId: input.userId,
      })
      .onConflictDoNothing();
    await tx.insert(identityAuditEvent).values({
      actorUserId: input.userId,
      credentialId,
      id: randomUUID(),
      kind: principal === undefined ? "wallet.linked" : "wallet.authenticated",
      metadata: {
        address: normalized,
        family: challenge.family,
        ...(challenge.chainId === null ? {} : { chainId: challenge.chainId }),
      },
      userId: input.userId,
    });
    return {
      address:
        challenge.family === "evm"
          ? getAddress(challenge.address)
          : challenge.address,
      credentialId,
      linked: true as const,
    };
  });
}
