import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  PeezyUserSchema,
  type PeezyUser,
  type WalletChallengeResponse,
  type WalletGrantResponse,
} from "@peezy.tech/identity";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { getAddress, verifyMessage, type Hex } from "viem";
import { createSiweMessage, parseSiweMessage } from "viem/siwe";

import type { IdentityDb } from "./db/client";
import {
  account,
  appClient,
  identityAuditEvent,
  user,
  walletAddress,
  walletChallenge,
  walletGrant,
  walletPrincipal,
} from "./db/schema";
import { consumeRateLimit } from "./rate-limit";

export const WALLET_CHALLENGE_TTL_MS = 10 * 60 * 1_000;
export const WALLET_GRANT_TTL_MS = 5 * 60 * 1_000;

export class WalletGrantError extends Error {
  readonly status: 400 | 401 | 403 | 404 | 409 | 429;

  constructor(status: WalletGrantError["status"], message: string) {
    super(message);
    this.name = "WalletGrantError";
    this.status = status;
  }
}

export async function createWalletChallenge(input: {
  address: string;
  chainId: number;
  clientIp: string;
  clientId: string;
  db: IdentityDb;
  now?: Date;
  origin: string;
  purpose?: "link" | "sign-in";
}): Promise<WalletChallengeResponse> {
  const [client] = await input.db
    .select()
    .from(appClient)
    .where(eq(appClient.id, input.clientId))
    .limit(1);
  if (client === undefined || client.disabled) {
    throw new WalletGrantError(404, "Unknown identity application");
  }
  const origin = new URL(input.origin).origin;
  if (!client.origins.includes(origin)) {
    throw new WalletGrantError(
      403,
      "Origin is not registered for this application",
    );
  }

  const issuedAt = input.now ?? new Date();
  const address = getAddress(input.address).toLowerCase() as `0x${string}`;
  if (
    !(await consumeRateLimit({
      db: input.db,
      key: `wallet-challenge:${client.id}:${origin}:${input.clientIp}:${address}`,
      limit: 20,
      now: issuedAt.getTime(),
      windowMs: 5 * 60 * 1_000,
    }))
  ) {
    throw new WalletGrantError(429, "Too many identity requests");
  }
  const expiresAt = new Date(issuedAt.getTime() + WALLET_CHALLENGE_TTL_MS);
  const nonce = randomBytes(24).toString("hex");
  const domain = new URL(origin).host;
  const purpose = input.purpose ?? "sign-in";
  const statement =
    purpose === "link" ? client.walletLinkSiweStatement : client.siweStatement;
  const message = createSiweMessage({
    address: getAddress(address),
    chainId: input.chainId,
    domain,
    expirationTime: expiresAt,
    issuedAt,
    nonce,
    statement,
    uri: origin,
    version: "1",
  });

  await input.db.transaction(async (transaction) => {
    await transaction
      .delete(walletChallenge)
      .where(lt(walletChallenge.expiresAt, issuedAt));
    await transaction.insert(walletChallenge).values({
      address,
      chainId: input.chainId,
      clientId: client.id,
      domain,
      expiresAt,
      issuedAt,
      nonce,
      purpose,
      statement,
      uri: origin,
    });
  });

  return {
    address,
    chainId: input.chainId,
    domain,
    expirationTime: expiresAt.toISOString(),
    issuedAt: issuedAt.toISOString(),
    message,
    nonce,
    statement,
    uri: origin,
    version: "1",
  };
}

export async function createWalletGrant(input: {
  clientIp?: string;
  clientId: string;
  db: IdentityDb;
  message: string;
  now?: Date;
  origin?: string;
  sessionSubject?: string;
  signature: string;
}): Promise<WalletGrantResponse> {
  let parsed: ReturnType<typeof parseSiweMessage>;
  try {
    parsed = parseSiweMessage(input.message);
  } catch {
    throw new WalletGrantError(400, "SIWE message is invalid");
  }
  if (
    parsed.nonce === undefined ||
    parsed.address === undefined ||
    parsed.chainId === undefined
  ) {
    throw new WalletGrantError(400, "SIWE message is missing required fields");
  }

  const now = input.now ?? new Date();
  const [challenge] = await input.db
    .select()
    .from(walletChallenge)
    .where(eq(walletChallenge.nonce, parsed.nonce))
    .limit(1);
  if (challenge === undefined || challenge.clientId !== input.clientId) {
    throw new WalletGrantError(400, "Unknown SIWE challenge");
  }
  if (
    input.origin !== undefined &&
    new URL(input.origin).origin !== new URL(challenge.uri).origin
  ) {
    throw new WalletGrantError(403, "Origin does not match the SIWE challenge");
  }
  if (challenge.usedAt !== null) {
    throw new WalletGrantError(409, "SIWE challenge has already been used");
  }
  if (challenge.expiresAt.getTime() <= now.getTime()) {
    throw new WalletGrantError(400, "SIWE challenge has expired");
  }
  if (
    input.clientIp !== undefined &&
    input.origin !== undefined &&
    !(await consumeRateLimit({
      db: input.db,
      key: `wallet-grant:${challenge.clientId}:${new URL(challenge.uri).origin}:${input.clientIp}:${challenge.address.toLowerCase()}`,
      limit: 30,
      now: now.getTime(),
      windowMs: 5 * 60 * 1_000,
    }))
  ) {
    throw new WalletGrantError(429, "Too many identity requests");
  }

  const expectedMessage = createSiweMessage({
    address: getAddress(challenge.address),
    chainId: challenge.chainId,
    domain: challenge.domain,
    expirationTime: challenge.expiresAt,
    issuedAt: challenge.issuedAt,
    nonce: challenge.nonce,
    statement: challenge.statement,
    uri: challenge.uri,
    version: "1",
  });
  if (input.message !== expectedMessage) {
    throw new WalletGrantError(
      400,
      "SIWE message does not match its challenge",
    );
  }
  let signatureValid = false;
  try {
    signatureValid = await verifyMessage({
      address: getAddress(challenge.address),
      message: input.message,
      signature: input.signature as Hex,
    });
  } catch {
    // viem throws for structurally malformed signatures instead of returning
    // false. Treat both outcomes as failed authentication.
  }
  if (!signatureValid) {
    throw new WalletGrantError(401, "SIWE signature is invalid");
  }

  const rawGrant = randomBytes(32).toString("base64url");
  const expiresAt = new Date(now.getTime() + WALLET_GRANT_TTL_MS);
  const identity = await input.db.transaction(async (tx) => {
    const normalizedAddress = getAddress(challenge.address).toLowerCase();
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtext(${`wallet-principal:evm:${normalizedAddress}`}))`,
    );

    const consumed = await tx
      .update(walletChallenge)
      .set({ usedAt: now })
      .where(
        and(
          eq(walletChallenge.nonce, challenge.nonce),
          isNull(walletChallenge.usedAt),
          gt(walletChallenge.expiresAt, now),
        ),
      )
      .returning({ nonce: walletChallenge.nonce });
    if (consumed[0] === undefined) {
      throw new WalletGrantError(409, "SIWE challenge could not be consumed");
    }

    const [existingPrincipal] = await tx
      .select()
      .from(walletPrincipal)
      .where(
        and(
          eq(walletPrincipal.accountKind, "eoa"),
          sql`lower(${walletPrincipal.address}) = ${normalizedAddress}`,
        ),
      )
      .for("update")
      .limit(1);

    if (challenge.purpose === "link" && input.sessionSubject === undefined) {
      throw new WalletGrantError(
        401,
        "An authenticated identity session is required to link a wallet",
      );
    }
    const linkSubject =
      challenge.purpose === "link" ? input.sessionSubject : undefined;
    if (
      linkSubject !== undefined &&
      existingPrincipal !== undefined &&
      existingPrincipal.userId !== linkSubject
    ) {
      throw new WalletGrantError(
        409,
        "Wallet is already linked to another account",
      );
    }
    if (
      challenge.purpose === "sign-in" &&
      existingPrincipal !== undefined &&
      !existingPrincipal.signInEnabled
    ) {
      throw new WalletGrantError(
        403,
        "Wallet sign-in is disabled for this credential",
      );
    }

    let subject = linkSubject ?? existingPrincipal?.userId;
    if (subject !== undefined) {
      const [existingUser] = await tx
        .select()
        .from(user)
        .where(eq(user.id, subject))
        .limit(1);
      if (existingUser === undefined || existingUser.status !== "active") {
        throw new WalletGrantError(403, "Identity account is unavailable");
      }
    } else {
      subject = randomUUID();
      const checksumAddress = getAddress(challenge.address);
      await tx.insert(user).values({
        createdAt: now,
        email: walletEmail(checksumAddress),
        emailVerified: false,
        id: subject,
        name: checksumAddress,
        status: "active",
        updatedAt: now,
      });
    }

    let principalId = existingPrincipal?.id;
    if (principalId === undefined) {
      principalId = randomUUID();
      await tx.insert(walletPrincipal).values({
        accountKind: "eoa",
        address: getAddress(challenge.address),
        createdAt: now,
        family: "evm",
        id: principalId,
        signInEnabled: true,
        updatedAt: now,
        userId: subject,
      });
    }

    const [existingWallet] = await tx
      .select({ id: walletAddress.id })
      .from(walletAddress)
      .where(eq(walletAddress.userId, subject))
      .limit(1);
    await tx
      .insert(walletAddress)
      .values({
        address: getAddress(challenge.address),
        chainId: challenge.chainId,
        createdAt: now,
        id: randomUUID(),
        isPrimary: existingWallet === undefined,
        userId: subject,
      })
      .onConflictDoNothing();
    await tx
      .insert(account)
      .values({
        accountId: `${getAddress(challenge.address)}:${challenge.chainId}`,
        createdAt: now,
        id: randomUUID(),
        providerId: "siwe",
        updatedAt: now,
        userId: subject,
      })
      .onConflictDoNothing();

    const grantId = randomUUID();
    await tx.delete(walletGrant).where(lt(walletGrant.expiresAt, now));
    await tx.insert(walletGrant).values({
      clientId: challenge.clientId,
      createdAt: now,
      expiresAt,
      grantHash: opaqueHash(rawGrant),
      id: grantId,
      userId: subject,
    });
    await tx.insert(identityAuditEvent).values({
      actorUserId: subject,
      clientId: challenge.clientId,
      createdAt: now,
      credentialId: principalId,
      id: randomUUID(),
      kind:
        existingPrincipal === undefined
          ? "wallet.linked"
          : "wallet.authenticated",
      metadata: {
        address: normalizedAddress,
        chainId: challenge.chainId,
      },
      userId: subject,
    });

    const [createdUser] = await tx
      .select()
      .from(user)
      .where(eq(user.id, subject))
      .limit(1);
    if (createdUser === undefined) {
      throw new Error("Created identity user is missing");
    }
    return toPeezyUser(createdUser);
  });

  return {
    expiresAt: expiresAt.toISOString(),
    grant: rawGrant,
    user: identity,
  };
}

export async function exchangeWalletGrant(input: {
  clientId: string;
  db: IdentityDb;
  grant: string;
  now?: Date;
}): Promise<{ expiresAt: string; subject: string }> {
  const now = input.now ?? new Date();
  const [consumed] = await input.db
    .update(walletGrant)
    .set({ consumedAt: now })
    .where(
      and(
        eq(walletGrant.clientId, input.clientId),
        eq(walletGrant.grantHash, opaqueHash(input.grant)),
        isNull(walletGrant.consumedAt),
        gt(walletGrant.expiresAt, now),
      ),
    )
    .returning({
      expiresAt: walletGrant.expiresAt,
      subject: walletGrant.userId,
    });
  if (consumed === undefined) {
    throw new WalletGrantError(401, "Wallet grant is invalid or expired");
  }
  return {
    expiresAt: consumed.expiresAt.toISOString(),
    subject: consumed.subject,
  };
}

function walletEmail(address: string): string {
  return `${createHash("sha256")
    .update(address.toLowerCase())
    .digest("hex")}@wallet.identity.peezy.tech.invalid`;
}

function opaqueHash(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function toPeezyUser(input: {
  createdAt: Date;
  email: string;
  emailVerified: boolean;
  id: string;
  image: string | null;
  name: string;
  status: string;
}): PeezyUser {
  const syntheticEmail = input.email.endsWith(".invalid");
  const displayName = input.name.trim().slice(0, 128);
  const avatarUrl = PeezyUserSchema.shape.avatarUrl
    .unwrap()
    .safeParse(input.image?.trim());
  const primaryEmail = PeezyUserSchema.shape.primaryEmail.unwrap().safeParse({
    value: input.email,
    verified: input.emailVerified,
  });
  return PeezyUserSchema.parse({
    createdAt: input.createdAt.toISOString(),
    id: input.id,
    status: input.status === "disabled" ? "disabled" : "active",
    ...(avatarUrl.success ? { avatarUrl: avatarUrl.data } : {}),
    ...(displayName.length === 0 ? {} : { displayName }),
    ...(syntheticEmail || !primaryEmail.success
      ? {}
      : { primaryEmail: primaryEmail.data }),
  });
}
