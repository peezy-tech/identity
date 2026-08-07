import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify as verifyEd25519,
} from "node:crypto";

import bs58 from "bs58";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { z } from "zod";

import {
  HOSTED_WALLET_PROOF_TTL_MS,
  HOSTED_WALLET_STATEMENT,
} from "./constants";
import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import {
  account,
  identityAuditEvent,
  solanaAuthChallenge,
  user,
  walletPrincipal,
} from "./db/schema";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SOLANA_ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export type SolanaAuthMode = "primary" | "proof";

export function parseSolanaAddress(value: string): string {
  if (!SOLANA_ADDRESS_PATTERN.test(value)) {
    throw new Error("Solana address is invalid");
  }
  let bytes: Uint8Array;
  try {
    bytes = bs58.decode(value);
  } catch {
    throw new Error("Solana address is invalid");
  }
  if (bytes.length !== 32 || bs58.encode(bytes) !== value) {
    throw new Error("Solana address is invalid");
  }
  return value;
}

export function createSiwsMessage(input: {
  address: string;
  baseUrl: string;
  expirationTime: Date;
  issuedAt: Date;
  nonce: string;
  statement?: string;
}): string {
  const address = parseSolanaAddress(input.address);
  const origin = new URL(input.baseUrl).origin;
  return `${new URL(origin).host} wants you to sign in with your Solana account:\n${address}\n\n${input.statement ?? HOSTED_WALLET_STATEMENT}\n\nURI: ${origin}\nVersion: 1\nNonce: ${input.nonce}\nIssued At: ${input.issuedAt.toISOString()}\nExpiration Time: ${input.expirationTime.toISOString()}`;
}

export function verifySiwsSignature(input: {
  address: string;
  message: string;
  signature: string;
}): boolean {
  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = bs58.decode(parseSolanaAddress(input.address));
  } catch {
    return false;
  }
  const signature = decodeCanonicalBase64(input.signature);
  if (signature === null || signature.length !== 64) return false;
  try {
    const publicKey = createPublicKey({
      format: "der",
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyBytes]),
      type: "spki",
    });
    return verifyEd25519(
      null,
      Buffer.from(input.message, "utf8"),
      publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

export function solanaAuthPlugin(
  db: IdentityDb,
  config: Pick<IdentityConfig, "baseUrl">,
  mode: SolanaAuthMode,
) {
  return {
    endpoints: {
      createSiwsChallenge: createAuthEndpoint(
        "/siws/challenge",
        {
          method: "POST",
          body: z.object({ address: z.string().min(32).max(44) }),
        },
        async (context) => {
          let address: string;
          try {
            address = parseSolanaAddress(context.body.address);
          } catch {
            throw new APIError("BAD_REQUEST", {
              message: "Solana address is invalid",
            });
          }
          const issuedAt = new Date();
          const expirationTime = new Date(
            issuedAt.getTime() + HOSTED_WALLET_PROOF_TTL_MS,
          );
          const nonce = randomBytes(24).toString("hex");
          const message = createSiwsMessage({
            address,
            baseUrl: config.baseUrl,
            expirationTime,
            issuedAt,
            nonce,
          });
          const id = randomUUID();
          await db.transaction(async (transaction) => {
            await transaction
              .delete(solanaAuthChallenge)
              .where(lt(solanaAuthChallenge.expiresAt, issuedAt));
            await transaction.insert(solanaAuthChallenge).values({
              address,
              expiresAt: expirationTime,
              id,
              message,
              mode,
              nonce,
            });
          });
          return context.json({
            address,
            challengeId: id,
            expiresAt: expirationTime.toISOString(),
            message,
          });
        },
      ),
      verifySiwsChallenge: createAuthEndpoint(
        "/siws/verify",
        {
          method: "POST",
          body: z.object({
            challengeId: z.string().uuid(),
            message: z.string().min(1).max(2_000),
            signature: z.string().min(1).max(256),
          }),
        },
        async (context) => {
          const [challenge] = await db
            .select()
            .from(solanaAuthChallenge)
            .where(
              and(
                eq(solanaAuthChallenge.id, context.body.challengeId),
                eq(solanaAuthChallenge.mode, mode),
                isNull(solanaAuthChallenge.usedAt),
                gt(solanaAuthChallenge.expiresAt, new Date()),
              ),
            )
            .limit(1);
          if (
            challenge === undefined ||
            challenge.message !== context.body.message ||
            !verifySiwsSignature({
              address: challenge.address,
              message: context.body.message,
              signature: context.body.signature,
            })
          ) {
            throw invalidSiwsProof();
          }

          const identityUser = await db.transaction(async (transaction) => {
            await transaction.execute(
              sql`SELECT pg_advisory_xact_lock(hashtext(${`wallet-principal:solana:${challenge.address}`}))`,
            );
            const [consumed] = await transaction
              .update(solanaAuthChallenge)
              .set({ usedAt: new Date() })
              .where(
                and(
                  eq(solanaAuthChallenge.id, challenge.id),
                  isNull(solanaAuthChallenge.usedAt),
                  gt(solanaAuthChallenge.expiresAt, new Date()),
                ),
              )
              .returning({ id: solanaAuthChallenge.id });
            if (consumed === undefined) throw invalidSiwsProof();

            const [owner] = await transaction
              .select({
                signInEnabled: walletPrincipal.signInEnabled,
                status: user.status,
                userId: walletPrincipal.userId,
              })
              .from(walletPrincipal)
              .innerJoin(user, eq(user.id, walletPrincipal.userId))
              .where(
                and(
                  eq(walletPrincipal.family, "solana"),
                  eq(walletPrincipal.address, challenge.address),
                ),
              )
              .for("update")
              .limit(1);
            if (owner !== undefined) {
              if (!owner.signInEnabled || owner.status !== "active") {
                throw invalidSiwsProof();
              }
              const [existingUser] = await transaction
                .select()
                .from(user)
                .where(eq(user.id, owner.userId))
                .limit(1);
              if (existingUser === undefined) throw invalidSiwsProof();
              return existingUser;
            }
            if (mode === "proof") throw invalidSiwsProof();

            const userId = randomUUID();
            const credentialId = randomUUID();
            const now = new Date();
            const [createdUser] = await transaction
              .insert(user)
              .values({
                createdAt: now,
                email: `${createHash("sha256").update(challenge.address).digest("hex")}@solana.wallet.identity.peezy.tech.invalid`,
                emailVerified: false,
                id: userId,
                name: `${challenge.address.slice(0, 6)}…${challenge.address.slice(-6)}`,
                status: "active",
                updatedAt: now,
              })
              .returning();
            await transaction.insert(walletPrincipal).values({
              accountKind: "eoa",
              address: challenge.address,
              family: "solana",
              id: credentialId,
              signInEnabled: true,
              userId,
            });
            await transaction.insert(account).values({
              accountId: challenge.address,
              id: randomUUID(),
              providerId: "siws",
              userId,
            });
            await transaction.insert(identityAuditEvent).values({
              actorUserId: userId,
              credentialId,
              id: randomUUID(),
              kind: "wallet.linked",
              metadata: { address: challenge.address, family: "solana" },
              userId,
            });
            if (createdUser === undefined) {
              throw new APIError("INTERNAL_SERVER_ERROR", {
                message: "Identity account could not be created",
              });
            }
            return createdUser;
          });

          const session = await context.context.internalAdapter.createSession(
            identityUser.id,
          );
          if (session === null) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Identity session could not be created",
            });
          }
          await setSessionCookie(context, { session, user: identityUser });
          return context.json({
            session: { expiresAt: session.expiresAt, id: session.id },
            user: { id: identityUser.id },
          });
        },
      ),
    },
    id: `peezy-solana-auth-${mode}`,
  } as const;
}

function decodeCanonicalBase64(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    return null;
  }
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.toString("base64") === value ? decoded : null;
  } catch {
    return null;
  }
}

function invalidSiwsProof(): APIError {
  return new APIError("UNAUTHORIZED", {
    message: "Solana wallet proof is invalid or expired",
  });
}
