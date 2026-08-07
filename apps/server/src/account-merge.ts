import { and, eq, inArray, lt, ne, or, sql } from "drizzle-orm";

import type { IdentityDb } from "./db/client";
import {
  account,
  accountWalletLinkChallenge,
  identityAuditEvent,
  identitySubjectMerge,
  invitation,
  member,
  oauthAccessToken,
  oauthClient,
  oauthConsent,
  oauthRefreshToken,
  privyMigrationClaim,
  privyMigrationAttempt,
  session,
  sessionHandoff,
  solanaAuthChallenge,
  user,
  walletAddress,
  walletChallenge,
  walletGrant,
  walletPrincipal,
} from "./db/schema";
import { identityMe } from "./identity";

const MERGE_ATTEMPT_TTL_MS = 10 * 60_000;

export class AccountMergeError extends Error {
  readonly code: string;
  readonly status: 400 | 401 | 403 | 404 | 409;

  constructor(
    status: AccountMergeError["status"],
    code: string,
    message: string,
  ) {
    super(message);
    this.name = "AccountMergeError";
    this.status = status;
    this.code = code;
  }
}

export type AccountMergePreview = {
  attemptId: string;
  expiresAt: string;
  source: {
    credentialCount: number;
    credentialKinds: string[];
    displayName?: string;
  };
};

export async function createAccountMergeAttempt(input: {
  db: IdentityDb;
  sourceUserId: string;
  targetUserId: string;
}): Promise<AccountMergePreview> {
  if (input.sourceUserId === input.targetUserId) {
    throw new AccountMergeError(
      409,
      "same_account",
      "Choose a different peezy.tech account to consolidate",
    );
  }
  const source = await identityMe(input.db, input.sourceUserId);
  const expiresAt = new Date(Date.now() + MERGE_ATTEMPT_TTL_MS);
  const [attempt] = await input.db.transaction(async (transaction) => {
    await transaction
      .delete(identitySubjectMerge)
      .where(
        and(
          eq(identitySubjectMerge.status, "prepared"),
          lt(identitySubjectMerge.expiresAt, new Date()),
        ),
      );
    return transaction
      .insert(identitySubjectMerge)
      .values({
        actorUserId: input.targetUserId,
        expiresAt,
        id: crypto.randomUUID(),
        metadata: {},
        sourceUserId: input.sourceUserId,
        status: "prepared",
        targetUserId: input.targetUserId,
      })
      .onConflictDoNothing({ target: identitySubjectMerge.sourceUserId })
      .returning({ id: identitySubjectMerge.id });
  });
  if (attempt === undefined) {
    throw new AccountMergeError(
      409,
      "attempt_failed",
      "Account consolidation could not be prepared",
    );
  }
  return {
    attemptId: attempt.id,
    expiresAt: expiresAt.toISOString(),
    source: {
      credentialCount: source.credentials.length,
      credentialKinds: [
        ...new Set(source.credentials.map((credential) => credential.kind)),
      ].sort(),
      ...(source.user.displayName === undefined
        ? {}
        : { displayName: source.user.displayName }),
    },
  };
}

export async function commitAccountMerge(input: {
  attemptId: string;
  db: IdentityDb;
  targetUserId: string;
}): Promise<{ merged: true }> {
  await input.db.transaction(async (transaction) => {
    const [attempt] = await transaction
      .select()
      .from(identitySubjectMerge)
      .where(
        and(
          eq(identitySubjectMerge.id, input.attemptId),
          eq(identitySubjectMerge.targetUserId, input.targetUserId),
          eq(identitySubjectMerge.status, "prepared"),
          sql`${identitySubjectMerge.expiresAt} > now()`,
        ),
      )
      .for("update")
      .limit(1);
    if (attempt === undefined) {
      throw new AccountMergeError(
        403,
        "invalid_attempt",
        "Account consolidation attempt is invalid or expired",
      );
    }

    const identities = await transaction
      .select({
        email: user.email,
        emailVerified: user.emailVerified,
        id: user.id,
        status: user.status,
      })
      .from(user)
      .where(inArray(user.id, [attempt.sourceUserId, attempt.targetUserId]))
      .for("update");
    const source = identities.find((item) => item.id === attempt.sourceUserId);
    const target = identities.find((item) => item.id === attempt.targetUserId);
    if (
      source === undefined ||
      target === undefined ||
      source.status !== "active" ||
      target.status !== "active"
    ) {
      throw new AccountMergeError(
        409,
        "account_unavailable",
        "Both accounts must be active and unmerged",
      );
    }

    const [ownedMembership, sentInvitation, ownedClient] = await Promise.all([
      transaction
        .select({ id: member.id })
        .from(member)
        .where(eq(member.userId, attempt.sourceUserId))
        .limit(1),
      transaction
        .select({ id: invitation.id })
        .from(invitation)
        .where(eq(invitation.inviterId, attempt.sourceUserId))
        .limit(1),
      transaction
        .select({ id: oauthClient.id })
        .from(oauthClient)
        .where(eq(oauthClient.userId, attempt.sourceUserId))
        .limit(1),
    ]);
    if (
      ownedMembership[0] !== undefined ||
      sentInvitation[0] !== undefined ||
      ownedClient[0] !== undefined
    ) {
      throw new AccountMergeError(
        409,
        "support_required",
        "This account owns organization or application state and requires support",
      );
    }

    const sourceHasEmailCredential = !source.email.endsWith(".invalid");
    if (sourceHasEmailCredential && !target.email.endsWith(".invalid")) {
      throw new AccountMergeError(
        409,
        "support_required",
        "Both accounts have email credentials and require support",
      );
    }
    if (sourceHasEmailCredential) {
      await transaction
        .update(user)
        .set({
          email: `merged-${crypto.randomUUID()}@identity.peezy.tech.invalid`,
          emailVerified: false,
          updatedAt: new Date(),
        })
        .where(eq(user.id, attempt.sourceUserId));
      await transaction
        .update(user)
        .set({
          email: source.email,
          emailVerified: source.emailVerified,
          updatedAt: new Date(),
        })
        .where(eq(user.id, attempt.targetUserId));
    }

    const affectedPrincipals = await transaction
      .select({
        address: walletPrincipal.address,
        family: walletPrincipal.family,
      })
      .from(walletPrincipal)
      .where(
        inArray(walletPrincipal.userId, [
          attempt.sourceUserId,
          attempt.targetUserId,
        ]),
      );
    const [targetPrimary] = await transaction
      .select({ id: walletAddress.id })
      .from(walletAddress)
      .where(
        and(
          eq(walletAddress.userId, attempt.targetUserId),
          eq(walletAddress.isPrimary, true),
        ),
      )
      .limit(1);
    if (targetPrimary !== undefined) {
      await transaction
        .update(walletAddress)
        .set({ isPrimary: false })
        .where(eq(walletAddress.userId, attempt.sourceUserId));
    }

    await transaction
      .update(account)
      .set({ userId: attempt.targetUserId, updatedAt: new Date() })
      .where(eq(account.userId, attempt.sourceUserId));
    await transaction
      .update(walletPrincipal)
      .set({ userId: attempt.targetUserId, updatedAt: new Date() })
      .where(eq(walletPrincipal.userId, attempt.sourceUserId));
    await transaction
      .update(walletAddress)
      .set({ userId: attempt.targetUserId })
      .where(eq(walletAddress.userId, attempt.sourceUserId));
    await transaction
      .update(privyMigrationClaim)
      .set({ userId: attempt.targetUserId, updatedAt: new Date() })
      .where(eq(privyMigrationClaim.userId, attempt.sourceUserId));

    const userIds = [attempt.sourceUserId, attempt.targetUserId];
    await transaction
      .delete(oauthAccessToken)
      .where(inArray(oauthAccessToken.userId, userIds));
    await transaction
      .delete(oauthRefreshToken)
      .where(inArray(oauthRefreshToken.userId, userIds));
    await transaction
      .delete(oauthConsent)
      .where(inArray(oauthConsent.userId, userIds));
    await transaction
      .delete(sessionHandoff)
      .where(inArray(sessionHandoff.userId, userIds));
    await transaction
      .delete(walletGrant)
      .where(inArray(walletGrant.userId, userIds));
    await transaction
      .delete(accountWalletLinkChallenge)
      .where(inArray(accountWalletLinkChallenge.userId, userIds));
    await transaction
      .delete(privyMigrationAttempt)
      .where(inArray(privyMigrationAttempt.userId, userIds));
    await transaction
      .delete(identitySubjectMerge)
      .where(
        and(
          eq(identitySubjectMerge.status, "prepared"),
          ne(identitySubjectMerge.id, attempt.id),
          or(
            inArray(identitySubjectMerge.sourceUserId, userIds),
            inArray(identitySubjectMerge.targetUserId, userIds),
          ),
        ),
      );
    const affectedEvmAddresses = affectedPrincipals
      .filter((principal) => principal.family === "evm")
      .map((principal) => principal.address.toLowerCase());
    if (affectedEvmAddresses.length > 0) {
      await transaction.delete(walletChallenge).where(
        sql`lower(${walletChallenge.address}) IN (${sql.join(
          affectedEvmAddresses.map((address) => sql`${address}`),
          sql`, `,
        )})`,
      );
    }
    const affectedSolanaAddresses = affectedPrincipals
      .filter((principal) => principal.family === "solana")
      .map((principal) => principal.address);
    if (affectedSolanaAddresses.length > 0) {
      await transaction
        .delete(solanaAuthChallenge)
        .where(inArray(solanaAuthChallenge.address, affectedSolanaAddresses));
    }

    await transaction
      .update(identitySubjectMerge)
      .set({
        committedAt: new Date(),
        metadata: { proofId: attempt.id },
        status: "committed",
      })
      .where(eq(identitySubjectMerge.id, attempt.id));
    await transaction
      .update(user)
      .set({ status: "merged", updatedAt: new Date() })
      .where(eq(user.id, attempt.sourceUserId));
    await transaction.insert(identityAuditEvent).values({
      actorUserId: attempt.targetUserId,
      id: crypto.randomUUID(),
      kind: "identity.merge-committed",
      metadata: {
        attemptId: attempt.id,
        sourceUserId: attempt.sourceUserId,
      },
      userId: attempt.targetUserId,
    });
    await transaction.delete(session).where(inArray(session.userId, userIds));
  });
  return { merged: true };
}
