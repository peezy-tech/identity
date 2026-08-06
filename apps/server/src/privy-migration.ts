import { createHash, randomBytes } from "node:crypto";

import { PrivyClient } from "@privy-io/node";
import { and, eq, gt, inArray, isNull, sql } from "drizzle-orm";

import type { PrivyMigrationConfig, SocialProviderName } from "./config";
import type { IdentityDb } from "./db/client";
import {
  account,
  identityAuditEvent,
  privyMigrationAttempt,
  privyMigrationClaim,
  privyMigrationIdentity,
  walletPrincipal,
} from "./db/schema";
import { parseSolanaAddress } from "./solana-auth";

const ATTEMPT_TTL_MS = 10 * 60_000;
const SUPPORTED_SOCIAL_TYPES: Record<string, SocialProviderName | undefined> = {
  apple_oauth: "apple",
  discord_oauth: "discord",
  github_oauth: "github",
  telegram: "telegram",
  telegram_oauth: "telegram",
  twitter_oauth: "twitter",
};

export type PrivyLinkedAccount = Record<string, unknown> & { type: string };

export type PrivyUserRecord = {
  createdAt: Date;
  id: string;
  linkedAccounts: PrivyLinkedAccount[];
};

export type PrivyGateway = {
  authenticateAccessToken(accessToken: string): Promise<PrivyUserRecord>;
};

export type PrivyIdentityDisposition =
  | "already_linked"
  | "needs_reverification"
  | "legacy_only"
  | "conflict"
  | "linked";

export type PrivyMigrationIdentityView = {
  chainType?: string;
  displayHint: string;
  disposition: PrivyIdentityDisposition;
  id: string;
  provider?: string;
  type: string;
  walletAddress?: string;
  walletType?: string;
};

export type PrivyMigrationClaimView = {
  claimedAt: string;
  id: string;
  identities: PrivyMigrationIdentityView[];
  privyUserHint: string;
};

type NormalizedPrivyIdentity = {
  chainType?: string;
  displayHint: string;
  metadata: Record<string, unknown>;
  provider?: SocialProviderName;
  sourceAccountId: string;
  sourceKey: string;
  type: string;
  verifiedAt?: Date;
  walletAddress?: string;
  walletType?: string;
};

export class PrivyMigrationError extends Error {
  readonly code: string;
  readonly status: 400 | 401 | 403 | 404 | 409 | 429 | 503;

  constructor(
    status: PrivyMigrationError["status"],
    code: string,
    message: string,
  ) {
    super(message);
    this.name = "PrivyMigrationError";
    this.status = status;
    this.code = code;
  }
}

export function createPrivyGateway(config: PrivyMigrationConfig): PrivyGateway {
  const client = new PrivyClient({
    appId: config.appId,
    appSecret: config.appSecret,
    ...(config.jwtVerificationKey === undefined
      ? {}
      : { jwtVerificationKey: config.jwtVerificationKey }),
  });
  return {
    async authenticateAccessToken(accessToken) {
      const verified = await client
        .utils()
        .auth()
        .verifyAccessToken(accessToken)
        .catch(() => {
          throw new PrivyMigrationError(
            401,
            "invalid_proof",
            "Privy authentication could not be verified",
          );
        });
      if (verified.app_id !== config.appId) {
        throw new PrivyMigrationError(
          401,
          "invalid_proof",
          "Privy authentication belongs to a different application",
        );
      }
      let privyUser: Awaited<
        ReturnType<ReturnType<typeof client.users>["_get"]>
      >;
      try {
        privyUser = await client.users()._get(verified.user_id);
      } catch {
        throw new PrivyMigrationError(
          503,
          "privy_unavailable",
          "Privy account details are temporarily unavailable",
        );
      }
      if (privyUser.id !== verified.user_id) {
        throw new PrivyMigrationError(
          401,
          "invalid_proof",
          "Privy account identity did not match the verified session",
        );
      }
      return {
        createdAt: new Date(privyUser.created_at * 1_000),
        id: privyUser.id,
        linkedAccounts:
          privyUser.linked_accounts as unknown as PrivyLinkedAccount[],
      };
    },
  };
}

export async function createPrivyMigrationAttempt(
  db: IdentityDb,
  userId: string,
): Promise<{ attemptId: string; csrfToken: string; expiresAt: string }> {
  const csrfToken = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + ATTEMPT_TTL_MS);
  const [attempt] = await db
    .insert(privyMigrationAttempt)
    .values({
      csrfHash: opaqueHash(csrfToken),
      expiresAt,
      id: crypto.randomUUID(),
      userId,
    })
    .returning({ id: privyMigrationAttempt.id });
  if (attempt === undefined) {
    throw new PrivyMigrationError(
      503,
      "attempt_unavailable",
      "Migration could not be started",
    );
  }
  return {
    attemptId: attempt.id,
    csrfToken,
    expiresAt: expiresAt.toISOString(),
  };
}

export async function claimPrivyMigration(input: {
  accessToken: string;
  attemptId: string;
  csrfToken: string;
  db: IdentityDb;
  gateway: PrivyGateway;
  userId: string;
}): Promise<PrivyMigrationClaimView> {
  const [preflight] = await input.db
    .select({ id: privyMigrationAttempt.id })
    .from(privyMigrationAttempt)
    .where(
      and(
        eq(privyMigrationAttempt.id, input.attemptId),
        eq(privyMigrationAttempt.userId, input.userId),
        eq(privyMigrationAttempt.csrfHash, opaqueHash(input.csrfToken)),
        isNull(privyMigrationAttempt.consumedAt),
        gt(privyMigrationAttempt.expiresAt, new Date()),
      ),
    )
    .limit(1);
  if (preflight === undefined) {
    throw new PrivyMigrationError(
      403,
      "invalid_attempt",
      "Migration attempt is invalid or expired",
    );
  }

  const privyUser = await input.gateway.authenticateAccessToken(
    input.accessToken,
  );
  const normalized = normalizePrivyIdentities(privyUser.linkedAccounts);
  const snapshotDigest = createHash("sha256")
    .update(JSON.stringify(normalized))
    .digest("hex");

  const outcome = await input.db.transaction(async (transaction) => {
    const [consumed] = await transaction
      .update(privyMigrationAttempt)
      .set({ consumedAt: new Date() })
      .where(
        and(
          eq(privyMigrationAttempt.id, input.attemptId),
          eq(privyMigrationAttempt.userId, input.userId),
          eq(privyMigrationAttempt.csrfHash, opaqueHash(input.csrfToken)),
          isNull(privyMigrationAttempt.consumedAt),
          gt(privyMigrationAttempt.expiresAt, new Date()),
        ),
      )
      .returning({ id: privyMigrationAttempt.id });
    if (consumed === undefined) return { kind: "invalid" as const };

    await transaction.execute(
      sql`SELECT pg_advisory_xact_lock(hashtext(${`privy-claim:${privyUser.id}`}))`,
    );

    const [existing] = await transaction
      .select()
      .from(privyMigrationClaim)
      .where(eq(privyMigrationClaim.privyUserId, privyUser.id))
      .limit(1);
    if (existing !== undefined && existing.userId !== input.userId) {
      return { kind: "claimed_elsewhere" as const };
    }

    const claim =
      existing ??
      (
        await transaction
          .insert(privyMigrationClaim)
          .values({
            id: crypto.randomUUID(),
            privyUserId: privyUser.id,
            snapshotDigest,
            userId: input.userId,
          })
          .returning()
      )[0];
    if (claim === undefined) return { kind: "invalid" as const };

    if (existing !== undefined) {
      await transaction
        .update(privyMigrationClaim)
        .set({ snapshotDigest, updatedAt: new Date() })
        .where(eq(privyMigrationClaim.id, claim.id));
    }

    for (const identity of normalized) {
      const resolved = await resolveDisposition(
        transaction,
        input.userId,
        identity,
      );
      await transaction
        .insert(privyMigrationIdentity)
        .values({
          claimId: claim.id,
          displayHint: identity.displayHint,
          disposition: resolved.disposition,
          id: crypto.randomUUID(),
          metadata: identity.metadata,
          sourceAccountId: identity.sourceAccountId,
          sourceKey: identity.sourceKey,
          type: identity.type,
          ...(identity.chainType === undefined
            ? {}
            : { chainType: identity.chainType }),
          ...(identity.provider === undefined
            ? {}
            : { provider: identity.provider }),
          ...(resolved.targetCredentialId === undefined
            ? {}
            : { targetCredentialId: resolved.targetCredentialId }),
          ...(identity.verifiedAt === undefined
            ? {}
            : { verifiedAt: identity.verifiedAt }),
          ...(identity.walletAddress === undefined
            ? {}
            : { walletAddress: identity.walletAddress }),
          ...(identity.walletType === undefined
            ? {}
            : { walletType: identity.walletType }),
        })
        .onConflictDoUpdate({
          target: [
            privyMigrationIdentity.claimId,
            privyMigrationIdentity.sourceKey,
          ],
          set: {
            displayHint: identity.displayHint,
            disposition: resolved.disposition,
            metadata: identity.metadata,
            targetCredentialId: resolved.targetCredentialId ?? null,
            updatedAt: new Date(),
          },
        });
    }

    if (existing === undefined) {
      await transaction.insert(identityAuditEvent).values({
        actorUserId: input.userId,
        id: crypto.randomUUID(),
        kind: "migration.privy-claimed",
        metadata: {
          identityCount: normalized.length,
          privyUserHint: privyUserHint(privyUser.id),
          snapshotDigest,
        },
        userId: input.userId,
      });
    }
    return { claimId: claim.id, kind: "claimed" as const };
  });

  if (outcome.kind === "invalid") {
    throw new PrivyMigrationError(
      403,
      "invalid_attempt",
      "Migration attempt is invalid or expired",
    );
  }
  if (outcome.kind === "claimed_elsewhere") {
    throw new PrivyMigrationError(
      409,
      "claimed_elsewhere",
      "This Privy account is already claimed by another peezy.tech account",
    );
  }
  const claims = await listCurrentPrivyClaims(input.db, input.userId);
  const claimed = claims.find((claim) => claim.id === outcome.claimId);
  if (claimed === undefined) {
    throw new PrivyMigrationError(
      503,
      "claim_unavailable",
      "Migration claim could not be loaded",
    );
  }
  return claimed;
}

export async function listCurrentPrivyClaims(
  db: IdentityDb,
  userId: string,
): Promise<PrivyMigrationClaimView[]> {
  const claims = await db
    .select()
    .from(privyMigrationClaim)
    .where(
      and(
        eq(privyMigrationClaim.userId, userId),
        eq(privyMigrationClaim.state, "claimed"),
      ),
    );
  if (claims.length === 0) return [];
  const identities = await db
    .select()
    .from(privyMigrationIdentity)
    .where(
      inArray(
        privyMigrationIdentity.claimId,
        claims.map((claim) => claim.id),
      ),
    );

  const views: PrivyMigrationClaimView[] = [];
  for (const claim of claims) {
    const claimIdentities = identities.filter(
      (identity) => identity.claimId === claim.id,
    );
    const identityViews: PrivyMigrationIdentityView[] = [];
    for (const identity of claimIdentities) {
      const normalized = persistedIdentity(identity);
      const resolved = await resolveDisposition(db, userId, normalized);
      let disposition = resolved.disposition;
      if (
        identity.disposition === "needs_reverification" &&
        resolved.disposition === "already_linked"
      ) {
        disposition = "linked";
        await db.transaction(async (transaction) => {
          const [updated] = await transaction
            .update(privyMigrationIdentity)
            .set({
              disposition,
              targetCredentialId: resolved.targetCredentialId ?? null,
              updatedAt: new Date(),
            })
            .where(
              and(
                eq(privyMigrationIdentity.id, identity.id),
                eq(privyMigrationIdentity.disposition, "needs_reverification"),
              ),
            )
            .returning({ id: privyMigrationIdentity.id });
          if (updated !== undefined) {
            await transaction.insert(identityAuditEvent).values({
              actorUserId: userId,
              credentialId: resolved.targetCredentialId,
              id: crypto.randomUUID(),
              kind: "migration.privy-identity-linked",
              metadata: { claimId: claim.id, type: identity.type },
              userId,
            });
          }
        });
      } else if (identity.disposition === "linked") {
        disposition = "linked";
      }
      identityViews.push({
        displayHint: identity.displayHint,
        disposition,
        id: identity.id,
        type: identity.type,
        ...(identity.chainType === null
          ? {}
          : { chainType: identity.chainType }),
        ...(identity.provider === null ? {} : { provider: identity.provider }),
        ...(identity.walletAddress === null
          ? {}
          : { walletAddress: identity.walletAddress }),
        ...(identity.walletType === null
          ? {}
          : { walletType: identity.walletType }),
      });
    }
    views.push({
      claimedAt: claim.claimedAt.toISOString(),
      id: claim.id,
      identities: identityViews.sort((left, right) =>
        left.type.localeCompare(right.type),
      ),
      privyUserHint: privyUserHint(claim.privyUserId),
    });
  }
  return views.sort((left, right) =>
    left.claimedAt.localeCompare(right.claimedAt),
  );
}

export function normalizePrivyIdentities(
  linkedAccounts: PrivyLinkedAccount[],
): NormalizedPrivyIdentity[] {
  const normalized = new Map<string, NormalizedPrivyIdentity>();
  for (const linkedAccount of linkedAccounts) {
    const type = stringField(linkedAccount, "type") ?? "unknown";
    const sourceAccountId = firstStringField(linkedAccount, [
      "subject",
      "user_id",
      "id",
      "credential_id",
      "address",
      "email",
      "number",
      "fid",
      "telegram_user_id",
      "custom_user_id",
      "public_key",
    ]);
    const fallback = createHash("sha256")
      .update(JSON.stringify(safePrimitiveMetadata(linkedAccount)))
      .digest("hex");
    const stableId = sourceAccountId ?? fallback;
    const sourceKey = createHash("sha256")
      .update(type)
      .update("\0")
      .update(stableId)
      .digest("hex");
    const address = stringField(linkedAccount, "address");
    const chainType = firstStringField(linkedAccount, [
      "chain_type",
      "chain",
    ])?.toLowerCase();
    const smartWallet = type === "smart_wallet";
    const wallet = type.includes("wallet") && address !== undefined;
    const provider = SUPPORTED_SOCIAL_TYPES[type];
    const verifiedAt = firstNumberField(linkedAccount, [
      "latest_verified_at",
      "verified_at",
      "first_verified_at",
    ]);
    normalized.set(sourceKey, {
      displayHint: displayHint(type, linkedAccount, stableId),
      metadata: safePrimitiveMetadata(linkedAccount),
      sourceAccountId: stableId,
      sourceKey,
      type,
      ...(chainType === undefined ? {} : { chainType }),
      ...(provider === undefined ? {} : { provider }),
      ...(verifiedAt === undefined
        ? {}
        : { verifiedAt: new Date(verifiedAt * 1_000) }),
      ...(wallet
        ? {
            walletAddress:
              chainType === "solana" ? address : address.toLowerCase(),
            walletType: smartWallet
              ? "smart-account"
              : (firstStringField(linkedAccount, [
                  "wallet_client_type",
                  "connector_type",
                ]) ?? (type.includes("embedded") ? "embedded" : "external")),
          }
        : {}),
    });
  }
  return [...normalized.values()].sort((left, right) =>
    left.sourceKey.localeCompare(right.sourceKey),
  );
}

async function resolveDisposition(
  db: IdentityDb,
  userId: string,
  identity: Pick<
    NormalizedPrivyIdentity,
    "provider" | "sourceAccountId" | "type" | "walletAddress" | "chainType"
  >,
): Promise<{
  disposition: PrivyIdentityDisposition;
  targetCredentialId?: string;
}> {
  // Privy smart_wallet records omit chain_type. Until a chain-scoped
  // smart-account proof path exists, retain them as legacy-only rather than
  // inferring an EVM EOA credential from the address.
  if (identity.type === "smart_wallet") {
    return { disposition: "legacy_only" };
  }
  if (
    identity.walletAddress !== undefined &&
    (identity.chainType === undefined ||
      identity.chainType === "ethereum" ||
      identity.chainType === "evm") &&
    /^0x[a-fA-F0-9]{40}$/.test(identity.walletAddress)
  ) {
    const [owner] = await db
      .select({ id: walletPrincipal.id, userId: walletPrincipal.userId })
      .from(walletPrincipal)
      .where(
        and(
          eq(walletPrincipal.accountKind, "eoa"),
          eq(walletPrincipal.family, "evm"),
          sql`lower(${walletPrincipal.address}) = ${identity.walletAddress.toLowerCase()}`,
        ),
      )
      .limit(1);
    if (owner === undefined) return { disposition: "needs_reverification" };
    return owner.userId === userId
      ? { disposition: "already_linked", targetCredentialId: owner.id }
      : { disposition: "conflict" };
  }
  if (identity.walletAddress !== undefined && identity.chainType === "solana") {
    try {
      parseSolanaAddress(identity.walletAddress);
    } catch {
      return { disposition: "legacy_only" };
    }
    const [owner] = await db
      .select({ id: walletPrincipal.id, userId: walletPrincipal.userId })
      .from(walletPrincipal)
      .where(
        and(
          eq(walletPrincipal.family, "solana"),
          eq(walletPrincipal.address, identity.walletAddress),
        ),
      )
      .limit(1);
    if (owner === undefined) return { disposition: "needs_reverification" };
    return owner.userId === userId
      ? { disposition: "already_linked", targetCredentialId: owner.id }
      : { disposition: "conflict" };
  }
  if (identity.provider !== undefined) {
    const [linked] = await db
      .select({ id: account.id, userId: account.userId })
      .from(account)
      .where(
        and(
          eq(account.providerId, identity.provider),
          eq(account.accountId, identity.sourceAccountId),
        ),
      )
      .limit(1);
    if (linked === undefined) return { disposition: "needs_reverification" };
    return linked.userId === userId
      ? { disposition: "already_linked", targetCredentialId: linked.id }
      : { disposition: "conflict" };
  }
  return { disposition: "legacy_only" };
}

function persistedIdentity(identity: {
  chainType: string | null;
  provider: string | null;
  sourceAccountId: string;
  type: string;
  walletAddress: string | null;
}): Pick<
  NormalizedPrivyIdentity,
  "provider" | "sourceAccountId" | "type" | "walletAddress" | "chainType"
> {
  return {
    sourceAccountId: identity.sourceAccountId,
    type: identity.type,
    ...(identity.chainType === null ? {} : { chainType: identity.chainType }),
    ...(identity.provider === null ||
    !Object.values(SUPPORTED_SOCIAL_TYPES).includes(
      identity.provider as SocialProviderName,
    )
      ? {}
      : { provider: identity.provider as SocialProviderName }),
    ...(identity.walletAddress === null
      ? {}
      : { walletAddress: identity.walletAddress }),
  };
}

function safePrimitiveMetadata(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const allowed = [
    "chain_type",
    "connector_type",
    "delegated",
    "embedded_wallet_type",
    "first_verified_at",
    "imported",
    "latest_verified_at",
    "verified_at",
    "wallet_client_type",
  ];
  return Object.fromEntries(
    allowed.flatMap((key) => {
      const item = value[key];
      return typeof item === "string" ||
        typeof item === "number" ||
        typeof item === "boolean"
        ? [[key, item] as const]
        : [];
    }),
  );
}

function displayHint(
  type: string,
  value: Record<string, unknown>,
  stableId: string,
): string {
  const address = stringField(value, "address");
  if (address !== undefined && address.includes("@")) return maskEmail(address);
  if (address !== undefined && address.startsWith("0x"))
    return compact(address);
  const number = stringField(value, "number");
  if (number !== undefined) return `•••${number.slice(-4)}`;
  const username = firstStringField(value, ["username", "name"]);
  if (username !== undefined) return `@${username.replace(/^@/, "")}`;
  return `${type.replaceAll("_", " ")} · ${compact(stableId)}`;
}

function maskEmail(value: string): string {
  const [local, domain] = value.split("@");
  if (local === undefined || domain === undefined) return "Verified email";
  return `${local.slice(0, 2)}•••@${domain}`;
}

function compact(value: string): string {
  return value.length <= 14 ? value : `${value.slice(0, 7)}…${value.slice(-5)}`;
}

function privyUserHint(value: string): string {
  return compact(value.replace(/^did:privy:/, ""));
}

function firstStringField(
  value: Record<string, unknown>,
  fields: string[],
): string | undefined {
  for (const field of fields) {
    const result = stringField(value, field);
    if (result !== undefined) return result;
  }
  return undefined;
}

function stringField(
  value: Record<string, unknown>,
  field: string,
): string | undefined {
  const result = value[field];
  return typeof result === "string" && result.trim().length > 0
    ? result.trim()
    : undefined;
}

function firstNumberField(
  value: Record<string, unknown>,
  fields: string[],
): number | undefined {
  for (const field of fields) {
    const result = value[field];
    if (typeof result === "number" && Number.isFinite(result)) return result;
  }
  return undefined;
}

function opaqueHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
