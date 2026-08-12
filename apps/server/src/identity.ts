import type {
  IdentityCredential,
  IdentityMeResponse,
  SocialProvider,
} from "@peezy.tech/identity";
import { eq } from "drizzle-orm";

import type { IdentityDb } from "./db/client";
import { account, user, walletAddress, walletPrincipal } from "./db/schema";
import { parseAvailableHandle, ReservedHandleError } from "./handles";
import { toPeezyUser } from "./wallet-grants";

const SOCIAL_PROVIDERS = new Set<SocialProvider>([
  "apple",
  "discord",
  "github",
  "telegram",
  "twitter",
]);

export class IdentityNotFoundError extends Error {
  constructor() {
    super("Identity account was not found");
    this.name = "IdentityNotFoundError";
  }
}

export class IdentityProfileError extends Error {
  readonly code: "handle_immutable" | "handle_reserved" | "handle_taken";
  readonly status = 409 as const;

  constructor(code: IdentityProfileError["code"], message: string) {
    super(message);
    this.name = "IdentityProfileError";
    this.code = code;
  }
}

export async function identityMe(
  db: IdentityDb,
  subject: string,
): Promise<IdentityMeResponse> {
  const [identityUser] = await db
    .select()
    .from(user)
    .where(eq(user.id, subject))
    .limit(1);
  if (identityUser === undefined || identityUser.status !== "active") {
    throw new IdentityNotFoundError();
  }

  const [linkedAccounts, principals] = await Promise.all([
    db.select().from(account).where(eq(account.userId, subject)),
    db
      .select()
      .from(walletPrincipal)
      .where(eq(walletPrincipal.userId, subject)),
  ]);
  const verifiedWallets =
    principals.length === 0
      ? []
      : await db
          .select()
          .from(walletAddress)
          .where(eq(walletAddress.userId, subject));

  const credentials: IdentityCredential[] = [];
  if (!identityUser.email.endsWith(".invalid")) {
    credentials.push({
      id: emailCredentialId(identityUser.id),
      kind: "email",
      linkedAt: identityUser.createdAt.toISOString(),
      value: identityUser.email,
      verified: identityUser.emailVerified,
    });
  }
  for (const linkedAccount of linkedAccounts) {
    if (!isSocialProvider(linkedAccount.providerId)) continue;
    credentials.push({
      id: linkedAccount.id,
      kind: "social",
      linkedAt: linkedAccount.createdAt.toISOString(),
      provider: linkedAccount.providerId,
    });
  }
  for (const principal of principals) {
    if (principal.family === "solana") {
      credentials.push({
        accountKind: "eoa",
        address: principal.address,
        family: "solana",
        id: principal.id,
        kind: "wallet",
        linkedAt: principal.createdAt.toISOString(),
        signInEnabled: principal.signInEnabled,
      });
      continue;
    }
    const chains = verifiedWallets
      .filter(
        (wallet) =>
          wallet.address.toLowerCase() === principal.address.toLowerCase(),
      )
      .map((wallet) => wallet.chainId)
      .sort((left, right) => left - right);
    credentials.push({
      accountKind:
        principal.accountKind === "smart-account" ? "smart-account" : "eoa",
      address: principal.address.toLowerCase() as `0x${string}`,
      ...(principal.accountKind === "smart-account" &&
      principal.chainId !== null
        ? { chainId: principal.chainId }
        : {}),
      family: "evm",
      id: principal.id,
      kind: "wallet",
      linkedAt: principal.createdAt.toISOString(),
      signInEnabled: principal.signInEnabled,
      verifiedChainIds: [...new Set(chains)],
    });
  }

  return {
    credentials,
    user: toPeezyUser(identityUser),
  };
}

export async function updateIdentityProfile(
  db: IdentityDb,
  input: {
    displayName: string;
    handle?: string;
    subject: string;
  },
): Promise<IdentityMeResponse> {
  let requestedHandle: string | undefined;
  if (input.handle !== undefined) {
    try {
      requestedHandle = parseAvailableHandle(input.handle);
    } catch (error) {
      if (error instanceof ReservedHandleError) {
        throw new IdentityProfileError(
          "handle_reserved",
          "This peezy.tech handle is reserved",
        );
      }
      throw error;
    }
  }

  try {
    return await db.transaction(async (transaction) => {
      const [identityUser] = await transaction
        .select({ handle: user.handle, id: user.id, status: user.status })
        .from(user)
        .where(eq(user.id, input.subject))
        .for("update")
        .limit(1);
      if (identityUser === undefined || identityUser.status !== "active") {
        throw new IdentityNotFoundError();
      }
      if (
        requestedHandle !== undefined &&
        identityUser.handle !== null &&
        identityUser.handle !== requestedHandle
      ) {
        throw new IdentityProfileError(
          "handle_immutable",
          "peezy.tech handles cannot be changed after they are claimed",
        );
      }
      await transaction
        .update(user)
        .set({
          ...(requestedHandle === undefined ? {} : { handle: requestedHandle }),
          name: input.displayName,
          updatedAt: new Date(),
        })
        .where(eq(user.id, input.subject));
      return identityMe(transaction, input.subject);
    });
  } catch (error) {
    if (postgresErrorCode(error) === "23505") {
      throw new IdentityProfileError(
        "handle_taken",
        "This peezy.tech handle is already claimed",
      );
    }
    throw error;
  }
}

function postgresErrorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return typeof error === "object" && error !== null && "cause" in error
      ? postgresErrorCode(error.cause)
      : undefined;
  }
  if (typeof error.code === "string") return error.code;
  return "cause" in error ? postgresErrorCode(error.cause) : undefined;
}

function isSocialProvider(value: string): value is SocialProvider {
  return SOCIAL_PROVIDERS.has(value as SocialProvider);
}

function emailCredentialId(subject: string): string {
  // The user ID is already a UUID and email is a single credential in v1.
  return subject;
}
