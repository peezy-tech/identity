import type {
  IdentityCredential,
  IdentityMeResponse,
  SocialProvider,
} from "@peezy.tech/identity";
import { eq } from "drizzle-orm";

import type { IdentityDb } from "./db/client";
import { account, user, walletAddress, walletPrincipal } from "./db/schema";
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
    subject: string;
  },
): Promise<IdentityMeResponse> {
  return db.transaction(async (transaction) => {
    const [identityUser] = await transaction
      .select({ id: user.id, status: user.status })
      .from(user)
      .where(eq(user.id, input.subject))
      .for("update")
      .limit(1);
    if (identityUser === undefined || identityUser.status !== "active") {
      throw new IdentityNotFoundError();
    }
    await transaction
      .update(user)
      .set({
        name: input.displayName,
        updatedAt: new Date(),
      })
      .where(eq(user.id, input.subject));
    return identityMe(transaction, input.subject);
  });
}

function isSocialProvider(value: string): value is SocialProvider {
  return SOCIAL_PROVIDERS.has(value as SocialProvider);
}

function emailCredentialId(subject: string): string {
  // The user ID is already a UUID and email is a single credential in v1.
  return subject;
}
