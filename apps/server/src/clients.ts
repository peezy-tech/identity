import { createHash, timingSafeEqual } from "node:crypto";

import { eq } from "drizzle-orm";

import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import { appClient, oauthClient } from "./db/schema";

export function secretHash(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url");
}

export function verifySecret(secret: string, expectedHash: string): boolean {
  const actual = Buffer.from(secretHash(secret));
  const expected = Buffer.from(expectedHash);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function seedConfiguredClients(
  db: IdentityDb,
  config: Pick<IdentityConfig, "appClients" | "oidcClients">,
): Promise<void> {
  for (const client of config.appClients) {
    const now = new Date();
    await db
      .insert(appClient)
      .values({
        createdAt: now,
        disabled: false,
        id: client.id,
        name: client.name,
        origins: client.origins,
        secretHash: secretHash(client.secret),
        siweStatement: client.siweStatement,
        updatedAt: now,
        walletLinkSiweStatement:
          client.walletLinkSiweStatement ?? client.siweStatement,
      })
      .onConflictDoUpdate({
        target: appClient.id,
        set: {
          disabled: false,
          name: client.name,
          origins: client.origins,
          secretHash: secretHash(client.secret),
          siweStatement: client.siweStatement,
          updatedAt: now,
          walletLinkSiweStatement:
            client.walletLinkSiweStatement ?? client.siweStatement,
        },
      });
  }

  for (const client of config.oidcClients) {
    const now = new Date();
    const existing = await db
      .select({ id: oauthClient.id })
      .from(oauthClient)
      .where(eq(oauthClient.clientId, client.clientId))
      .limit(1);
    const values = {
      clientId: client.clientId,
      clientSecret: secretHash(client.clientSecret),
      disabled: false,
      enableEndSession: true,
      grantTypes: ["authorization_code", "refresh_token"],
      metadata: { managedBy: "config" },
      name: client.name,
      public: false,
      redirectUris: client.redirectUris,
      requirePKCE: true,
      responseTypes: ["code"],
      scopes: ["openid", "profile", "email", "offline_access"],
      skipConsent: true,
      subjectType: "public",
      tokenEndpointAuthMethod: "client_secret_basic",
      type: "web",
      updatedAt: now,
    };
    if (existing[0] === undefined) {
      await db.insert(oauthClient).values({
        ...values,
        createdAt: now,
        id: crypto.randomUUID(),
      });
    } else {
      await db
        .update(oauthClient)
        .set(values)
        .where(eq(oauthClient.clientId, client.clientId));
    }
  }
}
