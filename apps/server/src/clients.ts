import { createHash, timingSafeEqual } from "node:crypto";

import { eq, sql } from "drizzle-orm";

import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import {
  appClient,
  oauthClient,
  oauthClientResource,
  oauthResource,
} from "./db/schema";

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
  await db.transaction(async (transaction) => {
    const now = new Date();
    await transaction.update(appClient).set({ disabled: true, updatedAt: now });
    await transaction
      .update(oauthClient)
      .set({ disabled: true, updatedAt: now })
      .where(sql`${oauthClient.metadata}->>'managedBy' = 'config'`);
    await transaction
      .delete(oauthClientResource)
      .where(sql`${oauthClientResource.metadata}->>'managedBy' = 'config'`);
    await transaction
      .update(oauthResource)
      .set({ disabled: true, updatedAt: now })
      .where(sql`${oauthResource.metadata}->>'managedBy' = 'config'`);

    for (const client of config.appClients) {
      await transaction
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
      const publicBrowser = client.type === "public-browser";
      const existing = await transaction
        .select({ id: oauthClient.id })
        .from(oauthClient)
        .where(eq(oauthClient.clientId, client.clientId))
        .limit(1);
      const values = {
        clientId: client.clientId,
        clientSecret: publicBrowser ? null : secretHash(client.clientSecret),
        disabled: false,
        enableEndSession: true,
        grantTypes: publicBrowser
          ? ["authorization_code"]
          : ["authorization_code", "refresh_token"],
        metadata: { managedBy: "config" },
        name: client.name,
        public: publicBrowser,
        redirectUris: client.redirectUris,
        requirePKCE: true,
        responseTypes: ["code"],
        scopes: publicBrowser
          ? ["openid", "profile"]
          : ["openid", "profile", "email", "offline_access"],
        skipConsent: true,
        subjectType: "public",
        tokenEndpointAuthMethod: publicBrowser ? "none" : "client_secret_basic",
        type: publicBrowser ? "user-agent-based" : "web",
        updatedAt: now,
      };
      if (existing[0] === undefined) {
        await transaction.insert(oauthClient).values({
          ...values,
          createdAt: now,
          id: crypto.randomUUID(),
        });
      } else {
        await transaction
          .update(oauthClient)
          .set(values)
          .where(eq(oauthClient.clientId, client.clientId));
      }

      for (const audience of client.audiences) {
        await transaction
          .insert(oauthResource)
          .values({
            createdAt: now,
            disabled: false,
            id: crypto.randomUUID(),
            identifier: audience,
            metadata: { managedBy: "config" },
            name: audience,
            updatedAt: now,
          })
          .onConflictDoUpdate({
            target: oauthResource.identifier,
            set: {
              disabled: false,
              metadata: { managedBy: "config" },
              name: audience,
              updatedAt: now,
            },
          });
        await transaction
          .insert(oauthClientResource)
          .values({
            clientId: client.clientId,
            createdAt: now,
            id: `${client.clientId}::${audience}`,
            metadata: { managedBy: "config" },
            resourceId: audience,
          })
          .onConflictDoUpdate({
            target: [
              oauthClientResource.clientId,
              oauthClientResource.resourceId,
            ],
            set: {
              metadata: { managedBy: "config" },
            },
          });
      }
    }
  });
}
