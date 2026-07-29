import { createHash, randomBytes, randomUUID } from "node:crypto";

import type {
  SocialLinkHandoffResponse,
  SocialProvider,
} from "@peezy.tech/identity";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { and, eq, gt, isNull } from "drizzle-orm";
import { z } from "zod";

import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import {
  appClient,
  identityAuditEvent,
  sessionHandoff,
  user,
} from "./db/schema";
import { WalletGrantError } from "./wallet-grants";

export const SESSION_HANDOFF_TTL_MS = 2 * 60 * 1_000;

export async function createSocialLinkHandoff(input: {
  baseUrl: string;
  callbackUrl: string;
  clientId: string;
  db: IdentityDb;
  now?: Date;
  provider: SocialProvider;
  subject: string;
}): Promise<SocialLinkHandoffResponse> {
  const [client] = await input.db
    .select()
    .from(appClient)
    .where(eq(appClient.id, input.clientId))
    .limit(1);
  if (client === undefined || client.disabled) {
    throw new WalletGrantError(404, "Unknown identity application");
  }
  const callbackUrl = new URL(input.callbackUrl);
  if (!client.origins.includes(callbackUrl.origin)) {
    throw new WalletGrantError(
      403,
      "Social-link callback is not registered for this application",
    );
  }
  const [identityUser] = await input.db
    .select({ id: user.id, status: user.status })
    .from(user)
    .where(eq(user.id, input.subject))
    .limit(1);
  if (identityUser === undefined || identityUser.status !== "active") {
    throw new WalletGrantError(403, "Identity account is unavailable");
  }

  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + SESSION_HANDOFF_TTL_MS);
  const token = randomBytes(32).toString("base64url");
  await input.db.transaction(async (transaction) => {
    await transaction.insert(sessionHandoff).values({
      callbackUrl: callbackUrl.toString(),
      clientId: client.id,
      createdAt: now,
      expiresAt,
      id: randomUUID(),
      provider: input.provider,
      tokenHash: opaqueHash(token),
      userId: identityUser.id,
    });
    await transaction.insert(identityAuditEvent).values({
      actorUserId: identityUser.id,
      clientId: client.id,
      createdAt: now,
      id: randomUUID(),
      kind: "social-link.handoff-created",
      metadata: {
        callbackOrigin: callbackUrl.origin,
        provider: input.provider,
      },
      userId: identityUser.id,
    });
  });

  const url = new URL("/api/auth/session-handoff", input.baseUrl);
  url.searchParams.set("token", token);
  return { expiresAt: expiresAt.toISOString(), url: url.toString() };
}

export function sessionHandoffPlugin(
  db: IdentityDb,
  config: Pick<IdentityConfig, "baseUrl">,
) {
  return {
    endpoints: {
      consumeSessionHandoff: createAuthEndpoint(
        "/session-handoff",
        {
          method: "GET",
          query: z.object({ token: z.string().min(32).max(256) }),
        },
        async (context) => {
          const now = new Date();
          const handoff = await db.transaction(async (transaction) => {
            const [consumed] = await transaction
              .update(sessionHandoff)
              .set({ consumedAt: now })
              .where(
                and(
                  eq(sessionHandoff.tokenHash, opaqueHash(context.query.token)),
                  isNull(sessionHandoff.consumedAt),
                  gt(sessionHandoff.expiresAt, now),
                ),
              )
              .returning();
            if (consumed === undefined) return null;
            const [identityUser] = await transaction
              .select()
              .from(user)
              .where(eq(user.id, consumed.userId))
              .limit(1);
            return identityUser === undefined
              ? null
              : { handoff: consumed, user: identityUser };
          });
          if (handoff === null || handoff.user.status !== "active") {
            throw new APIError("UNAUTHORIZED", {
              message: "Session handoff is invalid or expired",
            });
          }

          const session = await context.context.internalAdapter.createSession(
            handoff.user.id,
          );
          if (session === null) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Identity session could not be created",
            });
          }
          await setSessionCookie(context, {
            session,
            user: handoff.user,
          });

          const linkUrl = new URL("/link-social", config.baseUrl);
          linkUrl.searchParams.set("callback_url", handoff.handoff.callbackUrl);
          linkUrl.searchParams.set("provider", handoff.handoff.provider);
          throw context.redirect(linkUrl.toString());
        },
      ),
    },
    id: "peezy-session-handoff",
  } as const;
}

function opaqueHash(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}
