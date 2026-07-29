import {
  IdentityCapabilitiesSchema,
  IdentitySubjectSchema,
  SocialLinkHandoffRequestSchema,
  WalletGrantIssueRequestSchema,
  WalletChallengeRequestSchema,
  WalletGrantExchangeRequestSchema,
  WalletGrantRequestSchema,
} from "@peezy.tech/identity";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { ZodError } from "zod";

import type { IdentityAuth } from "./auth";
import { verifySecret } from "./clients";
import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import { appClient } from "./db/schema";
import { identityMe, IdentityNotFoundError } from "./identity";
import { consentPage, homePage, linkSocialPage, signInPage } from "./pages";
import { consumeRateLimit } from "./rate-limit";
import { createSocialLinkHandoff } from "./session-handoffs";
import {
  createWalletChallenge,
  createWalletGrant,
  exchangeWalletGrant,
  WalletGrantError,
} from "./wallet-grants";

type AppDependencies = {
  auth: IdentityAuth;
  config: IdentityConfig;
  db: IdentityDb;
  socialProviderNames: IdentityConfigSocialProvider[];
};

type IdentityConfigSocialProvider = keyof IdentityConfig["socialProviders"];

export function createIdentityApp(dependencies: AppDependencies): Hono {
  const app = new Hono();
  const trustedOrigins = new Set([
    dependencies.config.baseUrl,
    ...dependencies.config.trustedOrigins,
  ]);

  app.use("*", secureHeaders());
  app.use(
    "/v1/*",
    bodyLimit({
      maxSize: 20_000,
      onError: (context) =>
        errorResponse(context, 413, "Request body is too large"),
    }),
  );
  app.use(
    "/api/auth/*",
    bodyLimit({
      maxSize: 100_000,
      onError: (context) =>
        errorResponse(context, 413, "Request body is too large"),
    }),
  );
  app.use(
    "/v1/*",
    cors({
      allowHeaders: ["Authorization", "Content-Type"],
      allowMethods: ["GET", "POST", "OPTIONS"],
      credentials: true,
      maxAge: 600,
      origin: (requestOrigin) =>
        trustedOrigins.has(requestOrigin) ? requestOrigin : "",
    }),
  );

  app.get("/", (context) => context.html(homePage()));
  app.get("/sign-in", (context) => {
    const nonce = crypto.randomUUID().replaceAll("-", "");
    return context.html(
      signInPage(dependencies.socialProviderNames, nonce),
      200,
      contentSecurityHeaders(nonce),
    );
  });
  app.get("/consent", (context) => {
    const nonce = crypto.randomUUID().replaceAll("-", "");
    return context.html(consentPage(nonce), 200, contentSecurityHeaders(nonce));
  });
  app.get("/link-social", (context) => {
    const provider = context.req.query("provider");
    const callbackUrl = context.req.query("callback_url");
    if (
      !dependencies.socialProviderNames.includes(
        provider as IdentityConfigSocialProvider,
      ) ||
      callbackUrl === undefined
    ) {
      return errorResponse(context, 400, "Social-link request is invalid");
    }
    let callbackOrigin: string;
    try {
      callbackOrigin = new URL(callbackUrl).origin;
    } catch {
      return errorResponse(context, 400, "Social-link callback is invalid");
    }
    if (!trustedOrigins.has(callbackOrigin)) {
      return errorResponse(
        context,
        403,
        "Social-link callback is not registered",
      );
    }
    const nonce = crypto.randomUUID().replaceAll("-", "");
    return context.html(
      linkSocialPage(
        provider as IdentityConfigSocialProvider,
        callbackUrl,
        nonce,
      ),
      200,
      contentSecurityHeaders(nonce),
    );
  });

  app.get("/health/live", (context) =>
    context.json({ service: "peezy-tech-identity", status: "ok" }),
  );
  const readiness = async (context: {
    json: (body: object, status?: 200 | 503) => Response;
  }) => {
    try {
      await dependencies.db.execute("select 1");
      return context.json({ status: "ready" }, 200);
    } catch {
      return context.json({ status: "unavailable" }, 503);
    }
  };
  app.get("/health", readiness);
  app.get("/health/ready", readiness);

  app.get("/v1/capabilities", (context) =>
    context.json(
      IdentityCapabilitiesSchema.parse({
        accountCreation: {
          social: dependencies.socialProviderNames.length > 0,
          wallet: true,
        },
        socialProviders: dependencies.socialProviderNames,
      }),
    ),
  );

  app.get("/v1/me", async (context) => {
    const identitySession = await dependencies.auth.api.getSession({
      headers: context.req.raw.headers,
    });
    if (identitySession === null) {
      return errorResponse(context, 401, "Authentication is required");
    }
    return context.json(
      await identityMe(dependencies.db, identitySession.user.id),
    );
  });

  app.post("/v1/wallet/challenges", async (context) => {
    const origin = requiredOrigin(context.req.raw);
    const body = WalletChallengeRequestSchema.parse(await boundedJson(context));
    await requireRateLimit(dependencies.db, {
      key: `wallet-challenge:${body.clientId}:${origin}`,
      limit: 300,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(
      await createWalletChallenge({
        address: body.walletAddress,
        chainId: body.chainId,
        clientId: body.clientId,
        db: dependencies.db,
        origin,
        purpose: body.purpose,
      }),
      201,
    );
  });

  app.post("/v1/wallet/grants", async (context) => {
    const origin = requiredOrigin(context.req.raw);
    const body = WalletGrantRequestSchema.parse(await boundedJson(context));
    const identitySession = await dependencies.auth.api.getSession({
      headers: context.req.raw.headers,
    });
    await requireRateLimit(dependencies.db, {
      key: `wallet-grant:${body.clientId}:${origin}`,
      limit: 30,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(
      await createWalletGrant({
        ...body,
        db: dependencies.db,
        origin,
        ...(identitySession === null
          ? {}
          : { sessionSubject: identitySession.user.id }),
      }),
      201,
    );
  });

  app.post("/v1/wallet/grants/issue", async (context) => {
    const credentials = await authenticateAppClient(
      dependencies.db,
      context.req.raw,
    );
    const rawBody = await boundedJson(context);
    const body = WalletGrantIssueRequestSchema.parse(rawBody);
    if (credentials.clientId !== body.clientId) {
      return errorResponse(context, 403, "Client credentials do not match");
    }
    await requireRateLimit(dependencies.db, {
      key: `wallet-issue:${credentials.clientId}`,
      limit: 60,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(
      await createWalletGrant({
        clientId: body.clientId,
        db: dependencies.db,
        message: body.message,
        signature: body.signature,
        ...(body.subject === undefined ? {} : { sessionSubject: body.subject }),
      }),
      201,
    );
  });

  app.post("/v1/wallet/grants/exchange", async (context) => {
    const credentials = await authenticateAppClient(
      dependencies.db,
      context.req.raw,
    );
    const body = WalletGrantExchangeRequestSchema.parse(
      await boundedJson(context),
    );
    if (credentials.clientId !== body.clientId) {
      return errorResponse(context, 403, "Client credentials do not match");
    }
    await requireRateLimit(dependencies.db, {
      key: `wallet-exchange:${credentials.clientId}`,
      limit: 120,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(
      await exchangeWalletGrant({
        clientId: body.clientId,
        db: dependencies.db,
        grant: body.grant,
      }),
    );
  });

  app.get("/v1/users/:subject", async (context) => {
    const credentials = await authenticateAppClient(
      dependencies.db,
      context.req.raw,
    );
    const subject = IdentitySubjectSchema.parse(context.req.param("subject"));
    await requireRateLimit(dependencies.db, {
      key: `identity-read:${credentials.clientId}`,
      limit: 300,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(await identityMe(dependencies.db, subject));
  });

  app.post("/v1/social-link-handoffs", async (context) => {
    const credentials = await authenticateAppClient(
      dependencies.db,
      context.req.raw,
    );
    const body = SocialLinkHandoffRequestSchema.parse(
      await boundedJson(context),
    );
    if (credentials.clientId !== body.clientId) {
      return errorResponse(context, 403, "Client credentials do not match");
    }
    if (
      !dependencies.socialProviderNames.includes(
        body.provider as IdentityConfigSocialProvider,
      )
    ) {
      return errorResponse(context, 404, "Social provider is unavailable");
    }
    await requireRateLimit(dependencies.db, {
      key: `social-link:${credentials.clientId}:${body.subject}`,
      limit: 20,
      windowMs: 5 * 60 * 1_000,
    });
    return context.json(
      await createSocialLinkHandoff({
        baseUrl: dependencies.config.baseUrl,
        callbackUrl: body.callbackUrl,
        clientId: body.clientId,
        db: dependencies.db,
        provider: body.provider,
        subject: body.subject,
      }),
      201,
    );
  });

  app.all("/api/auth", (context) => dependencies.auth.handler(context.req.raw));
  app.all("/api/auth/*", (context) =>
    dependencies.auth.handler(context.req.raw),
  );

  app.notFound((context) =>
    errorResponse(context, 404, "Identity route was not found"),
  );
  app.onError((error, context) => {
    if (error instanceof ZodError) {
      return errorResponse(context, 400, "Request validation failed");
    }
    if (error instanceof WalletGrantError) {
      return errorResponse(context, error.status, error.message);
    }
    if (error instanceof IdentityNotFoundError) {
      return errorResponse(context, 404, error.message);
    }
    if (error instanceof RequestError) {
      return errorResponse(context, error.status, error.message);
    }
    console.error("Unhandled identity request error", error);
    return errorResponse(context, 500, "Identity request failed");
  });

  return app;
}

class RequestError extends Error {
  readonly status: 400 | 401 | 403 | 413 | 429;

  constructor(status: RequestError["status"], message: string) {
    super(message);
    this.name = "RequestError";
    this.status = status;
  }
}

async function boundedJson(context: {
  req: {
    json: () => Promise<unknown>;
  };
}): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new RequestError(400, "Request body must be valid JSON");
  }
}

function requiredOrigin(request: Request): string {
  const origin = request.headers.get("origin");
  if (origin === null) {
    throw new RequestError(403, "Origin header is required");
  }
  try {
    return new URL(origin).origin;
  } catch {
    throw new RequestError(400, "Origin header is invalid");
  }
}

async function authenticateAppClient(
  db: IdentityDb,
  request: Request,
): Promise<{ clientId: string }> {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Basic ")) {
    throw new RequestError(401, "Application authentication is required");
  }
  let decoded: string;
  try {
    decoded = Buffer.from(authorization.slice(6), "base64").toString("utf8");
  } catch {
    throw new RequestError(401, "Application credentials are invalid");
  }
  const separator = decoded.indexOf(":");
  if (separator <= 0) {
    throw new RequestError(401, "Application credentials are invalid");
  }
  const clientId = decoded.slice(0, separator);
  const secret = decoded.slice(separator + 1);
  const [client] = await db
    .select()
    .from(appClient)
    .where(and(eq(appClient.id, clientId), eq(appClient.disabled, false)))
    .limit(1);
  if (client === undefined || !verifySecret(secret, client.secretHash)) {
    throw new RequestError(401, "Application credentials are invalid");
  }
  return { clientId };
}

async function requireRateLimit(
  db: IdentityDb,
  input: { key: string; limit: number; windowMs: number },
): Promise<void> {
  if (!(await consumeRateLimit({ db, ...input }))) {
    throw new RequestError(429, "Too many identity requests");
  }
}

function errorResponse(
  context: { json: (body: object, status: number) => Response },
  status: number,
  message: string,
): Response {
  return context.json({ error: { message } }, status);
}

function contentSecurityHeaders(nonce: string): Record<string, string> {
  return {
    "Content-Security-Policy": [
      "default-src 'none'",
      "base-uri 'none'",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data:",
      `script-src 'nonce-${nonce}'`,
      "style-src 'unsafe-inline'",
    ].join("; "),
  };
}
