import { resolve } from "node:path";

import {
  IdentityCapabilitiesSchema,
  IdentitySubjectSchema,
  SocialLinkHandoffRequestSchema,
  WalletGrantIssueRequestSchema,
  WalletChallengeRequestSchema,
  WalletGrantExchangeRequestSchema,
  WalletGrantRequestSchema,
} from "@peezy.tech/identity";
import { getIPFromHeader, normalizeIP } from "@better-auth/core/utils/ip";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { getConnInfo } from "hono/bun";
import { serveStatic } from "hono/bun";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { ZodError } from "zod";

import type { IdentityAuth, IdentityProofAuth } from "./auth";
import {
  AccountMergeError,
  commitAccountMerge,
  createAccountMergeAttempt,
} from "./account-merge";
import {
  AccountWalletLinkError,
  createAccountWalletLinkChallenge,
  verifyAccountWalletLink,
} from "./account-wallet-link";
import { verifySecret } from "./clients";
import type { IdentityConfig } from "./config";
import type { IdentityDb } from "./db/client";
import { appClient, session } from "./db/schema";
import { identityMe, IdentityNotFoundError } from "./identity";
import {
  accountPage,
  consentPage,
  homePage,
  linkSocialPage,
  signInPage,
} from "./pages";
import {
  claimPrivyMigration,
  createPrivyMigrationAttempt,
  listCurrentPrivyClaims,
  PrivyMigrationError,
  type PrivyGateway,
} from "./privy-migration";
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
  privyGateway?: PrivyGateway;
  proofAuth: IdentityProofAuth;
  socialProviderNames: IdentityConfigSocialProvider[];
};

type IdentityConfigSocialProvider = keyof IdentityConfig["socialProviders"];

export function createIdentityApp(dependencies: AppDependencies): Hono {
  const app = new Hono();
  const applySecureHeaders = secureHeaders();
  const trustedOrigins = new Set([
    dependencies.config.baseUrl,
    ...dependencies.config.trustedOrigins,
  ]);

  app.use("*", async (context, next) => {
    await applySecureHeaders(context, next);
    if (context.req.path === "/account") {
      context.header("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    }
  });
  app.use(
    "/v1/*",
    bodyLimit({
      maxSize: 20_000,
      onError: (context) =>
        errorResponse(context, 413, "Request body is too large"),
    }),
  );
  app.use(
    "/api/proof-auth/*",
    bodyLimit({
      maxSize: 100_000,
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
  app.get(
    "/assets/account-client.js",
    serveStatic({
      path: resolve(import.meta.dir, "../dist/public/account-client.js"),
      root: "/",
    }),
  );
  app.get("/account", async (context) => {
    const identitySession = await dependencies.auth.api.getSession({
      headers: context.req.raw.headers,
    });
    if (identitySession === null) {
      return context.redirect("/sign-in?return_to=%2Faccount");
    }
    const nonce = crypto.randomUUID().replaceAll("-", "");
    return context.html(
      accountPage(
        {
          providers: dependencies.socialProviderNames,
          ...(dependencies.config.privyMigration === undefined
            ? {}
            : { privyAppId: dependencies.config.privyMigration.appId }),
        },
        nonce,
      ),
      200,
      accountSecurityHeaders(nonce),
    );
  });
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

  app.post("/v1/migrations/privy/attempts", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    if (
      dependencies.config.privyMigration === undefined ||
      dependencies.privyGateway === undefined
    ) {
      throw new PrivyMigrationError(
        404,
        "migration_unavailable",
        "Privy migration is not available",
      );
    }
    await requireRateLimit(dependencies.db, {
      key: `privy-attempt:${identitySession.user.id}`,
      limit: 20,
      windowMs: 5 * 60_000,
    });
    return context.json(
      await createPrivyMigrationAttempt(
        dependencies.db,
        identitySession.user.id,
      ),
      201,
    );
  });

  app.post("/v1/migrations/privy/claims", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    if (
      dependencies.config.privyMigration === undefined ||
      dependencies.privyGateway === undefined
    ) {
      throw new PrivyMigrationError(
        404,
        "migration_unavailable",
        "Privy migration is not available",
      );
    }
    const accessToken = bearerToken(context.req.raw);
    const body = (await boundedJson(context)) as {
      attemptId?: unknown;
      csrfToken?: unknown;
    };
    if (
      typeof body.attemptId !== "string" ||
      typeof body.csrfToken !== "string"
    ) {
      throw new PrivyMigrationError(
        400,
        "invalid_request",
        "Migration claim is invalid",
      );
    }
    await requireRateLimit(dependencies.db, {
      key: `privy-claim:${identitySession.user.id}`,
      limit: 10,
      windowMs: 5 * 60_000,
    });
    return context.json(
      await claimPrivyMigration({
        accessToken,
        attemptId: body.attemptId,
        csrfToken: body.csrfToken,
        db: dependencies.db,
        gateway: dependencies.privyGateway,
        userId: identitySession.user.id,
      }),
      201,
    );
  });

  app.get("/v1/migrations/privy/claims/current", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    return context.json({
      claims: await listCurrentPrivyClaims(
        dependencies.db,
        identitySession.user.id,
      ),
    });
  });

  app.post("/v1/account/wallet/challenges", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    const body = (await boundedJson(context)) as {
      address?: unknown;
      chainId?: unknown;
      family?: unknown;
    };
    const family = body.family === "solana" ? "solana" : "evm";
    if (
      typeof body.address !== "string" ||
      (family === "evm" && typeof body.chainId !== "number") ||
      (family === "solana" && body.chainId !== undefined)
    ) {
      throw new AccountWalletLinkError(
        400,
        "invalid_request",
        "Wallet link request is invalid",
      );
    }
    await requireRateLimit(dependencies.db, {
      key: `account-wallet:${identitySession.user.id}`,
      limit: 20,
      windowMs: 5 * 60_000,
    });
    return context.json(
      await createAccountWalletLinkChallenge({
        address: body.address,
        baseUrl: dependencies.config.baseUrl,
        ...(typeof body.chainId === "number" ? { chainId: body.chainId } : {}),
        db: dependencies.db,
        family,
        userId: identitySession.user.id,
      }),
      201,
    );
  });

  app.post("/v1/account/wallet/verify", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    const body = (await boundedJson(context)) as {
      challengeId?: unknown;
      message?: unknown;
      signature?: unknown;
    };
    if (
      typeof body.challengeId !== "string" ||
      typeof body.message !== "string" ||
      typeof body.signature !== "string"
    ) {
      throw new AccountWalletLinkError(
        400,
        "invalid_request",
        "Wallet proof is invalid",
      );
    }
    await requireRateLimit(dependencies.db, {
      key: `account-wallet-verify:${identitySession.user.id}`,
      limit: 10,
      windowMs: 5 * 60_000,
    });
    return context.json(
      await verifyAccountWalletLink({
        challengeId: body.challengeId,
        db: dependencies.db,
        message: body.message,
        signature: body.signature,
        userId: identitySession.user.id,
      }),
    );
  });

  app.post("/v1/account-merges/proofs", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const primarySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    if (!sessionIsRecent(primarySession)) {
      throw new AccountMergeError(
        403,
        "reauth_required",
        "Sign in again before consolidating accounts",
      );
    }
    const proofSession = await dependencies.proofAuth.api.getSession({
      headers: context.req.raw.headers,
    });
    if (proofSession === null) {
      throw new AccountMergeError(
        401,
        "proof_required",
        "Authenticate the account you want to consolidate",
      );
    }
    if (!sessionIsRecent(proofSession)) {
      throw new AccountMergeError(
        403,
        "reauth_required",
        "Sign in again before consolidating accounts",
      );
    }
    const preview = await createAccountMergeAttempt({
      db: dependencies.db,
      sourceUserId: proofSession.user.id,
      targetUserId: primarySession.user.id,
    });
    await dependencies.db
      .delete(session)
      .where(eq(session.id, proofSession.session.id));
    return context.json(preview, 201);
  });

  app.post("/v1/account-merges/commit", async (context) => {
    requireSameOrigin(context.req.raw, dependencies.config.baseUrl);
    const identitySession = await requireIdentitySession(
      dependencies.auth,
      context.req.raw.headers,
    );
    const body = (await boundedJson(context)) as { attemptId?: unknown };
    if (typeof body.attemptId !== "string") {
      throw new AccountMergeError(
        400,
        "invalid_request",
        "Account consolidation request is invalid",
      );
    }
    return context.json(
      await commitAccountMerge({
        attemptId: body.attemptId,
        db: dependencies.db,
        targetUserId: identitySession.user.id,
      }),
    );
  });

  app.post("/v1/wallet/challenges", async (context) => {
    const origin = requiredOrigin(context.req.raw);
    const body = WalletChallengeRequestSchema.parse(await boundedJson(context));
    const clientIp = requestClientIp(
      context,
      dependencies.config.trustedProxies,
    );
    return context.json(
      await createWalletChallenge({
        address: body.walletAddress,
        chainId: body.chainId,
        clientIp,
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
    return context.json(
      await createWalletGrant({
        ...body,
        clientIp: requestClientIp(context, dependencies.config.trustedProxies),
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
  app.all("/api/proof-auth", (context) =>
    dependencies.proofAuth.handler(context.req.raw),
  );
  app.all("/api/proof-auth/*", (context) =>
    dependencies.proofAuth.handler(context.req.raw),
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
    if (error instanceof PrivyMigrationError) {
      return errorResponse(context, error.status, error.message, error.code);
    }
    if (error instanceof AccountMergeError) {
      return errorResponse(context, error.status, error.message, error.code);
    }
    if (error instanceof AccountWalletLinkError) {
      return errorResponse(context, error.status, error.message, error.code);
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

function requestClientIp(
  context: Parameters<typeof getConnInfo>[0],
  trustedProxies: string[],
): string {
  let remoteAddress: string | undefined;
  try {
    remoteAddress = getConnInfo(context).remote.address;
  } catch {
    // Hono's in-process test client has no Bun server connection metadata.
  }
  if (remoteAddress === undefined) {
    return "unknown";
  }

  const normalizedRemote = normalizeIP(remoteAddress);
  const forwardedFor = context.req.raw.headers.get("x-forwarded-for");
  if (forwardedFor === null || trustedProxies.length === 0) {
    return normalizedRemote;
  }
  return (
    getIPFromHeader(`${forwardedFor}, ${remoteAddress}`, {
      trustedProxies,
    }) ?? normalizedRemote
  );
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
  code?: string,
): Response {
  return context.json(
    { error: { ...(code === undefined ? {} : { code }), message } },
    status,
  );
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

function accountSecurityHeaders(nonce: string): Record<string, string> {
  return {
    "Content-Security-Policy": [
      "default-src 'none'",
      "base-uri 'none'",
      "child-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org",
      "connect-src 'self' https://auth.privy.io https://*.rpc.privy.systems https://explorer-api.walletconnect.com https://rpc.walletconnect.org https://hcaptcha.com https://*.hcaptcha.com wss://relay.walletconnect.com wss://relay.walletconnect.org wss://www.walletlink.org",
      "font-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "frame-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com",
      "img-src 'self' data: blob: https:",
      "manifest-src 'self'",
      "object-src 'none'",
      `script-src 'self' 'nonce-${nonce}' https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com`,
      "style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com",
      "worker-src 'self'",
    ].join("; "),
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  };
}

async function requireIdentitySession(auth: IdentityAuth, headers: Headers) {
  const identitySession = await auth.api.getSession({ headers });
  if (identitySession === null) {
    throw new RequestError(401, "Authentication is required");
  }
  return identitySession;
}

function sessionIsRecent(identitySession: {
  session: { createdAt: Date | string };
}): boolean {
  const createdAt = new Date(identitySession.session.createdAt).getTime();
  return Number.isFinite(createdAt) && createdAt >= Date.now() - 10 * 60_000;
}

function requireSameOrigin(request: Request, baseUrl: string): void {
  const expectedOrigin = new URL(baseUrl).origin;
  const origin = request.headers.get("origin");
  if (origin !== null) {
    if (requiredOrigin(request) !== expectedOrigin) {
      throw new RequestError(403, "Request origin is not allowed");
    }
    return;
  }
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite !== null) {
    if (fetchSite === "same-origin") return;
    throw new RequestError(403, "Request origin is not allowed");
  }
  const referer = request.headers.get("referer");
  if (referer !== null) {
    try {
      if (new URL(referer).origin === expectedOrigin) return;
    } catch {
      // Invalid referrers are not same-origin proof.
    }
  }
  throw new RequestError(403, "Request origin is not allowed");
}

function bearerToken(request: Request): string {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Bearer ")) {
    throw new PrivyMigrationError(
      401,
      "invalid_proof",
      "Privy authentication is required",
    );
  }
  const token = authorization.slice(7).trim();
  if (token.length === 0 || token.length > 16_384) {
    throw new PrivyMigrationError(
      401,
      "invalid_proof",
      "Privy authentication is invalid",
    );
  }
  return token;
}
