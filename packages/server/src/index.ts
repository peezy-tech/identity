import {
  IdentityMeResponseSchema,
  SocialLinkHandoffRequestSchema,
  SocialLinkHandoffResponseSchema,
  WalletChallengeRequestSchema,
  WalletChallengeResponseSchema,
  WalletGrantExchangeRequestSchema,
  WalletGrantExchangeResponseSchema,
  WalletGrantIssueRequestSchema,
  WalletGrantResponseSchema,
} from "@peezy.tech/identity";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyOptions,
} from "jose";

import type {
  IdentityMeResponse,
  SocialLinkHandoffResponse,
  WalletChallengeResponse,
  WalletGrantExchangeResponse,
  WalletGrantResponse,
} from "./types";

export type {
  IdentityCredential,
  IdentityMeResponse,
  PeezyUser,
  SocialLinkHandoffResponse,
  WalletChallengeResponse,
  WalletGrantExchangeResponse,
  WalletGrantResponse,
} from "./types";

export type IdentityPrincipal = {
  claims: JWTPayload;
  subject: string;
};

export type AccessTokenIntrospectionOptions = {
  clientId: string;
  clientSecret: string;
  fetcher?: ServerFetch;
  url?: string;
};

export type AccessTokenVerifierOptions = {
  audience: string;
  issuer: string;
  introspection: AccessTokenIntrospectionOptions;
  jwksUrl?: string;
};

export type ServerFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export function createAccessTokenVerifier(options: AccessTokenVerifierOptions) {
  const issuer = options.issuer.replace(/\/+$/, "");
  const getKey = createRemoteJWKSet(
    new URL(options.jwksUrl ?? `${issuer}/jwks`),
  );
  const verifyOptions: JWTVerifyOptions = {
    audience: options.audience,
    issuer,
  };

  return async (token: string): Promise<IdentityPrincipal> => {
    const { payload } = await jwtVerify(token, getKey, verifyOptions);
    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      throw new Error("Identity access token is missing its subject");
    }
    const introspectionResponse = await (
      options.introspection.fetcher ?? fetch
    )(options.introspection.url ?? `${issuer}/oauth2/introspect`, {
      body: new URLSearchParams({
        token,
        token_type_hint: "access_token",
      }),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${basicCredentials(
          options.introspection.clientId,
          options.introspection.clientSecret,
        )}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    });
    const introspectionText = await introspectionResponse.text();
    if (!introspectionResponse.ok) {
      throw new Error("Identity access token introspection failed");
    }
    let introspection: unknown;
    try {
      introspection = JSON.parse(introspectionText);
    } catch {
      throw new Error("Identity access token introspection was invalid");
    }
    if (
      typeof introspection !== "object" ||
      introspection === null ||
      !("active" in introspection) ||
      introspection.active !== true
    ) {
      throw new Error("Identity access token is inactive");
    }
    if (!("sub" in introspection) || introspection.sub !== payload.sub) {
      throw new Error("Identity access token subject does not match");
    }
    return { claims: payload, subject: payload.sub };
  };
}

export function bearerToken(authorization: string | null | undefined): string {
  if (authorization === undefined || authorization === null) {
    throw new Error("Authorization header is required");
  }
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  if (match?.[1] === undefined) {
    throw new Error("Authorization header must contain one bearer token");
  }
  return match[1];
}

export async function exchangeWalletGrant(input: {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  fetcher?: ServerFetch;
  grant: string;
}): Promise<WalletGrantExchangeResponse> {
  const body = WalletGrantExchangeRequestSchema.parse({
    clientId: input.clientId,
    grant: input.grant,
  });
  const response = await (input.fetcher ?? fetch)(
    `${input.baseUrl.replace(/\/+$/, "")}/v1/wallet/grants/exchange`,
    {
      body: JSON.stringify(body),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${basicCredentials(
          input.clientId,
          input.clientSecret,
        )}`,
        "Content-Type": "application/json",
      },
      method: "POST",
    },
  );
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      text.length === 0
        ? `Wallet grant exchange failed with status ${response.status}.`
        : text,
    );
  }
  return WalletGrantExchangeResponseSchema.parse(JSON.parse(text));
}

export async function createWalletChallenge(input: {
  address: string;
  baseUrl: string;
  chainId: number;
  clientId: string;
  fetcher?: ServerFetch;
  origin: string;
  purpose?: "link" | "sign-in";
}): Promise<WalletChallengeResponse> {
  const body = WalletChallengeRequestSchema.parse({
    chainId: input.chainId,
    clientId: input.clientId,
    purpose: input.purpose ?? "sign-in",
    walletAddress: input.address,
  });
  const response = await (input.fetcher ?? fetch)(
    `${input.baseUrl.replace(/\/+$/, "")}/v1/wallet/challenges`,
    {
      body: JSON.stringify(body),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Origin: new URL(input.origin).origin,
      },
      method: "POST",
    },
  );
  return parseResponse(
    response,
    WalletChallengeResponseSchema,
    "Wallet challenge request",
  );
}

export async function issueWalletGrant(input: {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  fetcher?: ServerFetch;
  message: string;
  signature: string;
  subject?: string;
}): Promise<WalletGrantResponse> {
  const body = WalletGrantIssueRequestSchema.parse({
    clientId: input.clientId,
    message: input.message,
    signature: input.signature,
    ...(input.subject === undefined ? {} : { subject: input.subject }),
  });
  const response = await (input.fetcher ?? fetch)(
    `${input.baseUrl.replace(/\/+$/, "")}/v1/wallet/grants/issue`,
    {
      body: JSON.stringify(body),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${basicCredentials(
          input.clientId,
          input.clientSecret,
        )}`,
        "Content-Type": "application/json",
      },
      method: "POST",
    },
  );
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      text.length === 0
        ? `Wallet grant issuance failed with status ${response.status}.`
        : text,
    );
  }
  return WalletGrantResponseSchema.parse(JSON.parse(text));
}

export async function getIdentity(input: {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  fetcher?: ServerFetch;
  subject: string;
}): Promise<IdentityMeResponse> {
  const response = await (input.fetcher ?? fetch)(
    `${input.baseUrl.replace(/\/+$/, "")}/v1/users/${encodeURIComponent(
      input.subject,
    )}`,
    {
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${basicCredentials(
          input.clientId,
          input.clientSecret,
        )}`,
      },
    },
  );
  return parseResponse(response, IdentityMeResponseSchema, "Identity lookup");
}

export async function createSocialLinkHandoff(input: {
  baseUrl: string;
  callbackUrl: string;
  clientId: string;
  clientSecret: string;
  fetcher?: ServerFetch;
  provider: string;
  subject: string;
}): Promise<SocialLinkHandoffResponse> {
  const body = SocialLinkHandoffRequestSchema.parse({
    callbackUrl: input.callbackUrl,
    clientId: input.clientId,
    provider: input.provider,
    subject: input.subject,
  });
  const response = await (input.fetcher ?? fetch)(
    `${input.baseUrl.replace(/\/+$/, "")}/v1/social-link-handoffs`,
    {
      body: JSON.stringify(body),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${basicCredentials(
          input.clientId,
          input.clientSecret,
        )}`,
        "Content-Type": "application/json",
      },
      method: "POST",
    },
  );
  return parseResponse(
    response,
    SocialLinkHandoffResponseSchema,
    "Social-link handoff",
  );
}

async function parseResponse<T>(
  response: Response,
  schema: { parse(value: unknown): T },
  operation: string,
): Promise<T> {
  const text = await response.text();
  if (!response.ok) {
    throw new Error(
      text.length === 0
        ? `${operation} failed with status ${response.status}.`
        : text,
    );
  }
  return schema.parse(JSON.parse(text));
}

function basicCredentials(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
}
