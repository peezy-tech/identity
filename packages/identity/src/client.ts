import {
  IdentityCapabilitiesSchema,
  IdentityMeResponseSchema,
  WalletChallengeResponseSchema,
  WalletGrantResponseSchema,
  type IdentityCapabilities,
  type IdentityMeResponse,
  type WalletChallengeRequest,
  type WalletGrantRequest,
  type WalletGrantResponse,
} from "./contracts.js";

export type IdentityFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export type IdentityClientOptions = {
  baseUrl: string;
  fetcher?: IdentityFetch;
};

export class IdentityApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "IdentityApiError";
    this.status = status;
  }
}

export function createIdentityClient(options: IdentityClientOptions) {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const fetcher = options.fetcher ?? fetch;

  return {
    capabilities: (): Promise<IdentityCapabilities> =>
      request(baseUrl, fetcher, "/v1/capabilities", IdentityCapabilitiesSchema),
    createWalletChallenge: (body: WalletChallengeRequest) =>
      request(
        baseUrl,
        fetcher,
        "/v1/wallet/challenges",
        WalletChallengeResponseSchema,
        {
          body,
          method: "POST",
        },
      ),
    createWalletGrant: (
      body: WalletGrantRequest,
    ): Promise<WalletGrantResponse> =>
      request(
        baseUrl,
        fetcher,
        "/v1/wallet/grants",
        WalletGrantResponseSchema,
        {
          body,
          method: "POST",
        },
      ),
    me: (): Promise<IdentityMeResponse> =>
      request(baseUrl, fetcher, "/v1/me", IdentityMeResponseSchema, {
        credentials: "include",
      }),
  };
}

async function request<T>(
  baseUrl: string,
  fetcher: IdentityFetch,
  path: string,
  schema: { parse(value: unknown): T },
  options: {
    body?: unknown;
    credentials?: RequestCredentials;
    method?: "GET" | "POST";
  } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const init: RequestInit = {
    headers,
    method: options.method ?? "GET",
    ...(options.credentials === undefined
      ? {}
      : { credentials: options.credentials }),
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }

  const response = await fetcher(`${baseUrl}${path}`, init);
  const text = await response.text();
  if (!response.ok) {
    throw new IdentityApiError(
      response.status,
      errorMessage(response.status, text),
    );
  }
  return schema.parse(text.length === 0 ? {} : JSON.parse(text));
}

function errorMessage(status: number, body: string): string {
  if (body.length === 0)
    return `Identity request failed with status ${status}.`;
  try {
    const parsed = JSON.parse(body) as { error?: { message?: unknown } };
    if (typeof parsed.error?.message === "string") return parsed.error.message;
  } catch {
    return body;
  }
  return body;
}
