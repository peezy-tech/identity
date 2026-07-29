import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { jwt, organization, siwe } from "better-auth/plugins";
import { randomBytes } from "node:crypto";
import { verifyMessage } from "viem";

// This definition is used only by the Better Auth schema generator. Runtime
// configuration lives in auth.ts and is tested against the generated schema.
export const auth = betterAuth({
  appName: "peezy.tech",
  baseURL: "http://localhost:8790",
  secret: "schema-generation-secret-at-least-32-characters",
  plugins: [
    jwt(),
    siwe({
      anonymous: true,
      domain: "localhost:8790",
      emailDomainName: "wallet.identity.peezy.tech.invalid",
      getNonce: async () => randomBytes(24).toString("hex"),
      verifyMessage: async ({ address, message, signature }) =>
        verifyMessage({
          address: address as `0x${string}`,
          message,
          signature: signature as `0x${string}`,
        }),
    }),
    organization({
      allowUserToCreateOrganization: false,
      requireEmailVerificationOnInvitation: true,
    }),
    oauthProvider({
      consentPage: "/consent",
      loginPage: "/sign-in",
      scopes: ["openid", "profile", "email", "offline_access"],
    }),
  ],
});
