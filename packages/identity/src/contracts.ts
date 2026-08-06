import { z } from "zod";

export const IdentitySubjectSchema = z.string().uuid();
export const IsoDateSchema = z.string().datetime();
export const EvmAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/)
  .transform((value) => value.toLowerCase() as `0x${string}`);
export const SolanaAddressSchema = z
  .string()
  .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
export const HttpUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    if (!URL.canParse(value)) return false;
    const protocol = new URL(value).protocol;
    return protocol === "https:" || protocol === "http:";
  }, "Expected an HTTP or HTTPS URL");

export const PeezyUserSchema = z.object({
  avatarUrl: HttpUrlSchema.optional(),
  createdAt: IsoDateSchema,
  displayName: z.string().trim().min(1).max(128).optional(),
  id: IdentitySubjectSchema,
  primaryEmail: z
    .object({
      value: z.string().email(),
      verified: z.boolean(),
    })
    .optional(),
  status: z.enum(["active", "disabled"]),
});

export const SocialProviderSchema = z.enum([
  "apple",
  "discord",
  "github",
  "telegram",
  "twitter",
]);

export const SocialCredentialSchema = z.object({
  id: z.string().uuid(),
  kind: z.literal("social"),
  linkedAt: IsoDateSchema,
  provider: SocialProviderSchema,
});

export const EmailCredentialSchema = z.object({
  id: z.string().uuid(),
  kind: z.literal("email"),
  linkedAt: IsoDateSchema,
  value: z.string().email(),
  verified: z.boolean(),
});

export const PasskeyCredentialSchema = z.object({
  id: z.string().uuid(),
  kind: z.literal("passkey"),
  label: z.string().trim().min(1).max(128).optional(),
  linkedAt: IsoDateSchema,
});

export const EvmWalletCredentialSchema = z
  .object({
    accountKind: z.enum(["eoa", "smart-account"]),
    address: EvmAddressSchema,
    chainId: z.number().int().positive().optional(),
    family: z.literal("evm"),
    id: z.string().uuid(),
    kind: z.literal("wallet"),
    linkedAt: IsoDateSchema,
    signInEnabled: z.boolean(),
    verifiedChainIds: z.array(z.number().int().positive()),
  })
  .superRefine((wallet, context) => {
    if (
      wallet.accountKind === "smart-account" &&
      wallet.chainId === undefined
    ) {
      context.addIssue({
        code: "custom",
        message: "Smart-account credentials must be chain scoped",
        path: ["chainId"],
      });
    }
    if (wallet.accountKind === "eoa" && wallet.chainId !== undefined) {
      context.addIssue({
        code: "custom",
        message: "EOA credentials are global across the EVM family",
        path: ["chainId"],
      });
    }
  });

export const SolanaWalletCredentialSchema = z.object({
  accountKind: z.literal("eoa"),
  address: SolanaAddressSchema,
  family: z.literal("solana"),
  id: z.string().uuid(),
  kind: z.literal("wallet"),
  linkedAt: IsoDateSchema,
  signInEnabled: z.boolean(),
});

export const WalletCredentialSchema = z.union([
  EvmWalletCredentialSchema,
  SolanaWalletCredentialSchema,
]);

export const IdentityCredentialSchema = z.union([
  SocialCredentialSchema,
  EmailCredentialSchema,
  PasskeyCredentialSchema,
  WalletCredentialSchema,
]);

export const IdentityMeResponseSchema = z.object({
  credentials: z.array(IdentityCredentialSchema),
  user: PeezyUserSchema,
});

export const IdentityCapabilitiesSchema = z.object({
  accountCreation: z.object({
    social: z.boolean(),
    wallet: z.boolean(),
  }),
  socialProviders: z.array(SocialProviderSchema),
});

export const WalletChallengeRequestSchema = z.object({
  chainId: z.number().int().positive(),
  clientId: z.string().trim().min(1).max(128),
  purpose: z.enum(["link", "sign-in"]).default("sign-in"),
  walletAddress: EvmAddressSchema,
});

export const WalletChallengeResponseSchema = z.object({
  address: EvmAddressSchema,
  chainId: z.number().int().positive(),
  domain: z.string().min(1),
  expirationTime: IsoDateSchema,
  issuedAt: IsoDateSchema,
  message: z.string().min(1).max(16_384),
  nonce: z.string().min(16).max(128),
  statement: z.string().min(1).max(256),
  uri: z.string().url(),
  version: z.literal("1"),
});

export const WalletGrantRequestSchema = z.object({
  clientId: z.string().trim().min(1).max(128),
  message: z.string().min(1).max(16_384),
  signature: z.string().regex(/^0x(?:[a-fA-F0-9]{2})+$/),
});

export const WalletGrantIssueRequestSchema = WalletGrantRequestSchema.extend({
  subject: IdentitySubjectSchema.optional(),
});

export const WalletGrantResponseSchema = z.object({
  expiresAt: IsoDateSchema,
  grant: z.string().min(32),
  user: PeezyUserSchema,
});

export const WalletGrantExchangeRequestSchema = z.object({
  clientId: z.string().trim().min(1).max(128),
  grant: z.string().min(32),
});

export const WalletGrantExchangeResponseSchema = z.object({
  expiresAt: IsoDateSchema,
  subject: IdentitySubjectSchema,
});

export const SocialLinkHandoffRequestSchema = z.object({
  callbackUrl: z.string().url(),
  clientId: z.string().trim().min(1).max(128),
  provider: SocialProviderSchema,
  subject: IdentitySubjectSchema,
});

export const SocialLinkHandoffResponseSchema = z.object({
  expiresAt: IsoDateSchema,
  url: z.string().url(),
});

export type PeezyUser = z.infer<typeof PeezyUserSchema>;
export type SocialProvider = z.infer<typeof SocialProviderSchema>;
export type SocialCredential = z.infer<typeof SocialCredentialSchema>;
export type EmailCredential = z.infer<typeof EmailCredentialSchema>;
export type PasskeyCredential = z.infer<typeof PasskeyCredentialSchema>;
export type WalletCredential = z.infer<typeof WalletCredentialSchema>;
export type IdentityCredential = z.infer<typeof IdentityCredentialSchema>;
export type IdentityMeResponse = z.infer<typeof IdentityMeResponseSchema>;
export type IdentityCapabilities = z.infer<typeof IdentityCapabilitiesSchema>;
export type WalletChallengeRequest = z.infer<
  typeof WalletChallengeRequestSchema
>;
export type WalletChallengeResponse = z.infer<
  typeof WalletChallengeResponseSchema
>;
export type WalletGrantRequest = z.infer<typeof WalletGrantRequestSchema>;
export type WalletGrantIssueRequest = z.infer<
  typeof WalletGrantIssueRequestSchema
>;
export type WalletGrantResponse = z.infer<typeof WalletGrantResponseSchema>;
export type WalletGrantExchangeRequest = z.infer<
  typeof WalletGrantExchangeRequestSchema
>;
export type WalletGrantExchangeResponse = z.infer<
  typeof WalletGrantExchangeResponseSchema
>;
export type SocialLinkHandoffRequest = z.infer<
  typeof SocialLinkHandoffRequestSchema
>;
export type SocialLinkHandoffResponse = z.infer<
  typeof SocialLinkHandoffResponseSchema
>;
