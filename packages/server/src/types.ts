export type PeezyUser = {
  avatarUrl?: string | undefined;
  createdAt: string;
  displayName?: string | undefined;
  id: string;
  primaryEmail?:
    | {
        value: string;
        verified: boolean;
      }
    | undefined;
  status: "active" | "disabled";
};

export type IdentityCredential =
  | {
      id: string;
      kind: "social";
      linkedAt: string;
      provider: "apple" | "discord" | "github" | "telegram" | "twitter";
    }
  | {
      id: string;
      kind: "email";
      linkedAt: string;
      value: string;
      verified: boolean;
    }
  | {
      id: string;
      kind: "passkey";
      label?: string | undefined;
      linkedAt: string;
    }
  | {
      accountKind: "eoa" | "smart-account";
      address: `0x${string}`;
      chainId?: number | undefined;
      family: "evm";
      id: string;
      kind: "wallet";
      linkedAt: string;
      signInEnabled: boolean;
      verifiedChainIds: number[];
    };

export type IdentityMeResponse = {
  credentials: IdentityCredential[];
  user: PeezyUser;
};

export type WalletChallengeResponse = {
  address: `0x${string}`;
  chainId: number;
  domain: string;
  expirationTime: string;
  issuedAt: string;
  message: string;
  nonce: string;
  statement: string;
  uri: string;
  version: "1";
};

export type WalletGrantResponse = {
  expiresAt: string;
  grant: string;
  user: PeezyUser;
};

export type WalletGrantExchangeResponse = {
  expiresAt: string;
  subject: string;
};

export type SocialLinkHandoffResponse = {
  expiresAt: string;
  url: string;
};
