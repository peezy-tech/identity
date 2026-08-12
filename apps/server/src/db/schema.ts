import { relations, sql } from "drizzle-orm";
import {
  check,
  pgTable,
  text,
  timestamp,
  boolean,
  bigint,
  integer,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const user = pgTable(
  "user",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    name: text("name").notNull(),
    handle: text("handle"),
    email: text("email").notNull().unique(),
    emailVerified: boolean("email_verified").default(false).notNull(),
    image: text("image"),
    status: text("status").default("active").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [
    uniqueIndex("user_handle_uidx").on(table.handle),
    check(
      "user_handle_check",
      sql`${table.handle} IS NULL OR ${table.handle} ~ '^[a-z][a-z0-9-]{1,30}[a-z0-9]$'`,
    ),
    check(
      "user_status_check",
      sql`${table.status} IN ('active', 'disabled', 'merged')`,
    ),
  ],
);

export const session = pgTable(
  "session",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    expiresAt: timestamp("expires_at").notNull(),
    token: text("token").notNull().unique(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    activeOrganizationId: text("active_organization_id"),
  },
  (table) => [index("session_userId_idx").on(table.userId)],
);

export const account = pgTable(
  "account",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at"),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
    scope: text("scope"),
    password: text("password"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [
    uniqueIndex("account_provider_account_uidx").on(
      table.providerId,
      table.accountId,
    ),
    index("account_userId_idx").on(table.userId),
  ],
);

export const verification = pgTable(
  "verification",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [index("verification_identifier_idx").on(table.identifier)],
);

export const rateLimit = pgTable(
  "rate_limit",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    key: text("key").notNull().unique(),
    count: integer("count").notNull(),
    lastRequest: bigint("last_request", { mode: "number" }).notNull(),
  },
  (table) => [index("rate_limit_last_request_idx").on(table.lastRequest)],
);

export const jwks = pgTable("jwks", {
  id: text("id")
    .primaryKey()
    .default(sql`gen_random_uuid()::text`),
  publicKey: text("public_key").notNull(),
  privateKey: text("private_key").notNull(),
  createdAt: timestamp("created_at").notNull(),
  expiresAt: timestamp("expires_at"),
  alg: text("alg"),
  crv: text("crv"),
});

export const walletAddress = pgTable(
  "wallet_address",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    address: text("address").notNull(),
    chainId: integer("chain_id").notNull(),
    isPrimary: boolean("is_primary").default(false).notNull(),
    createdAt: timestamp("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("wallet_address_address_chain_uidx").on(
      sql`lower(${table.address})`,
      table.chainId,
    ),
    uniqueIndex("wallet_address_primary_uidx")
      .on(table.userId)
      .where(sql`${table.isPrimary} = true`),
    index("walletAddress_userId_idx").on(table.userId),
    check("wallet_address_chain_check", sql`${table.chainId} > 0`),
  ],
);

export const walletPrincipal = pgTable(
  "wallet_principal",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    family: text("family").default("evm").notNull(),
    accountKind: text("account_kind").default("eoa").notNull(),
    address: text("address").notNull(),
    chainId: integer("chain_id"),
    signInEnabled: boolean("sign_in_enabled").default(true).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [
    uniqueIndex("wallet_principal_eoa_address_uidx")
      .on(table.family, sql`lower(${table.address})`)
      .where(sql`${table.family} = 'evm' AND ${table.accountKind} = 'eoa'`),
    uniqueIndex("wallet_principal_solana_address_uidx")
      .on(table.family, table.address)
      .where(sql`${table.family} = 'solana'`),
    uniqueIndex("wallet_principal_smart_account_uidx")
      .on(table.family, table.chainId, sql`lower(${table.address})`)
      .where(
        sql`${table.family} = 'evm' AND ${table.accountKind} = 'smart-account'`,
      ),
    index("wallet_principal_user_idx").on(table.userId),
    check(
      "wallet_principal_family_check",
      sql`${table.family} IN ('evm', 'solana')`,
    ),
    check(
      "wallet_principal_kind_check",
      sql`${table.accountKind} IN ('eoa', 'smart-account')`,
    ),
    check(
      "wallet_principal_scope_check",
      sql`(${table.family} = 'evm' AND ${table.accountKind} = 'eoa' AND ${table.chainId} IS NULL)
        OR (${table.family} = 'evm' AND ${table.accountKind} = 'smart-account' AND ${table.chainId} > 0)
        OR (${table.family} = 'solana' AND ${table.accountKind} = 'eoa' AND ${table.chainId} IS NULL)`,
    ),
  ],
);

export const appClient = pgTable("app_client", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  secretHash: text("secret_hash").notNull(),
  origins: text("origins").array().notNull(),
  siweStatement: text("siwe_statement").notNull(),
  walletLinkSiweStatement: text("wallet_link_siwe_statement").notNull(),
  disabled: boolean("disabled").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at")
    .defaultNow()
    .$onUpdate(() => /* @__PURE__ */ new Date())
    .notNull(),
});

export const sessionHandoff = pgTable(
  "session_handoff",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    tokenHash: text("token_hash").notNull().unique(),
    clientId: text("client_id")
      .notNull()
      .references(() => appClient.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    callbackUrl: text("callback_url").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    consumedAt: timestamp("consumed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("session_handoff_client_idx").on(table.clientId, table.createdAt),
    index("session_handoff_expiry_idx").on(table.expiresAt),
    check(
      "session_handoff_provider_check",
      sql`${table.provider} IN ('apple', 'discord', 'github', 'telegram', 'twitter')`,
    ),
  ],
);

export const walletChallenge = pgTable(
  "wallet_challenge",
  {
    nonce: text("nonce").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => appClient.id, { onDelete: "cascade" }),
    address: text("address").notNull(),
    chainId: integer("chain_id").notNull(),
    domain: text("domain").notNull(),
    uri: text("uri").notNull(),
    statement: text("statement").notNull(),
    purpose: text("purpose").default("sign-in").notNull(),
    issuedAt: timestamp("issued_at").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("wallet_challenge_client_idx").on(table.clientId, table.createdAt),
    index("wallet_challenge_expiry_idx").on(table.expiresAt),
    check("wallet_challenge_chain_check", sql`${table.chainId} > 0`),
    check(
      "wallet_challenge_purpose_check",
      sql`${table.purpose} IN ('link', 'sign-in')`,
    ),
  ],
);

export const walletGrant = pgTable(
  "wallet_grant",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    grantHash: text("grant_hash").notNull().unique(),
    clientId: text("client_id")
      .notNull()
      .references(() => appClient.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at").notNull(),
    consumedAt: timestamp("consumed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("wallet_grant_client_idx").on(table.clientId, table.createdAt),
    index("wallet_grant_expiry_idx").on(table.expiresAt),
    index("wallet_grant_user_idx").on(table.userId),
  ],
);

export const identityAuditEvent = pgTable(
  "identity_audit_event",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    userId: text("user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    actorUserId: text("actor_user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    kind: text("kind").notNull(),
    clientId: text("client_id"),
    credentialId: text("credential_id"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("identity_audit_event_user_idx").on(table.userId, table.createdAt),
    index("identity_audit_event_kind_idx").on(table.kind, table.createdAt),
  ],
);

export const privyMigrationAttempt = pgTable(
  "privy_migration_attempt",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    csrfHash: text("csrf_hash").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    consumedAt: timestamp("consumed_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("privy_migration_attempt_user_idx").on(table.userId, table.createdAt),
    index("privy_migration_attempt_expiry_idx").on(table.expiresAt),
  ],
);

export const privyMigrationClaim = pgTable(
  "privy_migration_claim",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    privyUserId: text("privy_user_id").notNull().unique(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    snapshotDigest: text("snapshot_digest").notNull(),
    state: text("state").default("claimed").notNull(),
    claimedAt: timestamp("claimed_at").defaultNow().notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [
    index("privy_migration_claim_user_idx").on(table.userId, table.claimedAt),
    check(
      "privy_migration_claim_state_check",
      sql`${table.state} IN ('claimed', 'revoked')`,
    ),
  ],
);

export const privyMigrationIdentity = pgTable(
  "privy_migration_identity",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    claimId: text("claim_id")
      .notNull()
      .references(() => privyMigrationClaim.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    provider: text("provider"),
    sourceAccountId: text("source_account_id").notNull(),
    sourceKey: text("source_key").notNull(),
    displayHint: text("display_hint").notNull(),
    walletAddress: text("wallet_address"),
    walletType: text("wallet_type"),
    chainType: text("chain_type"),
    verifiedAt: timestamp("verified_at"),
    disposition: text("disposition").notNull(),
    targetCredentialId: text("target_credential_id"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at")
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
  },
  (table) => [
    uniqueIndex("privy_migration_identity_claim_source_uidx").on(
      table.claimId,
      table.sourceKey,
    ),
    index("privy_migration_identity_claim_idx").on(table.claimId),
    index("privy_migration_identity_provider_idx").on(
      table.provider,
      table.sourceAccountId,
    ),
    index("privy_migration_identity_wallet_idx").on(
      sql`lower(${table.walletAddress})`,
    ),
    check(
      "privy_migration_identity_disposition_check",
      sql`${table.disposition} IN ('already_linked', 'needs_reverification', 'legacy_only', 'conflict', 'linked')`,
    ),
  ],
);

export const accountWalletLinkChallenge = pgTable(
  "account_wallet_link_challenge",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    nonce: text("nonce").notNull().unique(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    address: text("address").notNull(),
    family: text("family").default("evm").notNull(),
    chainId: integer("chain_id"),
    message: text("message").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("account_wallet_link_challenge_user_idx").on(
      table.userId,
      table.createdAt,
    ),
    index("account_wallet_link_challenge_expiry_idx").on(table.expiresAt),
    check(
      "account_wallet_link_family_check",
      sql`${table.family} IN ('evm', 'solana')`,
    ),
    check(
      "account_wallet_link_chain_check",
      sql`(${table.family} = 'evm' AND ${table.chainId} > 0)
        OR (${table.family} = 'solana' AND ${table.chainId} IS NULL)`,
    ),
  ],
);

export const solanaAuthChallenge = pgTable(
  "solana_auth_challenge",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    nonce: text("nonce").notNull().unique(),
    mode: text("mode").notNull(),
    address: text("address").notNull(),
    message: text("message").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("solana_auth_challenge_expiry_idx").on(table.expiresAt),
    check(
      "solana_auth_challenge_mode_check",
      sql`${table.mode} IN ('primary', 'proof')`,
    ),
  ],
);

export const identitySubjectMerge = pgTable(
  "identity_subject_merge",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    sourceUserId: text("source_user_id")
      .notNull()
      .unique()
      .references(() => user.id, { onDelete: "restrict" }),
    targetUserId: text("target_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "restrict" }),
    actorUserId: text("actor_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "restrict" }),
    status: text("status").default("prepared").notNull(),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    committedAt: timestamp("committed_at"),
  },
  (table) => [
    index("identity_subject_merge_target_idx").on(table.targetUserId),
    check(
      "identity_subject_merge_status_check",
      sql`${table.status} IN ('prepared', 'committed')`,
    ),
    check(
      "identity_subject_merge_distinct_users_check",
      sql`${table.sourceUserId} <> ${table.targetUserId}`,
    ),
  ],
);

export const organization = pgTable(
  "organization",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    name: text("name").notNull(),
    slug: text("slug").notNull().unique(),
    logo: text("logo"),
    createdAt: timestamp("created_at").notNull(),
    metadata: text("metadata"),
  },
  (table) => [uniqueIndex("organization_slug_uidx").on(table.slug)],
);

export const member = pgTable(
  "member",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role").default("member").notNull(),
    createdAt: timestamp("created_at").notNull(),
  },
  (table) => [
    index("member_organizationId_idx").on(table.organizationId),
    index("member_userId_idx").on(table.userId),
  ],
);

export const invitation = pgTable(
  "invitation",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    role: text("role"),
    status: text("status").default("pending").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    inviterId: text("inviter_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
  },
  (table) => [
    index("invitation_organizationId_idx").on(table.organizationId),
    index("invitation_email_idx").on(table.email),
  ],
);

export const oauthClient = pgTable(
  "oauth_client",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    clientId: text("client_id").notNull().unique(),
    clientSecret: text("client_secret"),
    disabled: boolean("disabled").default(false),
    skipConsent: boolean("skip_consent"),
    enableEndSession: boolean("enable_end_session"),
    subjectType: text("subject_type"),
    scopes: text("scopes").array(),
    userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at"),
    updatedAt: timestamp("updated_at"),
    name: text("name"),
    uri: text("uri"),
    icon: text("icon"),
    contacts: text("contacts").array(),
    tos: text("tos"),
    policy: text("policy"),
    softwareId: text("software_id"),
    softwareVersion: text("software_version"),
    softwareStatement: text("software_statement"),
    redirectUris: text("redirect_uris").array().notNull(),
    postLogoutRedirectUris: text("post_logout_redirect_uris").array(),
    backchannelLogoutUri: text("backchannel_logout_uri"),
    backchannelLogoutSessionRequired: boolean(
      "backchannel_logout_session_required",
    ),
    tokenEndpointAuthMethod: text("token_endpoint_auth_method"),
    jwks: text("jwks"),
    jwksUri: text("jwks_uri"),
    grantTypes: text("grant_types").array(),
    responseTypes: text("response_types").array(),
    public: boolean("public"),
    type: text("type"),
    requirePKCE: boolean("require_pkce"),
    dpopBoundAccessTokens: boolean("dpop_bound_access_tokens").default(false),
    referenceId: text("reference_id"),
    metadata: jsonb("metadata"),
  },
  (table) => [index("oauthClient_userId_idx").on(table.userId)],
);

export const oauthResource = pgTable("oauth_resource", {
  id: text("id")
    .primaryKey()
    .default(sql`gen_random_uuid()::text`),
  identifier: text("identifier").notNull().unique(),
  name: text("name").notNull(),
  accessTokenTtl: integer("access_token_ttl"),
  refreshTokenTtl: integer("refresh_token_ttl"),
  signingAlgorithm: text("signing_algorithm"),
  signingKeyId: text("signing_key_id"),
  allowedScopes: text("allowed_scopes").array(),
  customClaims: jsonb("custom_claims"),
  dpopBoundAccessTokensRequired: boolean(
    "dpop_bound_access_tokens_required",
  ).default(false),
  disabled: boolean("disabled").default(false),
  createdAt: timestamp("created_at"),
  updatedAt: timestamp("updated_at"),
  policyVersion: integer("policy_version").default(1),
  metadata: jsonb("metadata"),
});

export const oauthClientResource = pgTable(
  "oauth_client_resource",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClient.clientId, { onDelete: "cascade" }),
    resourceId: text("resource_id")
      .notNull()
      .references(() => oauthResource.identifier, { onDelete: "cascade" }),
    metadata: jsonb("metadata"),
    createdAt: timestamp("created_at"),
  },
  (table) => [
    uniqueIndex("oauth_client_resource_pair_uidx").on(
      table.clientId,
      table.resourceId,
    ),
    index("oauthClientResource_clientId_idx").on(table.clientId),
    index("oauthClientResource_resourceId_idx").on(table.resourceId),
  ],
);

export const oauthRefreshToken = pgTable(
  "oauth_refresh_token",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    token: text("token").notNull().unique(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClient.clientId, { onDelete: "cascade" }),
    sessionId: text("session_id").references(() => session.id, {
      onDelete: "set null",
    }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    referenceId: text("reference_id"),
    authorizationCodeId: text("authorization_code_id"),
    resources: text("resources").array(),
    requestedUserInfoClaims: text("requested_user_info_claims").array(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").notNull(),
    revoked: timestamp("revoked"),
    rotatedAt: timestamp("rotated_at"),
    rotationReplayResponse: text("rotation_replay_response"),
    rotationReplayExpiresAt: timestamp("rotation_replay_expires_at"),
    authTime: timestamp("auth_time"),
    confirmation: jsonb("confirmation"),
    scopes: text("scopes").array().notNull(),
  },
  (table) => [
    index("oauthRefreshToken_clientId_idx").on(table.clientId),
    index("oauthRefreshToken_sessionId_idx").on(table.sessionId),
    index("oauthRefreshToken_userId_idx").on(table.userId),
    index("oauthRefreshToken_authorizationCodeId_idx").on(
      table.authorizationCodeId,
    ),
  ],
);

export const oauthAccessToken = pgTable(
  "oauth_access_token",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    token: text("token").notNull().unique(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClient.clientId, { onDelete: "cascade" }),
    sessionId: text("session_id").references(() => session.id, {
      onDelete: "set null",
    }),
    userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
    referenceId: text("reference_id"),
    authorizationCodeId: text("authorization_code_id"),
    resources: text("resources").array(),
    requestedUserInfoClaims: text("requested_user_info_claims").array(),
    refreshId: text("refresh_id").references(() => oauthRefreshToken.id, {
      onDelete: "cascade",
    }),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").notNull(),
    revoked: timestamp("revoked"),
    confirmation: jsonb("confirmation"),
    scopes: text("scopes").array().notNull(),
  },
  (table) => [
    index("oauthAccessToken_clientId_idx").on(table.clientId),
    index("oauthAccessToken_sessionId_idx").on(table.sessionId),
    index("oauthAccessToken_userId_idx").on(table.userId),
    index("oauthAccessToken_authorizationCodeId_idx").on(
      table.authorizationCodeId,
    ),
    index("oauthAccessToken_refreshId_idx").on(table.refreshId),
  ],
);

export const oauthConsent = pgTable(
  "oauth_consent",
  {
    id: text("id")
      .primaryKey()
      .default(sql`gen_random_uuid()::text`),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClient.clientId, { onDelete: "cascade" }),
    userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
    referenceId: text("reference_id"),
    resources: text("resources").array(),
    requestedUserInfoClaims: text("requested_user_info_claims").array(),
    scopes: text("scopes").array().notNull(),
    createdAt: timestamp("created_at").notNull(),
    updatedAt: timestamp("updated_at").notNull(),
  },
  (table) => [
    index("oauthConsent_clientId_idx").on(table.clientId),
    index("oauthConsent_userId_idx").on(table.userId),
  ],
);

export const oauthClientAssertion = pgTable("oauth_client_assertion", {
  id: text("id")
    .primaryKey()
    .default(sql`gen_random_uuid()::text`),
  expiresAt: timestamp("expires_at").notNull(),
});

export const userRelations = relations(user, ({ many }) => ({
  sessions: many(session),
  accounts: many(account),
  walletAddresss: many(walletAddress),
  walletPrincipals: many(walletPrincipal),
  members: many(member),
  invitations: many(invitation),
  oauthClients: many(oauthClient),
  oauthRefreshTokens: many(oauthRefreshToken),
  oauthAccessTokens: many(oauthAccessToken),
  oauthConsents: many(oauthConsent),
}));

export const sessionRelations = relations(session, ({ one, many }) => ({
  user: one(user, {
    fields: [session.userId],
    references: [user.id],
  }),
  oauthRefreshTokens: many(oauthRefreshToken),
  oauthAccessTokens: many(oauthAccessToken),
}));

export const accountRelations = relations(account, ({ one }) => ({
  user: one(user, {
    fields: [account.userId],
    references: [user.id],
  }),
}));

export const walletAddressRelations = relations(walletAddress, ({ one }) => ({
  user: one(user, {
    fields: [walletAddress.userId],
    references: [user.id],
  }),
}));

export const organizationRelations = relations(organization, ({ many }) => ({
  members: many(member),
  invitations: many(invitation),
}));

export const memberRelations = relations(member, ({ one }) => ({
  organization: one(organization, {
    fields: [member.organizationId],
    references: [organization.id],
  }),
  user: one(user, {
    fields: [member.userId],
    references: [user.id],
  }),
}));

export const invitationRelations = relations(invitation, ({ one }) => ({
  organization: one(organization, {
    fields: [invitation.organizationId],
    references: [organization.id],
  }),
  user: one(user, {
    fields: [invitation.inviterId],
    references: [user.id],
  }),
}));

export const oauthClientRelations = relations(oauthClient, ({ one, many }) => ({
  user: one(user, {
    fields: [oauthClient.userId],
    references: [user.id],
  }),
  oauthClientResources: many(oauthClientResource),
  oauthRefreshTokens: many(oauthRefreshToken),
  oauthAccessTokens: many(oauthAccessToken),
  oauthConsents: many(oauthConsent),
}));

export const oauthResourceRelations = relations(oauthResource, ({ many }) => ({
  oauthClientResources: many(oauthClientResource),
}));

export const oauthClientResourceRelations = relations(
  oauthClientResource,
  ({ one }) => ({
    oauthClient: one(oauthClient, {
      fields: [oauthClientResource.clientId],
      references: [oauthClient.clientId],
    }),
    oauthResource: one(oauthResource, {
      fields: [oauthClientResource.resourceId],
      references: [oauthResource.identifier],
    }),
  }),
);

export const oauthRefreshTokenRelations = relations(
  oauthRefreshToken,
  ({ one, many }) => ({
    oauthClient: one(oauthClient, {
      fields: [oauthRefreshToken.clientId],
      references: [oauthClient.clientId],
    }),
    session: one(session, {
      fields: [oauthRefreshToken.sessionId],
      references: [session.id],
    }),
    user: one(user, {
      fields: [oauthRefreshToken.userId],
      references: [user.id],
    }),
    oauthAccessTokens: many(oauthAccessToken),
  }),
);

export const oauthAccessTokenRelations = relations(
  oauthAccessToken,
  ({ one }) => ({
    oauthClient: one(oauthClient, {
      fields: [oauthAccessToken.clientId],
      references: [oauthClient.clientId],
    }),
    session: one(session, {
      fields: [oauthAccessToken.sessionId],
      references: [session.id],
    }),
    user: one(user, {
      fields: [oauthAccessToken.userId],
      references: [user.id],
    }),
    oauthRefreshToken: one(oauthRefreshToken, {
      fields: [oauthAccessToken.refreshId],
      references: [oauthRefreshToken.id],
    }),
  }),
);

export const oauthConsentRelations = relations(oauthConsent, ({ one }) => ({
  oauthClient: one(oauthClient, {
    fields: [oauthConsent.clientId],
    references: [oauthClient.clientId],
  }),
  user: one(user, {
    fields: [oauthConsent.userId],
    references: [user.id],
  }),
}));
