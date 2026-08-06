CREATE TABLE "account_wallet_link_challenge" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"nonce" text NOT NULL,
	"user_id" text NOT NULL,
	"address" text NOT NULL,
	"family" text DEFAULT 'evm' NOT NULL,
	"chain_id" integer,
	"message" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "account_wallet_link_challenge_nonce_unique" UNIQUE("nonce"),
	CONSTRAINT "account_wallet_link_family_check" CHECK ("account_wallet_link_challenge"."family" IN ('evm', 'solana')),
	CONSTRAINT "account_wallet_link_chain_check" CHECK (("account_wallet_link_challenge"."family" = 'evm' AND "account_wallet_link_challenge"."chain_id" > 0)
        OR ("account_wallet_link_challenge"."family" = 'solana' AND "account_wallet_link_challenge"."chain_id" IS NULL))
);
--> statement-breakpoint
CREATE TABLE "identity_subject_merge" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"source_user_id" text NOT NULL,
	"target_user_id" text NOT NULL,
	"actor_user_id" text NOT NULL,
	"status" text DEFAULT 'prepared' NOT NULL,
	"metadata" jsonb NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"committed_at" timestamp,
	CONSTRAINT "identity_subject_merge_source_user_id_unique" UNIQUE("source_user_id"),
	CONSTRAINT "identity_subject_merge_status_check" CHECK ("identity_subject_merge"."status" IN ('prepared', 'committed')),
	CONSTRAINT "identity_subject_merge_distinct_users_check" CHECK ("identity_subject_merge"."source_user_id" <> "identity_subject_merge"."target_user_id")
);
--> statement-breakpoint
CREATE TABLE "privy_migration_attempt" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"user_id" text NOT NULL,
	"csrf_hash" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"consumed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "privy_migration_claim" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"privy_user_id" text NOT NULL,
	"user_id" text NOT NULL,
	"snapshot_digest" text NOT NULL,
	"state" text DEFAULT 'claimed' NOT NULL,
	"claimed_at" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "privy_migration_claim_privy_user_id_unique" UNIQUE("privy_user_id"),
	CONSTRAINT "privy_migration_claim_state_check" CHECK ("privy_migration_claim"."state" IN ('claimed', 'revoked'))
);
--> statement-breakpoint
CREATE TABLE "privy_migration_identity" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"claim_id" text NOT NULL,
	"type" text NOT NULL,
	"provider" text,
	"source_account_id" text NOT NULL,
	"source_key" text NOT NULL,
	"display_hint" text NOT NULL,
	"wallet_address" text,
	"wallet_type" text,
	"chain_type" text,
	"verified_at" timestamp,
	"disposition" text NOT NULL,
	"target_credential_id" text,
	"metadata" jsonb NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "privy_migration_identity_disposition_check" CHECK ("privy_migration_identity"."disposition" IN ('already_linked', 'needs_reverification', 'legacy_only', 'conflict', 'linked'))
);
--> statement-breakpoint
CREATE TABLE "solana_auth_challenge" (
	"id" text PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"nonce" text NOT NULL,
	"mode" text NOT NULL,
	"address" text NOT NULL,
	"message" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "solana_auth_challenge_nonce_unique" UNIQUE("nonce"),
	CONSTRAINT "solana_auth_challenge_mode_check" CHECK ("solana_auth_challenge"."mode" IN ('primary', 'proof'))
);
--> statement-breakpoint
ALTER TABLE "user" DROP CONSTRAINT "user_status_check";--> statement-breakpoint
ALTER TABLE "wallet_principal" DROP CONSTRAINT "wallet_principal_family_check";--> statement-breakpoint
ALTER TABLE "wallet_principal" DROP CONSTRAINT "wallet_principal_scope_check";--> statement-breakpoint
DROP INDEX "wallet_principal_eoa_address_uidx";--> statement-breakpoint
DROP INDEX "wallet_principal_smart_account_uidx";--> statement-breakpoint
ALTER TABLE "account_wallet_link_challenge" ADD CONSTRAINT "account_wallet_link_challenge_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_subject_merge" ADD CONSTRAINT "identity_subject_merge_source_user_id_user_id_fk" FOREIGN KEY ("source_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_subject_merge" ADD CONSTRAINT "identity_subject_merge_target_user_id_user_id_fk" FOREIGN KEY ("target_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_subject_merge" ADD CONSTRAINT "identity_subject_merge_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "privy_migration_attempt" ADD CONSTRAINT "privy_migration_attempt_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "privy_migration_claim" ADD CONSTRAINT "privy_migration_claim_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "privy_migration_identity" ADD CONSTRAINT "privy_migration_identity_claim_id_privy_migration_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."privy_migration_claim"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "account_wallet_link_challenge_user_idx" ON "account_wallet_link_challenge" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "account_wallet_link_challenge_expiry_idx" ON "account_wallet_link_challenge" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "identity_subject_merge_target_idx" ON "identity_subject_merge" USING btree ("target_user_id");--> statement-breakpoint
CREATE INDEX "privy_migration_attempt_user_idx" ON "privy_migration_attempt" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "privy_migration_attempt_expiry_idx" ON "privy_migration_attempt" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "privy_migration_claim_user_idx" ON "privy_migration_claim" USING btree ("user_id","claimed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "privy_migration_identity_claim_source_uidx" ON "privy_migration_identity" USING btree ("claim_id","source_key");--> statement-breakpoint
CREATE INDEX "privy_migration_identity_claim_idx" ON "privy_migration_identity" USING btree ("claim_id");--> statement-breakpoint
CREATE INDEX "privy_migration_identity_provider_idx" ON "privy_migration_identity" USING btree ("provider","source_account_id");--> statement-breakpoint
CREATE INDEX "privy_migration_identity_wallet_idx" ON "privy_migration_identity" USING btree (lower("wallet_address"));--> statement-breakpoint
CREATE INDEX "solana_auth_challenge_expiry_idx" ON "solana_auth_challenge" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "wallet_principal_solana_address_uidx" ON "wallet_principal" USING btree ("family","address") WHERE "wallet_principal"."family" = 'solana';--> statement-breakpoint
CREATE UNIQUE INDEX "wallet_principal_eoa_address_uidx" ON "wallet_principal" USING btree ("family",lower("address")) WHERE "wallet_principal"."family" = 'evm' AND "wallet_principal"."account_kind" = 'eoa';--> statement-breakpoint
CREATE UNIQUE INDEX "wallet_principal_smart_account_uidx" ON "wallet_principal" USING btree ("family","chain_id",lower("address")) WHERE "wallet_principal"."family" = 'evm' AND "wallet_principal"."account_kind" = 'smart-account';--> statement-breakpoint
ALTER TABLE "user" ADD CONSTRAINT "user_status_check" CHECK ("user"."status" IN ('active', 'disabled', 'merged'));--> statement-breakpoint
ALTER TABLE "wallet_principal" ADD CONSTRAINT "wallet_principal_family_check" CHECK ("wallet_principal"."family" IN ('evm', 'solana'));--> statement-breakpoint
ALTER TABLE "wallet_principal" ADD CONSTRAINT "wallet_principal_scope_check" CHECK (("wallet_principal"."family" = 'evm' AND "wallet_principal"."account_kind" = 'eoa' AND "wallet_principal"."chain_id" IS NULL)
        OR ("wallet_principal"."family" = 'evm' AND "wallet_principal"."account_kind" = 'smart-account' AND "wallet_principal"."chain_id" > 0)
        OR ("wallet_principal"."family" = 'solana' AND "wallet_principal"."account_kind" = 'eoa' AND "wallet_principal"."chain_id" IS NULL));