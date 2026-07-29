CREATE TABLE "session_handoff" (
	"id" text PRIMARY KEY NOT NULL,
	"token_hash" text NOT NULL,
	"client_id" text NOT NULL,
	"user_id" text NOT NULL,
	"provider" text NOT NULL,
	"callback_url" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"consumed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "session_handoff_token_hash_unique" UNIQUE("token_hash"),
	CONSTRAINT "session_handoff_provider_check" CHECK ("session_handoff"."provider" IN ('apple', 'discord', 'github', 'telegram', 'twitter'))
);
--> statement-breakpoint
ALTER TABLE "app_client" ADD COLUMN "wallet_link_siwe_statement" text;--> statement-breakpoint
UPDATE "app_client"
SET "wallet_link_siwe_statement" = "siwe_statement"
WHERE "wallet_link_siwe_statement" IS NULL;--> statement-breakpoint
ALTER TABLE "app_client"
ALTER COLUMN "wallet_link_siwe_statement" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "session_handoff" ADD CONSTRAINT "session_handoff_client_id_app_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."app_client"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session_handoff" ADD CONSTRAINT "session_handoff_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "session_handoff_client_idx" ON "session_handoff" USING btree ("client_id","created_at");--> statement-breakpoint
CREATE INDEX "session_handoff_expiry_idx" ON "session_handoff" USING btree ("expires_at");
