ALTER TABLE "user" ADD COLUMN "handle" text;--> statement-breakpoint
CREATE UNIQUE INDEX "user_handle_uidx" ON "user" USING btree ("handle");--> statement-breakpoint
ALTER TABLE "user" ADD CONSTRAINT "user_handle_check" CHECK ("user"."handle" IS NULL OR "user"."handle" ~ '^[a-z][a-z0-9-]{1,30}[a-z0-9]$');