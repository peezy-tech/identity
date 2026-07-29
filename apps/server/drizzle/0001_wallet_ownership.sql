CREATE OR REPLACE FUNCTION ensure_evm_wallet_principal_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  existing_owner text;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtext('wallet-principal:evm:' || lower(NEW.address))
  );

  SELECT "user_id"
  INTO existing_owner
  FROM "wallet_principal"
  WHERE "family" = 'evm'
    AND "account_kind" = 'eoa'
    AND lower("address") = lower(NEW.address)
  LIMIT 1;

  IF existing_owner IS NULL THEN
    INSERT INTO "wallet_principal" (
      "id",
      "user_id",
      "family",
      "account_kind",
      "address",
      "chain_id",
      "sign_in_enabled",
      "created_at",
      "updated_at"
    )
    VALUES (
      gen_random_uuid()::text,
      NEW.user_id,
      'evm',
      'eoa',
      NEW.address,
      NULL,
      true,
      now(),
      now()
    );
  ELSIF existing_owner <> NEW.user_id THEN
    RAISE EXCEPTION 'EVM wallet is already linked to another identity'
      USING ERRCODE = '23505',
        CONSTRAINT = 'wallet_principal_eoa_address_uidx';
  END IF;

  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER wallet_address_owner_guard
BEFORE INSERT OR UPDATE OF "address", "user_id"
ON "wallet_address"
FOR EACH ROW
EXECUTE FUNCTION ensure_evm_wallet_principal_owner();
