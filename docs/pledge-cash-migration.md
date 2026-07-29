# PledgeCash compatibility migration

## Required behavior

The extraction must preserve these existing behaviors:

- the current wallet-first entry path remains available;
- the first valid wallet SIWE proof creates an account;
- every explicitly linked EOA wallet can sign into the same account;
- disabling PledgeCash alert coverage does not remove a sign-in credential;
- configured social providers can be linked explicitly;
- social-provider or email matches never link accounts implicitly;
- existing PledgeCash user UUIDs become the same peezy.tech OIDC subjects;
- current PledgeCash sessions remain valid until their existing expiry;
- Telegram social authentication and Telegram alert delivery stay separate;
- Boardroom-control proofs remain fresh, chain scoped, and PledgeCash owned.

The new provider additionally permits walletless account creation. A
social-first peezy.tech user may enter PledgeCash and is asked to link a wallet
only when using a wallet-dependent feature.

## Data ownership

Canonicalize in peezy.tech Identity:

- `users`
- `auth_accounts`
- `auth_wallets`
- `wallet_owners`
- shared `organizations`, members, and invitations

Existing PledgeCash sessions and transient verification rows are deliberately
not copied. The compatibility adapter continues to validate already-issued
PledgeCash sessions locally while all new authentication proofs are handled by
Identity.

Keep in PledgeCash:

- alert-wallet coverage, renamed so it cannot be confused with credentials;
- wallet-link compatibility nonces until the old route is retired;
- notification channels and Telegram link codes;
- subscriptions and notification deliveries;
- Boardroom-control challenges and claims.

PledgeCash product tables retain the immutable identity subject as a value, not
as a cross-database foreign key.

## Cutover

1. Import identity rows while preserving all user UUIDs. Dry-run first:

   ```sh
   PLEDGE_DATABASE_URL=postgres://... \
   DATABASE_URL=postgres://... \
   bun --cwd apps/server import:pledge-cash
   ```

   Apply only after the report passes:

   ```sh
   CONFIRM_IDENTITY_IMPORT=pledge-cash \
   PLEDGE_DATABASE_URL=postgres://... \
   DATABASE_URL=postgres://... \
   bun --cwd apps/server import:pledge-cash --apply
   ```

2. Compare row counts, provider-subject uniqueness, normalized wallet ownership,
   organization membership, and the importer's source-to-target ID mappings.
3. Deploy the provider and configure the PledgeCash compatibility adapter.
4. Switch credential writes to Identity exactly once.
5. Continue accepting legacy PledgeCash sessions until their original expiry,
   while issuing new product sessions through Identity.
6. Remove legacy credential writes and database triggers after the compatibility
   window and reconciliation complete.

Permanent dual writing is forbidden.
