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

Existing PledgeCash sessions and transient verification rows are deliberately
not copied. The compatibility adapter continues to validate already-issued
PledgeCash sessions locally while all new authentication proofs are handled by
Identity.

Keep in PledgeCash:

- organizations, memberships, invitations, and product roles;
- alert-wallet coverage, renamed so it cannot be confused with credentials;
- wallet-link compatibility nonces until the old route is retired;
- notification channels and Telegram link codes;
- subscriptions and notification deliveries;
- Boardroom-control challenges and claims.

PledgeCash product tables retain the immutable identity subject as a value, not
as a cross-database foreign key.

## Cutover

1. Deploy the provider schema and service without directing client traffic to
   it, then configure the PledgeCash compatibility adapter.
2. Enter an identity-write maintenance window across every PledgeCash
   instance. Stop user creation and every provider, email, and wallet
   credential mutation; disable background writers and legacy database
   triggers; drain in-flight identity requests; and revoke or otherwise block
   the legacy credential writer role. Existing product reads and already-issued
   sessions may remain available. Keep this write barrier in place through
   step 6.
3. After the write barrier is confirmed, import identity rows while preserving
   all user UUIDs. Run the final dry-run against the quiesced source:

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

   A preliminary dry-run may happen before the maintenance window, but it does
   not replace this final quiesced read. If any legacy credential write occurs
   after the final dry-run starts, do not cut over; restore the barrier and
   repeat the final import and verification.

4. While legacy writes remain blocked, compare row counts, provider-subject
   uniqueness, normalized wallet ownership, and the importer's source-to-target
   ID mappings.
5. Atomically enable Identity as the sole credential writer and disable the
   legacy credential-write routes exactly once.
6. Remove the maintenance barrier only after confirming new credential writes
   reach Identity. Continue accepting legacy PledgeCash sessions until their
   original expiry while issuing new product sessions through Identity.
7. Reconcile the source and target again after cutover.
8. Remove legacy credential writes, writer privileges, and database triggers
   after the compatibility window and reconciliation complete.

Permanent dual writing is forbidden.
