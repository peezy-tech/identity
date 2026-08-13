# peezy.tech Identity

Shared identity provider and SDKs for peezy.tech projects.

The service gives every person one stable peezy.tech subject across products.
Social accounts and wallets are credentials attached to that subject; a wallet
is never required to create an account. Verified email is exposed as an
identity attribute when a social provider supplies it. Passkeys are reserved as
a future credential type in the public contract, but are not enabled in v0.1.
An account may also claim one permanent, globally unique peezy.tech handle.
OIDC clients receive it as `preferred_username` while continuing to authenticate
the person by the stable issuer and subject.

The provider exposes OAuth 2.1 / OpenID Connect for normal application sign-in,
hosted EVM SIWE and Solana SIWS sign-in, and a bounded EVM wallet-grant flow for
applications that need to preserve an in-page SIWE experience. Product
authorization remains in each product:
PledgeCash, for example, continues to own alert preferences, notification
channels, subscriptions, and fresh Boardroom-control proofs.

Identity also supports explicitly registered public browser clients through
authorization code + PKCE-S256. These clients hold no secret and may use only
cosmetic profile identity unless a product introduces a separate server-side
authorization boundary.

## Packages

- `@peezy.tech/identity`: versioned public contracts and a small HTTP client.
- `@peezy.tech/identity-server`: access-token verification and confidential
  server helpers.
- `apps/server`: the self-hosted identity provider.

The first release is also attached to the GitHub release as installable package
tarballs. npm trusted publishing can be enabled later without changing the
package API.

## Development

Requirements:

- Bun 1.3.11
- PostgreSQL 15 or newer

```sh
bun install --frozen-lockfile
bun run typecheck
bun run test
bun run build
bun run package:smoke
bun run format:check
```

Run the service after configuring the variables documented in
[`apps/server/.env.example`](apps/server/.env.example):

```sh
bun run dev
```

See [`docs/architecture.md`](docs/architecture.md) for the trust boundaries,
[`docs/operations.md`](docs/operations.md) for the production contract, and
[`docs/pledge-cash-migration.md`](docs/pledge-cash-migration.md) for the
compatibility migration.
