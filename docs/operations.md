# Production operations

## Durable state

PostgreSQL and `IDENTITY_SECRET` form one recoverable unit. The secret encrypts
stored provider material and protects identity signing state, so it must be a
stable, randomly generated deployment secret of at least 32 characters. Back it
up through the secret manager alongside database recovery procedures. Changing
or losing it in place invalidates sessions and can make persisted signing or
provider material unreadable; a future key-rotation procedure must explicitly
decrypt and re-encrypt that state before the old key is removed.

Keep the app API secret, OIDC client secret, social-provider secrets, database
credentials, and `IDENTITY_SECRET` distinct. The service rejects reuse of a
PledgeCash app API secret as its OIDC client secret. Removing a config-managed
app or OIDC client from deployment configuration disables it atomically on the
next successful start. Resource audiences and client-to-resource grants are
reconciled in the same transaction, so a removed audience is disabled and its
config-managed grants are deleted before the service begins listening.

## OIDC client registration

Every entry in `IDENTITY_OIDC_CLIENTS` declares its `type` explicitly:

- `confidential` clients require a distinct `clientSecret`, use
  `client_secret_basic`, and retain the current authorization-code and refresh
  behavior. They must not declare browser `origins`.
- `public-browser` clients forbid `clientSecret`, require one or more exact
  `origins`, use token authentication method `none`, and receive only
  authorization-code grants with PKCE-S256 and `openid profile` scopes.

Redirect URIs are exact allowlist entries. Public-client redirect origins must
also appear in that client's origin list. Remote entries require HTTPS;
loopback HTTP is allowed only for local development. Wildcards, credentials,
fragments, and path-bearing origin entries are rejected at startup. A public
client ID is intentionally non-secret and may be shipped in browser assets.

The combined origins of enabled public clients receive CORS only on:

- `/api/auth/.well-known/openid-configuration`;
- `/api/auth/oauth2/token`;
- `/api/auth/oauth2/userinfo`; and
- `/api/auth/jwks`.

These responses never use wildcard origins or credentialed CORS. Registering a
public client does not add its origins to `IDENTITY_TRUSTED_ORIGINS` and does
not grant cross-origin access to `/v1/*`, hosted session endpoints, account
management, wallet grants, or proof flows.

To add or change a public client, review every redirect and origin literally,
update deployment configuration, and restart Identity so client seeding is one
transaction. Verify discovery advertises `none`, an allowed-origin preflight
succeeds, an unregistered origin receives no CORS grant, and a real code + PKCE
exchange works without a secret. Removing the entry and restarting disables
the managed client atomically; stale registrations cannot authorize or exchange
new codes.

Rollback the service image and its matching configuration together. If a
public-client rollout must be withdrawn without rolling back code, remove its
entry, restart, and verify the row is disabled. Public clients have no secret
to rotate. Rotate a confidential client secret by replacing it in the protected
runtime environment and restarting; coordinate the consumer cutover so the old
secret is not assumed to remain usable.

## Network edge

Terminate TLS at `identity.peezy.tech` and make the service origin reachable
only through the deployment's reverse proxy or private network. The proxy must:

- replace, rather than append to, client-supplied forwarding headers at the
  public edge;
- send the normalized client chain in `X-Forwarded-For`;
- preserve the original HTTPS host and scheme;
- apply a client-IP rate limit before requests reach the service;
- enforce an upstream request-body limit no larger than the service's public
  API limit where practical.

Set `IDENTITY_TRUSTED_PROXIES` to the exact proxy addresses or narrow CIDRs.
Never use a broad private range that can also contain untrusted clients. An
empty value accepts only a single forwarded address. The configured
`IDENTITY_BASE_URL` remains authoritative, so forwarded host headers do not
select the issuer.

## Release and startup

Build the checked-in Dockerfile from a reviewed tag. Run migrations and client
seeding as part of service startup; a failed migration or seed prevents the
server from listening. Use PostgreSQL 15 or newer and take a restorable backup
before applying a release that changes schema or import behavior.

The v0.1 OAuth provider is pinned to Better Auth `1.7.0-rc.1`, the first release
candidate containing the resource-binding fix for GHSA-p2fr-6hmx-4528 without
the subsequent account-schema transition. Treat dependency upgrades as schema
changes: regenerate migrations and rerun the successful-resource and
cross-resource rejection tests before release.

Monitor:

- `/health/live` for process liveness;
- `/health/ready` for database readiness;
- application logs for unhandled request failures;
- `identity_audit_event` for credential and migration lifecycle events.

Do not send traffic until readiness succeeds. Keep at least one previously
working image reference available for rollback, but never roll the database
back independently of the compatible service and secret state.

## Social provider callback registration

Every enabled social provider must register both production Identity callbacks
directly: `/api/auth` completes ordinary sign-in and account linking, while
`/api/proof-auth` proves a duplicate account before consolidation. OAuth
providers compare these values literally; redirecting an older service domain
to Identity is not a substitute and can also break the state cookie that
completes the flow.

- Discord: `https://identity.peezy.tech/api/auth/callback/discord` and
  `https://identity.peezy.tech/api/proof-auth/callback/discord`
- Telegram: `https://identity.peezy.tech/api/auth/callback/telegram` and
  `https://identity.peezy.tech/api/proof-auth/callback/telegram`
- X: `https://identity.peezy.tech/api/auth/callback/twitter` and
  `https://identity.peezy.tech/api/proof-auth/callback/twitter`
- GitHub, when enabled: `https://identity.peezy.tech/api/auth/callback/github`
  and `https://identity.peezy.tech/api/proof-auth/callback/github`
- Apple, when enabled: `https://identity.peezy.tech/api/auth/callback/apple`
  and `https://identity.peezy.tech/api/proof-auth/callback/apple`

Provider configuration is a release gate. For each enabled provider, complete
a hosted sign-in and a duplicate-account proof, confirm the provider receives
the matching exact callback above, and verify the browser returns to
`/account`. The normal flow must show “Signed in to peezy.tech Identity”; the
proof flow must show its consolidation preview. Test these separately from
application OIDC callbacks such as PledgeCash. A committed account
consolidation revokes both subjects' sessions and OAuth material, so the user
must complete a fresh sign-in to the surviving account.

## PledgeCash cutover

Follow the dry-run, confirmed import, and reconciliation procedure in
[`pledge-cash-migration.md`](pledge-cash-migration.md). The source and target
must be separate databases; the importer resolves both live endpoints and
rejects a same-database configuration. Applying rows, verifying every mapping,
and writing the migration audit event happen in one transaction.

Do not enable permanent dual writes. Switch new credential proofs to Identity
once, retain existing PledgeCash sessions for their original lifetime, and keep
all Boardroom authorization and product organization state in PledgeCash.
