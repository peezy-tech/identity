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

## PledgeCash cutover

Follow the dry-run, confirmed import, and reconciliation procedure in
[`pledge-cash-migration.md`](pledge-cash-migration.md). The source and target
must be separate databases; the importer resolves both live endpoints and
rejects a same-database configuration. Applying rows, verifying every mapping,
and writing the migration audit event happen in one transaction.

Do not enable permanent dual writes. Switch new credential proofs to Identity
once, retain existing PledgeCash sessions for their original lifetime, and keep
all Boardroom authorization and product organization state in PledgeCash.
