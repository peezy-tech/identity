# Public browser OIDC clients

## Goal

Add an explicitly registered public-client mode to peezy.tech Identity so a
browser-only application can offer **Sign in with peezy.tech** without holding
a client secret or operating an application backend.

The first consumer is Public Stream Theater. It needs identity only for
presentation, such as showing a person's peezy.tech handle, display name, and
avatar in the arena. The game must not treat browser-held identity material as
authority for moderation, purchases, private data, durable ownership, or game
simulation decisions.

This is a normal OpenID Connect authorization-code flow with PKCE. It is not a
custom lightweight login protocol, an implicit flow, or a shared Identity
cookie read from another origin.

## Implementation status

Implemented on 2026-08-13:

- explicit `confidential` and `public-browser` configuration variants;
- nullable-secret public-client seeding with authorization-code-only grants,
  PKCE-S256, `none` token authentication, and `openid profile` scopes;
- conditional discovery advertisement without dynamic client registration;
- exact-origin, non-credentialed CORS limited to discovery, token, user-info,
  and JWKS endpoints;
- signed profile claims for name, picture, and `preferred_username`;
- PostgreSQL-backed positive and negative provider integration coverage;
- operations, architecture, environment, and release documentation; and
- a Public Stream Theater integration using `oauth4webapi` with per-tab state,
  signature validation, a cosmetic profile, anonymous fallback, and local
  sign-out.

The OAuth client schema already allowed a null secret, so no database migration
was required.

## Starting state

Identity already provides the main protocol primitives:

- OpenID Connect discovery at
  `/api/auth/.well-known/openid-configuration`;
- authorization-code grants;
- mandatory PKCE support;
- ID-token claims including `sub`, `name`, `picture`, and
  `preferred_username`;
- exact registered redirect URIs;
- an OAuth client table that can represent public clients; and
- an OAuth provider dependency that supports
  `token_endpoint_auth_method: "none"` and requires PKCE for public clients.

The checked-in configuration path does not expose that capability yet.
`IDENTITY_OIDC_CLIENTS` requires every client to have a secret, and
`seedConfiguredClients` currently creates every configured client as a
confidential `web` client using `client_secret_basic`. The application also
applies browser CORS only to `/v1/*`; a browser on a product origin therefore
cannot complete a cross-origin token or user-info request today. Production
discovery consequently does not advertise `none` as a supported token endpoint
authentication method.

## Product and trust boundary

Public-client login proves an Identity authentication flow to the browser. It
does not make the browser a trusted application server.

Public Stream Theater may use the result for:

- an avatar image or scene background;
- a display name or claimed peezy.tech handle;
- local visual preferences;
- signed-in versus signed-out presentation; and
- other consequences that are harmless if a modified browser lies about them.

It must not use browser-only login as sufficient authority for:

- moderation or administration;
- purchases, payouts, or scarce inventory;
- access to another person's private information;
- durable ownership or server-persisted progression;
- posting as a user to external services;
- authoritative multiplayer state; or
- signing or authorizing blockchain transactions.

If a product later needs one of those capabilities, its server must validate an
audience-bound access token or create its own server-side session. The product
must bind a user by the stable pair `(issuer, sub)`. `preferred_username`,
email, name, and picture are attributes, not authentication keys.

## Intended browser flow

1. The application creates a cryptographically random `state`, OIDC `nonce`,
   and PKCE `code_verifier`.
2. It derives an S256 `code_challenge` and retains the temporary values for the
   callback in `sessionStorage` or equivalent per-tab storage.
3. It redirects the top-level browser to Identity's registered authorization
   endpoint with:
   - `client_id`;
   - the exact registered `redirect_uri`;
   - `response_type=code`;
   - `scope=openid profile`;
   - `state`;
   - `nonce`;
   - `code_challenge`; and
   - `code_challenge_method=S256`.
4. Identity performs its normal hosted sign-in and consent behavior.
5. Identity returns an authorization code to the registered application
   callback.
6. The browser rejects a missing, expired, or mismatched callback state.
7. The browser posts the code, client ID, exact redirect URI, and PKCE verifier
   to the token endpoint. It sends no client secret.
8. The browser validates the returned ID token: signature, issuer, audience,
   expiration, and nonce. An established OIDC client library should own these
   checks rather than application code assembling them ad hoc.
9. The application derives its cosmetic profile from the validated ID token or
   from the user-info endpoint using the access token.
10. Tokens remain in memory when possible. A page refresh may require login
    again. `sessionStorage` is acceptable for this low-authority experience;
    persistent `localStorage` is not the default.
11. Signing out clears local state. Provider logout may be offered separately
    because clearing one game's local presentation state should not
    unexpectedly sign the person out of every peezy.tech product.

Do not add the OAuth implicit flow. Do not embed a nominal client secret in the
JavaScript bundle. A client ID is public metadata, not a credential.

## Provider configuration design

Extend the existing `IDENTITY_OIDC_CLIENTS` schema rather than creating a
second unrelated registration system. Each configured client should declare
its kind explicitly.

Suggested confidential client shape:

```json
{
  "clientId": "pledge-cash",
  "clientSecret": "deployment-secret-at-least-32-characters",
  "name": "PledgeCash",
  "type": "confidential",
  "redirectUris": ["https://api.pledge.cash/auth/oauth2/callback/peezy"],
  "audiences": ["https://api.pledge.cash"],
  "requireHandle": false
}
```

Suggested public browser client shape:

```json
{
  "clientId": "public-stream-theater",
  "name": "Public Stream Theater",
  "type": "public-browser",
  "redirectUris": [
    "https://stream-theater.tmp.peezy.tech/auth/callback",
    "http://localhost:5173/auth/callback"
  ],
  "origins": ["https://stream-theater.tmp.peezy.tech", "http://localhost:5173"],
  "audiences": [],
  "requireHandle": false
}
```

Rules:

- `type` is required. Do not infer security behavior merely from the presence
  or absence of a secret.
- A confidential client requires `clientSecret` and must not declare browser
  `origins` for direct token exchange.
- A public browser client forbids `clientSecret`, requires at least one exact
  browser origin, and has no client credentials.
- Redirect URIs remain exact allow-list entries. Wildcards are forbidden.
- Origins are HTTPS origins without paths, except loopback HTTP in development.
- Public browser clients always require PKCE-S256.
- Public browser clients use authorization code grants only for the first
  release. Do not grant `client_credentials`.
- Start with `openid profile`. Do not issue `offline_access` by default.
- Start with no resource audiences. Add an audience only when a real protected
  API and server-side validation boundary exist.
- `requireHandle` stays false for Public Stream Theater unless the product
  explicitly requires every participant to claim a permanent handle.
- Config-managed client removal continues to disable that client atomically.

Discriminated configuration types are preferable to a collection of loosely
related booleans. They make it difficult to accidentally seed a public client
with a secret or a confidential client with public token CORS.

## Provider implementation

### 1. Extend configuration parsing

Update `apps/server/src/config.ts` to represent confidential and public browser
clients as a discriminated union.

Validation must reject:

- a confidential client without a secret;
- a public browser client with a secret;
- a public browser client without an origin;
- wildcard, credential-bearing, path-bearing, or otherwise invalid origins;
- non-HTTPS non-loopback redirects or origins;
- duplicate client IDs;
- duplicate origins after URL normalization; and
- a redirect whose origin is not registered for that public browser client,
  unless a documented native-client case is added later.

Retain the existing check that an application API secret and confidential OIDC
secret cannot be the same.

### 2. Seed the correct OAuth client metadata

Update `apps/server/src/clients.ts`.

Confidential clients retain the current behavior:

- `public: false`;
- `type: "web"`;
- `tokenEndpointAuthMethod: "client_secret_basic"`;
- a hashed client secret; and
- authorization-code and refresh-token grants as currently intended.

Public browser clients use:

- `public: true`;
- `type: "user-agent-based"`;
- `tokenEndpointAuthMethod: "none"`;
- no client secret or secret hash;
- `requirePKCE: true`;
- `grantTypes: ["authorization_code"]` initially;
- `responseTypes: ["code"]`; and
- scopes limited to the configured public-client policy.

Confirm how the current database schema represents a missing secret before
changing the seeder. Add a migration only if the column currently cannot be
null. Do not store an empty string or a known dummy secret.

### 3. Enable provider-level public-client support

Update `apps/server/src/auth.ts` so the OAuth provider advertises and accepts
pre-registered public clients. The discovery document must include `none` in
`token_endpoint_auth_methods_supported` whenever at least one enabled public
client exists.

Do not enable unrestricted dynamic client registration as a shortcut. Clients
remain deployment-configured and reviewed. If the dependency only exposes
public-client metadata through a dynamic-registration option, use the narrowest
supported provider hook or metadata override and cover it with integration
tests.

Keep authorization code lifetimes short and preserve the existing exact
redirect and PKCE validation.

### 4. Add narrow OAuth CORS

The browser must be able to call the token endpoint and, if used, user-info and
JWKS endpoints. Add CORS only where the public flow requires it.

The allowed origin must be resolved from enabled public-client configuration,
not from an unrestricted reflection of the request's `Origin` header. Permit
only the methods and headers each endpoint needs. Do not use
`Access-Control-Allow-Origin: *` for credentialed account/session endpoints.

Expected browser endpoints are:

- the token endpoint for code exchange;
- the user-info endpoint if the client uses it; and
- the JWKS endpoint if the selected OIDC library fetches keys directly.

Authorization and hosted sign-in remain top-level navigations and do not need
cross-origin XHR access. Identity cookies remain scoped to Identity and are not
made readable by product origins.

Preflight and response behavior must be tested from both an allowed origin and
an unregistered origin. Ensure CORS caching varies by `Origin` where necessary.

### 5. Keep claims minimal

For `openid profile`, the ID token or user-info response may provide:

- `iss`;
- `sub`;
- `aud`;
- `exp` and `iat`;
- `nonce` where required by the flow;
- `name`;
- `picture`; and
- `preferred_username` when the account has a handle.

Do not expose linked wallets, social-provider identifiers, or email without the
corresponding scope and a demonstrated product need. The browser must tolerate
missing `picture` and `preferred_username` values.

Remote avatar URLs are untrusted presentation input. Consumers must not inject
them as HTML. They should use ordinary image or CSS URL assignment, provide a
fallback, and avoid assuming every upstream host permits canvas-safe CORS.

## Test plan

### Configuration tests

Add cases proving:

- existing confidential configuration remains valid;
- a valid public browser registration parses without a secret;
- the invalid combinations listed above fail closed;
- loopback HTTP is accepted for development but remote HTTP is rejected; and
- public origins become trusted only for the intended OAuth browser endpoints,
  not implicitly for every account-management endpoint.

### Client seeding tests

Prove the persisted public client has:

- no client secret;
- `public = true`;
- `type = user-agent-based`;
- token authentication method `none`;
- mandatory PKCE;
- authorization-code-only grants; and
- its exact redirect URI set.

Also prove that changing or removing config disables the previous managed
client and does not leave a usable stale registration.

### Provider integration tests

Exercise the complete public flow:

1. discovery advertises authorization code, S256, and token auth method `none`;
2. authorization rejects an unregistered redirect;
3. authorization rejects missing or non-S256 PKCE;
4. authorization succeeds with an exact redirect and S256 challenge;
5. token exchange succeeds with client ID and matching verifier and no secret;
6. token exchange rejects a client secret for the public client;
7. token exchange rejects a missing or incorrect verifier;
8. authorization codes are single-use and expire;
9. the ID token has the correct issuer, audience, nonce, subject, and profile
   claims;
10. an allowed browser origin receives the required CORS response;
11. an unregistered origin does not; and
12. a confidential client's behavior is unchanged.

Add a negative test that a public client cannot use client-credentials grants,
introspection as a confidential client, or another client's redirect URI.

### Browser proof

Tests are not the complete acceptance gate. Use a real browser from Public
Stream Theater's HTTPS preview origin to prove:

- the sign-in button navigates to hosted Identity;
- an existing Identity session can return without re-entering credentials;
- a new hosted sign-in returns successfully;
- callback state and nonce are consumed once;
- the displayed handle/name/avatar matches the returned profile;
- refresh and sign-out behavior match the documented storage choice;
- cancel and error returns produce useful UI rather than a dead callback page;
- no client secret appears in source, built assets, requests, or browser
  storage; and
- there are no unexpected browser console, CSP, CORS, or mixed-content errors.

## Public Stream Theater integration

Identity support should land and deploy before the game depends on it.

After the public client is available, the game needs:

- a small browser OIDC module backed by an established library;
- environment-visible public configuration containing only issuer, client ID,
  redirect URI, and scopes;
- a `/auth/callback` client-side route or startup branch;
- sign-in, signed-in profile, sign-out, cancel, and error states;
- a fallback avatar/background when `picture` is absent or fails to load; and
- an explicit label that the profile is cosmetic unless server authority is
  introduced later.

Recommended initial values:

```text
issuer: https://identity.peezy.tech/api/auth
client_id: public-stream-theater
scopes: openid profile
preview redirect: https://stream-theater.tmp.peezy.tech/auth/callback
local redirect: http://localhost:5173/auth/callback
```

Do not couple login to entering or watching the arena. Anonymous use should
remain available unless the product decision changes. Login should enhance the
visitor's presentation rather than become a loading or availability dependency.

## Documentation and operational updates

Update the following with the implementation:

- `apps/server/.env.example` with one confidential and one public-browser
  example that contain no real secrets;
- `docs/architecture.md` with the public-client trust boundary;
- `docs/operations.md` with registration, origin, CORS, rotation/removal, and
  rollback procedures;
- the deployment `.env.example` in the peezy.tech infrastructure repository
  with the reviewed Public Stream Theater registration; and
- release notes describing the new public-client capability.

Never commit the live confidential client secrets or Identity deployment
environment. A public client's client ID is intentionally non-secret.

## Deployment sequence

1. Implement and verify the provider change in the Identity repository.
2. Review the exact database migration, if any, and confirm it is backward
   compatible with existing confidential clients.
3. Add the Public Stream Theater registration to the infrastructure deployment
   configuration with its exact origins and redirects.
4. Back up the production Identity database and preserve the current deployment
   environment before rollout.
5. Deploy the reviewed Identity revision without changing PledgeCash or Jojo
   client semantics.
6. Verify health, readiness, capabilities, discovery, JWKS, existing
   confidential clients, and the new public flow.
7. Confirm discovery now advertises `none`, authorization still requires S256,
   and unregistered browser origins fail.
8. Integrate and deploy the game client.
9. Run the real HTTPS browser proof from the preview origin.
10. Retain the previous Identity image and environment so the provider change
    can be rolled back independently of the game.

Production deployment, database changes, and secret/environment mutation
require explicit operator authorization. Implementing and testing the source
change does not itself authorize rollout.

## Suggested implementation slices

### Slice A: configuration and persistence

- Add the discriminated client configuration.
- Seed public-client metadata correctly.
- Add focused config and seeding tests.
- Confirm no migration is necessary, or add and test the smallest migration.

This slice is complete when a configured public client exists in a test
database with no secret and cannot authenticate as a confidential client.

### Slice B: protocol and CORS

- Enable registered public clients in the provider.
- Update discovery metadata.
- Add exact-origin OAuth endpoint CORS.
- Add full positive and negative integration coverage.

This slice is complete when a simulated browser completes code + PKCE with no
secret and all redirect, origin, verifier, and grant-type failures are proven.

### Slice C: consumer proof

- Add the Public Stream Theater client registration to reviewed deployment
  configuration.
- Add the game's browser OIDC module and UI.
- Deploy Identity only with operator approval.
- Prove the flow through the game's HTTPS preview.

This slice is complete when a user can sign in, see their cosmetic profile,
sign out locally, and continue using the arena anonymously, with no secret in
the browser and no server-authority claims.

## Repository validation

Before handing off the Identity source change, run the repository's complete
documented validation set:

```sh
bun install --frozen-lockfile
bun run typecheck
bun run test
bun run build
bun run package:smoke
bun run format:check
```

Also inspect the final Git diff and status so generated artifacts, deployment
secrets, and unrelated work are not included.

## Decisions already made

- Use OpenID Connect authorization code with PKCE.
- Support pre-registered public browser clients; do not expose unrestricted
  dynamic client registration.
- A client ID is public and a browser client has no secret.
- Keep anonymous Public Stream Theater access.
- Use the initial login only for cosmetic identity.
- Request only `openid profile` initially.
- Do not request a resource audience or refresh token initially.
- Keep product authority separate from Identity authentication.
- Bind authoritative product records by `(issuer, sub)`, never handle or email.

## Consumer decisions

- The game uses `oauth4webapi` 3.8.7, an OpenID-certified, dependency-free ESM
  implementation that runs directly in browsers.
- Temporary state and the derived cosmetic profile use `sessionStorage`, so a
  same-tab refresh retains presentation. ID and access tokens are never
  persisted.
- Local sign-out clears only the arena profile. Provider-wide sign-out is not
  offered in the first release.
- The game derives its profile from a fully validated and signature-checked ID
  token. Identity supports user-info CORS for standards-compatible clients, but
  Public Stream Theater does not need a second profile request.

These choices preserve the provider security model established in Slices A and
B.
