# Architecture

## Purpose

peezy.tech Identity gives every person one stable subject across peezy.tech
projects. It authenticates the person and records the credentials they have
explicitly proved. It does not decide what that person may do inside a product.

In v0.1, an account may be created with a configured social provider or an EVM
wallet. Wallets are optional credentials, so a social-first account can remain
walletless indefinitely. Verified email is an attribute learned from a social
provider, not a standalone sign-in method. Passkeys are a reserved extension
point rather than an enabled credential.

## Trust boundaries

The identity provider owns:

- immutable global user subjects and lifecycle state;
- social and wallet credentials, plus verified email attributes;
- explicit credential linking and collision prevention;
- identity sessions, OAuth grants, refresh-token rotation, and revocation;
- shared human organizations and membership;
- security audit events;
- registered OAuth clients and their exact redirect origins.

Each product owns:

- product roles, preferences, subscriptions, and entitlements;
- product delivery channels and operational data;
- transaction construction and signing;
- authorization that depends on current chain state;
- any fresh proof required for a privileged operation.

Products store the opaque `sub` from this issuer. They do not read the identity
database or use cross-service foreign keys.

## Protocol

OAuth 2.1 authorization code with PKCE and OpenID Connect are the primary
application integration. Access tokens are audience-bound and verified through
the issuer's JWKS.

Tokens stay small and contain only stable or short-lived claims. Linked wallets,
social providers, email addresses, and organization membership are fetched from
the identity API when current state is required.

The provider also supports a confidential, one-time wallet grant:

1. A registered application requests an app-bound SIWE challenge.
2. The browser signs it without navigating away from the product.
3. Identity verifies the signature and creates or resolves the global subject.
4. Identity returns one opaque, short-lived, single-use grant.
5. The application's backend exchanges the grant using its confidential client
   authentication and creates its own application session.

The grant is authentication only. It is never a transaction authorization.

## Credential invariants

- A user must retain at least one usable sign-in credential when credential
  removal is introduced. v0.1 does not expose credential removal.
- Provider subjects and wallet principals are unique across users.
- Credentials are linked only after explicit proof while authenticated.
- Matching email text never implicitly merges two users.
- Merging two existing subjects requires reauthentication of both sides and an
  auditable, atomic operation.
- An EOA address has one owner across the EVM family. A verified chain is an
  observation, not a different person.
- Smart-contract accounts are chain scoped and are not accepted as ordinary EOA
  credentials until their verification and recovery semantics are explicitly
  supported.
- A future credential-removal operation must emit an idempotent lifecycle
  event.

## PledgeCash authority boundary

A peezy.tech session establishes only off-chain user identity. PledgeCash
Boardroom-control challenges remain PledgeCash resources and continue to bind
the current chain, canonical Boardroom, controller, controller generation,
configuration epoch, destination, scope, nonce, audience, and expiry. Every
privileged write requires a fresh proof.
