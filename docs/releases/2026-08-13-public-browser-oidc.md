# Public browser OIDC clients

Identity now supports explicitly registered browser-only OpenID Connect
clients. They use authorization code + PKCE-S256, authenticate at the token
endpoint with `none`, hold no client secret, and are limited to `openid profile`
with no refresh token or resource audience by default.

Public-client origins receive exact, non-credentialed CORS on OIDC discovery,
token, user-info, and JWKS endpoints only. They do not become trusted Identity
account or application origins. Existing confidential clients keep their
client-secret, refresh-token, scope, and resource behavior.

The first registration is Public Stream Theater. Its sign-in is cosmetic: the
arena may show a person's peezy.tech handle, display name, and avatar, while
anonymous entry remains available and all product authority stays outside the
browser profile.
