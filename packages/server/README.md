# @peezy.tech/identity-server

Server-side helpers for integrating a confidential peezy.tech application with
the shared identity provider.

The release tarball bundles the shared runtime schemas used by these helpers,
so it installs without registry access to `@peezy.tech/identity`. Install the
public identity package separately only when importing its contracts directly.

The package verifies audience-bound access tokens through the provider JWKS and
supports the one-time wallet-grant and social-link handoff flows. Keep the
application client secret on the server.

```ts
import {
  createAccessTokenVerifier,
  getIdentity,
} from "@peezy.tech/identity-server";

const verify = createAccessTokenVerifier({
  audience: "https://api.my-app.example",
  issuer: "https://identity.peezy.tech/api/auth",
  introspection: {
    clientId: "my-app",
    clientSecret: process.env.IDENTITY_OIDC_CLIENT_SECRET!,
    // Optional; defaults to 2 seconds and includes reading the response body.
    timeoutMs: 2_000,
  },
});

const principal = await verify(token);
const identity = await getIdentity({
  baseUrl: "https://identity.peezy.tech",
  clientId: "my-app",
  clientSecret: process.env.IDENTITY_APP_CLIENT_SECRET!,
  subject: principal.subject,
});
```

The verifier introspects every token after local signature validation and fails
closed when the provider reports it inactive or the request exceeds its
deadline. Use the registered OIDC client credentials for introspection; keep
the separate application API secret for identity lookups. Custom deadlines
must be greater than `0` and no greater than `2_147_483_647` milliseconds, the
largest delay supported safely by JavaScript timers.

See the [source repository](https://github.com/peezy-tech/identity) for complete
examples and trust-boundary documentation.
