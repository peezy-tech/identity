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
});

const principal = await verify(token);
const identity = await getIdentity({
  baseUrl: "https://identity.peezy.tech",
  clientId: "my-app",
  clientSecret: process.env.IDENTITY_APP_CLIENT_SECRET!,
  subject: principal.subject,
});
```

See the [source repository](https://github.com/peezy-tech/identity) for complete
examples and trust-boundary documentation.
