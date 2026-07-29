# @peezy.tech/identity-server

Server-side helpers for integrating a confidential peezy.tech application with
the shared identity provider.

Install this package together with `@peezy.tech/identity`; the server helpers
consume the shared runtime schemas as well as their TypeScript types.

The package verifies audience-bound access tokens through the provider JWKS and
supports the one-time wallet-grant and social-link handoff flows. Keep the
application client secret on the server.

```ts
import {
  createAccessTokenVerifier,
  getIdentity,
} from "@peezy.tech/identity-server";

const verify = createAccessTokenVerifier({
  audience: "my-app",
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
