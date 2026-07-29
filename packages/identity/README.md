# @peezy.tech/identity

Public, runtime-validated identity contracts and a small HTTP client for
peezy.tech applications.

```ts
import { createIdentityClient } from "@peezy.tech/identity";

const identity = createIdentityClient({
  baseUrl: "https://identity.peezy.tech",
  clientId: "my-app",
});

const capabilities = await identity.getCapabilities();
```

The stable `PeezyUser` subject does not require a wallet. Social accounts,
verified email attributes, and linked wallets are modeled as credentials or
attributes around that subject. Product roles and on-chain authorization remain
owned by the integrating application.

See the [source repository](https://github.com/peezy-tech/identity) for the
protocol, security model, and migration guide.
