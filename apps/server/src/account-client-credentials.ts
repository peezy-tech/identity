export type AccountCredentialKind = "email" | "passkey" | "social" | "wallet";

export function isSignInCredential(input: {
  kind: AccountCredentialKind;
}): boolean {
  return input.kind !== "email";
}

export function linkedSocialProviders<Provider extends string>(
  credentials: readonly {
    kind: AccountCredentialKind;
    provider?: Provider;
  }[],
): Set<Provider> {
  const providers = new Set<Provider>();
  for (const credential of credentials) {
    if (credential.kind === "social" && credential.provider !== undefined) {
      providers.add(credential.provider);
    }
  }
  return providers;
}
