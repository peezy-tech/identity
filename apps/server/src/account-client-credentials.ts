export type AccountCredentialKind = "email" | "passkey" | "social" | "wallet";

export function isSignInCredential(input: {
  kind: AccountCredentialKind;
}): boolean {
  return input.kind !== "email";
}
