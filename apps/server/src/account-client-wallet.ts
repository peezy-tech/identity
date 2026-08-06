export function selectEthereumAccount(
  accounts: readonly string[],
  addressHint?: string,
): string | undefined {
  if (addressHint === undefined) return accounts[0];
  const normalizedHint = addressHint.toLowerCase();
  return accounts.find((account) => account.toLowerCase() === normalizedHint);
}
