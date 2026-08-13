export const PENDING_PRIVY_ATTEMPT_KEY =
  "peezy.identity.pending-privy-migration.v1";

export type PendingPrivyMigrationAttempt = {
  attemptId: string;
  csrfToken: string;
  expiresAt: string;
};

export type PrivyAttemptStorage = Pick<
  Storage,
  "getItem" | "removeItem" | "setItem"
>;

export function readPendingPrivyMigrationAttempt(
  storage: PrivyAttemptStorage | null,
  now = Date.now(),
): PendingPrivyMigrationAttempt | null {
  if (storage === null) return null;
  try {
    const raw = storage.getItem(PENDING_PRIVY_ATTEMPT_KEY);
    if (raw === null) return null;
    const value = JSON.parse(raw) as Partial<PendingPrivyMigrationAttempt>;
    const expiresAt = Date.parse(value.expiresAt ?? "");
    if (
      typeof value.attemptId !== "string" ||
      value.attemptId.length === 0 ||
      typeof value.csrfToken !== "string" ||
      value.csrfToken.length === 0 ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= now
    ) {
      storage.removeItem(PENDING_PRIVY_ATTEMPT_KEY);
      return null;
    }
    return {
      attemptId: value.attemptId,
      csrfToken: value.csrfToken,
      expiresAt: new Date(expiresAt).toISOString(),
    };
  } catch {
    try {
      storage.removeItem(PENDING_PRIVY_ATTEMPT_KEY);
    } catch {
      // Browser storage is unavailable; there is no persisted value to recover.
    }
    return null;
  }
}

export function writePendingPrivyMigrationAttempt(
  storage: PrivyAttemptStorage | null,
  attempt: PendingPrivyMigrationAttempt,
): boolean {
  if (storage === null) return false;
  try {
    storage.setItem(PENDING_PRIVY_ATTEMPT_KEY, JSON.stringify(attempt));
    return true;
  } catch {
    return false;
  }
}

export function clearPendingPrivyMigrationAttempt(
  storage: PrivyAttemptStorage | null,
): void {
  if (storage === null) return;
  try {
    storage.removeItem(PENDING_PRIVY_ATTEMPT_KEY);
  } catch {
    // The in-memory attempt is still cleared when browser storage is blocked.
  }
}
