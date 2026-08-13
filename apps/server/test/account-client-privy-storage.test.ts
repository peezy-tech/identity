import { describe, expect, test } from "bun:test";

import {
  clearPendingPrivyMigrationAttempt,
  PENDING_PRIVY_ATTEMPT_KEY,
  readPendingPrivyMigrationAttempt,
  type PrivyAttemptStorage,
  writePendingPrivyMigrationAttempt,
} from "../src/account-client-privy";

function memoryStorage(): PrivyAttemptStorage & {
  values: Map<string, string>;
} {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    removeItem: (key) => {
      values.delete(key);
    },
    setItem: (key, value) => {
      values.set(key, value);
    },
  };
}

describe("pending Privy migration attempts", () => {
  test("survive a page lifecycle until their server expiry", () => {
    const storage = memoryStorage();
    const attempt = {
      attemptId: "attempt-1",
      csrfToken: "csrf-1",
      expiresAt: "2026-08-13T17:00:00.000Z",
    };

    expect(writePendingPrivyMigrationAttempt(storage, attempt)).toBe(true);
    expect(
      readPendingPrivyMigrationAttempt(
        storage,
        Date.parse("2026-08-13T16:59:59.000Z"),
      ),
    ).toEqual(attempt);
  });

  test("discard expired or malformed attempts instead of retrying them", () => {
    const storage = memoryStorage();
    storage.setItem(
      PENDING_PRIVY_ATTEMPT_KEY,
      JSON.stringify({
        attemptId: "attempt-1",
        csrfToken: "csrf-1",
        expiresAt: "2026-08-13T17:00:00.000Z",
      }),
    );
    expect(
      readPendingPrivyMigrationAttempt(
        storage,
        Date.parse("2026-08-13T17:00:00.000Z"),
      ),
    ).toBeNull();
    expect(storage.getItem(PENDING_PRIVY_ATTEMPT_KEY)).toBeNull();

    storage.setItem(PENDING_PRIVY_ATTEMPT_KEY, "not-json");
    expect(readPendingPrivyMigrationAttempt(storage)).toBeNull();
    expect(storage.getItem(PENDING_PRIVY_ATTEMPT_KEY)).toBeNull();
  });

  test("clear removes a completed attempt", () => {
    const storage = memoryStorage();
    storage.setItem(PENDING_PRIVY_ATTEMPT_KEY, "pending");
    clearPendingPrivyMigrationAttempt(storage);
    expect(storage.getItem(PENDING_PRIVY_ATTEMPT_KEY)).toBeNull();
  });

  test("degrades to in-memory state when session storage is unavailable", () => {
    expect(
      writePendingPrivyMigrationAttempt(null, {
        attemptId: "attempt-1",
        csrfToken: "csrf-1",
        expiresAt: "2026-08-13T17:00:00.000Z",
      }),
    ).toBe(false);
    expect(readPendingPrivyMigrationAttempt(null)).toBeNull();
    expect(() => clearPendingPrivyMigrationAttempt(null)).not.toThrow();
  });
});
