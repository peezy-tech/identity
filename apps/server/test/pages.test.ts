import { describe, expect, test } from "bun:test";

import { signInPage } from "../src/pages";

describe("hosted sign-in page", () => {
  test("routes Telegram through the generic OAuth endpoints", () => {
    const page = signInPage(["discord", "telegram"], "test-nonce");

    expect(page).toContain(
      'telegram ? "/api/auth/sign-in/oauth2" : "/api/auth/sign-in/social"',
    );
    expect(page).toContain('{ callbackURL, providerId: "telegram" }');
    expect(page).toContain(": { callbackURL, provider }");
  });
});
