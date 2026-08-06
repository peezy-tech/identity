import { describe, expect, test } from "bun:test";

import { selectEthereumAccount } from "../src/account-client-wallet";

describe("account wallet selection", () => {
  test("selects the requested account without falling back to another one", () => {
    const accounts = [
      "0x1000000000000000000000000000000000000000",
      "0x2000000000000000000000000000000000000000",
    ];

    expect(
      selectEthereumAccount(
        accounts,
        "0x2000000000000000000000000000000000000000",
      ),
    ).toBe(accounts[1]);
    expect(
      selectEthereumAccount(
        accounts,
        "0x3000000000000000000000000000000000000000",
      ),
    ).toBeUndefined();
  });

  test("uses the first account only when no account was requested", () => {
    expect(
      selectEthereumAccount(["0x1000000000000000000000000000000000000000"]),
    ).toBe("0x1000000000000000000000000000000000000000");
  });
});
