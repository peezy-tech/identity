import { deepStrictEqual, equal } from "node:assert";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

type ShamirModule = {
  combine(shares: Uint8Array[]): Promise<Uint8Array>;
  split(
    secret: Uint8Array,
    shares: number,
    threshold: number,
  ): Promise<Uint8Array[]>;
};

const root = resolve(import.meta.dir, "..");
const source = join(root, "vendor/privy-io/shamir-secret-sharing");
const temporaryRoot = await mkdtemp(
  join(tmpdir(), "peezy-identity-vendor-shamir-"),
);

try {
  await cp(source, temporaryRoot, { recursive: true });
  await execute(
    ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    temporaryRoot,
  );
  await execute(["npm", "run", "build"], temporaryRoot);

  const shamir = (await import(
    pathToFileURL(join(temporaryRoot, "esm/index.js")).href
  )) as ShamirModule;
  const secret = new TextEncoder().encode(
    "identity.peezy.tech vendored Shamir proof",
  );
  const shares = await shamir.split(secret, 5, 3);
  equal(shares.length, 5);

  const recovered = await shamir.combine([shares[0]!, shares[2]!, shares[4]!]);
  deepStrictEqual(recovered, secret);

  console.log(
    "Vendored Shamir snapshot recovered the original secret from 3 of 5 shares.",
  );
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}

async function execute(command: string[], cwd: string): Promise<void> {
  const process = Bun.spawn(command, {
    cwd,
    stderr: "inherit",
    stdout: "inherit",
  });
  const exitCode = await process.exited;
  if (exitCode !== 0) {
    throw new Error(`${command.join(" ")} failed in ${cwd}`);
  }
}
