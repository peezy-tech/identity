import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

type PackResult = {
  filename: string;
};

const root = resolve(import.meta.dir, "..");
const temporaryRoot = await mkdtemp(
  join(tmpdir(), "peezy-identity-package-smoke-"),
);

try {
  const artifacts = join(temporaryRoot, "artifacts");
  await mkdir(artifacts);
  const identity = await pack(join(root, "packages/identity"), artifacts);
  const server = await pack(join(root, "packages/server"), artifacts);

  await Promise.all([
    smokeConsumer("npm", temporaryRoot, artifacts, identity, server),
    smokeConsumer("bun", temporaryRoot, artifacts, identity, server),
  ]);
  console.log("SDK tarballs install and execute with npm/Node and Bun.");
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}

async function pack(
  packageDirectory: string,
  artifacts: string,
): Promise<PackResult> {
  const output = await execute(
    ["npm", "pack", "--json", "--pack-destination", artifacts],
    packageDirectory,
  );
  const parsed = JSON.parse(output) as PackResult[];
  const result = parsed[0];
  if (result === undefined || result.filename.length === 0) {
    throw new Error(`npm pack returned no artifact for ${packageDirectory}`);
  }
  return result;
}

async function smokeConsumer(
  packageManager: "bun" | "npm",
  temporaryRoot: string,
  artifacts: string,
  identity: PackResult,
  server: PackResult,
): Promise<void> {
  const directory = join(temporaryRoot, packageManager);
  await mkdir(directory);
  await Bun.write(
    join(directory, "package.json"),
    JSON.stringify(
      {
        name: `peezy-identity-${packageManager}-smoke`,
        private: true,
        type: "module",
        dependencies: {
          "@peezy.tech/identity": `file:${join(artifacts, identity.filename)}`,
          "@peezy.tech/identity-server": `file:${join(
            artifacts,
            server.filename,
          )}`,
        },
      },
      null,
      2,
    ),
  );
  await Bun.write(
    join(directory, "index.mjs"),
    `
      import {
        IdentityCapabilitiesSchema,
        PeezyUserSchema,
      } from "@peezy.tech/identity";
      import {
        bearerToken,
        createAccessTokenVerifier,
      } from "@peezy.tech/identity-server";

      const user = PeezyUserSchema.parse({
        createdAt: new Date(0).toISOString(),
        id: "00000000-0000-4000-8000-000000000001",
        status: "active",
      });
      const capabilities = IdentityCapabilitiesSchema.parse({
        accountCreation: { social: true, wallet: true },
        socialProviders: ["github"],
      });
      const token = bearerToken("Bearer package-smoke");
      const verifier = createAccessTokenVerifier({
        audience: "package-smoke",
        issuer: "https://identity.example.test/api/auth",
      });

      if (
        user.id !== "00000000-0000-4000-8000-000000000001" ||
        capabilities.socialProviders[0] !== "github" ||
        token !== "package-smoke" ||
        typeof verifier !== "function"
      ) {
        throw new Error("SDK package smoke failed");
      }
    `,
  );

  if (packageManager === "npm") {
    await execute(
      ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
      directory,
    );
    await execute(["node", "index.mjs"], directory);
  } else {
    await execute(["bun", "install"], directory);
    await execute(["bun", "index.mjs"], directory);
  }
}

async function execute(command: string[], cwd: string): Promise<string> {
  const process = Bun.spawn(command, {
    cwd,
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(
      `${command.join(" ")} failed in ${cwd}\n${stdout}\n${stderr}`,
    );
  }
  return stdout;
}
