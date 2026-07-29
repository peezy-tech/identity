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
  await assertServerPackageContract();
  const artifacts = join(temporaryRoot, "artifacts");
  await mkdir(artifacts);
  await pack(join(root, "packages/identity"), artifacts);
  const server = await pack(join(root, "packages/server"), artifacts);
  await assertServerArtifactContract();

  await Promise.all([
    smokeConsumer("npm", temporaryRoot, artifacts, server),
    smokeConsumer("bun", temporaryRoot, artifacts, server),
  ]);
  console.log("SDK tarballs install and execute with npm/Node and Bun.");
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}

async function assertServerPackageContract(): Promise<void> {
  const manifest = (await Bun.file(
    join(root, "packages/server/package.json"),
  ).json()) as {
    dependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
  };
  const manifests = [
    manifest.dependencies,
    manifest.optionalDependencies,
    manifest.peerDependencies,
  ];
  if (manifests.some((entries) => entries?.["@peezy.tech/identity"])) {
    throw new Error(
      "@peezy.tech/identity-server must not require the unpublished identity package",
    );
  }
}

async function assertServerArtifactContract(): Promise<void> {
  const [bundle, declarations, responseTypes] = await Promise.all([
    Bun.file(join(root, "packages/server/dist/index.js")).text(),
    Bun.file(join(root, "packages/server/dist/index.d.ts")).text(),
    Bun.file(join(root, "packages/server/dist/types.d.ts")).text(),
  ]);
  if (
    [bundle, declarations, responseTypes].some((artifact) =>
      artifact.includes("@peezy.tech/identity"),
    )
  ) {
    throw new Error("The server artifact must bundle its identity runtime");
  }
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
        bearerToken,
        createAccessTokenVerifier,
      } from "@peezy.tech/identity-server";

      const token = bearerToken("Bearer package-smoke");
      const verifier = createAccessTokenVerifier({
        audience: "package-smoke",
        issuer: "https://identity.example.test/api/auth",
      });

      if (
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
