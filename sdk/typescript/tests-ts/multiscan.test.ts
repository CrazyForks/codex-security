import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  access,
  appendFile,
  chmod,
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import type { ScanResult } from "../src/result.js";
import {
  MAX_BULK_SCAN_INVENTORY_BYTES,
  MAX_BULK_SCAN_REPOSITORIES,
} from "../src/bulk-scan-limits.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const COMPLETED_SCAN = join(PLUGIN_ROOT, "examples", "completed-scan");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture(): Promise<{
  root: string;
  input: string;
  output: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-multiscan-"));
  temporaryDirectories.push(root);
  return {
    root,
    input: join(root, "repositories.csv"),
    output: join(root, "results"),
  };
}

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function repository(
  root: string,
  name: string,
): Promise<{ path: string; revision: string }> {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q");
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

async function completedScan(
  outputDir: string,
  completeness: "complete" | "partial" = "complete",
): Promise<ScanResult> {
  await cp(COMPLETED_SCAN, outputDir, { recursive: true });
  const campaign = dirname(dirname(dirname(outputDir)));
  const taskId = basename(dirname(outputDir));
  const campaignManifest = JSON.parse(
    await readFile(join(campaign, "manifest.json"), "utf8"),
  ) as {
    tasks: Array<{
      id: string;
      revision: string;
      mode: string;
      scope?: string;
    }>;
  };
  const task = campaignManifest.tasks.find(
    (candidate) => candidate.id === taskId,
  );
  if (task === undefined) throw new Error("missing multiscan fixture task");
  const plugin = JSON.parse(
    await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
  ) as { version: string };
  const manifestPath = join(outputDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: {
      producer: { version: string };
      target: { revision: string };
      scope: { includePaths: string[] };
    };
  };
  manifest.scan.producer.version = plugin.version;
  manifest.scan.target.revision = task.revision;
  if (task.scope !== undefined) manifest.scan.scope.includePaths = [task.scope];
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const coveragePath = join(outputDir, "coverage.json");
  const coverage = JSON.parse(await readFile(coveragePath, "utf8")) as {
    mode: string;
    includePaths: string[];
  };
  coverage.includePaths = manifest.scan.scope.includePaths;
  coverage.mode =
    task.scope !== undefined
      ? "scoped_path"
      : task.mode === "deep"
        ? "deep_repository"
        : "repository";
  await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
  await reseal(outputDir);
  await writeFile(join(outputDir, "report.md"), "# Scan report\n");
  return { coverage: { completeness } } as ScanResult;
}

function client(
  run: SecurityClient["run"],
  close: SecurityClient["close"] = async () => {},
): SecurityClient {
  return { run, close };
}

function options(
  paths: { input: string; output: string },
  security: SecurityClient,
  overrides: Partial<MultiscanOptions> = {},
): MultiscanOptions {
  return {
    inputPath: paths.input,
    outputDir: paths.output,
    workers: 1,
    mode: "standard",
    maxAttempts: 2,
    config: {},
    createSecurity: () => security,
    ...overrides,
  };
}

async function results(path: string): Promise<Record<string, unknown>[]> {
  return (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function reseal(scanDir: string): Promise<void> {
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDir, artifact.path)))
      .digest("hex");
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

describe("multiscan", () => {
  test("scopes GitHub CLI credentials to the discovered GitHub host", () => {
    expect(buildGitHubCredentialArgs(undefined)).toEqual([]);
    expect(buildGitHubCredentialArgs("github.com")).toEqual([
      "-c",
      "credential.https://github.com.helper=",
      "-c",
      "credential.https://github.com.helper=!gh auth git-credential",
    ]);
    expect(buildGitHubCredentialArgs("github.acme.example")).toEqual([
      "-c",
      "credential.https://github.acme.example.helper=",
      "-c",
      "credential.https://github.acme.example.helper=!gh auth git-credential",
    ]);
    for (const host of [
      "github.com/another-owner",
      "user@github.com",
      "github.com?token=secret",
      "github.com#fragment",
    ]) {
      expect(() => buildGitHubCredentialArgs(host)).toThrow(
        "GitHub credential host is invalid",
      );
    }
  });

  test("uses GitHub credentials for discovered checkouts without changing global Git configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "github-credentials");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const configured = execFileSync(
      "git",
      [
        ...buildGitHubCredentialArgs("github.acme.example"),
        "config",
        "--get-all",
        "credential.https://github.acme.example.helper",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    expect(configured.trim()).toBe("!gh auth git-credential");

    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (_checkout, scanOptions = {}) =>
            await completedScan(scanOptions.outputDir!),
        ),
        { githubHost: "github.acme.example" },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
  });

  test("parses quoted CSV fields, embedded delimiters, and Windows line endings", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "comma, quoted");
    await writeFile(
      paths.input,
      `\uFEFF"id","repository","revision","scope","mode","notes"\r\n"payments","${source.path}","${source.revision}","src","deep","contains ""quotes"""\r\n\r\n`,
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.target).toEqual(["src"]);
          expect(scanOptions.mode).toBe("deep");
          return await completedScan(scanOptions.outputDir!);
        }),
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "payments", repository: source.path },
    ]);
  });

  test("resumes equivalent canonical repository scopes", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "canonical-scope");
    const inventory = (scope: string): string =>
      `id,repository,revision,scope\nscoped,${source.path},${source.revision},${scope}\n`;
    await writeFile(paths.input, inventory("./src//"));
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      expect(scanOptions.target).toEqual(["src"]);
      return await completedScan(scanOptions.outputDir!);
    });
    await runMultiscan(options(paths, security));
    await writeFile(paths.input, inventory("src/."));

    expect(await runMultiscan(options(paths, security))).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(scans).toBe(1);
  });

  test("preserves UTF-8 repository paths split across inventory stream chunks", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "caf\u00e9");
    const header = "id,notes,repository,revision\n";
    const accentedOffset = source.path.indexOf("\u00e9");
    const prefix = `${header}unicode,`;
    const padding =
      64 * 1024 -
      1 -
      Buffer.byteLength(`${prefix},${source.path.slice(0, accentedOffset)}`);
    await writeFile(
      paths.input,
      `${prefix}${"x".repeat(padding)},${source.path},${source.revision}\n`,
    );

    let scans = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          scans += 1;
          return await completedScan(scanOptions.outputDir!);
        }),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(scans).toBe(1);
  });

  test.skipIf(process.platform === "win32")(
    "resumes symlinked scopes using their canonical repository paths",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "symlinked-scope");
      await symlink("src", join(source.path, "alias"));
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add scope alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nscoped,${source.path},${revision},alias\n`,
      );
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        const result = await completedScan(scanOptions.outputDir!);
        for (const artifact of ["scan-manifest.json", "coverage.json"]) {
          const path = join(scanOptions.outputDir!, artifact);
          const document = JSON.parse(await readFile(path, "utf8")) as {
            scan?: { scope: { includePaths: string[] } };
            includePaths?: string[];
          };
          if (document.scan !== undefined) {
            document.scan.scope.includePaths = ["src"];
          } else {
            document.includePaths = ["src"];
          }
          await writeFile(path, `${JSON.stringify(document, null, 2)}\n`);
        }
        await reseal(scanOptions.outputDir!);
        return result;
      });

      await runMultiscan(options(paths, security));
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toBe(1);

      const remote = "ssh://127.0.0.1:1/symlinked-scope.git";
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nscoped,${remote},${revision},alias\n`,
      );
      const manifestPath = join(paths.output, "manifest.json");
      const campaign = JSON.parse(await readFile(manifestPath, "utf8")) as {
        tasks: Array<{ repository: string }>;
      };
      campaign.tasks[0]!.repository = remote;
      await writeFile(manifestPath, `${JSON.stringify(campaign, null, 2)}\n`);
      const ledgerPath = join(paths.output, "results.jsonl");
      const receipts = await results(ledgerPath);
      for (const receipt of receipts) receipt["repository"] = remote;
      await writeFile(
        ledgerPath,
        `${receipts.map((receipt) => JSON.stringify(receipt)).join("\n")}\n`,
      );

      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toBe(1);

      const manipulated = await results(ledgerPath);
      manipulated[manipulated.length - 1]!["canonicalScope"] = "another";
      await writeFile(
        ledgerPath,
        `${manipulated.map((receipt) => JSON.stringify(receipt)).join("\n")}\n`,
      );
      const scanManifestPath = join(
        paths.output,
        "artifacts",
        "scoped",
        "attempt-1",
        "scan-manifest.json",
      );
      const scanManifest = JSON.parse(
        await readFile(scanManifestPath, "utf8"),
      ) as { scan: { scope: { includePaths: string[] } } };
      scanManifest.scan.scope.includePaths = ["another"];
      await writeFile(
        scanManifestPath,
        `${JSON.stringify(scanManifest, null, 2)}\n`,
      );
      const coveragePath = join(dirname(scanManifestPath), "coverage.json");
      const coverage = JSON.parse(await readFile(coveragePath, "utf8")) as {
        includePaths: string[];
      };
      coverage.includePaths = ["another"];
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
      await reseal(dirname(scanManifestPath));
      await writeFile(
        join(dirname(scanManifestPath), ".multiscan-scope.json"),
        `${JSON.stringify({ scope: "alias", canonicalScope: "another" })}\n`,
      );

      const resumed = await runMultiscan(options(paths, security));
      expect(resumed.skipped).toBe(0);
    },
  );

  test.skipIf(process.platform === "win32")(
    "normalizes a symlinked repository-root scope for resumable scans",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "repository-root-alias");
      await symlink(".", join(source.path, "root-alias"));
      git(source.path, "add", "root-alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add repository-root alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nroot,${source.path},${revision},root-alias\n`,
      );
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        const result = await completedScan(scanOptions.outputDir!);
        for (const artifact of ["scan-manifest.json", "coverage.json"]) {
          const artifactPath = join(scanOptions.outputDir!, artifact);
          const document = JSON.parse(await readFile(artifactPath, "utf8")) as {
            scan?: { scope: { includePaths: string[] } };
            includePaths?: string[];
          };
          if (document.scan === undefined) document.includePaths = ["."];
          else document.scan.scope.includePaths = ["."];
          await writeFile(
            artifactPath,
            `${JSON.stringify(document, null, 2)}\n`,
          );
        }
        await reseal(scanOptions.outputDir!);
        return result;
      });

      await runMultiscan(options(paths, security));
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(
        (await results(join(paths.output, "results.jsonl")))[0],
      ).toMatchObject({
        scope: "root-alias",
        canonicalScope: ".",
      });
      expect(scans).toBe(1);
    },
  );

  test("records each completed scan's cost in the resumable ledger", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "priced");
    await writeFile(
      paths.input,
      `id,repository,revision\npriced,${source.path},${source.revision}\n`,
    );
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    };

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          Object.assign(await completedScan(scanOptions.outputDir!), { cost }),
        ),
      ),
    );

    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "priced", status: "completed", cost },
    ]);
  });

  test("rejects malformed CSV and duplicate headers before starting scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "csv");
    const invalid = [
      `id,repository,revision\npayments,"${source.path},${source.revision}\n`,
      `id,repository,revision,id\npayments,${source.path},${source.revision},again\n`,
      `id,repository,revision\npayments,${source.path}\n`,
    ];
    let scans = 0;

    for (const input of invalid) {
      await writeFile(paths.input, input);
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/CSV/);
    }

    expect(scans).toBe(0);
  });

  test("rejects oversized and excessive inventories before creating campaign state", async () => {
    for (const prepare of [
      async (path: string) => {
        await writeFile(path, "id,repository,revision\n");
        await truncate(path, MAX_BULK_SCAN_INVENTORY_BYTES + 1);
      },
      async (path: string) => {
        const rows = Array.from(
          { length: MAX_BULK_SCAN_REPOSITORIES + 1 },
          (_value, index) =>
            `repository-${index},.,0123456789abcdef0123456789abcdef01234567`,
        );
        await writeFile(path, `id,repository,revision\n${rows.join("\n")}\n`);
      },
    ]) {
      const paths = await fixture();
      await prepare(paths.input);
      let clients = 0;
      await expect(
        runMultiscan({
          ...options(
            paths,
            client(async () => {
              throw new Error("scan must not start");
            }),
          ),
          createSecurity: () => {
            clients += 1;
            return client(async () => {
              throw new Error("scan must not start");
            });
          },
        }),
      ).rejects.toThrow(/8 MiB|at most 1,000 repositories/u);
      expect(clients).toBe(0);
      await expect(lstat(paths.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  });

  test("materializes the pinned commit, applies row options, and removes its checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "payments");
    await writeFile(
      join(source.path, "src", "app.ts"),
      "export const changed = true;\n",
    );
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "later",
    );
    await writeFile(
      paths.input,
      `id,repository,revision,scope,mode\npayments,${source.path},${source.revision},src,deep\n`,
    );

    let checkout = "";
    let closed = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (path, scanOptions = {}) => {
            checkout = path;
            expect(git(path, "rev-parse", "HEAD")).toBe(source.revision);
            expect(
              await readFile(join(path, "src", "app.ts"), "utf8"),
            ).toContain('name = "payments"');
            expect(scanOptions.target).toEqual(["src"]);
            expect(scanOptions.mode).toBe("deep");
            expect(scanOptions.outputDir).toBe(
              join(paths.output, "artifacts", "payments", "attempt-1"),
            );
            return await completedScan(scanOptions.outputDir!);
          },
          async () => {
            closed += 1;
          },
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(closed).toBe(1);
    await expect(access(checkout)).rejects.toThrow();
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "payments",
        repository: source.path,
        revision: source.revision,
        scope: "src",
        mode: "deep",
        status: "completed",
        attempt: 1,
      },
    ]);
  });

  test("limits simultaneous checkouts to the requested worker count", async () => {
    const paths = await fixture();
    const sources = await Promise.all(
      ["one", "two", "three"].map((name) => repository(paths.root, name)),
    );
    await writeFile(
      paths.input,
      `id,repository,revision\n${sources
        .map(
          (source, index) => `${index + 1},${source.path},${source.revision}`,
        )
        .join("\n")}\n`,
    );

    let active = 0;
    let maximum = 0;
    let created = 0;
    let closed = 0;
    let release!: () => void;
    const simultaneous = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 2) release();
      await simultaneous;
      active -= 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, {
        workers: 2,
        createSecurity: () => {
          created += 1;
          let running = false;
          return client(
            async (repository, scanOptions) => {
              if (running) {
                throw new Error("A scan is already running for this client.");
              }
              running = true;
              try {
                return await security.run(repository, scanOptions);
              } finally {
                running = false;
              }
            },
            async () => {
              closed += 1;
            },
          );
        },
      }),
    );

    expect(maximum).toBe(2);
    expect(created).toBe(2);
    expect(closed).toBe(2);
    expect(summary).toMatchObject({ total: 3, completed: 3, failed: 0 });
    expect(await results(summary.resultsPath)).toHaveLength(3);
  });

  test("rejects another supervisor and recovers a crashed owner's checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "exclusive");
    await writeFile(
      paths.input,
      `id,repository,revision\nexclusive,${source.path},${source.revision}\n`,
    );
    let started!: () => void;
    let release!: () => void;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    const finish = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      started();
      await finish;
      return await completedScan(scanOptions.outputDir!);
    });
    const lock = join(paths.output, ".lock");
    const first = runMultiscan(options(paths, security));
    await running;
    try {
      expect((await lstat(lock)).isFile()).toBe(true);
      expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({
        pid: process.pid,
        token: expect.any(String),
      });
      expect(
        (await readdir(paths.output)).some((name) =>
          name.startsWith(".lock.pending-"),
        ),
      ).toBe(false);
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        /running|locked|supervisor/iu,
      );
    } finally {
      release();
      await first;
    }

    const [receipt] = await results(join(paths.output, "results.jsonl"));
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    await mkdir(lock);
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
    );
    const checkout = join(paths.output, "checkouts", "exclusive");
    await mkdir(checkout);

    const recovered = await runMultiscan(options(paths, security));
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    await expect(access(lock)).rejects.toThrow();
  });

  test("recovers missing and malformed legacy lock ownership", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "lock-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nlock-recovery,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output);
    const lock = join(paths.output, ".lock");
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    for (const owner of [undefined, '{"pid":', '{"pid":"invalid"}']) {
      await mkdir(lock);
      if (owner !== undefined) {
        await writeFile(join(lock, "owner.json"), owner);
      }
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
      });
      await expect(access(lock)).rejects.toThrow();
    }

    expect(scans).toBe(1);
    expect(
      (await readdir(paths.output)).some(
        (name) =>
          name.startsWith(".lock.pending-") || name.startsWith(".lock.stale-"),
      ),
    ).toBe(false);
  });

  test("never recovers a lock while another live owner is publishing it", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "lock-publication");
    await writeFile(
      paths.input,
      `id,repository,revision\npublishing,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output);
    const lock = join(paths.output, ".lock");
    await writeFile(lock, "");
    await writeFile(
      join(paths.output, ".lock.pending-other-owner"),
      `${JSON.stringify({ pid: process.pid, token: "other-owner" })}\n`,
    );
    let scans = 0;

    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scans += 1;
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      ),
    ).rejects.toThrow(/running|supervisor/iu);
    expect(scans).toBe(0);
    expect(await readFile(lock, "utf8")).toBe("");
  });

  test("never overwrites a supervisor lock published during stale-lock recovery", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "lock-replacement");
    await writeFile(
      paths.input,
      `id,repository,revision\nlock-replacement,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output);
    const lock = join(paths.output, ".lock");
    await writeFile(lock, JSON.stringify({ pid: process.pid, token: "moved" }));
    const originalKill = process.kill;
    let checks = 0;
    process.kill = ((pid: number, signal?: NodeJS.Signals | number) => {
      if (pid !== process.pid) return originalKill.call(process, pid, signal);
      checks += 1;
      if (checks === 1) {
        const error = new Error(
          "simulated stale owner",
        ) as NodeJS.ErrnoException;
        error.code = "ESRCH";
        throw error;
      }
      if (checks === 2) {
        writeFileSync(lock, JSON.stringify({ pid, token: "replacement" }));
      }
      return true;
    }) as typeof process.kill;

    try {
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) =>
              completedScan(scanOptions.outputDir!),
            ),
          ),
        ),
      ).rejects.toThrow("A multiscan supervisor is already running.");
      expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({
        pid: process.pid,
        token: "replacement",
      });
    } finally {
      process.kill = originalKill;
      await rm(lock, { force: true });
    }
  });

  test("does not delete a recovery owner published by a concurrent supervisor", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "recovery-replacement");
    await writeFile(
      paths.input,
      `id,repository,revision\nrecovery,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output);
    const lock = join(paths.output, ".lock");
    const recovery = join(paths.output, ".lock.recovery");
    await writeFile(lock, JSON.stringify({ pid: 999_999_997, token: "stale" }));
    await writeFile(
      recovery,
      JSON.stringify({ pid: 999_999_998, token: "stale-recovery" }),
    );
    const originalKill = process.kill;
    process.kill = ((pid: number, signal?: NodeJS.Signals | number) => {
      if (pid === 999_999_998) {
        writeFileSync(
          recovery,
          JSON.stringify({ pid: process.pid, token: "replacement" }),
        );
        const error = new Error(
          "simulated stale recovery",
        ) as NodeJS.ErrnoException;
        error.code = "ESRCH";
        throw error;
      }
      return originalKill.call(process, pid, signal);
    }) as typeof process.kill;

    try {
      await expect(
        runMultiscan(
          options(
            paths,
            client(async () => {
              throw new Error("scan must not start");
            }),
          ),
        ),
      ).rejects.toThrow(/supervisor/iu);
      expect(JSON.parse(await readFile(recovery, "utf8"))).toMatchObject({
        pid: process.pid,
        token: "replacement",
      });
      expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({
        pid: 999_999_997,
        token: "stale",
      });
    } finally {
      process.kill = originalKill;
    }
  });

  test("retries a failed attempt and records both durable receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retry");
    const secret = "sk-proj-SYNTHETIC_MULTISCAN_SECRET_123";
    await writeFile(
      paths.input,
      `id,repository,revision\nretry,${source.path},${source.revision}\n`,
    );

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          attempts += 1;
          if (attempts === 1) throw new Error(`temporary failure ${secret}`);
          return await completedScan(scanOptions.outputDir!);
        }),
      ),
    );

    expect(attempts).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "retry", status: "failed", attempt: 1 },
      { id: "retry", status: "completed", attempt: 2 },
    ]);
    expect(await readFile(summary.resultsPath, "utf8")).not.toContain(secret);
  });

  test("does not exceed the durable maximum attempt count across resumes", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "attempt-budget");
    await writeFile(
      paths.input,
      `id,repository,revision\nattempt-budget,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    let clients = 0;
    const security = client(async () => {
      attempts += 1;
      throw new Error("persistent failure");
    });
    const run = async (maxAttempts: number) =>
      await runMultiscan(
        options(paths, security, {
          maxAttempts,
          createSecurity: () => {
            clients += 1;
            return security;
          },
        }),
      );

    expect(await run(2)).toMatchObject({
      total: 1,
      completed: 0,
      failed: 1,
      skipped: 0,
    });
    expect(attempts).toBe(2);
    expect(clients).toBe(1);
    expect(await results(join(paths.output, "results.jsonl"))).toMatchObject([
      { status: "failed", attempt: 1 },
      { status: "failed", attempt: 2 },
    ]);

    expect(await run(2)).toMatchObject({
      total: 1,
      completed: 0,
      failed: 1,
      skipped: 0,
    });
    expect(attempts).toBe(2);
    expect(clients).toBe(1);
    expect(await results(join(paths.output, "results.jsonl"))).toHaveLength(2);

    expect(await run(3)).toMatchObject({
      total: 1,
      completed: 0,
      failed: 1,
      skipped: 0,
    });
    expect(attempts).toBe(3);
    expect(clients).toBe(2);
    expect(
      (await results(join(paths.output, "results.jsonl"))).at(-1),
    ).toMatchObject({ status: "failed", attempt: 3 });

    await run(3);
    expect(attempts).toBe(3);
    expect(clients).toBe(2);
  });

  test("does not exhaust attempts using a receipt from a different task", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "foreign-failed-receipt");
    await writeFile(
      paths.input,
      `id,repository,revision\nforeign,${source.path},${source.revision}\n`,
    );
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      if (scans === 1) throw new Error("initial failure");
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(
      options(paths, security, { maxAttempts: 1 }),
    );
    const [receipt] = await results(initial.resultsPath);
    await writeFile(
      initial.resultsPath,
      `${JSON.stringify({ ...receipt, revision: "0".repeat(40) })}\n`,
    );

    const resumed = await runMultiscan(
      options(paths, security, { maxAttempts: 1 }),
    );

    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(scans).toBe(2);
  });

  test("resumes complete bundles, repairs missing output, and rejects manifest drift", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume");
    const csv = `id,repository,revision\nresume,${source.path},${source.revision}\n`;
    await writeFile(paths.input, csv);
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls += 1;
      await expect(access(scanOptions.outputDir!)).rejects.toMatchObject({
        code: "ENOENT",
      });
      return await completedScan(scanOptions.outputDir!);
    });

    const initial = await runMultiscan(options(paths, security));
    await appendFile(initial.resultsPath, '{"id":"interrupted"');
    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(calls).toBe(1);

    const [receipt] = await results(initial.resultsPath);
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(2);
    expect((await results(repaired.resultsPath)).at(-1)?.["outputDir"]).toBe(
      join(paths.output, "artifacts", "resume", "attempt-2"),
    );

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(calls).toBe(2);
  });

  test.skipIf(process.platform === "win32")(
    "resumes a completed campaign when its receipt ledger is read-only",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "readonly-ledger");
      await writeFile(
        paths.input,
        `id,repository,revision\nreadonly,${source.path},${source.revision}\n`,
      );
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        return await completedScan(scanOptions.outputDir!);
      });
      const initial = await runMultiscan(options(paths, security));
      await chmod(initial.resultsPath, 0o400);
      try {
        const resumed = await runMultiscan(options(paths, security));

        expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
        expect(scans).toBe(1);
      } finally {
        await chmod(initial.resultsPath, 0o600);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects symlinked receipt ledgers without reading or changing external files",
    async () => {
      for (const contents of ["", '{"id":"interrupted"']) {
        const paths = await fixture();
        const source = await repository(paths.root, "ledger-source");
        const external = join(paths.root, "external-results.jsonl");
        await writeFile(
          paths.input,
          `id,repository,revision\nledger,${source.path},${source.revision}\n`,
        );
        await mkdir(paths.output);
        await writeFile(external, contents);
        await symlink(external, join(paths.output, "results.jsonl"));

        let scans = 0;
        await expect(
          runMultiscan(
            options(
              paths,
              client(async (_repository, scanOptions = {}) => {
                scans += 1;
                return await completedScan(scanOptions.outputDir!);
              }),
            ),
          ),
        ).rejects.toThrow(/ledger|symbolic link|ELOOP/iu);

        expect(scans).toBe(0);
        expect(await readFile(external, "utf8")).toBe(contents);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects dangling receipt-ledger symlinks without creating external files",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "dangling-ledger");
      const external = join(paths.root, "missing-external-results.jsonl");
      await writeFile(
        paths.input,
        `id,repository,revision\ndangling,${source.path},${source.revision}\n`,
      );
      await mkdir(paths.output);
      await symlink(external, join(paths.output, "results.jsonl"));

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/ledger|symbolic link|ELOOP/iu);

      expect(scans).toBe(0);
      await expect(access(external)).rejects.toThrow();
    },
  );

  test("rejects hard-linked receipt ledgers without changing external files", async () => {
    for (const contents of ["", '{"id":"interrupted"']) {
      const paths = await fixture();
      const source = await repository(paths.root, "hard-linked-ledger");
      const external = join(paths.root, "external-results.jsonl");
      await writeFile(
        paths.input,
        `id,repository,revision\nledger,${source.path},${source.revision}\n`,
      );
      await mkdir(paths.output);
      await writeFile(external, contents);
      await link(external, join(paths.output, "results.jsonl"));

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/ledger|regular|link/iu);

      expect(scans).toBe(0);
      expect(await readFile(external, "utf8")).toBe(contents);
    }
  });

  test("rejects non-regular receipt ledgers before starting scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "directory-ledger");
    await writeFile(
      paths.input,
      `id,repository,revision\ndirectory,${source.path},${source.revision}\n`,
    );
    await mkdir(join(paths.output, "results.jsonl"), { recursive: true });

    let scans = 0;
    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scans += 1;
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      ),
    ).rejects.toThrow(/ledger|regular/iu);

    expect(scans).toBe(0);
  });

  test.skipIf(process.platform === "win32")(
    "rejects FIFO receipt ledgers without opening or blocking",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "fifo-ledger");
      await writeFile(
        paths.input,
        `id,repository,revision\nfifo,${source.path},${source.revision}\n`,
      );
      await mkdir(paths.output);
      execFileSync("mkfifo", [join(paths.output, "results.jsonl")], {
        stdio: "ignore",
      });

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/ledger|regular/iu);

      expect(scans).toBe(0);
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a receipt ledger replaced by a symlink before appending",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "ledger-replacement");
      const external = join(paths.root, "external-results.jsonl");
      const preserved = "external file must not receive a scan receipt\n";
      await writeFile(
        paths.input,
        `id,repository,revision\nledger,${source.path},${source.revision}\n`,
      );
      await writeFile(external, preserved);

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              await symlink(external, join(paths.output, "results.jsonl"));
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/ledger|symbolic link|ELOOP/iu);

      expect(scans).toBe(1);
      expect(await readFile(external, "utf8")).toBe(preserved);
    },
  );

  test("rejects a receipt ledger replaced by a hard link before appending", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "hard-link-replacement");
    const external = join(paths.root, "external-results.jsonl");
    const preserved = "external file must not receive a scan receipt\n";
    await writeFile(
      paths.input,
      `id,repository,revision\nledger,${source.path},${source.revision}\n`,
    );
    await writeFile(external, preserved);

    let scans = 0;
    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scans += 1;
            await link(external, join(paths.output, "results.jsonl"));
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      ),
    ).rejects.toThrow(/ledger|regular|link/iu);

    expect(scans).toBe(1);
    expect(await readFile(external, "utf8")).toBe(preserved);
  });

  test("repairs an interrupted regular ledger without dropping completed receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "ledger-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nledger,${source.path},${source.revision}\n`,
    );

    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(options(paths, security));
    const completed = await readFile(initial.resultsPath, "utf8");
    await appendFile(
      initial.resultsPath,
      '{"id":"interrupted","error":"\u20ac',
    );

    const recovered = await runMultiscan(options(paths, security));

    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(scans).toBe(1);
    expect(await readFile(initial.resultsPath, "utf8")).toBe(completed);
  });

  test("rescans completed receipts with invalid, unsealed, or incomplete artifacts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume-integrity");
    await writeFile(
      paths.input,
      `id,repository,revision\nresume-integrity,${source.path},${source.revision}\n`,
    );
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const run = async () =>
      await runMultiscan(options(paths, security, { maxAttempts: 4 }));
    const latestOutput = async (): Promise<string> =>
      (await results(join(paths.output, "results.jsonl"))).at(-1)?.[
        "outputDir"
      ] as string;

    await run();
    expect(calls).toBe(1);

    await writeFile(join(await latestOutput(), "findings.json"), "");
    expect(await run()).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(2);

    await appendFile(join(await latestOutput(), "coverage.json"), "\n");
    expect(await run()).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(3);

    const incompleteOutput = await latestOutput();
    const coveragePath = join(incompleteOutput, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8")) as {
      completeness: string;
    };
    coverage.completeness = "partial";
    await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
    await reseal(incompleteOutput);
    expect(
      (
        await loadContract(incompleteOutput, {
          pluginRoot: PLUGIN_ROOT,
        })
      ).coverage.completeness,
    ).toBe("partial");
    expect(await run()).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(4);
    expect(await latestOutput()).toBe(
      join(paths.output, "artifacts", "resume-integrity", "attempt-4"),
    );

    await writeFile(join(await latestOutput(), "findings.json"), "");
    expect(await run()).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(5);
    expect(await latestOutput()).toBe(
      join(paths.output, "artifacts", "resume-integrity", "attempt-4"),
    );
  });

  test("does not reuse a directory snapshot for a pinned Git campaign", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "snapshot-mismatch");
    await writeFile(
      paths.input,
      `id,repository,revision\nsnapshot,${source.path},${source.revision}\n`,
    );
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(options(paths, security));
    const [receipt] = await results(initial.resultsPath);
    const manifestPath = join(
      receipt!["outputDir"] as string,
      "scan-manifest.json",
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      scan: { target: { kind: string } };
    };
    manifest.scan.target.kind = "directory_snapshot";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    expect(await runMultiscan(options(paths, security))).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 0,
    });
    expect(scans).toBe(2);
  });

  test("recovers interrupted receipt replacement without dropping valid history", async () => {
    for (const interruption of ["truncated", "missing", "published"]) {
      const paths = await fixture();
      const source = await repository(paths.root, `repair-${interruption}`);
      await writeFile(
        paths.input,
        `id,repository,revision\nrepair,${source.path},${source.revision}\n`,
      );
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        return await completedScan(scanOptions.outputDir!);
      });
      const initial = await runMultiscan(options(paths, security));
      const saved = await readFile(initial.resultsPath, "utf8");
      const replacement = join(
        paths.output,
        ".results.repair-interrupted.jsonl",
      );
      await writeFile(replacement, saved, { flag: "wx", mode: 0o600 });
      if (interruption === "truncated") {
        await writeFile(initial.resultsPath, saved.slice(0, 10));
      } else if (interruption === "missing") {
        await rm(initial.resultsPath);
      }

      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toBe(1);
      expect(await readFile(initial.resultsPath, "utf8")).toBe(saved);
      await expect(access(replacement)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  });

  test("never publishes an unfinished receipt-repair construction file", async () => {
    const paths = await fixture();
    const first = await repository(paths.root, "repair-first");
    const second = await repository(paths.root, "repair-second");
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `first,${first.path},${first.revision}`,
        `second,${second.path},${second.revision}`,
        "",
      ].join("\n"),
    );
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(options(paths, security));
    const saved = await readFile(initial.resultsPath, "utf8");
    const unfinished = join(
      paths.output,
      ".results.repair-interrupted.jsonl.pending",
    );
    await writeFile(unfinished, `${saved.split("\n")[0]}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await appendFile(initial.resultsPath, '{"id":"interrupted"');

    expect(await runMultiscan(options(paths, security))).toMatchObject({
      completed: 2,
      failed: 0,
      skipped: 2,
    });
    expect(scans).toBe(2);
    expect(await readFile(initial.resultsPath, "utf8")).toBe(saved);
    await expect(access(unfinished)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("binds resumed scan bundles to their pinned task and plugin version", async () => {
    for (const mismatch of ["revision", "plugin"] as const) {
      const paths = await fixture();
      const source = await repository(paths.root, `foreign-bundle-${mismatch}`);
      await writeFile(
        paths.input,
        `id,repository,revision\nforeign,${source.path},${source.revision}\n`,
      );
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        return await completedScan(scanOptions.outputDir!);
      });
      const initial = await runMultiscan(options(paths, security));
      const [receipt] = await results(initial.resultsPath);
      const outputDir = receipt!["outputDir"] as string;
      const manifestPath = join(outputDir, "scan-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
        scan: { producer: { version: string }; target: { revision: string } };
      };
      if (mismatch === "revision") {
        manifest.scan.target.revision = "0".repeat(40);
      } else {
        manifest.scan.producer.version = "0.0.0";
      }
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

      const resumed = await runMultiscan(options(paths, security));

      expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
      expect(scans).toBe(2);
    }
  });

  test("quarantines malformed committed receipts and preserves valid history", async () => {
    const corruptions = (
      receipt: Record<string, unknown>,
    ): Array<[string, string]> => {
      const { id: _id, ...withoutId } = receipt;
      return [
        ["malformed JSON", '{"broken":\n'],
        ["non-object JSON", "null\n"],
        ["missing ID", `${JSON.stringify(withoutId)}\n`],
        ["invalid attempt", `${JSON.stringify({ ...receipt, attempt: 0 })}\n`],
        [
          "invalid status",
          `${JSON.stringify({ ...receipt, status: "running" })}\n`,
        ],
        [
          "invalid output path",
          `${JSON.stringify({ ...receipt, outputDir: 42 })}\n`,
        ],
        [
          "oversized line",
          `${JSON.stringify({ padding: "x".repeat(1024 * 1024) })}\n`,
        ],
      ];
    };

    for (const [index] of Array.from({ length: 7 }).entries()) {
      const paths = await fixture();
      const source = await repository(paths.root, `corrupt-${index}`);
      await writeFile(
        paths.input,
        `id,repository,revision\ncorrupt-${index},${source.path},${source.revision}\n`,
      );
      let calls = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        calls += 1;
        return await completedScan(scanOptions.outputDir!);
      });
      const initial = await runMultiscan(options(paths, security));
      const [receipt] = await results(initial.resultsPath);
      const [, corruption] = corruptions(receipt!)[index]!;
      await appendFile(
        initial.resultsPath,
        `${corruption}${JSON.stringify(receipt)}\n`,
      );

      const resumed = await runMultiscan(options(paths, security));
      expect(resumed).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(calls).toBe(1);
      expect(await results(resumed.resultsPath)).toHaveLength(2);
      const quarantines = (await readdir(paths.output)).filter((entry) =>
        entry.startsWith("results.corrupt-"),
      );
      expect(quarantines).toHaveLength(1);
      expect(
        await readFile(join(paths.output, quarantines[0]!), "utf8"),
      ).toContain(corruption.trim());
    }
  });

  test("quarantines an oversized receipt ledger before rescanning", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "oversized-ledger");
    await writeFile(
      paths.input,
      `id,repository,revision\noversized-ledger,${source.path},${source.revision}\n`,
    );
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls += 1;
      await expect(access(scanOptions.outputDir!)).rejects.toMatchObject({
        code: "ENOENT",
      });
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(options(paths, security));
    await truncate(initial.resultsPath, 64 * 1024 * 1024 + 1);

    const resumed = await runMultiscan(options(paths, security));

    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(2);
    expect(await results(resumed.resultsPath)).toHaveLength(1);
    const quarantines = (await readdir(paths.output)).filter((entry) =>
      entry.startsWith("results.corrupt-"),
    );
    expect(quarantines).toHaveLength(1);
    expect(
      (await lstat(join(paths.output, quarantines[0]!))).size,
    ).toBeGreaterThan(64 * 1024 * 1024);
  });

  test("never appends a receipt beyond the durable total-ledger limit", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "bounded-ledger");
    await writeFile(
      paths.input,
      `id,repository,revision\nbounded,${source.path},${source.revision}\n`,
    );
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const initial = await runMultiscan(options(paths, security));
    const [receipt] = await results(initial.resultsPath);
    const base = { ...receipt, error: "" };
    const empty = `${JSON.stringify(base)}\n`;
    const padded = `${JSON.stringify({ ...base, error: "x".repeat(64_000) })}\n`;
    const maximum = 64 * 1024 * 1024;
    let count = Math.floor(maximum / Buffer.byteLength(padded));
    let remaining = maximum - count * Buffer.byteLength(padded);
    if (remaining < Buffer.byteLength(empty)) {
      count -= 1;
      remaining += Buffer.byteLength(padded);
    }
    const tail = `${JSON.stringify({
      ...base,
      error: "x".repeat(remaining - Buffer.byteLength(empty)),
    })}\n`;
    await writeFile(initial.resultsPath, padded.repeat(count) + tail);
    await rm(join(receipt!["outputDir"] as string, "report.md"));

    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      /64 MiB safety limit/u,
    );

    expect(scans).toBe(2);
    expect((await lstat(initial.resultsPath)).size).toBe(maximum);
  });

  test("ignores repository-local Git shims while preserving credential configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "private");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const shimDirectory = join(paths.root, "node_modules", ".bin");
    const leakedCredential = join(paths.root, "leaked-credential");
    await mkdir(shimDirectory, { recursive: true });
    await writeFile(
      join(shimDirectory, "git"),
      `#!/bin/sh\nprintf '%s' "$GIT_CONFIG_VALUE_0" > "${leakedCredential}"\nexit 1\n`,
      { mode: 0o700 },
    );
    const previousDirectory = process.cwd();
    const environment = new Map(
      [
        "PATH",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
      ].map((name) => [name, process.env[name]] as const),
    );

    try {
      process.chdir(paths.root);
      process.env["PATH"] =
        `${shimDirectory}${process.platform === "win32" ? ";" : ":"}${environment.get("PATH") ?? ""}`;
      process.env["GIT_CONFIG_COUNT"] = "1";
      process.env["GIT_CONFIG_KEY_0"] = "multiscan.credential";
      process.env["GIT_CONFIG_VALUE_0"] = "SYNTHETIC_GIT_CREDENTIAL";

      const summary = await runMultiscan(
        options(
          paths,
          client(async (checkout, scanOptions = {}) => {
            const trustedGit = await resolveTrustedExecutable(
              "git",
              { ...process.env, PATH: environment.get("PATH") ?? "" },
              paths.root,
            );
            if (trustedGit === null) {
              throw new Error("Git is not available on a trusted PATH.");
            }
            const credential = execFileSync(
              trustedGit.executable,
              ["-C", checkout, "config", "--get", "multiscan.credential"],
              {
                encoding: "utf8",
                env: trustedGit.environment,
                stdio: ["ignore", "pipe", "pipe"],
              },
            ).trim();
            expect(credential).toBe("SYNTHETIC_GIT_CREDENTIAL");
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(leakedCredential)).rejects.toThrow();
    } finally {
      process.chdir(previousDirectory);
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("rejects output-directory symlinks before deleting external checkouts", async () => {
    for (const directory of ["", "checkouts", "artifacts"]) {
      const paths = await fixture();
      const source = await repository(paths.root, "victim");
      await writeFile(
        paths.input,
        `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
      );
      const external = join(paths.root, "external");
      const preserved = join(external, "victim", "keep.txt");
      await mkdir(join(external, "victim"), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (directory) await mkdir(paths.output);
      await symlink(
        external,
        directory ? join(paths.output, directory) : paths.output,
      );

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow("symbolic links");
      expect(scans).toBe(0);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    }
  });

  test("rejects unsafe input without starting scans or exposing URL credentials", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "safe");
    const secret = "MULTISCAN_CREDENTIAL_SHOULD_NOT_APPEAR";
    const invalid = [
      {
        name: "task-id",
        row: `../escape,${source.path},${source.revision},.`,
      },
      {
        name: "scope",
        row: `safe,${source.path},${source.revision},../outside`,
      },
      {
        name: "revision",
        row: `safe,${source.path},HEAD,.`,
      },
      {
        name: "duplicate-id",
        row: `safe,${source.path},${source.revision},.\nsafe,${source.path},${source.revision},.`,
      },
      {
        name: "credentials",
        row: `safe,https://user:${secret}@example.test/private.git,${source.revision},.`,
      },
    ];
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    for (const entry of invalid) {
      await writeFile(
        paths.input,
        `id,repository,revision,scope\n${entry.row}\n`,
      );
      const output = join(paths.root, entry.name);
      const error = await runMultiscan(
        options(paths, security, { outputDir: output }),
      ).then(
        () => null,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(secret);
    }

    expect(scans).toBe(0);
  });

  test("treats incomplete coverage as a failure and still finishes other repositories", async () => {
    const paths = await fixture();
    const incomplete = await repository(paths.root, "incomplete");
    const complete = await repository(paths.root, "complete");
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `incomplete,${incomplete.path},${incomplete.revision}`,
        `complete,${complete.path},${complete.revision}`,
        "",
      ].join("\n"),
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (checkout, scanOptions = {}) =>
          completedScan(
            scanOptions.outputDir!,
            (await readFile(join(checkout, "src", "app.ts"), "utf8")).includes(
              'name = "incomplete"',
            )
              ? "partial"
              : "complete",
          ),
        ),
        { maxAttempts: 1 },
      ),
    );

    expect(summary).toMatchObject({ total: 2, completed: 1, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "incomplete", status: "failed", attempt: 1 },
      { id: "complete", status: "completed", attempt: 1 },
    ]);
  });
});
