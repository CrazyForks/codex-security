import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import createDebug from "debug";
import {
  NoopTrace,
  Usage,
  getGlobalTraceProvider,
  setTracingDisabled,
  type Model,
  type ModelProvider,
  type ModelRequest,
  type ModelResponse,
  type StreamEvent,
} from "@openai/agents";
import {
  AgentsSecurity,
  AuthenticationRequiredError,
  DiffTarget,
  InvalidTargetError,
  ScanInterruptedError,
  IncompleteScanError,
  OutputDirectoryError,
  agentsManifest,
  agentsScanPrompt,
  runAgentsScan,
  type AgentsScanRequest,
} from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const TestClient = AgentsSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => AgentsSecurity;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-agents-thin-")),
  );
  temporaryDirectories.push(root);
  return root;
}

function git(
  cwd: string,
  args: string[],
  environment: NodeJS.ProcessEnv = process.env,
): string {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", ...args], {
    cwd,
    env: environment,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

async function initializeGitRepository(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
  git(path, ["init", "--quiet"]);
  git(path, ["config", "user.email", "test@example.invalid"]);
  git(path, ["config", "user.name", "test"]);
}

function request(root: string): AgentsScanRequest {
  return {
    repository: join(root, "repository"),
    hostRepositoryRoot: join(root, "repository"),
    target: { kind: "repository", paths: [] },
    scanDir: join(root, "scan"),
    pluginRoot: PLUGIN_ROOT,
    python: "python3",
    sandboxBaseDir: join(root, "workspace"),
    sandboxInputRoot: join(root, "scan-inputs"),
    repositoryRevision: "deadbeef",
    repositoryIdentity: `codex-security-target/v1:sha256:${"a".repeat(64)}`,
    apiKey: "synthetic-agents-key",
    model: "gpt-test",
    reasoningEffort: "low",
    maxTurns: 8,
    workerMaxTurns: 4,
    signal: new AbortController().signal,
  };
}

async function completedScan(
  scanDir: string,
  targetId: string,
  snapshotDigest: string,
): Promise<void> {
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  await writeFile(join(scanDir, "report.md"), "# Scan report\n");
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: {
      producer: { version: string };
      target: Record<string, unknown>;
      sealedAt?: string;
      artifacts?: unknown[];
    };
  };
  manifest.scan.producer.version = "0.1.14";
  manifest.scan.target = {
    kind: "directory_snapshot",
    targetId,
    displayName: "repository",
    snapshotDigest,
  };
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  execFileSync(
    "python3",
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
      "--scan-dir",
      scanDir,
    ],
    { stdio: "pipe" },
  );
}

describe("Agents SDK thin scan adapter", () => {
  test("mounts source and plugin read-only, output writable, and binds scan inputs", async () => {
    const root = await temporaryDirectory();
    const value = request(root);
    await mkdir(value.repository);
    await mkdir(value.scanDir);
    await mkdir(value.sandboxInputRoot);
    const manifest = await agentsManifest(value);
    expect(manifest.root).toBe("/workspace");
    expect(manifest.entries["repository"]).toMatchObject({
      type: "mount",
      source: value.repository,
      readOnly: true,
    });
    expect(manifest.entries["output"]).toMatchObject({
      type: "mount",
      source: value.scanDir,
      readOnly: false,
    });
    expect(manifest.entries["scan-inputs"]).toMatchObject({
      type: "mount",
      source: value.sandboxInputRoot,
      readOnly: true,
    });
    for (const name of ["scripts", "references", "schemas", "skills"]) {
      expect(manifest.entries[`plugin/${name}`]).toMatchObject({
        type: "mount",
        readOnly: true,
      });
    }
    expect(manifest.environment).toMatchObject({
      CODEX_SECURITY_AGENT_RUNTIME: { value: "agents-sdk" },
      CODEX_SECURITY_TARGET_PATHS_FILE: {
        value: "scan-inputs/target-paths.json",
      },
      CODEX_SECURITY_REPOSITORY_IDENTITY_FILE: {
        value: "scan-inputs/repository-identity.json",
      },
    });
    expect(manifest.environment["OPENAI_API_KEY"]).toBeUndefined();
    expect(manifest.environment["CODEX_API_KEY"]).toBeUndefined();
  });

  test("builds a compact, path-safe scan prompt", () => {
    const prompt = agentsScanPrompt({
      target: {
        kind: "paths",
        paths: ['src/with"scope', "tests/$(do-not-run)"],
      },
      repositoryRevision: "deadbeef",
      repositoryIdentity: "target-id",
    });
    expect(prompt).toContain(
      "Read and use the $security-scan skill at plugin/skills/security-scan/SKILL.md.",
    );
    expect(prompt).toContain("delegate_security_task");
    expect(prompt).toContain("--scopes-file scan-inputs/target-paths.json");
    expect(prompt).toContain("--usable-worker-slots 1");
    expect(prompt).toContain("Repository revision: deadbeef");
    expect(prompt).toContain("Repository targetId: target-id");
    expect(prompt).not.toContain('src/with"scope');
    expect(prompt).not.toContain("$(do-not-run)");
  });

  test("validates targets and credentials before starting the runtime", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    let reached = false;
    const client = new TestClient(
      {},
      {
        environment: {},
        runAgents: async () => {
          reached = true;
          throw new Error("must-not-run");
        },
      },
    );
    await expect(client.run(repository)).rejects.toBeInstanceOf(
      AuthenticationRequiredError,
    );
    await expect(
      client.run(repository, {
        target: DiffTarget.refs({ base: "HEAD", head: "HEAD" }),
      }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(reached).toBe(false);
    await client.close();
    await expect(
      runAgentsScan({
        ...request(root),
        target: { kind: "refs", base: "base", head: "head", paths: [] },
      }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
  });

  test("runs the standard adapter and validates the canonical contract and stable target identity", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    await writeFile(
      join(repository, ".gitignore"),
      "private-generated/\n.env\n",
    );
    await mkdir(join(repository, "private-generated"));
    await writeFile(
      join(repository, "private-generated", "secret.ts"),
      "export const secret = 'ignored';\n",
    );
    await writeFile(join(repository, ".env"), "SYNTHETIC_SECRET=ignored\n");
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
    execFileSync("git", ["add", "app.ts", ".gitignore"], { cwd: repository });
    const identities: string[] = [];
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, model: "gpt-test", maxTurns: 12 },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async (value: AgentsScanRequest) => {
          identities.push(value.repositoryIdentity);
          expect(value.repository).not.toBe(repository);
          expect(value.pluginRoot).not.toBe(await realpath(PLUGIN_ROOT));
          expect(existsSync(join(value.repository, ".git"))).toBe(false);
          expect(existsSync(join(value.repository, ".env"))).toBe(false);
          expect(
            existsSync(
              join(value.repository, "private-generated", "secret.ts"),
            ),
          ).toBe(false);
          expect(await readFile(join(value.repository, "app.ts"), "utf8")).toBe(
            "export const ok = true;\n",
          );
          expect(value.repositoryRevision).toBeNull();
          expect(value.python).toBe("python3");
          expect(value.sandboxBaseDir.startsWith(`${workspace}/`)).toBe(true);
          expect(value.repositorySnapshotDigest).toMatch(
            /^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/u,
          );
          expect(
            JSON.parse(
              await readFile(
                join(value.sandboxInputRoot, "repository-identity.json"),
                "utf8",
              ),
            ),
          ).toEqual({
            targetId: value.repositoryIdentity,
            snapshotDigest: value.repositorySnapshotDigest,
          });
          await completedScan(
            value.scanDir,
            value.repositoryIdentity,
            value.repositorySnapshotDigest!,
          );
          return { responseId: "resp_agents", finalResponse: "complete" };
        },
      },
    );
    try {
      const result = await client.run(repository, { outputDir: scanDir });
      expect(result.threadId).toBe("resp_agents");
      expect(result.turnResult).toMatchObject({
        engine: "agents",
        status: "completed",
        finalResponse: "complete",
      });
      expect(result.manifest.scan.target.targetId).toBe(identities[0]!);
      expect(identities[0]!).toMatch(
        /^codex-security-target\/v1:sha256:[0-9a-f]{64}$/u,
      );
      expect(await readFile(result.reportPath, "utf8")).toContain(
        "# Security Review:",
      );
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("preserves the output location when a scan is canceled", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    const controller = new AbortController();
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async (value: AgentsScanRequest) => {
          await writeFile(join(value.scanDir, "partial.txt"), "partial\n");
          controller.abort();
          throw new DOMException("canceled", "AbortError");
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          outputDir: scanDir,
          signal: controller.signal,
        }),
      ).rejects.toMatchObject({ name: ScanInterruptedError.name, scanDir });
      expect(await readFile(join(scanDir, "partial.txt"), "utf8")).toBe(
        "partial\n",
      );
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects a filesystem-root target before staging can write inside it",
    async () => {
      const root = await temporaryDirectory();
      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: join(root, "workspaces"),
          },
          runAgents: async () => {
            reached = true;
            throw new Error("must-not-run");
          },
        },
      );
      try {
        await expect(
          client.run("/", { outputDir: join(root, "scan") }),
        ).rejects.toThrow("must be outside the repository");
        expect(reached).toBe(false);
      } finally {
        await client.close();
      }
    },
  );

  test("uses a credential-free remote identity across equivalent Git checkouts", async () => {
    const root = await temporaryDirectory();
    const workspace = join(root, "workspaces");
    const identities: string[] = [];
    for (const [name, remote] of [
      [
        "checkout-a",
        "https://user:SYNTHETIC_REMOTE_TOKEN@example.invalid/org/shared.git?token=first#fragment",
      ],
      ["checkout-b", "git@example.invalid:org/shared.git"],
      ["checkout-c", "ssh://git@example.invalid:22/org/shared.git"],
    ] as const) {
      const repository = join(root, name);
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "initial"]);
      git(repository, ["config", "remote.origin.url", remote]);
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async (value: AgentsScanRequest) => {
            identities.push(value.repositoryIdentity);
            throw new Error("stop after identity inspection");
          },
        },
      );
      try {
        await expect(
          client.run(repository, { outputDir: join(root, `scan-${name}`) }),
        ).rejects.toThrow("stop after identity inspection");
      } finally {
        await client.close();
      }
    }
    expect(identities[0]).toBe(identities[1]);
    expect(identities[0]).toBe(identities[2]);
    expect(identities[0]).toMatch(
      /^codex-security-target\/v1:sha256:[0-9a-f]{64}$/u,
    );
    expect(await readdir(workspace)).toEqual([]);
  });

  test("stages tracked files while excluding untracked content, submodules, and Git credentials", async () => {
    const root = await temporaryDirectory();
    const child = join(root, "child");
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await initializeGitRepository(child);
    await writeFile(join(child, "sub.ts"), "export const sub = true;\n");
    git(child, ["add", "."]);
    git(child, ["commit", "--quiet", "-m", "child"]);
    await initializeGitRepository(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    await writeFile(
      join(repository, "deleted.ts"),
      "export const deleted = true;\n",
    );
    await symlink("app.ts", join(repository, "linked.ts"));
    await writeFile(join(repository, ".gitignore"), "private/\n");
    await writeFile(
      join(repository, ".git-credentials"),
      "https://user:SYNTHETIC_GIT_TOKEN@example.invalid\n",
    );
    git(repository, ["add", "."]);
    git(repository, ["commit", "--quiet", "-m", "parent"]);
    await rm(join(repository, "deleted.ts"));
    git(repository, [
      "-c",
      "protocol.file.allow=always",
      "submodule",
      "add",
      "--quiet",
      child,
      "vendor/service",
    ]);
    git(repository, ["commit", "--quiet", "-am", "submodule"]);
    await rm(join(repository, "vendor", "service"), {
      recursive: true,
      force: true,
    });
    await writeFile(
      join(repository, "vendor", "service"),
      "SYNTHETIC_REPLACED_GITLINK_SECRET\n",
    );
    await writeFile(
      join(repository, ".gitmodules"),
      '[submodule "vendor/service"]\n  path = vendor/service\n  url = https://user:SYNTHETIC_MODULE_TOKEN@example.invalid/repo.git\n',
    );
    await writeFile(
      join(repository, "untracked.ts"),
      "export const untracked = true;\n",
    );
    await mkdir(join(repository, "private"));
    await writeFile(
      join(repository, "private", "secret.ts"),
      "SYNTHETIC_IGNORED_SECRET\n",
    );
    await chmod(join(repository, "private"), 0o000);
    const nested = join(repository, "services", "nested");
    await initializeGitRepository(nested);
    await writeFile(join(nested, "source.ts"), "export const nested = true;\n");
    git(nested, ["add", "."]);
    git(nested, ["commit", "--quiet", "-m", "nested"]);
    const bare = join(repository, "cache", "private-mirror");
    await mkdir(join(repository, "cache"));
    git(repository, ["clone", "--quiet", "--bare", child, bare]);
    const bareConfig = join(bare, "config");
    await writeFile(
      bareConfig,
      `${(await readFile(bareConfig, "utf8")).replace(/^\s*bare\s*=\s*true\s*$/mu, "\tbare")}\n[remote "origin"]\n  url = https://user:SYNTHETIC_BARE_TOKEN@example.invalid/private.git\n`,
    );
    let reached = false;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async (value: AgentsScanRequest) => {
          reached = true;
          expect(existsSync(join(value.repository, "app.ts"))).toBe(true);
          for (const path of [
            ".git",
            ".git-credentials",
            ".gitmodules",
            "untracked.ts",
            "linked.ts",
            "deleted.ts",
            "private/secret.ts",
            "vendor/service",
            "services/nested/source.ts",
            "cache/private-mirror/config",
          ]) {
            expect(existsSync(join(value.repository, path))).toBe(false);
          }
          throw new Error("stop after staging inspection");
        },
      },
    );
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan-all") }),
      ).rejects.toThrow("stop after staging inspection");
      expect(reached).toBe(true);
      reached = false;
      await chmod(join(repository, "private"), 0o700);
      await expect(
        client.run(repository, {
          target: ["private"],
          outputDir: join(root, "scan-untracked"),
        }),
      ).rejects.toThrow("must contain tracked regular files");
      expect(reached).toBe(false);
      await expect(
        client.run(bare, { outputDir: join(root, "scan-bare") }),
      ).rejects.toThrow("Bare Git repositories cannot be staged safely");
      expect(reached).toBe(false);
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await chmod(join(repository, "private"), 0o700);
      await client.close();
    }
  });

  test("distinguishes Git subdirectories while keeping equivalent checkout identities stable", async () => {
    const root = await temporaryDirectory();
    const identities = new Map<string, string[]>();
    for (const [name, remote] of [
      ["checkout-a", "https://user:SECRET@example.invalid/org/shared.git"],
      ["checkout-b", "git@example.invalid:org/shared.git"],
    ] as const) {
      const repository = join(root, name);
      await initializeGitRepository(repository);
      for (const service of ["service-a", "service-b"]) {
        await mkdir(join(repository, service));
        await writeFile(
          join(repository, service, "app.ts"),
          "export const app = true;\n",
        );
      }
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "initial"]);
      git(repository, ["config", "remote.origin.url", remote]);
      for (const service of ["service-a", "service-b"]) {
        const client = new TestClient(
          { pluginPath: PLUGIN_ROOT },
          {
            environment: {
              OPENAI_API_KEY: "synthetic-agents-key",
              CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: join(root, "workspaces"),
            },
            runAgents: async (value: AgentsScanRequest) => {
              identities.set(service, [
                ...(identities.get(service) ?? []),
                value.repositoryIdentity,
              ]);
              throw new Error("stop after scoped identity inspection");
            },
          },
        );
        try {
          await expect(
            client.run(join(repository, service), {
              outputDir: join(root, `scan-${name}-${service}`),
            }),
          ).rejects.toThrow("stop after scoped identity inspection");
        } finally {
          await client.close();
        }
      }
    }
    expect(identities.get("service-a")?.[0]).toBe(
      identities.get("service-a")?.[1],
    );
    expect(identities.get("service-b")?.[0]).toBe(
      identities.get("service-b")?.[1],
    );
    expect(identities.get("service-a")?.[0]).not.toBe(
      identities.get("service-b")?.[0],
    );
  });

  test.skipIf(process.platform === "win32")(
    "stages populated sparse-checkout paths and excludes absent paths",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await initializeGitRepository(repository);
      await mkdir(join(repository, "service-a"));
      await mkdir(join(repository, "service-b"));
      await writeFile(
        join(repository, "service-a", "a.ts"),
        "export const a = true;\n",
      );
      await writeFile(
        join(repository, "service-b", "b.ts"),
        "export const b = true;\n",
      );
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "initial"]);
      git(repository, ["sparse-checkout", "init", "--cone"]);
      git(repository, ["sparse-checkout", "set", "service-a"]);
      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: join(root, "workspaces"),
          },
          runAgents: async (value: AgentsScanRequest) => {
            reached = true;
            expect(
              existsSync(join(value.repository, "service-a", "a.ts")),
            ).toBe(true);
            expect(
              existsSync(join(value.repository, "service-b", "b.ts")),
            ).toBe(false);
            throw new Error("stop after sparse staging inspection");
          },
        },
      );
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "scan") }),
        ).rejects.toThrow("stop after sparse staging inspection");
        expect(reached).toBe(true);
      } finally {
        await client.close();
      }
    },
  );

  test("excludes case-insensitive env and key files from unversioned and plugin inputs", async () => {
    const root = await temporaryDirectory();
    const plugin = join(root, "plugin");
    const repository = join(root, "repository");
    const names = [
      ".env",
      ".ENV",
      ".env.production",
      ".ENV.PRODUCTION",
      "private.pem",
      "PRIVATE.PEM",
      "private.key",
      "PRIVATE.KEY",
      ".git-credentials",
      ".GIT-CREDENTIALS",
      ".gitmodules",
      ".GITMODULES",
    ];
    await cp(PLUGIN_ROOT, plugin, { recursive: true });
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    const mirror = join(repository, "private-mirror");
    await mkdir(join(mirror, "objects"), { recursive: true });
    await mkdir(join(mirror, "refs"));
    await writeFile(join(mirror, "HEAD"), "malformed bare HEAD\n");
    await writeFile(join(mirror, "objects", "history"), "SYNTHETIC_HISTORY\n");
    const mirrorConfig = join(root, "mirror-config");
    await writeFile(mirrorConfig, "SYNTHETIC_MIRROR_TOKEN\n");
    await symlink(mirrorConfig, join(mirror, "config"));
    for (const name of names) {
      await writeFile(join(repository, name), "SYNTHETIC_SOURCE_SECRET\n");
      await writeFile(
        join(plugin, "scripts", name),
        "SYNTHETIC_PLUGIN_SECRET\n",
      );
    }
    let reached = false;
    const client = new TestClient(
      { pluginPath: plugin },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: join(root, "workspaces"),
        },
        runAgents: async (value: AgentsScanRequest) => {
          reached = true;
          expect(existsSync(join(value.repository, "app.ts"))).toBe(true);
          expect(
            existsSync(join(value.repository, "private-mirror", "objects")),
          ).toBe(false);
          for (const name of names) {
            expect(existsSync(join(value.repository, name))).toBe(false);
            expect(existsSync(join(value.pluginRoot, "scripts", name))).toBe(
              false,
            );
          }
          throw new Error("stop after secret staging inspection");
        },
      },
    );
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("stop after secret staging inspection");
      expect(reached).toBe(true);
      reached = false;
      await expect(
        client.run(mirror, { outputDir: join(root, "mirror-scan") }),
      ).rejects.toThrow("Bare Git repositories cannot be staged safely");
      expect(reached).toBe(false);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "sanitizes ambient Git state and validates only the metadata needed for tracked staging",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspace = join(root, "workspaces");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "parent"]);
      await writeFile(join(repository, "untracked.env"), "SYNTHETIC_SECRET\n");
      const repositoryBin = join(repository, "node_modules", ".bin");
      const repositoryBinLink = join(root, "repository-bin-link");
      const repositoryBinCaseAlias = join(
        root,
        "REPOSITORY",
        "node_modules",
        ".bin",
      );
      const hostGitLog = join(root, "host-git-log");
      await mkdir(repositoryBin, { recursive: true });
      await symlink(repositoryBin, repositoryBinLink, "dir");
      await writeFile(
        join(repositoryBin, "git"),
        `#!/bin/sh\nprintf '%s\\n' UNTRUSTED_GIT >> '${hostGitLog}'\nexit 42\n`,
        { mode: 0o755 },
      );
      await writeFile(
        join(repository, "git"),
        `#!/bin/sh\nprintf '%s\\n' UNTRUSTED_CWD_GIT >> '${hostGitLog}'\nexit 42\n`,
        { mode: 0o755 },
      );
      const alternateIndex = join(root, "alternate.index");
      git(repository, ["add", "-f", "untracked.env"], {
        ...process.env,
        GIT_INDEX_FILE: alternateIndex,
      });

      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async (value: AgentsScanRequest) => {
            reached = true;
            expect(existsSync(join(value.repository, ".git"))).toBe(false);
            expect(existsSync(join(value.repository, "app.ts"))).toBe(true);
            expect(existsSync(join(value.repository, "untracked.env"))).toBe(
              false,
            );
            throw new Error("stop after staging inspection");
          },
        },
      );
      const previousDir = process.env["GIT_DIR"];
      const previousIndex = process.env["GIT_INDEX_FILE"];
      const previousPath = process.env["PATH"];
      process.env["GIT_DIR"] = "/dev/null";
      process.env["GIT_INDEX_FILE"] = alternateIndex;
      process.env["PATH"] =
        `${existsSync(repositoryBinCaseAlias) ? `${repositoryBinCaseAlias}:` : ""}${repositoryBinLink}`;
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "regular-scan") }),
        ).rejects.toThrow("stop after staging inspection");
      } finally {
        if (previousDir === undefined) delete process.env["GIT_DIR"];
        else process.env["GIT_DIR"] = previousDir;
        if (previousIndex === undefined) delete process.env["GIT_INDEX_FILE"];
        else process.env["GIT_INDEX_FILE"] = previousIndex;
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
      expect(reached).toBe(true);
      expect(existsSync(hostGitLog)).toBe(false);

      const expectUnsafe = async (name: string): Promise<void> => {
        await expect(
          client.run(repository, { outputDir: join(root, name) }),
        ).rejects.toThrow("Git input must be a regular file before staging");
        expect(await readdir(workspace)).toEqual([]);
      };
      for (const metadataName of ["HEAD", "index"]) {
        const metadataPath = join(repository, ".git", metadataName);
        const previous = await readFile(metadataPath);
        await rm(metadataPath);
        execFileSync("mkfifo", [metadataPath]);
        await expectUnsafe(`${metadataName.toLowerCase()}-fifo-scan`);
        await rm(metadataPath);
        await writeFile(metadataPath, previous);
      }
      const includedConfig = join(root, 'included-"config');
      const continuedConfig = join(root, "continued-config");
      execFileSync("mkfifo", [includedConfig]);
      execFileSync("mkfifo", [continuedConfig]);
      const gitConfig = join(repository, ".git", "config");
      await writeFile(
        gitConfig,
        `${await readFile(gitConfig, "utf8")}\n[include]\n  path = ${JSON.stringify(includedConfig)}\n  path = ${continuedConfig.replace("continued-config", "continued-\\\nconfig")}\n`,
      );
      await expect(
        client.run(repository, { outputDir: join(root, "include-fifo-scan") }),
      ).rejects.toThrow(
        "Git configuration input must be a bounded regular file",
      );
      expect(await readdir(workspace)).toEqual([]);
      await rm(includedConfig);
      await expect(
        client.run(repository, {
          outputDir: join(root, "continued-include-fifo-scan"),
        }),
      ).rejects.toThrow(
        "Git configuration input must be a bounded regular file",
      );
      expect(await readdir(workspace)).toEqual([]);
      await client.close();
    },
  );

  test("stages tracked path contents and preserves ordinary Git-shaped fixtures", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await initializeGitRepository(repository);
    await mkdir(join(repository, "src"));
    await mkdir(join(repository, "fixtures", "not-a-repository.git"), {
      recursive: true,
    });
    await mkdir(join(repository, "fixtures", "gitlike", "objects"), {
      recursive: true,
    });
    await mkdir(join(repository, "fixtures", "gitlike", "refs"));
    await writeFile(join(repository, ".gitignore"), "src/ignored.ts\n");
    await writeFile(
      join(repository, "src", "tracked.ts"),
      "export const tracked = true;\n",
    );
    await writeFile(
      join(repository, "ordinary-source.git"),
      "export const ordinary = true;\n",
    );
    await writeFile(
      join(repository, "fixtures", "not-a-repository.git", "source.ts"),
      "export const fixture = true;\n",
    );
    await writeFile(
      join(repository, "fixtures", "gitlike", "HEAD"),
      "ordinary fixture data\n",
    );
    await writeFile(
      join(repository, "fixtures", "gitlike", "config"),
      "[core]\n  bare = false\n",
    );
    await writeFile(
      join(repository, "fixtures", "gitlike", "objects", "source.ts"),
      "export const gitlike = true;\n",
    );
    git(repository, ["add", "."]);
    git(repository, ["commit", "--quiet", "-m", "tracked"]);
    await writeFile(
      join(repository, "src", "ignored.ts"),
      "export const ignored = true;\n",
    );
    let reached = false;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async (value: AgentsScanRequest) => {
          reached = true;
          expect(existsSync(join(value.repository, "src", "tracked.ts"))).toBe(
            true,
          );
          expect(existsSync(join(value.repository, "src", "ignored.ts"))).toBe(
            false,
          );
          expect(
            existsSync(join(value.repository, "ordinary-source.git")),
          ).toBe(true);
          expect(
            existsSync(
              join(
                value.repository,
                "fixtures",
                "gitlike",
                "objects",
                "source.ts",
              ),
            ),
          ).toBe(true);
          expect(
            existsSync(
              join(
                value.repository,
                "fixtures",
                "not-a-repository.git",
                "source.ts",
              ),
            ),
          ).toBe(true);
          throw new Error("stop after scoped staging inspection");
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          target: ["src"],
          outputDir: join(root, "scan"),
        }),
      ).rejects.toThrow("stop after scoped staging inspection");
      expect(reached).toBe(true);
      reached = false;
      await expect(
        client.run(repository, {
          target: ["src/ignored.ts"],
          outputDir: join(root, "scan-ignored"),
        }),
      ).rejects.toThrow("must contain tracked regular files");
      expect(reached).toBe(false);
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects linked-worktree config includes and strips enclosing-worktree PATH entries",
    async () => {
      const root = await temporaryDirectory();
      const main = join(root, "main");
      const worktree = join(root, "linked-worktree");
      const workspace = join(root, "workspaces");
      await initializeGitRepository(main);
      await mkdir(join(main, "service"));
      await writeFile(
        join(main, "service", "app.ts"),
        "export const app = true;\n",
      );
      await writeFile(join(main, ".gitignore"), ".venv/\n");
      git(main, ["add", "."]);
      git(main, ["commit", "--quiet", "-m", "initial"]);
      git(main, ["config", "extensions.worktreeConfig", "true"]);
      git(main, [
        "worktree",
        "add",
        "--quiet",
        "-b",
        "linked",
        worktree,
        "HEAD",
      ]);
      const gitDirectory = (await readFile(join(worktree, ".git"), "utf8"))
        .trim()
        .replace(/^gitdir:\s*/u, "");
      const includedTarget = join(root, "included-worktree-config");
      const includedLink = join(root, "included-worktree-link");
      await writeFile(includedTarget, "[core]\n  ignoreCase = false\n");
      await symlink(includedTarget, includedLink);
      await writeFile(
        join(gitDirectory, "config.worktree"),
        `[include]\n  path = ${includedLink}\n`,
      );
      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async () => {
            reached = true;
            throw new Error("stop after staging inspection");
          },
        },
      );
      try {
        await expect(
          client.run(worktree, { outputDir: join(root, "worktree-scan") }),
        ).rejects.toThrow(
          "Git configuration input must be a bounded regular file",
        );
        expect(reached).toBe(false);
        await rm(join(gitDirectory, "config.worktree"));
        const commonPointer = join(gitDirectory, "commondir");
        const originalPointer = await readFile(commonPointer);
        await truncate(commonPointer, 64 * 1024 + 1);
        await expect(
          client.run(worktree, { outputDir: join(root, "oversized-pointer") }),
        ).rejects.toThrow(
          "Git common-directory metadata must be a bounded regular file",
        );
        expect(reached).toBe(false);
        await writeFile(commonPointer, originalPointer);
        const controlledBin = join(main, ".venv", "bin");
        const marker = join(root, "host-git-executed");
        await mkdir(controlledBin, { recursive: true });
        await writeFile(
          join(controlledBin, "git"),
          `#!/bin/sh\nprintf '%s\\n' UNTRUSTED_GIT > '${marker}'\nexit 42\n`,
          { mode: 0o755 },
        );
        const previousPath = process.env["PATH"];
        process.env["PATH"] = `${controlledBin}:${previousPath ?? ""}`;
        try {
          await expect(
            client.run(join(main, "service"), {
              outputDir: join(root, "service-scan"),
            }),
          ).rejects.toThrow("stop after staging inspection");
        } finally {
          if (previousPath === undefined) delete process.env["PATH"];
          else process.env["PATH"] = previousPath;
        }
        expect(reached).toBe(true);
        expect(existsSync(marker)).toBe(false);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await client.close();
      }
    },
  );

  test("bounds staged inputs before starting the Agents runtime", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await mkdir(repository);
    await writeFile(join(repository, "large.bin"), "");
    await truncate(join(repository, "large.bin"), 256 * 1024 * 1024 + 1);
    let reached = false;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async () => {
          reached = true;
          throw new Error("must-not-run");
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          target: ["large.bin"],
          outputDir: join(root, "scan"),
        }),
      ).rejects.toThrow("Repository input file is too large to stage safely");
      expect(reached).toBe(false);
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects Git metadata targets and lossy Git path output before sandbox work",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspace = join(root, "workspaces");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      await writeFile(
        join(repository, ".git-credentials"),
        "https://user:SYNTHETIC_TOKEN@example.invalid\n",
      );
      await writeFile(
        join(repository, ".gitmodules"),
        '[submodule "x"]\n  path = x\n  url = https://user:SYNTHETIC_TOKEN@example.invalid/repo.git\n',
      );
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "initial"]);
      git(repository, [
        "config",
        "remote.origin.url",
        "https://SYNTHETIC_GIT_TOKEN@example.invalid/private.git",
      ]);
      await mkdir(join(repository, "private"));
      await writeFile(
        join(repository, "private", "secret.ts"),
        "SYNTHETIC_SYMLINK_SECRET\n",
      );
      await symlink(join("private", "secret.ts"), join(repository, "link.ts"));
      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async () => {
            reached = true;
            throw new Error("must-not-run");
          },
        },
      );
      try {
        for (const [index, target] of [
          ".git",
          ".git/config",
          ".git-credentials",
          ".gitmodules",
        ].entries()) {
          await expect(
            client.run(repository, {
              target: [target],
              outputDir: join(root, `metadata-scan-${index}`),
            }),
          ).rejects.toThrow("must not select Git metadata or credentials");
        }
        await expect(
          client.run(repository, {
            target: ["link.ts"],
            outputDir: join(root, "symlink-scan"),
          }),
        ).rejects.toThrow("must not traverse a symbolic link");
        const shim = join(root, "git-shim");
        await mkdir(shim);
        const actualGit = execFileSync("which", ["git"], {
          encoding: "utf8",
        }).trim();
        await writeFile(
          join(shim, "git"),
          `#!/bin/sh\nfor value in "$@"; do if test "$value" = ls-files; then printf '\\377\\000'; exit 0; fi; done\nexec '${actualGit}' "$@"\n`,
          { mode: 0o755 },
        );
        const previousPath = process.env["PATH"];
        process.env["PATH"] = `${shim}:${previousPath ?? ""}`;
        try {
          await expect(
            client.run(repository, { outputDir: join(root, "non-utf8-scan") }),
          ).rejects.toThrow("Git returned a non-UTF-8 repository path");
        } finally {
          if (previousPath === undefined) delete process.env["PATH"];
          else process.env["PATH"] = previousPath;
        }
        expect(reached).toBe(false);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await client.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "excludes plugin-checkout secrets, rejects tracked source swaps, and rejects retargeted roots",
    async () => {
      const root = await temporaryDirectory();
      const plugin = join(root, "plugin-checkout");
      const repository = join(root, "repository");
      const outside = join(root, "outside");
      const workspace = join(root, "workspaces");
      await cp(PLUGIN_ROOT, plugin, { recursive: true });
      await initializeGitRepository(plugin);
      git(plugin, [
        "config",
        "remote.origin.url",
        "https://SYNTHETIC_PLUGIN_TOKEN@example.invalid/private.git",
      ]);
      await writeFile(join(plugin, ".env"), "SYNTHETIC_PLUGIN_SECRET\n");
      await mkdir(join(plugin, "private"));
      await writeFile(
        join(plugin, "private", "credentials.json"),
        "SYNTHETIC_PLUGIN_CREDENTIALS\n",
      );
      await initializeGitRepository(repository);
      await mkdir(join(repository, "src"));
      await writeFile(
        join(repository, "src", "app.ts"),
        "export const app = true;\n",
      );
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "parent"]);
      await mkdir(outside);
      await writeFile(
        join(outside, "app.ts"),
        "SYNTHETIC_OUTSIDE_SOURCE_SECRET\n",
      );
      let reached = false;
      const client = new TestClient(
        { pluginPath: plugin },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async (value: AgentsScanRequest) => {
            reached = true;
            expect(existsSync(join(value.repository, "src", "app.ts"))).toBe(
              true,
            );
            expect(existsSync(join(value.pluginRoot, ".git"))).toBe(false);
            expect(existsSync(join(value.pluginRoot, ".env"))).toBe(false);
            expect(existsSync(join(value.pluginRoot, "private"))).toBe(false);
            throw new Error("stop after staging inspection");
          },
        },
      );
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "source-scan") }),
        ).rejects.toThrow("stop after staging inspection");
        expect(reached).toBe(true);
        reached = false;
        await rm(join(repository, "src"), { recursive: true, force: true });
        await symlink(outside, join(repository, "src"), "dir");
        await expect(
          client.run(repository, { outputDir: join(root, "source-swap-scan") }),
        ).rejects.toThrow("Tracked repository input is missing or non-regular");
        expect(reached).toBe(false);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await client.close();
      }

      const original = join(root, "original");
      const moved = join(root, "moved");
      const swapped = join(root, "swapped");
      await mkdir(original);
      await mkdir(swapped);
      await writeFile(join(original, "app.ts"), "export const app = true;\n");
      await writeFile(join(swapped, "credentials.json"), "SYNTHETIC_SECRET\n");
      let swapReached = false;
      const swapClient = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async () => {
            swapReached = true;
            throw new Error("must-not-run");
          },
        },
      );
      try {
        await expect(
          swapClient.run(original, {
            outputDir: join(root, "swap-scan"),
            onOutputDirReady: () => {
              execFileSync("mv", [original, moved]);
              execFileSync("ln", ["-s", swapped, original]);
            },
          }),
        ).rejects.toThrow("Repository changed before staging");
        expect(swapReached).toBe(false);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await swapClient.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects an output directory retargeted before artifact handoff",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspace = join(root, "workspaces");
      const output = join(root, "scan");
      const protectedDirectory = join(root, "protected");
      await mkdir(repository);
      await mkdir(protectedDirectory);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async (value: AgentsScanRequest) => {
            await mkdir(join(value.scanDir, "artifacts"));
            await writeFile(
              join(value.scanDir, "artifacts", "payload.txt"),
              "SYNTHETIC_UNTRUSTED_OUTPUT\n",
            );
            await rm(output, { recursive: true, force: true });
            await symlink(protectedDirectory, output, "dir");
            return { finalResponse: "complete" };
          },
        },
      );
      try {
        await expect(
          client.run(repository, { outputDir: output }),
        ).rejects.toThrow(
          "Scan output directory changed before artifact handoff",
        );
        expect(
          existsSync(join(protectedDirectory, "artifacts", "payload.txt")),
        ).toBe(false);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await client.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a nested destination symlink before copying model-generated output",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspace = join(root, "workspaces");
      const output = join(root, "scan");
      const protectedDirectory = join(root, "protected");
      await mkdir(repository);
      await mkdir(protectedDirectory);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
          },
          runAgents: async (value: AgentsScanRequest) => {
            await mkdir(join(value.scanDir, "artifacts"));
            await writeFile(
              join(value.scanDir, "artifacts", "payload.txt"),
              "SYNTHETIC_UNTRUSTED_OUTPUT\n",
            );
            await symlink(protectedDirectory, join(output, "artifacts"), "dir");
            return { finalResponse: "complete" };
          },
        },
      );
      try {
        await expect(
          client.run(repository, { outputDir: output }),
        ).rejects.toThrow(
          "Agents SDK scan output destination contains a non-directory entry",
        );
        expect(existsSync(join(protectedDirectory, "payload.txt"))).toBe(false);
      } finally {
        await client.close();
      }
    },
  );

  test("bounds staged output before loading the canonical contract", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await mkdir(repository);
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async (value: AgentsScanRequest) => {
          await writeFile(join(value.scanDir, "scan-manifest.json"), "");
          await truncate(
            join(value.scanDir, "scan-manifest.json"),
            64 * 1024 * 1024 + 1,
          );
          return { finalResponse: "complete" };
        },
      },
    );
    try {
      await expect(client.run(repository)).rejects.toBeInstanceOf(
        OutputDirectoryError,
      );
      expect(await readdir(workspace)).toHaveLength(1);
      expect((await readdir(workspace))[0]!).toStartWith(
        "codex-security-repository-",
      );
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "uses the SDK Docker runner, reads the scan skill, delegates a worker, and disconnects the network",
    async () => {
      const root = await temporaryDirectory();
      const value = request(root);
      const bin = join(root, "bin");
      const repositoryBin = join(value.repository, "node_modules", ".bin");
      const log = join(root, "docker-calls");
      await mkdir(value.repository);
      await mkdir(value.scanDir);
      await mkdir(value.sandboxBaseDir);
      await mkdir(value.sandboxInputRoot);
      await writeFile(
        join(value.sandboxInputRoot, "target-paths.json"),
        '["."]\n',
      );
      await writeFile(
        join(value.sandboxInputRoot, "repository-identity.json"),
        `${JSON.stringify({ targetId: value.repositoryIdentity })}\n`,
      );
      await mkdir(bin);
      await mkdir(repositoryBin, { recursive: true });
      await writeFile(
        join(value.repository, "app.ts"),
        "export const ok = true;\n",
      );
      await writeFile(
        join(bin, "docker"),
        [
          "#!/bin/sh",
          "set -eu",
          `printf '<%s>\\n' \"$@\" >> '${log}'`,
          `case "\${1-}" in run) printf "%s\\n" synthetic-container;; inspect) if grep -q "<disconnect>" '${log}'; then printf "%s\\n" '{}'; else printf "%s\\n" '{"bridge":{}}'; fi;; exec) printf "%s\\n" '## Phase Sequence';; esac`,
          "exit 0",
          "",
        ].join("\n"),
      );
      await chmod(join(bin, "docker"), 0o755);
      await writeFile(
        join(repositoryBin, "docker"),
        [
          "#!/bin/sh",
          `printf '%s\\n' "UNTRUSTED_DOCKER key=\${OPENAI_API_KEY-absent}" >> '${log}'`,
          "exit 42",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
      const previousPath = process.env["PATH"];
      const previousHostKey = process.env["OPENAI_API_KEY"];
      process.env["PATH"] =
        `${repositoryBin}:${bin}:${previousPath ?? "/usr/bin:/bin"}`;
      process.env["OPENAI_API_KEY"] = "SYNTHETIC_HOST_KEY";
      const tracingWasDisabled =
        getGlobalTraceProvider().createTrace({ name: "before scan" }) instanceof
        NoopTrace;
      setTracingDisabled(false);
      const previousModelLogGuard =
        process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
      const previousToolLogGuard =
        process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
      const previousOpenAILog = process.env["OPENAI_LOG"];
      const previousDebugNamespaces = createDebug.disable();
      createDebug.enable("openai-agents:*");
      delete process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
      delete process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
      process.env["OPENAI_LOG"] = "debug";
      const requests: ModelRequest[] = [];
      let coordinatorTurn = 0;
      let workerTurn = 0;
      let response = 0;
      const model: Model = {
        async getResponse(_request: ModelRequest): Promise<ModelResponse> {
          return { usage: new Usage(), output: [] };
        },
        async *getStreamedResponse(
          modelRequest: ModelRequest,
        ): AsyncIterable<StreamEvent> {
          expect(
            getGlobalTraceProvider().createTrace({ name: "during scan" }),
          ).toBeInstanceOf(NoopTrace);
          expect(process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"]).toBe("1");
          expect(process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"]).toBe("1");
          expect(process.env["OPENAI_LOG"]).toBe("warn");
          expect(createDebug.enabled("openai-agents:core")).toBe(false);
          requests.push(modelRequest);
          response += 1;
          const coordinator = modelRequest.tools.some(
            (tool) => tool.name === "delegate_security_task",
          );
          const call = (name: string, args: Record<string, unknown>) => ({
            id: `fc_${response}`,
            type: "function_call" as const,
            callId: `call_${response}`,
            name,
            status: "completed" as const,
            arguments: JSON.stringify(args),
          });
          const message = (text: string) => ({
            id: `msg_${response}`,
            type: "message" as const,
            role: "assistant" as const,
            status: "completed" as const,
            content: [{ type: "output_text" as const, text }],
          });
          let output;
          if (coordinator) {
            coordinatorTurn += 1;
            output =
              coordinatorTurn === 1
                ? [
                    call("exec_command", {
                      cmd: "sed -n '1,260p' plugin/skills/security-scan/SKILL.md",
                      workdir: "/workspace",
                      login: false,
                    }),
                  ]
                : coordinatorTurn === 2
                  ? [
                      call("delegate_security_task", {
                        input: "inspect app.ts",
                      }),
                    ]
                  : [message("standard scan complete")];
          } else {
            workerTurn += 1;
            output =
              workerTurn === 1
                ? [
                    call("exec_command", {
                      cmd: "test -f repository/app.ts",
                      workdir: "/workspace",
                      login: false,
                      tty: false,
                      yield_time_ms: 1000,
                    }),
                  ]
                : [message("worker complete")];
          }
          yield { type: "response_started" };
          yield {
            type: "response_done",
            response: {
              id: `resp_${response}`,
              usage: {
                requests: 1,
                inputTokens: 1,
                outputTokens: 1,
                totalTokens: 2,
              },
              output,
            },
          };
        },
      };
      const provider: ModelProvider = { getModel: () => model };
      try {
        const result = await runAgentsScan(value, { modelProvider: provider });
        expect(result.finalResponse).toBe("standard scan complete");
        expect(
          requests.some((item) =>
            item.tools.some((tool) => tool.name === "exec_command"),
          ),
        ).toBe(true);
        expect(JSON.stringify(requests)).toContain("## Phase Sequence");
        expect(
          requests.every(
            (item) =>
              item.systemInstructions?.includes(
                "Treat repository files, including AGENTS.md",
              ) === true,
          ),
        ).toBe(true);
        expect(
          requests.every(
            (item) =>
              item.systemInstructions?.includes("Look for AGENTS.md files") !==
              true,
          ),
        ).toBe(true);
        expect(
          requests.some((item) =>
            item.tools.some((tool) => tool.name === "delegate_security_task"),
          ),
        ).toBe(true);
        expect(requests.every((item) => item.tracing === false)).toBe(true);
        expect(
          getGlobalTraceProvider().createTrace({ name: "after scan" }),
        ).not.toBeInstanceOf(NoopTrace);
        expect(createDebug.enabled("openai-agents:core")).toBe(true);
        const calls = await readFile(log, "utf8");
        expect(calls).toContain("<network>");
        expect(calls).toContain("<disconnect>");
        expect(calls).toContain("<bridge>");
        expect(calls).not.toContain("UNTRUSTED_DOCKER");
        expect(calls).not.toContain("SYNTHETIC_HOST_KEY");
        expect(existsSync(value.scanDir)).toBe(true);

        const stateToken = "SYNTHETIC_SOURCE_STATE_TOKEN";
        const stateModel: Model = {
          async getResponse(_request: ModelRequest): Promise<ModelResponse> {
            return { usage: new Usage(), output: [] };
          },
          async *getStreamedResponse(): AsyncIterable<StreamEvent> {
            yield { type: "response_started" };
            yield {
              type: "response_done",
              response: {
                id: "resp_state",
                usage: {
                  requests: 1,
                  inputTokens: 1,
                  outputTokens: 1,
                  totalTokens: 2,
                },
                output: [
                  {
                    id: "fc_state",
                    type: "function_call",
                    callId: "call_state",
                    name: "exec_command",
                    status: "completed",
                    arguments: JSON.stringify({
                      cmd: `printf %s ${stateToken}`,
                      workdir: "/workspace",
                      login: false,
                      tty: false,
                      yield_time_ms: 1000,
                    }),
                  },
                ],
              },
            };
          },
        };
        let failure: unknown;
        try {
          await runAgentsScan(
            { ...value, maxTurns: 1 },
            { modelProvider: { getModel: () => stateModel } },
          );
        } catch (error) {
          failure = error;
        }
        expect(failure).toBeInstanceOf(IncompleteScanError);
        expect(JSON.stringify(failure)).not.toContain(stateToken);
      } finally {
        setTracingDisabled(tracingWasDisabled);
        if (previousModelLogGuard === undefined)
          delete process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
        else
          process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"] =
            previousModelLogGuard;
        if (previousToolLogGuard === undefined)
          delete process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
        else
          process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"] =
            previousToolLogGuard;
        if (previousOpenAILog === undefined) delete process.env["OPENAI_LOG"];
        else process.env["OPENAI_LOG"] = previousOpenAILog;
        createDebug.enable(previousDebugNamespaces);
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
        if (previousHostKey === undefined) delete process.env["OPENAI_API_KEY"];
        else process.env["OPENAI_API_KEY"] = previousHostKey;
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "keeps host execution isolated until an aborted Docker creation is cleaned up",
    async () => {
      const root = await temporaryDirectory();
      const value = request(root);
      const controller = new AbortController();
      value.signal = controller.signal;
      const safeBin = join(root, "safe-bin");
      const repositoryBin = join(value.repository, "node_modules", ".bin");
      const log = join(root, "docker-calls");
      for (const path of [
        value.repository,
        value.scanDir,
        value.sandboxBaseDir,
        value.sandboxInputRoot,
        safeBin,
        repositoryBin,
      ]) {
        await mkdir(path, { recursive: true });
      }
      await writeFile(
        join(value.repository, "app.ts"),
        "export const app = true;\n",
      );
      await writeFile(
        join(value.sandboxInputRoot, "target-paths.json"),
        '["."]\n',
      );
      await writeFile(
        join(value.sandboxInputRoot, "repository-identity.json"),
        `${JSON.stringify({ targetId: value.repositoryIdentity })}\n`,
      );
      await writeFile(
        join(safeBin, "docker"),
        [
          "#!/bin/sh",
          `printf '%s\\n' \"SAFE \${1-}\" >> '${log}'`,
          'case "${1-}" in run) sleep 1; printf "%s\\n" synthetic-container;; esac',
          "exit 0",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
      await writeFile(
        join(repositoryBin, "docker"),
        [
          "#!/bin/sh",
          `printf '%s\\n' \"UNTRUSTED \${1-} key=\${OPENAI_API_KEY-absent}\" >> '${log}'`,
          "exit 42",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
      const previousPath = process.env["PATH"];
      const previousHostKey = process.env["OPENAI_API_KEY"];
      process.env["PATH"] =
        `${repositoryBin}:${safeBin}:${previousPath ?? "/usr/bin:/bin"}`;
      process.env["OPENAI_API_KEY"] = "SYNTHETIC_HOST_SECRET";
      const timer = setTimeout(() => controller.abort(), 100);
      try {
        await expect(runAgentsScan(value)).rejects.toMatchObject({
          name: "AbortError",
        });
        const calls = await readFile(log, "utf8");
        expect(calls).toContain("SAFE run");
        expect(calls).toContain("SAFE rm");
        expect(calls).not.toContain("UNTRUSTED");
        expect(calls).not.toContain("SYNTHETIC_HOST_SECRET");
        expect(process.env["OPENAI_API_KEY"]).toBe("SYNTHETIC_HOST_SECRET");
      } finally {
        clearTimeout(timer);
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
        if (previousHostKey === undefined) delete process.env["OPENAI_API_KEY"];
        else process.env["OPENAI_API_KEY"] = previousHostKey;
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves ambient credentials for an overlapping Agents scan",
    async () => {
      const root = await temporaryDirectory();
      const repositoryA = join(root, "repository-a");
      const repositoryB = join(root, "repository-b");
      const workspace = join(root, "workspaces");
      const safeBin = join(root, "safe-bin");
      await mkdir(repositoryA);
      await mkdir(repositoryB);
      await mkdir(safeBin);
      await writeFile(join(repositoryA, "app.ts"), "export const a = true;\n");
      await writeFile(join(repositoryB, "app.ts"), "export const b = true;\n");
      await writeFile(
        join(safeBin, "docker"),
        [
          "#!/bin/sh",
          'case "${1-}" in run) printf "%s\\n" synthetic-container;; inspect) printf "%s\\n" "{}";; esac',
          "exit 0",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
      const previousPath = process.env["PATH"];
      const previousHostKey = process.env["OPENAI_API_KEY"];
      const previousWorkspace =
        process.env["CODEX_SECURITY_DOCKER_WORKSPACE_ROOT"];
      process.env["PATH"] = `${safeBin}:${previousPath ?? "/usr/bin:/bin"}`;
      process.env["OPENAI_API_KEY"] = "SYNTHETIC_CONCURRENCY_KEY";
      process.env["CODEX_SECURITY_DOCKER_WORKSPACE_ROOT"] = workspace;
      let enterModel!: () => void;
      const entered = new Promise<void>((resolve) => {
        enterModel = resolve;
      });
      let releaseModel!: () => void;
      const released = new Promise<void>((resolve) => {
        releaseModel = resolve;
      });
      const blockingModel: Model = {
        async getResponse(_request: ModelRequest): Promise<ModelResponse> {
          return { usage: new Usage(), output: [] };
        },
        async *getStreamedResponse(): AsyncIterable<StreamEvent> {
          enterModel();
          await released;
          yield { type: "response_started" };
          yield {
            type: "response_done",
            response: {
              id: "first",
              usage: {
                requests: 1,
                inputTokens: 1,
                outputTokens: 1,
                totalTokens: 2,
              },
              output: [
                {
                  id: "done",
                  type: "message",
                  role: "assistant",
                  status: "completed",
                  content: [{ type: "output_text", text: "done" }],
                },
              ],
            },
          };
        },
      };
      let secondReached = false;
      const first = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: process.env,
          runAgents: (value: AgentsScanRequest) =>
            runAgentsScan(value, {
              modelProvider: { getModel: () => blockingModel },
            }),
        },
      );
      const second = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: process.env,
          runAgents: async () => {
            secondReached = true;
            throw new Error("SECOND_RUNTIME_REACHED");
          },
        },
      );
      const firstRun = first.run(repositoryA, {
        outputDir: join(root, "output-a"),
      });
      try {
        await entered;
        expect(process.env["OPENAI_API_KEY"]).toBe("SYNTHETIC_CONCURRENCY_KEY");
        await expect(
          second.run(repositoryB, { outputDir: join(root, "output-b") }),
        ).rejects.toThrow("SECOND_RUNTIME_REACHED");
        expect(secondReached).toBe(true);
        releaseModel();
        await expect(firstRun).rejects.toThrow("required artifacts");
        expect(process.env["OPENAI_API_KEY"]).toBe("SYNTHETIC_CONCURRENCY_KEY");
      } finally {
        releaseModel();
        await first.close();
        await second.close();
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
        if (previousHostKey === undefined) delete process.env["OPENAI_API_KEY"];
        else process.env["OPENAI_API_KEY"] = previousHostKey;
        if (previousWorkspace === undefined)
          delete process.env["CODEX_SECURITY_DOCKER_WORKSPACE_ROOT"];
        else
          process.env["CODEX_SECURITY_DOCKER_WORKSPACE_ROOT"] =
            previousWorkspace;
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "serializes multiple delegated assignments and propagates Docker cleanup failure",
    async () => {
      const root = await temporaryDirectory();
      const value = request(root);
      const bin = join(root, "bin");
      const log = join(root, "docker-calls");
      for (const path of [
        value.repository,
        value.scanDir,
        value.sandboxBaseDir,
        value.sandboxInputRoot,
        bin,
      ]) {
        await mkdir(path, { recursive: true });
      }
      await writeFile(
        join(value.repository, "app.ts"),
        "export const app = true;\n",
      );
      await writeFile(
        join(value.sandboxInputRoot, "target-paths.json"),
        '["."]\n',
      );
      await writeFile(
        join(value.sandboxInputRoot, "repository-identity.json"),
        `${JSON.stringify({ targetId: value.repositoryIdentity })}\n`,
      );
      const docker = join(bin, "docker");
      const writeDocker = async (failRemove: boolean): Promise<void> => {
        await writeFile(
          docker,
          [
            "#!/bin/sh",
            "set -eu",
            `printf '<%s>\\n' \"$@\" >> '${log}'`,
            ...(failRemove
              ? [
                  'if [ "${1-}" = rm ] && [ "${2-}" = -f ]; then printf "%s\\n" SYNTHETIC_DOCKER_REMOVE_FAILURE >&2; exit 42; fi',
                ]
              : []),
            `case "\${1-}" in run) printf "%s\\n" synthetic-container;; inspect) if grep -q "<disconnect>" '${log}'; then printf "%s\\n" '{}'; else printf "%s\\n" '{"bridge":{}}'; fi;; esac`,
            "exit 0",
            "",
          ].join("\n"),
        );
        await chmod(docker, 0o755);
      };
      await writeDocker(false);
      const previousPath = process.env["PATH"];
      process.env["PATH"] = `${bin}:${previousPath ?? "/usr/bin:/bin"}`;
      let coordinatorTurns = 0;
      let workerCalls = 0;
      let activeWorkers = 0;
      let maxActiveWorkers = 0;
      const model: Model = {
        async getResponse(_request: ModelRequest): Promise<ModelResponse> {
          workerCalls += 1;
          activeWorkers += 1;
          maxActiveWorkers = Math.max(maxActiveWorkers, activeWorkers);
          await new Promise((resolve) => setTimeout(resolve, 50));
          activeWorkers -= 1;
          return {
            usage: new Usage(),
            output: [
              {
                id: `worker-${workerCalls}`,
                type: "message",
                role: "assistant",
                status: "completed",
                content: [{ type: "output_text", text: "worker complete" }],
              },
            ],
          };
        },
        async *getStreamedResponse(): AsyncIterable<StreamEvent> {
          coordinatorTurns += 1;
          const output =
            coordinatorTurns === 1
              ? [1, 2].map((slot) => ({
                  id: `call-${slot}`,
                  type: "function_call" as const,
                  callId: `call-${slot}`,
                  name: "delegate_security_task",
                  status: "completed" as const,
                  arguments: JSON.stringify({ input: `assignment ${slot}` }),
                }))
              : [
                  {
                    id: "done",
                    type: "message" as const,
                    role: "assistant" as const,
                    status: "completed" as const,
                    content: [{ type: "output_text" as const, text: "done" }],
                  },
                ];
          yield { type: "response_started" };
          yield {
            type: "response_done",
            response: {
              id: `coordinator-${coordinatorTurns}`,
              usage: {
                requests: 1,
                inputTokens: 1,
                outputTokens: 1,
                totalTokens: 2,
              },
              output,
            },
          };
        },
      };
      try {
        const result = await runAgentsScan(value, {
          modelProvider: { getModel: () => model },
        });
        expect(result.finalResponse).toBe("done");
        expect(workerCalls).toBe(2);
        expect(maxActiveWorkers).toBe(1);

        await writeDocker(true);
        coordinatorTurns = 1;
        await expect(
          runAgentsScan(value, { modelProvider: { getModel: () => model } }),
        ).rejects.toThrow(
          "Unable to remove the Agents SDK sandbox after the scan",
        );
      } finally {
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
    },
  );
});
