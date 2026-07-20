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

async function completedScan(scanDir: string, targetId: string): Promise<void> {
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
    snapshotDigest: `codex-security-snapshot/v1:sha256:${"b".repeat(64)}`,
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
      "Use the $security-scan skill at plugin/skills/security-scan/SKILL.md.",
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
          await completedScan(value.scanDir, value.repositoryIdentity);
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

  test("uses a credential-free remote identity across equivalent Git checkouts", async () => {
    const root = await temporaryDirectory();
    const workspace = join(root, "workspaces");
    const identities: string[] = [];
    for (const [name, remote] of [
      [
        "checkout-a",
        "https://user:SYNTHETIC_REMOTE_TOKEN@example.invalid/org/shared.git?token=first#fragment",
      ],
      [
        "checkout-b",
        "https://other:SYNTHETIC_OTHER_TOKEN@example.invalid/org/shared?token=second",
      ],
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
    expect(identities[0]).toMatch(
      /^codex-security-target\/v1:sha256:[0-9a-f]{64}$/u,
    );
    expect(await readdir(workspace)).toEqual([]);
  });

  test("stages nested Git source and explicit ignored paths without Git metadata or ignored secrets", async () => {
    const root = await temporaryDirectory();
    const child = join(root, "child");
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await initializeGitRepository(child);
    await writeFile(join(child, "sub.ts"), "export const sub = true;\n");
    await writeFile(join(child, ".gitignore"), ".env\nignored/\n");
    git(child, ["add", "."]);
    git(child, ["commit", "--quiet", "-m", "child"]);
    await initializeGitRepository(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    await writeFile(join(repository, ".gitignore"), "vendor-private/\n");
    git(repository, ["add", "."]);
    git(repository, ["commit", "--quiet", "-m", "parent"]);
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
    await writeFile(
      join(repository, "vendor", "service", "local.ts"),
      "export const local = true;\n",
    );
    await writeFile(
      join(repository, "vendor", "service", ".env"),
      "SYNTHETIC_SUBMODULE_SECRET=ignored\n",
    );
    await mkdir(join(repository, "vendor", "service", "ignored"));
    await writeFile(
      join(repository, "vendor", "service", "ignored", "secret.ts"),
      "SYNTHETIC_IGNORED_SECRET\n",
    );

    const nested = join(repository, "services", "nested");
    await initializeGitRepository(nested);
    await writeFile(join(nested, "source.ts"), "export const nested = true;\n");
    await writeFile(join(nested, ".gitignore"), ".env\n");
    git(nested, ["add", "."]);
    git(nested, ["commit", "--quiet", "-m", "nested"]);
    await writeFile(join(nested, "local.ts"), "export const local = true;\n");
    await writeFile(join(nested, ".env"), "SYNTHETIC_NESTED_SECRET=ignored\n");
    git(nested, [
      "config",
      "remote.origin.url",
      "https://SYNTHETIC_NESTED_TOKEN@example.invalid/private.git",
    ]);

    const explicit = join(repository, "vendor-private");
    await initializeGitRepository(explicit);
    await writeFile(
      join(explicit, "explicit.ts"),
      "export const explicit = true;\n",
    );
    git(explicit, ["add", "."]);
    git(explicit, ["commit", "--quiet", "-m", "explicit"]);
    git(explicit, [
      "config",
      "remote.origin.url",
      "https://SYNTHETIC_EXPLICIT_TOKEN@example.invalid/private.git",
    ]);
    const bare = join(repository, "cache", "private-mirror");
    await mkdir(join(repository, "cache"));
    git(repository, ["clone", "--quiet", "--bare", child, bare]);
    git(repository, [
      `--git-dir=${bare}`,
      "config",
      "remote.origin.url",
      "https://SYNTHETIC_BARE_TOKEN@example.invalid/private.git",
    ]);

    const run = async (target?: string[]): Promise<void> => {
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
            expect(
              existsSync(join(value.repository, "cache", "private-mirror")),
            ).toBe(false);
            if (target === undefined) {
              expect(
                existsSync(
                  join(value.repository, "vendor", "service", "sub.ts"),
                ),
              ).toBe(true);
              expect(
                existsSync(
                  join(value.repository, "vendor", "service", "local.ts"),
                ),
              ).toBe(true);
              expect(
                existsSync(join(value.repository, "vendor", "service", ".env")),
              ).toBe(false);
              expect(
                existsSync(
                  join(
                    value.repository,
                    "vendor",
                    "service",
                    "ignored",
                    "secret.ts",
                  ),
                ),
              ).toBe(false);
              expect(
                existsSync(
                  join(value.repository, "services", "nested", "source.ts"),
                ),
              ).toBe(true);
              expect(
                existsSync(
                  join(value.repository, "services", "nested", "local.ts"),
                ),
              ).toBe(true);
              expect(
                existsSync(
                  join(value.repository, "services", "nested", ".env"),
                ),
              ).toBe(false);
              expect(existsSync(join(value.repository, "vendor-private"))).toBe(
                false,
              );
            } else {
              expect(
                existsSync(
                  join(value.repository, "vendor-private", "explicit.ts"),
                ),
              ).toBe(true);
              expect(
                existsSync(join(value.repository, "vendor-private", ".git")),
              ).toBe(false);
            }
            throw new Error("stop after staging inspection");
          },
        },
      );
      try {
        await expect(
          client.run(repository, {
            outputDir: join(
              root,
              target === undefined ? "scan-all" : "scan-path",
            ),
            ...(target === undefined ? {} : { target }),
          }),
        ).rejects.toThrow("stop after staging inspection");
        expect(reached).toBe(true);
        expect(await readdir(workspace)).toEqual([]);
      } finally {
        await client.close();
      }
    };
    await run();
    await run(["vendor-private"]);

    const nestedExclude = join(root, "nested-exclude");
    await writeFile(nestedExclude, "hidden.ts\n");
    await writeFile(join(nested, "hidden.ts"), "SYNTHETIC_HIDDEN_SOURCE\n");
    await rm(join(nested, ".git", "info", "exclude"), { force: true });
    await symlink(nestedExclude, join(nested, ".git", "info", "exclude"));
    const nestedClient = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspace,
        },
        runAgents: async () => {
          throw new Error("must-not-run");
        },
      },
    );
    try {
      await expect(
        nestedClient.run(repository, {
          outputDir: join(root, "scan-nested-unsafe"),
        }),
      ).rejects.toThrow("Git input must be a regular file before staging");
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await nestedClient.close();
    }

    let reached = false;
    const bareClient = new TestClient(
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
        bareClient.run(bare, { outputDir: join(root, "scan-bare") }),
      ).rejects.toThrow("Bare Git repositories cannot be staged safely");
      expect(reached).toBe(false);
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await bareClient.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "sanitizes ambient Git state and fails closed on non-regular ignore inputs",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspace = join(root, "workspaces");
      const configuredExclude = join(root, "configured-exclude");
      const globalExclude = join(root, "global-exclude");
      const systemExclude = join(root, "system-exclude");
      const globalConfig = join(root, "global-config");
      const systemConfig = join(root, "system-config");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      await writeFile(join(repository, ".gitignore"), "private/\n");
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "parent"]);
      await mkdir(join(repository, "private"));
      await writeFile(
        join(repository, "private", "credentials.json"),
        "SYNTHETIC_PRIVATE_SECRET\n",
      );
      await writeFile(configuredExclude, "configured.env\n");
      git(repository, ["config", "core.excludesFile", configuredExclude]);
      await mkdir(join(repository, ".git", "info"), { recursive: true });
      await writeFile(
        join(repository, ".git", "info", "exclude"),
        "info.env\n",
      );
      await writeFile(
        join(repository, "configured.env"),
        "SYNTHETIC_CONFIGURED\n",
      );
      await writeFile(join(repository, "info.env"), "SYNTHETIC_INFO\n");
      await writeFile(globalExclude, "global.env\n");
      await writeFile(systemExclude, "system.env\n");
      await writeFile(
        globalConfig,
        `[core]\n  excludesFile = ${globalExclude}\n`,
      );
      await writeFile(
        systemConfig,
        `[core]\n  excludesFile = ${systemExclude}\n`,
      );
      await writeFile(join(repository, "global.env"), "SYNTHETIC_GLOBAL\n");
      await writeFile(join(repository, "system.env"), "SYNTHETIC_SYSTEM\n");
      const repositoryBin = join(repository, "node_modules", ".bin");
      const hostGitLog = join(root, "host-git-log");
      await mkdir(repositoryBin, { recursive: true });
      await writeFile(
        join(repositoryBin, "git"),
        `#!/bin/sh\nprintf '%s\\n' UNTRUSTED_GIT >> '${hostGitLog}'\nexit 42\n`,
        { mode: 0o755 },
      );
      await writeFile(
        join(repository, ".gitignore"),
        "private/\nnode_modules/\n",
      );
      const alternateIndex = join(root, "alternate.index");
      git(repository, ["add", "-f", "private/credentials.json"], {
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
            expect(
              existsSync(join(value.repository, "private", "credentials.json")),
            ).toBe(false);
            expect(existsSync(join(value.repository, "configured.env"))).toBe(
              false,
            );
            expect(existsSync(join(value.repository, "info.env"))).toBe(false);
            expect(existsSync(join(value.repository, "global.env"))).toBe(
              false,
            );
            expect(existsSync(join(value.repository, "system.env"))).toBe(
              false,
            );
            throw new Error("stop after staging inspection");
          },
        },
      );
      const previousDir = process.env["GIT_DIR"];
      const previousIndex = process.env["GIT_INDEX_FILE"];
      const previousGlobal = process.env["GIT_CONFIG_GLOBAL"];
      const previousSystem = process.env["GIT_CONFIG_SYSTEM"];
      const previousNoSystem = process.env["GIT_CONFIG_NOSYSTEM"];
      const previousPath = process.env["PATH"];
      process.env["GIT_DIR"] = "/dev/null";
      process.env["GIT_INDEX_FILE"] = alternateIndex;
      process.env["GIT_CONFIG_GLOBAL"] = globalConfig;
      process.env["GIT_CONFIG_SYSTEM"] = systemConfig;
      process.env["GIT_CONFIG_NOSYSTEM"] = "0";
      process.env["PATH"] = `${repositoryBin}:${previousPath ?? ""}`;
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "regular-scan") }),
        ).rejects.toThrow("stop after staging inspection");
      } finally {
        if (previousDir === undefined) delete process.env["GIT_DIR"];
        else process.env["GIT_DIR"] = previousDir;
        if (previousIndex === undefined) delete process.env["GIT_INDEX_FILE"];
        else process.env["GIT_INDEX_FILE"] = previousIndex;
        if (previousGlobal === undefined)
          delete process.env["GIT_CONFIG_GLOBAL"];
        else process.env["GIT_CONFIG_GLOBAL"] = previousGlobal;
        if (previousSystem === undefined)
          delete process.env["GIT_CONFIG_SYSTEM"];
        else process.env["GIT_CONFIG_SYSTEM"] = previousSystem;
        if (previousNoSystem === undefined)
          delete process.env["GIT_CONFIG_NOSYSTEM"];
        else process.env["GIT_CONFIG_NOSYSTEM"] = previousNoSystem;
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
      await rm(join(repository, ".gitignore"));
      execFileSync("mkfifo", [join(repository, ".gitignore")]);
      await expectUnsafe("root-fifo-scan");
      await rm(join(repository, ".gitignore"));
      await writeFile(join(repository, ".gitignore"), "private/\n");
      await mkdir(join(repository, "nested"));
      execFileSync("mkfifo", [join(repository, "nested", ".gitignore")]);
      await expectUnsafe("nested-fifo-scan");
      await rm(join(repository, "nested", ".gitignore"));
      await rm(join(repository, ".gitignore"));
      await symlink(configuredExclude, join(repository, ".gitignore"));
      await expectUnsafe("symlink-scan");
      await rm(join(repository, ".gitignore"));
      await writeFile(join(repository, ".gitignore"), "private/\n");
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
      execFileSync("mkfifo", [includedConfig]);
      const gitConfig = join(repository, ".git", "config");
      await writeFile(
        gitConfig,
        `${await readFile(gitConfig, "utf8")}\n[include]\n  path = ${JSON.stringify(includedConfig)}\n`,
      );
      await expect(
        client.run(repository, { outputDir: join(root, "include-fifo-scan") }),
      ).rejects.toThrow(
        "Git configuration input must be a bounded regular file",
      );
      expect(await readdir(workspace)).toEqual([]);
      await client.close();
    },
  );

  test("stages tracked and explicitly selected ignored files in a directory once", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspace = join(root, "workspaces");
    await initializeGitRepository(repository);
    await mkdir(join(repository, "src"));
    await mkdir(join(repository, "fixtures", "not-a-repository.git"), {
      recursive: true,
    });
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
            true,
          );
          expect(
            existsSync(join(value.repository, "ordinary-source.git")),
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
      expect(await readdir(workspace)).toEqual([]);
    } finally {
      await client.close();
    }
  });

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
      git(repository, ["add", "."]);
      git(repository, ["commit", "--quiet", "-m", "initial"]);
      git(repository, [
        "config",
        "remote.origin.url",
        "https://SYNTHETIC_GIT_TOKEN@example.invalid/private.git",
      ]);
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
        for (const [index, target] of [".git", ".git/config"].entries()) {
          await expect(
            client.run(repository, {
              target: [target],
              outputDir: join(root, `metadata-scan-${index}`),
            }),
          ).rejects.toThrow("must not select Git metadata");
        }
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
    "excludes plugin-checkout secrets and symlinked source parents, and rejects retargeted roots",
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
      await rm(join(repository, "src"), { recursive: true, force: true });
      await symlink(outside, join(repository, "src"), "dir");
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
              false,
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
          execFileSync("truncate", [
            "-s",
            String(64 * 1024 * 1024 + 1),
            join(value.scanDir, "scan-manifest.json"),
          ]);
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
    "uses the SDK Docker runner, loads the scan skill, delegates a worker, and disconnects the network",
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
          `case "\${1-}" in run) printf "%s\\n" synthetic-container;; inspect) if grep -q "<disconnect>" '${log}'; then printf "%s\\n" '{}'; else printf "%s\\n" '{"bridge":{}}'; fi;; esac`,
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
                ? [call("load_skill", { skill_name: "security-scan" })]
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
            item.tools.some((tool) => tool.name === "load_skill"),
          ),
        ).toBe(true);
        expect(JSON.stringify(requests)).toContain("## Phase Sequence");
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
