import { execFileSync } from "node:child_process";
import { existsSync, symlinkSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  Usage,
  type Model,
  type ModelProvider,
  type ModelRequest,
  type ModelResponse,
  type StreamEvent,
} from "@openai/agents";
import {
  AgentsSecurity,
  IncompleteScanError,
  InvalidTargetError,
  ScanInterruptedError,
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
const gitEnvironment = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TEMPLATE_DIR: "/dev/null",
  GIT_TERMINAL_PROMPT: "0",
};

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-agents-hardening-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function git(args: string[], cwd?: string): string {
  return execFileSync(
    "git",
    ["-c", "core.hooksPath=/dev/null", ...(cwd ? ["-C", cwd] : []), ...args],
    {
      encoding: "utf8",
      env: gitEnvironment,
      stdio: ["ignore", "pipe", "pipe"],
    },
  ).trim();
}

async function initializeGitRepository(repository: string): Promise<void> {
  await mkdir(repository, { recursive: true });
  git(["init", "--quiet", repository]);
  git(["config", "user.email", "test@example.invalid"], repository);
  git(["config", "user.name", "test"], repository);
}

function dockerClient(
  workspaceRoot: string,
  runAgents: (request: AgentsScanRequest) => Promise<never>,
  dependencies: Record<string, unknown> = {},
): AgentsSecurity {
  return new TestClient(
    { pluginPath: PLUGIN_ROOT, sandbox: "docker" },
    {
      environment: {
        OPENAI_API_KEY: "synthetic-agents-key",
        CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspaceRoot,
      },
      runAgents,
      ...dependencies,
    },
  );
}

describe("Agents SDK scan hardening regressions", () => {
  test("keeps ordinary tracked source with bare-Git-like marker names", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const fixture = join(repository, "fixtures", "gitlike");
    const workspaceRoot = join(root, "workspaces");
    await initializeGitRepository(repository);
    await mkdir(join(fixture, "objects"), { recursive: true });
    await mkdir(join(fixture, "refs"));
    await writeFile(join(fixture, "HEAD"), "ordinary fixture data\n");
    await writeFile(join(fixture, "config"), "[core]\n  bare = false\n");
    await writeFile(
      join(fixture, "objects", "vulnerable.ts"),
      "export const vulnerable = true;\n",
    );
    await writeFile(join(fixture, "refs", "keep"), "fixture\n");
    git(["add", "."], repository);
    git(["commit", "--quiet", "-m", "fixture"], repository);
    let reached = false;
    const client = dockerClient(workspaceRoot, async (request) => {
      reached = true;
      expect(
        await readFile(
          join(
            request.repository,
            "fixtures",
            "gitlike",
            "objects",
            "vulnerable.ts",
          ),
          "utf8",
        ),
      ).toBe("export const vulnerable = true;\n");
      throw new Error("staging-inspected");
    });
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("staging-inspected");
      expect(reached).toBe(true);
      expect(await readdir(workspaceRoot)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects a nested repository whose Git marker is a host symlink",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const external = join(root, "external");
      const nested = join(repository, "services", "nested");
      const workspaceRoot = join(root, "workspaces");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      git(["add", "."], repository);
      git(["commit", "--quiet", "-m", "parent"], repository);
      await initializeGitRepository(external);
      await writeFile(join(external, "external.ts"), "external\n");
      git(["add", "."], external);
      git(["commit", "--quiet", "-m", "external"], external);
      await mkdir(nested, { recursive: true });
      await writeFile(
        join(nested, "source.ts"),
        "export const nested = true;\n",
      );
      symlinkSync(join(external, ".git"), join(nested, ".git"), "dir");
      let reached = false;
      const client = dockerClient(workspaceRoot, async () => {
        reached = true;
        throw new Error("sandbox-must-not-start");
      });
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "scan") }),
        ).rejects.toBeInstanceOf(InvalidTargetError);
        expect(reached).toBe(false);
        expect(await readdir(workspaceRoot)).toEqual([]);
      } finally {
        await client.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "honors regular recursive Git config includes and rejects an included FIFO before Git runs",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspaceRoot = join(root, "workspaces");
      const firstInclude = join(root, "first#included.conf");
      const secondInclude = join(root, "second.conf");
      const exclude = join(root, "exclude");
      const fifo = join(root, "included-config.fifo");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      git(["add", "."], repository);
      git(["commit", "--quiet", "-m", "initial"], repository);
      await writeFile(
        join(repository, "private.env"),
        "PRIVATE=must-not-stage\n",
      );
      await writeFile(exclude, "private.env\n");
      await writeFile(secondInclude, `[core]\n  excludesFile = ${exclude}\n`);
      await writeFile(
        firstInclude,
        `[includeIf \"gitdir:**\"]\n  path = ${secondInclude}\n`,
      );
      const config = join(repository, ".git", "config");
      const originalConfig = await readFile(config, "utf8");
      await writeFile(
        config,
        `${originalConfig}\n[include]\n  path = \"${firstInclude}\"\n`,
      );
      let reached = false;
      const client = dockerClient(workspaceRoot, async (request) => {
        reached = true;
        expect(existsSync(join(request.repository, "private.env"))).toBe(false);
        throw new Error("regular-include-inspected");
      });
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "regular-scan") }),
        ).rejects.toThrow("regular-include-inspected");
        expect(reached).toBe(true);
        execFileSync("mkfifo", [fifo]);
        await writeFile(secondInclude, `[include]\n  path = ${fifo}\n`);
        const started = performance.now();
        await expect(
          client.run(repository, { outputDir: join(root, "fifo-scan") }),
        ).rejects.toThrow(
          "Git configuration include must be a regular file before staging",
        );
        expect(performance.now() - started).toBeLessThan(4000);
        expect(await readdir(workspaceRoot)).toEqual([]);
      } finally {
        await client.close();
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "never invokes a hostile promisor transport or passes ambient API credentials to host Git",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspaceRoot = join(root, "workspaces");
      const marker = join(root, "host-command-ran");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      const head = (await readFile(join(repository, ".git", "HEAD"), "utf8"))
        .trim()
        .replace(/^ref:\s*/u, "");
      const ref = join(repository, ".git", head);
      await mkdir(join(ref, ".."), { recursive: true });
      await writeFile(ref, `${"0".repeat(39)}1\n`);
      const config = join(repository, ".git", "config");
      await writeFile(
        config,
        `${await readFile(config, "utf8")}\n[extensions]\n  partialClone = origin\n[remote \"origin\"]\n  url = ssh://invalid.example.invalid/repository\n  promisor = true\n  partialclonefilter = blob:none\n[core]\n  sshCommand = sh -c 'printf %s \"$OPENAI_API_KEY\" > ${marker}; exit 1' --\n`,
      );
      const previousKey = process.env["OPENAI_API_KEY"];
      process.env["OPENAI_API_KEY"] =
        "SYNTHETIC_HOST_GIT_KEY_DO_NOT_STAGE_000000";
      let reached = false;
      const client = dockerClient(workspaceRoot, async (request) => {
        reached = true;
        expect(request.repositoryRevision).toBeNull();
        expect(await readFile(join(request.repository, "app.ts"), "utf8")).toBe(
          "export const app = true;\n",
        );
        expect(existsSync(marker)).toBe(false);
        throw new Error("host-git-inspected");
      });
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "scan") }),
        ).rejects.toThrow("host-git-inspected");
        expect(reached).toBe(true);
        expect(existsSync(marker)).toBe(false);
      } finally {
        if (previousKey === undefined) delete process.env["OPENAI_API_KEY"];
        else process.env["OPENAI_API_KEY"] = previousKey;
        await client.close();
      }
    },
  );

  test("falls back to an available directory snapshot for a scoped sparse partial clone", async () => {
    const root = await temporaryDirectory();
    const seed = join(root, "seed");
    const origin = join(root, "origin.git");
    const repository = join(root, "partial");
    const workspaceRoot = join(root, "workspaces");
    await initializeGitRepository(seed);
    await mkdir(join(seed, "keep"));
    await mkdir(join(seed, "omitted"));
    await writeFile(
      join(seed, "keep", "selected.ts"),
      "export const selected = true;\n",
    );
    await writeFile(
      join(seed, "omitted", "unmaterialized.ts"),
      `export const omitted = \"${"x".repeat(300_000)}\";\n`,
    );
    git(["add", "."], seed);
    git(["commit", "--quiet", "-m", "initial"], seed);
    git(["clone", "--bare", "--quiet", seed, origin]);
    git([`--git-dir=${origin}`, "config", "uploadpack.allowFilter", "true"]);
    git([
      `--git-dir=${origin}`,
      "config",
      "uploadpack.allowAnySHA1InWant",
      "true",
    ]);
    git([
      "-c",
      "protocol.file.allow=always",
      "clone",
      "--quiet",
      "--filter=blob:none",
      "--no-checkout",
      `file://${origin}`,
      repository,
    ]);
    git(["sparse-checkout", "init", "--cone"], repository);
    git(["sparse-checkout", "set", "keep"], repository);
    git(["checkout", "--quiet", "HEAD"], repository);
    expect(existsSync(join(repository, "keep", "selected.ts"))).toBe(true);
    expect(existsSync(join(repository, "omitted", "unmaterialized.ts"))).toBe(
      false,
    );
    let reached = false;
    const client = dockerClient(workspaceRoot, async (request) => {
      reached = true;
      expect(request.repositoryRevision).toBeNull();
      expect(existsSync(join(request.repository, ".git"))).toBe(false);
      expect(
        await readFile(join(request.repository, "keep", "selected.ts"), "utf8"),
      ).toBe("export const selected = true;\n");
      expect(
        existsSync(join(request.repository, "omitted", "unmaterialized.ts")),
      ).toBe(false);
      expect(agentsScanPrompt(request)).toContain(
        "Repository identity: unversioned directory snapshot.",
      );
      throw new Error("partial-clone-inspected");
    });
    try {
      await expect(
        client.run(repository, {
          target: ["keep/selected.ts"],
          outputDir: join(root, "scan"),
        }),
      ).rejects.toThrow("partial-clone-inspected");
      expect(reached).toBe(true);
      expect(await readdir(workspaceRoot)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("does not mistake a disabled promisor remote for a partial clone", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspaceRoot = join(root, "workspaces");
    await initializeGitRepository(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    git(["add", "."], repository);
    git(["commit", "--quiet", "-m", "initial"], repository);
    git(
      ["config", "remote.origin.url", "https://example.invalid/repository"],
      repository,
    );
    git(["config", "remote.origin.promisor", "false"], repository);
    const revision = git(["rev-parse", "HEAD"], repository);
    let reached = false;
    const client = dockerClient(workspaceRoot, async (request) => {
      reached = true;
      expect(request.repositoryRevision).toBe(revision);
      expect(existsSync(join(request.repository, ".git"))).toBe(true);
      throw new Error("promisor-disabled-inspected");
    });
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("promisor-disabled-inspected");
      expect(reached).toBe(true);
    } finally {
      await client.close();
    }
  });

  test("preserves the selected Git revision for an independent nested repository root", async () => {
    const root = await temporaryDirectory();
    const outer = join(root, "outer");
    const inner = join(outer, "vendor", "service");
    const workspaceRoot = join(root, "workspaces");
    await initializeGitRepository(outer);
    await writeFile(join(outer, "outer.ts"), "export const outer = true;\n");
    git(["add", "."], outer);
    git(["commit", "--quiet", "-m", "outer"], outer);
    await initializeGitRepository(inner);
    await writeFile(join(inner, "inner.ts"), "export const inner = true;\n");
    git(["add", "."], inner);
    git(["commit", "--quiet", "-m", "inner"], inner);
    const revision = git(["rev-parse", "HEAD"], inner);
    let reached = false;
    const client = dockerClient(workspaceRoot, async (request) => {
      reached = true;
      expect(request.repositoryRevision).toBe(revision);
      expect(existsSync(join(request.repository, ".git"))).toBe(true);
      expect(agentsScanPrompt(request)).toContain(
        `Repository revision: ${revision}`,
      );
      throw new Error("nested-revision-inspected");
    });
    try {
      await expect(
        client.run(inner, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("nested-revision-inspected");
      expect(reached).toBe(true);
    } finally {
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "stages decomposed Unicode and case-renamed tracked paths from a case-insensitive Git worktree",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const source = join(repository, "src");
      const workspaceRoot = join(root, "workspaces");
      const decomposed = "cafe\u0301-NFD.ts";
      const composed = "caf\u00e9-NFC.ts";
      await initializeGitRepository(repository);
      await mkdir(source);
      await writeFile(join(source, decomposed), "export const nfd = true;\n");
      await writeFile(join(source, composed), "export const nfc = true;\n");
      await writeFile(join(source, "App.ts"), "export const app = true;\n");
      git(["config", "core.precomposeUnicode", "true"], repository);
      git(["config", "core.ignorecase", "true"], repository);
      git(["add", "."], repository);
      git(["commit", "--quiet", "-m", "initial"], repository);
      await rename(join(source, "App.ts"), join(source, "case-tmp.ts"));
      await rename(join(source, "case-tmp.ts"), join(source, "app.ts"));
      const listed = git(["ls-files", "-z"], repository);
      expect(listed).toContain("src/App.ts");
      expect(listed).toContain(`src/${decomposed.normalize("NFC")}`);
      let reached = false;
      const client = dockerClient(workspaceRoot, async (request) => {
        reached = true;
        const names = (await readdir(join(request.repository, "src")))
          .map((name) => name.normalize("NFC").toLowerCase())
          .sort();
        expect(names).toEqual(
          [
            "app.ts",
            decomposed.normalize("NFC").toLowerCase(),
            composed.toLowerCase(),
          ].sort(),
        );
        expect(
          await readFile(join(request.repository, "src", "app.ts"), "utf8"),
        ).toBe("export const app = true;\n");
        throw new Error("normalized-paths-inspected");
      });
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "scan") }),
        ).rejects.toThrow("normalized-paths-inspected");
        expect(reached).toBe(true);
      } finally {
        await client.close();
      }
    },
  );

  test("supplies a stable immutable target identity across scans and distinct repositories", async () => {
    const root = await temporaryDirectory();
    const first = join(root, "first");
    const second = join(root, "second");
    const workspaceRoot = join(root, "workspaces");
    await mkdir(first);
    await mkdir(second);
    await writeFile(join(first, "app.ts"), "export const app = true;\n");
    await writeFile(join(second, "app.ts"), "export const app = true;\n");
    const identities: string[] = [];
    const client = dockerClient(workspaceRoot, async (request) => {
      const value = request.repositoryIdentity!;
      expect(value).toMatch(/^codex-security-target\/v1:sha256:[0-9a-f]{64}$/u);
      const staged = JSON.parse(
        await readFile(
          join(request.sandboxInputRoot!, "repository-identity.json"),
          "utf8",
        ),
      ) as { targetId: string };
      expect(staged.targetId).toBe(value);
      expect(agentsScanPrompt(request)).toContain(
        `Repository targetId: ${value}.`,
      );
      identities.push(value);
      throw new Error("identity-inspected");
    });
    try {
      for (const [repository, name] of [
        [first, "first-scan"],
        [first, "first-repeat"],
        [second, "second-scan"],
      ] as const) {
        await expect(
          client.run(repository, { outputDir: join(root, name) }),
        ).rejects.toThrow("identity-inspected");
      }
      expect(identities[0]).toBe(identities[1]);
      expect(identities[2]).not.toBe(identities[0]);
    } finally {
      await client.close();
    }
  });

  test("omits inherited reflog and committer metadata from a staged Git snapshot", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspaceRoot = join(root, "workspaces");
    await initializeGitRepository(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    git(["add", "."], repository);
    git(["commit", "--quiet", "-m", "initial"], repository);
    const priorAction = process.env["GIT_REFLOG_ACTION"];
    const priorName = process.env["GIT_COMMITTER_NAME"];
    const priorEmail = process.env["GIT_COMMITTER_EMAIL"];
    process.env["GIT_REFLOG_ACTION"] = "SYNTHETIC_PRIVATE_REFLOG_ACTION";
    process.env["GIT_COMMITTER_NAME"] = "Synthetic Private Name";
    process.env["GIT_COMMITTER_EMAIL"] = "synthetic-private@example.invalid";
    let reached = false;
    const client = dockerClient(workspaceRoot, async (request) => {
      reached = true;
      expect(existsSync(join(request.repository, ".git", "logs"))).toBe(false);
      const config = await readFile(
        join(request.repository, ".git", "config"),
        "utf8",
      );
      expect(config).not.toContain("SYNTHETIC_PRIVATE_REFLOG_ACTION");
      expect(config).not.toContain("Synthetic Private Name");
      expect(config).not.toContain("synthetic-private@example.invalid");
      throw new Error("reflog-inspected");
    });
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("reflog-inspected");
      expect(reached).toBe(true);
    } finally {
      if (priorAction === undefined) delete process.env["GIT_REFLOG_ACTION"];
      else process.env["GIT_REFLOG_ACTION"] = priorAction;
      if (priorName === undefined) delete process.env["GIT_COMMITTER_NAME"];
      else process.env["GIT_COMMITTER_NAME"] = priorName;
      if (priorEmail === undefined) delete process.env["GIT_COMMITTER_EMAIL"];
      else process.env["GIT_COMMITTER_EMAIL"] = priorEmail;
      await client.close();
    }
  });

  test.skipIf(process.platform === "win32")(
    "uses repository-scoped safe.directory overrides for differently owned worktrees",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const workspaceRoot = join(root, "workspaces");
      const bin = join(root, "bin");
      await initializeGitRepository(repository);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      git(["add", "."], repository);
      git(["commit", "--quiet", "-m", "initial"], repository);
      const revision = git(["rev-parse", "HEAD"], repository);
      const actualGit = execFileSync("which", ["git"], {
        encoding: "utf8",
        env: gitEnvironment,
      }).trim();
      await mkdir(bin);
      const wrapper = join(bin, "git");
      await writeFile(
        wrapper,
        `#!/bin/sh\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1\nexport GIT_TEST_ASSUME_DIFFERENT_OWNER\nexec '${actualGit}' \"$@\"\n`,
      );
      await chmod(wrapper, 0o755);
      const priorPath = process.env["PATH"];
      process.env["PATH"] = `${bin}:${priorPath ?? "/usr/bin:/bin"}`;
      let reached = false;
      const client = dockerClient(workspaceRoot, async (request) => {
        reached = true;
        expect(request.repositoryRevision).toBe(revision);
        expect(existsSync(join(request.repository, ".git"))).toBe(true);
        throw new Error("safe-directory-inspected");
      });
      try {
        await expect(
          client.run(repository, { outputDir: join(root, "scan") }),
        ).rejects.toThrow("safe-directory-inspected");
        expect(reached).toBe(true);
      } finally {
        if (priorPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = priorPath;
        await client.close();
      }
    },
  );

  test("rejects an oversized regular input before copying it into staging", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspaceRoot = join(root, "workspaces");
    const large = join(repository, "large-artifact.bin");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const app = true;\n");
    await writeFile(large, "");
    await truncate(large, 256 * 1024 * 1024 + 1);
    let reached = false;
    const client = dockerClient(workspaceRoot, async () => {
      reached = true;
      throw new Error("sandbox-must-not-start");
    });
    try {
      await expect(
        client.run(repository, { outputDir: join(root, "scan") }),
      ).rejects.toThrow("Repository input file is too large to stage safely");
      expect(reached).toBe(false);
      expect(await readdir(workspaceRoot)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("rebounds cancellation during staging to the retained output directory", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspaceRoot = join(root, "workspaces");
    const scanDir = join(root, "scan");
    await mkdir(join(repository, "source"), { recursive: true });
    await Promise.all(
      Array.from({ length: 3_000 }, (_, index) =>
        writeFile(
          join(repository, "source", `${index}.ts`),
          `export const value = ${index};\n`,
        ),
      ),
    );
    const controller = new AbortController();
    let revisionReads = 0;
    let reached = false;
    const client = dockerClient(
      workspaceRoot,
      async () => {
        reached = true;
        throw new Error("sandbox-must-not-start");
      },
      {
        repositoryRevision: async () => {
          revisionReads += 1;
          if (revisionReads === 1) setTimeout(() => controller.abort(), 0);
          return "deadbeef";
        },
      },
    );
    try {
      const started = performance.now();
      await expect(
        client.run(repository, {
          outputDir: scanDir,
          signal: controller.signal,
        }),
      ).rejects.toMatchObject({ name: ScanInterruptedError.name, scanDir });
      expect(performance.now() - started).toBeLessThan(10_000);
      expect(reached).toBe(false);
      expect(await readdir(workspaceRoot)).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("strips source-bearing Agents run state from an exhausted scan failure", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const work = join(root, "work");
    const sourceToken = "SYNTHETIC_SOURCE_SECRET_9d714";
    await mkdir(repository);
    await mkdir(scanDir);
    await mkdir(work);
    await writeFile(
      join(repository, "private.ts"),
      `const PRIVATE_SOURCE_TOKEN = \"${sourceToken}\";\n`,
    );
    let turn = 0;
    const model: Model = {
      async getResponse(_request: ModelRequest): Promise<ModelResponse> {
        return { usage: new Usage(), output: [] };
      },
      async *getStreamedResponse(
        _request: ModelRequest,
      ): AsyncIterable<StreamEvent> {
        turn += 1;
        yield { type: "response_started" };
        yield {
          type: "response_done",
          response: {
            id: `resp_${turn}`,
            usage: {
              requests: 1,
              inputTokens: 1,
              outputTokens: 1,
              totalTokens: 2,
            },
            output: [
              {
                id: `fc_${turn}`,
                type: "function_call",
                callId: `call_${turn}`,
                name: "exec_command",
                status: "completed",
                arguments: JSON.stringify({
                  cmd: "cat repository/private.ts",
                  workdir: "/workspace",
                  login: false,
                  tty: false,
                  yield_time_ms: 10_000,
                }),
              },
            ],
          },
        };
      },
    };
    const provider: ModelProvider = { getModel: () => model };
    let failure: unknown;
    try {
      await runAgentsScan(
        {
          repository,
          target: { kind: "repository", paths: [] },
          scanDir,
          pluginRoot: PLUGIN_ROOT,
          python: "python3",
          sandbox: "unsafe-local",
          sandboxBaseDir: work,
          repositoryRevision: null,
          apiKey: "synthetic-api-key",
          model: "gpt-test",
          reasoningEffort: "low",
          maxTurns: 2,
          workerMaxTurns: 1,
          signal: new AbortController().signal,
        },
        { modelProvider: provider },
      );
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(IncompleteScanError);
    expect((failure as { state?: unknown }).state).toBeUndefined();
    expect(JSON.stringify(failure)).not.toContain(sourceToken);
    expect(String((failure as Error).message)).toContain(
      "MaxTurnsExceededError",
    );
  });

  test.skipIf(process.platform === "win32")(
    "returns promptly when Docker startup is canceled and cleans the late creation failure",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const work = join(root, "work");
      const bin = join(root, "bin");
      await mkdir(repository);
      await mkdir(scanDir);
      await mkdir(work);
      await mkdir(bin);
      await writeFile(join(repository, "app.ts"), "export const app = true;\n");
      const fakeDocker = join(bin, "docker");
      await writeFile(
        fakeDocker,
        "#!/bin/sh\nsleep 1\nprintf '%s\\n' 'simulated slow Docker daemon' >&2\nexit 1\n",
      );
      await chmod(fakeDocker, 0o755);
      const priorPath = process.env["PATH"];
      process.env["PATH"] = `${bin}:${priorPath ?? "/usr/bin:/bin"}`;
      const controller = new AbortController();
      const started = performance.now();
      const timer = setTimeout(() => controller.abort(), 50);
      try {
        await expect(
          runAgentsScan({
            repository,
            target: { kind: "repository", paths: [] },
            scanDir,
            pluginRoot: PLUGIN_ROOT,
            python: "python3",
            sandbox: "docker",
            sandboxBaseDir: work,
            repositoryRevision: null,
            apiKey: "synthetic-api-key",
            model: "gpt-test",
            reasoningEffort: "low",
            maxTurns: 2,
            workerMaxTurns: 1,
            signal: controller.signal,
          }),
        ).rejects.toMatchObject({ name: ScanInterruptedError.name, scanDir });
        expect(performance.now() - started).toBeLessThan(750);
        await new Promise((resolve) => setTimeout(resolve, 1200));
        expect(await readdir(work)).toEqual([]);
      } finally {
        clearTimeout(timer);
        if (priorPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = priorPath;
      }
    },
  );
});
