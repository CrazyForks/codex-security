import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
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
import createDebug from "debug";
import { localDir } from "@openai/agents/sandbox";
import {
  UnixLocalSandboxClient,
  localDirLazySkillSource,
} from "@openai/agents/sandbox/local";
import {
  AgentsSecurity,
  AuthenticationRequiredError,
  DiffTarget,
  IncompleteScanError,
  InvalidTargetError,
  OutputDirectoryError,
  ScanInterruptedError,
  agentsManifest,
  agentsScanPrompt,
  copySandboxOutput,
  runAgentsScan,
  type AgentsScanRequest,
} from "../src/index.js";
import { suppressReferencedSandboxTimeouts } from "../src/agents.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const EXAMPLE = join(PLUGIN_ROOT, "examples", "completed-scan");
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
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-agents-test-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function request(
  repository: string,
  overrides: Partial<AgentsScanRequest> = {},
): AgentsScanRequest {
  return {
    repository,
    target: { kind: "repository", paths: [] },
    scanDir: join(repository, "..", "scan"),
    pluginRoot: PLUGIN_ROOT,
    python: process.execPath,
    sandbox: "unsafe-local",
    sandboxBaseDir: join(repository, ".."),
    repositoryRevision: "deadbeef",
    apiKey: "synthetic-agents-key",
    model: "gpt-test",
    reasoningEffort: "low",
    maxTurns: 20,
    workerMaxTurns: 8,
    signal: new AbortController().signal,
    ...overrides,
  };
}

async function writeCompletedScan(scanDir: string): Promise<void> {
  await cp(EXAMPLE, scanDir, { recursive: true });
  await writeFile(join(scanDir, "report.md"), "# Scan report\n");
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { producer: { version: string } };
  };
  manifest.scan.producer.version = "0.1.14";
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

class ScriptedScanModel implements Model {
  public readonly requests: ModelRequest[] = [];
  #coordinatorTurn = 0;
  #workerTurn = 0;
  #response = 0;

  public async getResponse(request: ModelRequest): Promise<ModelResponse> {
    const response = this.#next(request);
    return {
      responseId: response.id,
      usage: new Usage(response.usage),
      output: response.output,
    };
  }

  public async *getStreamedResponse(
    request: ModelRequest,
  ): AsyncIterable<StreamEvent> {
    yield { type: "response_started" };
    yield { type: "response_done", response: this.#next(request) };
  }

  #next(
    request: ModelRequest,
  ): Extract<StreamEvent, { type: "response_done" }>["response"] {
    this.requests.push(request);
    this.#response += 1;
    const coordinator = request.tools.some(
      (tool) => tool.name === "delegate_security_task",
    );
    const call = (name: string, args: Record<string, unknown>) => ({
      id: `fc_${this.#response}`,
      type: "function_call" as const,
      callId: `call_${this.#response}`,
      name,
      status: "completed" as const,
      arguments: JSON.stringify(args),
    });
    const message = (text: string) => ({
      id: `msg_${this.#response}`,
      type: "message" as const,
      role: "assistant" as const,
      status: "completed" as const,
      content: [{ type: "output_text" as const, text }],
    });
    let output: Extract<
      StreamEvent,
      { type: "response_done" }
    >["response"]["output"];
    if (coordinator) {
      this.#coordinatorTurn += 1;
      if (this.#coordinatorTurn === 1) {
        output = [call("load_skill", { skill_name: "security-scan" })];
      } else if (this.#coordinatorTurn === 2) {
        output = [
          call("delegate_security_task", {
            input:
              "Review repository/app.ts and write one bounded discovery receipt to output/artifacts/worker.txt.",
          }),
        ];
      } else if (this.#coordinatorTurn === 3) {
        output = [
          call("exec_command", {
            cmd: [
              'test -z "${OPENAI_API_KEY-}"',
              'test -z "${CODEX_API_KEY-}"',
              "test -f plugin/skills/security-scan/SKILL.md",
              "test -f output/artifacts/worker.txt",
              "cp -R plugin/examples/completed-scan/. output/",
              `\"$PYTHON\" -c 'import json,pathlib; p=pathlib.Path("output/scan-manifest.json"); d=json.loads(p.read_text()); d["scan"]["producer"]["version"]="0.1.14"; p.write_text(json.dumps(d,indent=2)+"\\n")'`,
              "printf '%s\\n' '# Scan report' > output/report.md",
            ].join(" && "),
            workdir: "/workspace",
            login: false,
            tty: false,
            yield_time_ms: 10_000,
          }),
        ];
      } else {
        output = [message("standard scan complete")];
      }
    } else {
      this.#workerTurn += 1;
      if (this.#workerTurn === 1) {
        output = [
          call("exec_command", {
            cmd: [
              'test -z "${OPENAI_API_KEY-}"',
              'test -z "${CODEX_API_KEY-}"',
              "test -f repository/app.ts",
              "mkdir -p output/artifacts",
              "printf '%s\\n' 'worker receipt' > output/artifacts/worker.txt",
            ].join(" && "),
            workdir: "/workspace",
            login: false,
            tty: false,
            yield_time_ms: 10_000,
          }),
        ];
      } else {
        output = [message("worker receipt complete")];
      }
    }
    return {
      id: `resp_${this.#response}`,
      usage: {
        requests: 1,
        inputTokens: 8,
        outputTokens: 4,
        totalTokens: 12,
      },
      output,
    };
  }
}

describe("Agents SDK scan workspace", () => {
  test("stages the repository, plugin helpers, skills, and scoped paths without API credentials", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(join(repository, "src"), { recursive: true });
    await writeFile(
      join(repository, "src", "app.ts"),
      "export const ok = true;\n",
    );
    await writeFile(
      join(repository, "src", "validate.sh"),
      "#!/bin/sh\nexit 0\n",
    );
    await chmod(join(repository, "src", "validate.sh"), 0o751);
    const scanRequest = request(repository, {
      target: { kind: "paths", paths: ["src"] },
    });
    const manifest = await agentsManifest(scanRequest);
    const lazySource = localDirLazySkillSource({
      src: join(PLUGIN_ROOT, "skills"),
      baseDir: PLUGIN_ROOT,
    });
    expect(
      lazySource
        .getIndex?.(manifest, "plugin/skills")
        .some((skill) => skill.name === "security-scan"),
    ).toBe(true);
    const session = await new UnixLocalSandboxClient({
      workspaceBaseDir: root,
    }).create({ manifest });
    try {
      await session.materializeEntry({
        path: "plugin/skills/security-scan",
        entry: localDir({ src: join(PLUGIN_ROOT, "skills", "security-scan") }),
      });
      const result = await session.exec({
        cmd: [
          "test -f repository/src/app.ts",
          "test -f plugin/scripts/finalize_scan_contract.py",
          "test -f plugin/references/scan-artifacts.md",
          "test -f plugin/skills/security-scan/SKILL.md",
          "test -d output",
          "test \"$(tr -d '\\n' < target-paths.json)\" = '[\"src\"]'",
          "test ! -w target-paths.json",
          "test ! -w repository-executables.json",
          `test "$(tr -d '\\n' < repository-executables.json)" = '[["src/validate.sh",73]]'`,
          'test "${CODEX_SECURITY_AGENT_RUNTIME-}" = agents-sdk',
          'test "${CODEX_SECURITY_TARGET_PATHS_FILE-}" = target-paths.json',
          'test -z "${OPENAI_API_KEY-}"',
          'test -z "${CODEX_API_KEY-}"',
        ].join(" && "),
        workdir: "/workspace",
        login: false,
      });
      expect(result.exitCode).toBe(0);
    } finally {
      await session.close();
    }
  });

  test("builds a path-safe prompt that invokes the migrated scan skill and worker tool", () => {
    const prompt = agentsScanPrompt(
      request("/repository", {
        target: {
          kind: "paths",
          paths: ['src/with"scope', "tests/$(do-not-run)"],
        },
        python: "/managed/python $(do-not-run) with spaces",
      }),
    );
    expect(prompt).toContain(
      "Use the $security-scan skill at plugin/skills/security-scan/SKILL.md.",
    );
    expect(prompt).toContain("delegate_security_task");
    expect(prompt).toContain("--scopes-file target-paths.json");
    expect(prompt).toContain("--usable-worker-slots 1");
    expect(prompt).toContain(
      "do not wait for a Codex capability-preflight result",
    );
    expect(prompt).toContain("Repository revision: deadbeef");
    expect(prompt).toContain(
      '"$PYTHON" plugin/scripts/finalize_scan_contract.py',
    );
    expect(prompt).not.toContain("/managed/python");
    expect(prompt).not.toContain('src/with"scope');
    expect(prompt).not.toContain("$(do-not-run)");
  });

  test("does not let completed sandbox shell commands keep the host process alive", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const session = await new UnixLocalSandboxClient({
      workspaceBaseDir: root,
    }).create({ manifest: await agentsManifest(request(repository)) });
    const previousSetTimeout = globalThis.setTimeout;
    const observed: Array<ReturnType<typeof setTimeout>> = [];
    globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
      const timeout = previousSetTimeout(...args);
      if (args[1] === 30_000) observed.push(timeout);
      return timeout;
    }) as typeof setTimeout;
    const restoreSandboxTimeouts = suppressReferencedSandboxTimeouts();
    try {
      const result = await session.exec({
        cmd: "true",
        workdir: "/workspace",
        login: false,
        yieldTimeMs: 30_000,
      });
      expect(result.exitCode).toBe(0);
      expect(observed.length).toBeGreaterThan(0);
      expect(observed.every((timeout) => !timeout.hasRef())).toBe(true);
    } finally {
      await session.close();
      restoreSandboxTimeouts();
      globalThis.setTimeout = previousSetTimeout;
    }
  });

  test("copies nested regular output while rejecting unsafe and non-regular entries", async () => {
    const root = await temporaryDirectory();
    const destination = join(root, "output");
    await mkdir(destination);
    await copySandboxOutput(
      {
        async listDir({ path }) {
          if (path === "output") {
            return [
              { name: "report.md", path: "output/report.md", type: "file" },
              { name: "artifacts", path: "output/artifacts", type: "dir" },
            ];
          }
          return [
            {
              name: "coverage.json",
              path: "output/artifacts/coverage.json",
              type: "file",
            },
          ];
        },
        async readFile({ path }) {
          return new TextEncoder().encode(`content:${path}`);
        },
      },
      destination,
    );
    expect(await readFile(join(destination, "report.md"), "utf8")).toBe(
      "content:output/report.md",
    );
    expect(
      await readFile(join(destination, "artifacts", "coverage.json"), "utf8"),
    ).toBe("content:output/artifacts/coverage.json");

    const unsafeDestination = join(root, "unsafe");
    await mkdir(unsafeDestination);
    await expect(
      copySandboxOutput(
        {
          async listDir() {
            return [{ name: "../escape", path: "../escape", type: "file" }];
          },
          async readFile() {
            return "unexpected";
          },
        },
        unsafeDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);

    const nestedDestination = join(root, "nested-swap");
    const escapedDestination = join(root, "escaped");
    await mkdir(nestedDestination);
    await mkdir(escapedDestination);
    await expect(
      copySandboxOutput(
        {
          async listDir({ path }) {
            if (path === "output") {
              return [
                { name: "artifacts", path: "output/artifacts", type: "dir" },
              ];
            }
            return [
              {
                name: "outside.txt",
                path: "output/artifacts/outside.txt",
                type: "file",
              },
            ];
          },
          async readFile() {
            rmSync(join(nestedDestination, "artifacts"), {
              recursive: true,
              force: true,
            });
            symlinkSync(
              escapedDestination,
              join(nestedDestination, "artifacts"),
              "dir",
            );
            return "must-not-escape";
          },
        },
        nestedDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);
    await expect(
      readFile(join(escapedDestination, "outside.txt"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });

    const swappedDestination = join(root, "swapped");
    await mkdir(swappedDestination);
    await expect(
      copySandboxOutput(
        {
          async listDir() {
            return [
              { name: "report.md", path: "output/report.md", type: "file" },
            ];
          },
          async readFile() {
            rmSync(swappedDestination, { recursive: true, force: true });
            symlinkSync(destination, swappedDestination, "dir");
            return "unexpected";
          },
        },
        swappedDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);

    const oversizedDestination = join(root, "oversized");
    await mkdir(oversizedDestination);
    const oversized = new Uint8Array(64 * 1024 * 1024 + 1);
    await expect(
      copySandboxOutput(
        {
          async listDir() {
            return [
              {
                name: "results.sarif",
                path: "output/results.sarif",
                type: "file",
              },
            ];
          },
          async readFile({ maxBytes }) {
            return oversized.subarray(0, maxBytes);
          },
        },
        oversizedDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);

    const redirectedDestination = join(root, "redirected");
    symlinkSync(destination, redirectedDestination, "dir");
    await expect(
      copySandboxOutput(
        {
          async listDir() {
            return [
              { name: "report.md", path: "output/report.md", type: "file" },
            ];
          },
          async readFile() {
            return "unexpected";
          },
        },
        redirectedDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);

    await expect(
      copySandboxOutput(
        {
          async listDir() {
            return [{ name: "symlink", path: "output/symlink", type: "other" }];
          },
          async readFile() {
            return "unexpected";
          },
        },
        unsafeDestination,
      ),
    ).rejects.toBeInstanceOf(OutputDirectoryError);
  });

  test("fails closed when the selected plugin does not contain the scan skill", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const pluginRoot = join(root, "plugin");
    await mkdir(repository);
    await mkdir(join(pluginRoot, "scripts"), { recursive: true });
    await expect(
      agentsManifest(request(repository, { pluginRoot })),
    ).rejects.toBeInstanceOf(IncompleteScanError);
  });

  test("accepts a minimal external plugin without optional preflight or example directories", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const pluginRoot = join(root, "plugin");
    await mkdir(repository);
    for (const directory of ["references", "schemas", "scripts"]) {
      await mkdir(join(pluginRoot, directory), { recursive: true });
    }
    await mkdir(join(pluginRoot, "skills", "security-scan"), {
      recursive: true,
    });
    await writeFile(
      join(pluginRoot, "skills", "security-scan", "SKILL.md"),
      "---\nname: security-scan\ndescription: test\n---\n",
    );
    const manifest = await agentsManifest(request(repository, { pluginRoot }));
    expect(Object.keys(manifest.entries)).toEqual([
      "repository",
      "output",
      "target-paths.json",
      "repository-executables.json",
      "plugin/references",
      "plugin/schemas",
      "plugin/scripts",
    ]);
  });
});

describe("AgentsSecurity orchestration", () => {
  test("validates targets before credential or runtime work", async () => {
    const client = new AgentsSecurity();
    await expect(
      client.run("/definitely/missing/repository"),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    await client.close();
  });

  test("rejects diff targets and missing API credentials", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const client = new TestClient({}, { environment: {} });
    await expect(client.run(repository)).rejects.toBeInstanceOf(
      AuthenticationRequiredError,
    );
    await expect(
      client.run(repository, {
        target: DiffTarget.refs({ base: "HEAD", head: "HEAD" }),
      }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    await client.close();
  });

  test("runs a standard scan through the Agents runner and validates the canonical contract", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    let captured: AgentsScanRequest | null = null;
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        model: "gpt-test",
        reasoningEffort: "medium",
        maxTurns: 32,
        workerMaxTurns: 12,
        sandbox: "unsafe-local",
      },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          OPENAI_BASE_URL: "https://example.invalid/v1",
        },
        resolvePluginPython: async () => "/managed/python",
        repositoryRevision: async () => "deadbeef",
        runAgents: async (value: AgentsScanRequest) => {
          captured = value;
          await writeCompletedScan(value.scanDir);
          return {
            responseId: "resp_agents_1",
            finalResponse: "scan complete",
            usage: { requests: 2, totalTokens: 40 },
          };
        },
      },
    );
    let ready: string | undefined;
    const result = await client.run(repository, {
      outputDir: scanDir,
      onOutputDirReady: (path) => {
        ready = path;
      },
    });
    expect(ready).toBe(scanDir);
    expect(captured).toMatchObject({
      repository,
      scanDir,
      pluginRoot: await realpath(PLUGIN_ROOT),
      python: "/managed/python",
      apiKey: "synthetic-agents-key",
      baseURL: "https://example.invalid/v1",
      model: "gpt-test",
      reasoningEffort: "medium",
      maxTurns: 32,
      workerMaxTurns: 12,
      sandbox: "unsafe-local",
      repositoryRevision: "deadbeef",
    });
    expect(result.threadId).toBe("resp_agents_1");
    expect(result.turnResult).toMatchObject({
      id: "resp_agents_1",
      engine: "agents",
      status: "completed",
      finalResponse: "scan complete",
    });
    expect(result.pluginVersion).toBe("0.1.14");
    await client.close();
  });

  test("stages Docker inputs under the configured shared workspace root and uses container Python", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const workspaceRoot = join(root, "docker-workspaces");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    let captured: AgentsScanRequest | null = null;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspaceRoot,
        },
        repositoryRevision: async () => "deadbeef",
        runAgents: async (value: AgentsScanRequest) => {
          captured = value;
          expect(await readFile(join(value.repository, "app.ts"), "utf8")).toBe(
            "export const ok = true;\n",
          );
          expect(
            await readFile(
              join(value.pluginRoot, "scripts", "finalize_scan_contract.py"),
              "utf8",
            ),
          ).toContain("def finalize_scan");
          await writeCompletedScan(value.scanDir);
          return { responseId: "resp_docker_1", finalResponse: "complete" };
        },
      },
    );
    await client.run(repository, { outputDir: scanDir });
    expect(captured).toMatchObject({
      sandbox: "docker",
      python: "python3",
      repositoryRevision: "deadbeef",
    });
    const capturedRequest = captured as unknown as AgentsScanRequest;
    expect(capturedRequest.repository.startsWith(`${workspaceRoot}/`)).toBe(
      true,
    );
    expect(capturedRequest.pluginRoot.startsWith(`${workspaceRoot}/`)).toBe(
      true,
    );
    expect(capturedRequest.sandboxBaseDir.startsWith(`${workspaceRoot}/`)).toBe(
      true,
    );
    expect(await readdir(workspaceRoot)).toEqual([]);
    await client.close();
  });

  test("executes the migrated skill, delegated worker, sandbox shell, and output handoff through a real Agents runner", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    const model = new ScriptedScanModel();
    const provider: ModelProvider = { getModel: () => model };
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        model: "gpt-scripted",
        maxTurns: 12,
        sandbox: "unsafe-local",
      },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () =>
          execFileSync("python3", ["-c", "import sys; print(sys.executable)"], {
            encoding: "utf8",
          }).trim(),
        repositoryRevision: async () => "deadbeef",
        runAgents: async (value: AgentsScanRequest) =>
          await runAgentsScan(value, { modelProvider: provider }),
      },
    );
    const result = await client.run(repository, { outputDir: scanDir });
    expect(result.turnResult).toMatchObject({
      engine: "agents",
      status: "completed",
      finalResponse: "standard scan complete",
    });
    expect(
      await readFile(join(scanDir, "artifacts", "worker.txt"), "utf8"),
    ).toBe("worker receipt\n");
    expect(model.requests.length).toBeGreaterThanOrEqual(6);
    expect(
      model.requests.some((value) =>
        value.tools.some((tool) => tool.name === "delegate_security_task"),
      ),
    ).toBe(true);
    expect(
      model.requests.some((value) =>
        value.tools.some((tool) => tool.name === "load_skill"),
      ),
    ).toBe(true);
    expect(
      model.requests.every(
        (value) =>
          value.tracing === false &&
          !value.systemInstructions?.includes("synthetic-agents-key") &&
          !JSON.stringify(value.input).includes("synthetic-agents-key"),
      ),
    ).toBe(true);
    await client.close();
  });

  test.skipIf(process.platform === "win32")(
    "omits repository FIFOs while staging Docker inputs",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const workspaceRoot = join(root, "docker-workspaces");
      await mkdir(repository);
      await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
      execFileSync("mkfifo", [join(repository, "runtime.sock")]);
      let reached = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT, sandbox: "docker" },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-agents-key",
            CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspaceRoot,
          },
          repositoryRevision: async () => "deadbeef",
          runAgents: async (value: AgentsScanRequest) => {
            reached = true;
            expect(
              await readFile(join(value.repository, "app.ts"), "utf8"),
            ).toBe("export const ok = true;\n");
            expect(
              await lstat(join(value.repository, "runtime.sock")).catch(
                () => null,
              ),
            ).toBeNull();
            await writeCompletedScan(value.scanDir);
            return { responseId: "resp_fifo_1", finalResponse: "complete" };
          },
        },
      );
      await client.run(repository, { outputDir: scanDir });
      expect(reached).toBe(true);
      expect(await readdir(workspaceRoot)).toEqual([]);
      await client.close();
    },
  );

  test("preserves the partial-output location when an Agents scan is canceled", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    const external = new AbortController();
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "unsafe-local" },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () => "/managed/python",
        runAgents: async ({ signal }: AgentsScanRequest) => {
          external.abort();
          await new Promise<void>((resolve) => {
            if (signal.aborted) resolve();
            else
              signal.addEventListener("abort", () => resolve(), { once: true });
          });
          throw new DOMException("aborted", "AbortError");
        },
      },
    );
    await expect(
      client.run(repository, { outputDir: scanDir, signal: external.signal }),
    ).rejects.toMatchObject({ name: ScanInterruptedError.name, scanDir });
    await client.close();
  });

  test("restores host tracing and debug settings after a failed Agents run", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    const traceProvider = getGlobalTraceProvider();
    const previouslyDisabled =
      traceProvider.createTrace({ name: "prior tracing state" }) instanceof
      NoopTrace;
    const previousDebug = createDebug.disable();
    const previousModel = process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
    const previousTool = process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
    const previousOpenAILog = process.env["OPENAI_LOG"];
    setTracingDisabled(false);
    createDebug.enable("openai-agents:*");
    process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"] = "0";
    process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"] = "0";
    process.env["OPENAI_LOG"] = "debug";
    try {
      await expect(
        runAgentsScan(
          request(repository, {
            scanDir,
            python: execFileSync(
              "python3",
              ["-c", "import sys; print(sys.executable)"],
              { encoding: "utf8" },
            ).trim(),
          }),
          {
            modelProvider: {
              getModel() {
                expect(process.env["OPENAI_LOG"]).toBe("warn");
                throw new Error("expected model-provider failure");
              },
            },
          },
        ),
      ).rejects.toThrow("expected model-provider failure");
      expect(createDebug.enabled("openai-agents:core")).toBe(true);
      expect(process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"]).toBe("0");
      expect(process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"]).toBe("0");
      expect(process.env["OPENAI_LOG"]).toBe("debug");
      expect(
        traceProvider.createTrace({ name: "restored tracing state" }),
      ).not.toBeInstanceOf(NoopTrace);
    } finally {
      createDebug.enable(previousDebug);
      setTracingDisabled(previouslyDisabled);
      if (previousModel === undefined) {
        delete process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
      } else {
        process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"] = previousModel;
      }
      if (previousTool === undefined) {
        delete process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
      } else {
        process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"] = previousTool;
      }
      if (previousOpenAILog === undefined) {
        delete process.env["OPENAI_LOG"];
      } else {
        process.env["OPENAI_LOG"] = previousOpenAILog;
      }
    }
  });

  test("drops repository symlinks before sandbox materialization and preserves the scan revision", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
    symlinkSync("app.ts", join(repository, "app-link.ts"));
    const model = new ScriptedScanModel();
    const provider: ModelProvider = { getModel: () => model };
    let stagedRepository: string | undefined;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "unsafe-local", maxTurns: 12 },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () =>
          execFileSync("python3", ["-c", "import sys; print(sys.executable)"], {
            encoding: "utf8",
          }).trim(),
        repositoryRevision: async () => "deadbeef",
        runAgents: async (value: AgentsScanRequest) => {
          stagedRepository = value.repository;
          expect(value.repositoryRevision).toBe("deadbeef");
          return await runAgentsScan(value, { modelProvider: provider });
        },
      },
    );
    await client.run(repository, { outputDir: scanDir });
    expect(stagedRepository).not.toBe(repository);
    expect(model.requests.length).toBeGreaterThan(0);
    await client.close();
  });

  test("materializes a self-contained linked Git worktree and restores executable files in the sandbox", async () => {
    const root = await temporaryDirectory();
    const main = join(root, "main");
    const repository = join(root, "worktree");
    const scanDir = join(root, "scan");
    await mkdir(main);
    execFileSync("git", ["init", "--quiet"], { cwd: main });
    execFileSync("git", ["config", "user.email", "test@example.invalid"], {
      cwd: main,
    });
    execFileSync("git", ["config", "user.name", "test"], { cwd: main });
    await writeFile(join(main, "app.ts"), "export const value = 'clean';\n");
    await writeFile(
      join(main, "validate.sh"),
      "#!/bin/sh\nprintf '%s\\n' worktree-executable-ok\n",
    );
    await chmod(join(main, "validate.sh"), 0o755);
    execFileSync("git", ["add", "."], { cwd: main });
    execFileSync("git", ["commit", "--quiet", "-m", "initial"], { cwd: main });
    execFileSync(
      "git",
      ["worktree", "add", "--quiet", "-b", "scan-target", repository],
      { cwd: main },
    );
    const revision = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repository,
      encoding: "utf8",
    }).trim();
    await writeFile(
      join(repository, "app.ts"),
      "export const value = 'modified';\n",
    );
    await writeFile(
      join(repository, "untracked.ts"),
      "export const extra = 1;\n",
    );

    let turn = 0;
    const requests: ModelRequest[] = [];
    const model: Model = {
      async getResponse(): Promise<ModelResponse> {
        return { usage: new Usage(), output: [] };
      },
      async *getStreamedResponse(
        value: ModelRequest,
      ): AsyncIterable<StreamEvent> {
        requests.push(value);
        turn += 1;
        yield { type: "response_started" };
        yield {
          type: "response_done",
          response: {
            id: `resp_worktree_${turn}`,
            usage: {
              requests: 1,
              inputTokens: 2,
              outputTokens: 2,
              totalTokens: 4,
            },
            output:
              turn === 1
                ? [
                    {
                      id: "fc_worktree",
                      type: "function_call",
                      callId: "call_worktree",
                      name: "exec_command",
                      status: "completed",
                      arguments: JSON.stringify({
                        cmd: [
                          "test -x repository/validate.sh",
                          "repository/validate.sh",
                          `test \"$(git -C repository rev-parse --verify 'HEAD^{commit}')\" = ${revision}`,
                          "test \"$(git -C repository status --porcelain=v1 --untracked-files=all | tr '\\n' ',')\" = ' M app.ts,?? untracked.ts,'",
                          'test -z "$(git -C repository remote)"',
                          "cp -R plugin/examples/completed-scan/. output/",
                          `"$PYTHON" -c 'import json,subprocess,pathlib; p=pathlib.Path("output/scan-manifest.json"); d=json.loads(p.read_text()); d["scan"]["producer"]["version"]="0.1.14"; d["scan"]["target"]["revision"]=subprocess.check_output(["git","-C","repository","rev-parse","HEAD"],text=True).strip(); p.write_text(json.dumps(d,indent=2)+"\\n")'`,
                          "printf '%s\\n' '# Scan report' > output/report.md",
                        ].join(" && "),
                        workdir: "/workspace",
                        login: false,
                        tty: false,
                        yield_time_ms: 10_000,
                      }),
                    },
                  ]
                : [
                    {
                      id: "msg_worktree",
                      type: "message",
                      role: "assistant",
                      status: "completed",
                      content: [
                        { type: "output_text", text: "worktree scan complete" },
                      ],
                    },
                  ],
          },
        };
      },
    };
    const provider: ModelProvider = { getModel: () => model };
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "unsafe-local", maxTurns: 8 },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () =>
          execFileSync("python3", ["-c", "import sys; print(sys.executable)"], {
            encoding: "utf8",
          }).trim(),
        runAgents: async (value: AgentsScanRequest) => {
          expect(value.repository).not.toBe(repository);
          expect(value.repositoryRevision).toBe(revision);
          return await runAgentsScan(value, { modelProvider: provider });
        },
      },
    );
    const result = await client.run(repository, { outputDir: scanDir });
    expect(result.turnResult.finalResponse).toBe("worktree scan complete");
    expect(JSON.stringify(requests)).toContain("worktree-executable-ok");
    await client.close();
  });

  test("waits for sensitive staging cleanup before close resolves", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const workspaceRoot = join(root, "docker-workspaces");
    await mkdir(repository);
    await writeFile(join(repository, "app.ts"), "export const value = 1;\n");
    let releaseStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      releaseStarted = resolve;
    });
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "docker" },
      {
        environment: {
          OPENAI_API_KEY: "synthetic-agents-key",
          CODEX_SECURITY_DOCKER_WORKSPACE_ROOT: workspaceRoot,
        },
        repositoryRevision: async () => "deadbeef",
        runAgents: async ({ sandboxBaseDir, signal }: AgentsScanRequest) => {
          const bulk = join(sandboxBaseDir, "sensitive-staging");
          await mkdir(bulk);
          await Promise.all(
            Array.from({ length: 2_000 }, async (_, index) =>
              writeFile(join(bulk, `${index}.txt`), "sensitive\n"),
            ),
          );
          releaseStarted();
          await new Promise<void>((resolve) => {
            if (signal.aborted) resolve();
            else
              signal.addEventListener("abort", () => resolve(), { once: true });
          });
          throw new DOMException("aborted", "AbortError");
        },
      },
    );
    const running = client.run(repository).catch((error: unknown) => error);
    await started;
    expect((await readdir(workspaceRoot)).length).toBe(1);
    const firstClose = client.close();
    let secondCloseResolved = false;
    const secondClose = client.close().then(() => {
      secondCloseResolved = true;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(secondCloseResolved).toBe(false);
    await Promise.all([firstClose, secondClose]);
    expect(await readdir(workspaceRoot)).toEqual([]);
    expect(await running).toBeInstanceOf(ScanInterruptedError);
  });

  test("rejects an output directory retargeted by the readiness callback before sandbox work", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    let runReached = false;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "unsafe-local" },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () => "/managed/python",
        runAgents: async () => {
          runReached = true;
          throw new Error("unexpected");
        },
      },
    );
    await expect(
      client.run(repository, {
        outputDir: scanDir,
        onOutputDirReady: (path) => {
          rmSync(path, { recursive: true, force: true });
          symlinkSync(repository, path, "dir");
        },
      }),
    ).rejects.toBeInstanceOf(OutputDirectoryError);
    expect(runReached).toBe(false);
    await client.close();
  });

  test("rejects a repository revision changed while staging before sandbox work", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    let revisionReads = 0;
    let runReached = false;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, sandbox: "unsafe-local" },
      {
        environment: { OPENAI_API_KEY: "synthetic-agents-key" },
        resolvePluginPython: async () => "/managed/python",
        repositoryRevision: async () =>
          ++revisionReads === 1 ? "deadbeef" : "ffffffff",
        runAgents: async () => {
          runReached = true;
          throw new Error("unexpected");
        },
      },
    );
    await expect(client.run(repository)).rejects.toBeInstanceOf(
      InvalidTargetError,
    );
    expect(runReached).toBe(false);
    await client.close();
  });
});
