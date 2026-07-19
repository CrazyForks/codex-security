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
  writeFile,
} from "node:fs/promises";
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

function request(root: string): AgentsScanRequest {
  return {
    repository: join(root, "repository"),
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
      const previousPath = process.env["PATH"];
      process.env["PATH"] = `${bin}:${previousPath ?? "/usr/bin:/bin"}`;
      const tracingWasDisabled =
        getGlobalTraceProvider().createTrace({ name: "before scan" }) instanceof
        NoopTrace;
      setTracingDisabled(false);
      const previousModelLogGuard =
        process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
      const previousToolLogGuard =
        process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
      delete process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
      delete process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
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
        expect(
          requests.some((item) =>
            item.tools.some((tool) => tool.name === "delegate_security_task"),
          ),
        ).toBe(true);
        expect(requests.every((item) => item.tracing === false)).toBe(true);
        expect(
          getGlobalTraceProvider().createTrace({ name: "after scan" }),
        ).not.toBeInstanceOf(NoopTrace);
        const calls = await readFile(log, "utf8");
        expect(calls).toContain("<network>");
        expect(calls).toContain("<disconnect>");
        expect(calls).toContain("<bridge>");
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
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
    },
  );
});
