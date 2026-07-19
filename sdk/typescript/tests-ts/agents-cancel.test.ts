import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, expect, test } from "bun:test";
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
  ScanInterruptedError,
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

class CancelAfterShellModel implements Model {
  #turn = 0;

  public constructor(private readonly controller: AbortController) {}

  public async getResponse(_request: ModelRequest): Promise<ModelResponse> {
    return { usage: new Usage(), output: [] };
  }

  public async *getStreamedResponse(
    _request: ModelRequest,
  ): AsyncIterable<StreamEvent> {
    this.#turn += 1;
    if (this.#turn > 1) {
      this.controller.abort();
      throw new DOMException("aborted", "AbortError");
    }
    yield { type: "response_started" };
    yield {
      type: "response_done",
      response: {
        id: "resp_partial",
        usage: { requests: 1, inputTokens: 2, outputTokens: 2, totalTokens: 4 },
        output: [
          {
            id: "fc_partial",
            type: "function_call",
            callId: "call_partial",
            name: "exec_command",
            status: "completed",
            arguments: JSON.stringify({
              cmd: "mkdir -p output/artifacts && printf '%s\\n' partial > output/artifacts/partial.txt",
              workdir: "/workspace",
              login: false,
              tty: false,
              yield_time_ms: 10_000,
            }),
          },
        ],
      },
    };
  }
}

test("copies sandbox partial output before closing an interrupted Agents run", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-agents-cancel-")),
  );
  temporaryDirectories.push(root);
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await writeFile(join(repository, "app.ts"), "export const ok = true;\n");
  const controller = new AbortController();
  const model = new CancelAfterShellModel(controller);
  const provider: ModelProvider = {
    getModel: () => model,
  };
  const client = new TestClient(
    {
      pluginPath: PLUGIN_ROOT,
      model: "gpt-scripted",
      maxTurns: 4,
      sandbox: "unsafe-local",
    },
    {
      environment: { OPENAI_API_KEY: "synthetic-agents-key" },
      resolvePluginPython: async () =>
        execFileSync("python3", ["-c", "import sys; print(sys.executable)"], {
          encoding: "utf8",
        }).trim(),
      runAgents: async (value: AgentsScanRequest) =>
        await runAgentsScan(value, { modelProvider: provider }),
    },
  );
  await expect(
    client.run(repository, { outputDir: scanDir, signal: controller.signal }),
  ).rejects.toMatchObject({ name: ScanInterruptedError.name, scanDir });
  expect(
    await readFile(join(scanDir, "artifacts", "partial.txt"), "utf8"),
  ).toBe("partial\n");
  await client.close();
});
