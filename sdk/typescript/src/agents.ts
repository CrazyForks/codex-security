import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { promisify } from "node:util";
import createDebug from "debug";
import OpenAI from "openai";
import {
  NoopTrace,
  OpenAIProvider,
  Runner,
  getGlobalTraceProvider,
  setTracingDisabled,
  tool,
  type ModelProvider,
} from "@openai/agents";
import {
  Capabilities,
  Manifest,
  SandboxAgent,
  mount,
} from "@openai/agents/sandbox";
import {
  DockerSandboxClient,
  type DockerSandboxSession,
  localDirLazySkillSource,
} from "@openai/agents/sandbox/local";
import { z } from "zod";
import {
  loadContract,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import {
  AuthenticationRequiredError,
  CodexSecurityError,
  IncompleteScanError,
  InvalidTargetError,
  OutputDirectoryError,
  ScanInterruptedError,
} from "./errors.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import {
  pluginMetadata,
  prepareOutputDir,
  requireModelSafeOutputDir,
  resolvePluginPath,
  validateOutputDir,
  validatePreparedOutputDir,
  type ProcessEnvironment,
} from "./runtime.js";
import {
  enclosingGitWorktreeRoot,
  normalizeRepository,
  normalizeTarget,
  resolveRepositoryPath,
  type NormalizedTarget,
  type ScanTarget,
} from "./targets.js";

const execFile = promisify(execFileCallback);
const DEFAULT_MODEL = "gpt-5.6";
const DEFAULT_REASONING_EFFORT: AgentsReasoningEffort = "high";
const DEFAULT_MAX_TURNS = 200;
const DEFAULT_WORKER_MAX_TURNS = 100;
const DEFAULT_DOCKER_IMAGE = "node:22-bookworm";
const REQUIRED_PLUGIN_DIRECTORIES = ["references", "schemas", "scripts"];
const OPTIONAL_PLUGIN_DIRECTORIES = [".codex-plugin", "examples", "preflight"];
const MAX_OUTPUT_ENTRIES = 20_000;
const MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 512 * 1024 * 1024;
const MAX_INPUT_ENTRIES = 2_000_000;
const MAX_INPUT_FILE_BYTES = 256 * 1024 * 1024;
const MAX_INPUT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_GIT_CONFIG_FILES = 128;
const MAX_GIT_CONFIG_BYTES = 1024 * 1024;
let tracingUsers = 0;
let hostEnvironmentUsers = 0;
let savedHostPath: string | undefined;
let savedHostOpenAIKey: string | undefined;
let savedHostCodexKey: string | undefined;
let tracingWasDisabled = false;
let savedModelLogGuard: string | undefined;
let savedToolLogGuard: string | undefined;
let savedOpenAILogLevel: string | undefined;
let savedDebugNamespaces = "";
let timeoutUsers = 0;
let savedSetTimeout: typeof setTimeout | undefined;

export type AgentsReasoningEffort =
  | "none"
  | "minimal"
  | "low"
  | "medium"
  | "high"
  | "xhigh"
  | "max";

export interface AgentsSecurityConfig {
  pluginPath?: string;
  pythonPath?: string;
  model?: string;
  reasoningEffort?: AgentsReasoningEffort;
  maxTurns?: number;
  workerMaxTurns?: number;
}

export interface AgentsScanOptions {
  target?: ScanTarget;
  outputDir?: string;
  onOutputDirReady?: (scanDir: string) => void;
  signal?: AbortSignal;
}

export interface AgentsScanRequest {
  repository: string;
  hostRepositoryRoot?: string;
  target: NormalizedTarget;
  scanDir: string;
  pluginRoot: string;
  python: string;
  sandboxBaseDir: string;
  sandboxInputRoot: string;
  repositoryRevision: string | null;
  repositoryIdentity: string;
  apiKey: string;
  baseURL?: string;
  organization?: string;
  project?: string;
  model: string;
  reasoningEffort: AgentsReasoningEffort;
  maxTurns: number;
  workerMaxTurns: number;
  signal: AbortSignal;
}

export interface AgentsScanSummary {
  responseId?: string;
  finalResponse?: string;
  usage?: unknown;
}

export interface AgentsRuntimeDependencies {
  modelProvider?: ModelProvider;
}

interface ClientDependencies {
  environment: ProcessEnvironment;
  runAgents?: (request: AgentsScanRequest) => Promise<AgentsScanSummary>;
  prepareOutputDir?: typeof prepareOutputDir;
}

const DEFAULT_DEPENDENCIES: ClientDependencies = { environment: process.env };

class AgentsSandboxCleanupError extends IncompleteScanError {}

export class AgentsSecurity {
  public readonly config: Readonly<AgentsSecurityConfig>;
  readonly #dependencies: ClientDependencies;
  readonly #controllers = new Set<AbortController>();
  readonly #runs = new Set<Promise<void>>();
  #closed = false;

  public constructor(config?: AgentsSecurityConfig);
  public constructor(
    config: AgentsSecurityConfig = {},
    dependencies: ClientDependencies = DEFAULT_DEPENDENCIES,
  ) {
    this.config = structuredClone(config);
    this.#dependencies = dependencies;
  }

  public async run(
    repository: string,
    options: AgentsScanOptions = {},
  ): Promise<ScanResult> {
    this.#requireOpen();
    const controller = new AbortController();
    const removeAbort = forwardAbort(options.signal, controller);
    this.#controllers.add(controller);
    let finish!: () => void;
    const running = new Promise<void>((resolve) => {
      finish = resolve;
    });
    this.#runs.add(running);
    let staging: string | undefined;
    let scanDir = "";
    try {
      const repositoryPath = resolveRepositoryPath(repository);
      const repo = await normalizeRepository(repositoryPath, controller.signal);
      const repositoryMetadata = await lstat(repo);
      const target = await normalizeTarget(
        repo,
        options.target ?? "repository",
        controller.signal,
      );
      if (target.kind !== "repository" && target.kind !== "paths") {
        throw new InvalidTargetError(
          "Agents SDK scans support repository and path targets only; use the Codex engine for diff scans.",
        );
      }
      if (
        target.kind === "paths" &&
        target.paths.some((path) =>
          path.split("/").some((part) => part.toLowerCase() === ".git"),
        )
      ) {
        throw new InvalidTargetError(
          "Agents SDK path targets must not select Git metadata.",
        );
      }
      const protectedRoot =
        (await enclosingGitWorktreeRoot(repo, controller.signal)) ?? repo;
      const requestedOutput = await validateOutputDir(options.outputDir);
      const temporaryRoot = await realpath(tmpdir());
      if (requestedOutput !== null) {
        requireOutsideRepository(protectedRoot, requestedOutput);
      } else {
        requireOutsideRepository(protectedRoot, temporaryRoot);
      }
      const apiKey = environmentApiKey(this.#dependencies.environment);
      if (apiKey === null) {
        throw new AuthenticationRequiredError(
          "Agents SDK scans require OPENAI_API_KEY or CODEX_API_KEY. File-backed Codex authentication is available only with the Codex engine.",
        );
      }
      const workspaceRoot = await dockerWorkspaceRoot(
        this.#dependencies.environment,
        protectedRoot,
      );
      staging = await mkdtemp(join(workspaceRoot, "codex-security-agents-"));
      const pluginRoot = await resolvePluginPath(
        this.config.pluginPath,
        staging,
        controller.signal,
      );
      const plugin = await pluginMetadata(pluginRoot);
      scanDir = await (this.#dependencies.prepareOutputDir ?? prepareOutputDir)(
        requestedOutput ?? undefined,
        basename(repo),
        requestedOutput === null ? workspaceRoot : temporaryRoot,
        (path) => requireOutsideRepository(protectedRoot, path),
      );
      requireModelSafeOutputDir(scanDir);
      const outputMetadata = await lstat(scanDir);
      options.onOutputDirReady?.(scanDir);
      scanDir = await validatePreparedOutputDir(
        scanDir,
        (path) => requireOutsideRepository(protectedRoot, path),
        outputMetadata,
      );
      const stagedRepository = join(staging, "repository");
      const stagedPlugin = join(staging, "plugin");
      const sandboxOutput = join(staging, "output");
      const sandboxInputRoot = join(staging, "scan-inputs");
      const inputState = { entries: 0, bytes: 0 };
      await requireUnchangedDirectory(repo, repositoryMetadata);
      await stageRepository(
        repo,
        stagedRepository,
        controller.signal,
        target,
        inputState,
      );
      await requireUnchangedDirectory(repo, repositoryMetadata);
      const repositoryIdentity = await stableRepositoryIdentity(
        repo,
        controller.signal,
      );
      for (const name of [
        ...REQUIRED_PLUGIN_DIRECTORIES,
        ...OPTIONAL_PLUGIN_DIRECTORIES,
        "skills",
      ]) {
        const source = join(pluginRoot, name);
        const metadata = await lstat(source).catch(() => null);
        if (metadata === null) continue;
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
          throw new IncompleteScanError(
            `Selected plugin has an invalid Agents scan runtime directory: ${name}`,
          );
        }
        await stageTree(
          source,
          join(stagedPlugin, name),
          controller.signal,
          {
            skip: (entry) =>
              entry === ".git" ||
              entry.toLowerCase().endsWith(".git") ||
              entry === ".env" ||
              entry.startsWith(".env.") ||
              entry.endsWith(".pem") ||
              entry.endsWith(".key") ||
              entry === "__pycache__" ||
              entry.endsWith(".pyc"),
          },
          inputState,
        );
      }
      await mkdir(sandboxOutput, { mode: 0o700 });
      await mkdir(sandboxInputRoot, { mode: 0o700 });
      await writeFile(
        join(sandboxInputRoot, "target-paths.json"),
        `${JSON.stringify(target.kind === "paths" ? target.paths : ["."])}\n`,
        { flag: "wx", mode: 0o400 },
      );
      await writeFile(
        join(sandboxInputRoot, "repository-identity.json"),
        `${JSON.stringify({ targetId: repositoryIdentity })}\n`,
        { flag: "wx", mode: 0o400 },
      );
      let summary: AgentsScanSummary;
      let copyOutput = true;
      try {
        summary = await (this.#dependencies.runAgents ?? runAgentsScan)({
          repository: stagedRepository,
          hostRepositoryRoot: repo,
          target,
          scanDir: sandboxOutput,
          pluginRoot: stagedPlugin,
          python: this.config.pythonPath ?? "python3",
          sandboxBaseDir: staging,
          sandboxInputRoot,
          repositoryRevision: null,
          repositoryIdentity,
          apiKey,
          baseURL: environmentValue(
            this.#dependencies.environment,
            "OPENAI_BASE_URL",
          ),
          organization: environmentValue(
            this.#dependencies.environment,
            "OPENAI_ORG_ID",
          ),
          project: environmentValue(
            this.#dependencies.environment,
            "OPENAI_PROJECT_ID",
          ),
          model: nonEmpty(this.config.model, "model") ?? DEFAULT_MODEL,
          reasoningEffort:
            this.config.reasoningEffort ?? DEFAULT_REASONING_EFFORT,
          maxTurns: positiveInteger(this.config.maxTurns, DEFAULT_MAX_TURNS),
          workerMaxTurns: positiveInteger(
            this.config.workerMaxTurns,
            DEFAULT_WORKER_MAX_TURNS,
          ),
          signal: controller.signal,
        });
      } catch (error) {
        copyOutput = !(error instanceof AgentsSandboxCleanupError);
        throw error;
      } finally {
        if (copyOutput) {
          await requireUnchangedOutputDirectory(scanDir, outputMetadata);
          await copyStagedOutput(sandboxOutput, scanDir);
        }
      }
      return await collectAgentsResult(
        scanDir,
        pluginRoot,
        {
          repository: repo,
          repositoryRevision: null,
          repositoryIdentity,
          target,
          mode: "standard",
          pluginVersion: plugin.version,
        },
        summary,
        controller.signal,
      );
    } catch (error) {
      if (controller.signal.aborted) {
        throw new ScanInterruptedError(
          `Codex Security scan was interrupted${scanDir ? `; partial output remains at ${scanDir}` : ""}.`,
          scanDir,
        );
      }
      throw error;
    } finally {
      removeAbort();
      this.#controllers.delete(controller);
      try {
        if (staging !== undefined) {
          await rm(staging, { recursive: true, force: true });
        }
      } finally {
        this.#runs.delete(running);
        finish();
      }
    }
  }

  public async close(): Promise<void> {
    this.#closed = true;
    for (const controller of this.#controllers) controller.abort();
    await Promise.allSettled(this.#runs);
  }

  #requireOpen(): void {
    if (this.#closed) throw new CodexSecurityError("AgentsSecurity is closed.");
  }
}

export async function runAgentsScan(
  request: AgentsScanRequest,
  dependencies: AgentsRuntimeDependencies = {},
): Promise<AgentsScanSummary> {
  if (request.target.kind !== "repository" && request.target.kind !== "paths") {
    throw new InvalidTargetError(
      "Agents SDK scans support repository and path targets only; use the Codex engine for diff scans.",
    );
  }
  const manifest = await agentsManifest(request);
  const client = new DockerSandboxClient({
    image: DEFAULT_DOCKER_IMAGE,
    workspaceBaseDir: request.sandboxBaseDir,
  });
  const releaseHostEnvironment = suppressUnsafeHostEnvironment(
    request.hostRepositoryRoot,
  );
  const session = await createDockerSession(
    client,
    manifest,
    request.signal,
  ).catch((error: unknown) => {
    releaseHostEnvironment();
    throw error;
  });
  const releaseTracing = suppressAgentsTracing();
  const releaseTimeouts = suppressReferencedSandboxTimeouts();
  let ownedProvider: OpenAIProvider | undefined;
  try {
    await isolateDockerSession(session);
    const preflight = await session.exec({
      cmd: [
        'command -v "$PYTHON" >/dev/null',
        "command -v git >/dev/null",
        "test -f plugin/scripts/finalize_scan_contract.py",
        "test -f plugin/scripts/generate_rank_input.py",
        "test -r scan-inputs/target-paths.json",
        "test -r scan-inputs/repository-identity.json",
      ].join(" && "),
      workdir: "/workspace",
      login: false,
    });
    if (preflight.exitCode !== 0) {
      throw new IncompleteScanError(
        `Agents SDK sandbox is missing required scan tools or inputs: ${preflight.stderr.trim() || preflight.stdout.trim() || `exit ${preflight.exitCode}`}`,
      );
    }
    const provider =
      dependencies.modelProvider ??
      (ownedProvider = new OpenAIProvider({
        openAIClient: new OpenAI({
          apiKey: request.apiKey,
          baseURL: request.baseURL,
          organization: request.organization,
          project: request.project,
          logLevel: "warn",
        }),
        useResponses: true,
        useResponsesWebSocket: false,
      }));
    const runConfig = {
      modelProvider: provider,
      tracingDisabled: true,
      traceIncludeSensitiveData: false,
      workflowName: "Codex Security standard scan",
      sandbox: { session },
      toolExecution: { maxFunctionToolConcurrency: 1 },
    };
    const worker = new SandboxAgent({
      name: "Codex Security scan worker",
      model: request.model,
      modelSettings: {
        reasoning: { effort: request.reasoningEffort },
        parallelToolCalls: true,
        store: false,
      },
      instructions: [
        "Follow the coordinator assignment and the referenced phase skill under plugin/skills.",
        "Use repository, plugin, output, and scan-inputs as workspace-relative paths. Never edit repository or plugin files.",
        "Write only the requested worker-local artifacts and return a concise receipt.",
      ].join("\n"),
      capabilities: Capabilities.default(),
    });
    const delegate = worker.asTool({
      toolName: "delegate_security_task",
      toolDescription:
        "Run one bounded Codex Security ranking, review, validation, or write-up assignment in the shared scan sandbox.",
      runConfig,
      runOptions: { sandbox: { session }, maxTurns: request.workerMaxTurns },
    });
    const skillIndex =
      localDirLazySkillSource({
        src: join(request.pluginRoot, "skills"),
        baseDir: request.pluginRoot,
      }).getIndex?.(manifest, "plugin/skills") ?? [];
    const loadSkill = tool({
      name: "load_skill",
      description: "Load a bundled Codex Security phase skill.",
      parameters: z.object({ skill_name: z.string().min(1) }),
      execute: async ({ skill_name }) => {
        const matches = skillIndex.filter((entry) => entry.name === skill_name);
        if (matches.length !== 1) {
          throw new IncompleteScanError(
            `Unknown or ambiguous Agents scan skill: ${skill_name}`,
          );
        }
        return {
          status: "already_loaded",
          skill_name,
          path: `plugin/skills/${matches[0]!.path ?? skill_name}`,
          instructions: await readFile(
            join(
              request.pluginRoot,
              "skills",
              matches[0]!.path ?? skill_name,
              "SKILL.md",
            ),
            "utf8",
          ),
        };
      },
    });
    const coordinator = new SandboxAgent({
      name: "Codex Security scan coordinator",
      model: request.model,
      modelSettings: {
        reasoning: { effort: request.reasoningEffort },
        parallelToolCalls: false,
        store: false,
      },
      instructions: [
        "Coordinate a non-interactive Codex Security standard scan inside the shared Agents SDK sandbox.",
        'Use "$PYTHON" for plugin helpers and delegate_security_task for required subagent assignments.',
        "The host has no Codex app, MCP workbench, goals, or capability-preflight tools; use the terminal/chat workflow and preserve required receipts.",
      ].join("\n"),
      tools: [delegate, loadSkill],
      capabilities: Capabilities.default(),
    });
    const stream = await new Runner(runConfig).run(
      coordinator,
      agentsScanPrompt(request),
      {
        stream: true,
        signal: request.signal,
        sandbox: { session },
        maxTurns: request.maxTurns,
      },
    );
    for await (const _event of stream) {
      // Consume tool and model events until the scan completes.
    }
    await stream.completed;
    if (stream.error !== undefined && stream.error !== null) throw stream.error;
    if (stream.cancelled || request.signal.aborted) {
      throw new DOMException("Agents SDK scan was aborted.", "AbortError");
    }
    return {
      responseId: stream.lastResponseId,
      finalResponse:
        typeof stream.finalOutput === "string" ? stream.finalOutput : undefined,
      usage: stream.runContext.usage,
    };
  } catch (error) {
    throw sanitizeAgentsRuntimeFailure(error);
  } finally {
    try {
      let cleanupFailure: unknown;
      try {
        await session.close();
      } catch (error) {
        cleanupFailure = error;
      }
      await ownedProvider?.close().catch(() => undefined);
      if (cleanupFailure !== undefined) {
        throw new AgentsSandboxCleanupError(
          "Unable to remove the Agents SDK sandbox after the scan.",
          { cause: cleanupFailure },
        );
      }
    } finally {
      releaseTimeouts();
      releaseTracing();
      releaseHostEnvironment();
    }
  }
}

function suppressUnsafeHostEnvironment(repository?: string): () => void {
  if (hostEnvironmentUsers++ === 0) {
    savedHostPath = process.env["PATH"];
    savedHostOpenAIKey = process.env["OPENAI_API_KEY"];
    savedHostCodexKey = process.env["CODEX_API_KEY"];
    process.env["PATH"] = safeHostPath(repository);
    delete process.env["OPENAI_API_KEY"];
    delete process.env["CODEX_API_KEY"];
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--hostEnvironmentUsers !== 0) return;
    restoreEnvironmentValue("PATH", savedHostPath);
    restoreEnvironmentValue("OPENAI_API_KEY", savedHostOpenAIKey);
    restoreEnvironmentValue("CODEX_API_KEY", savedHostCodexKey);
  };
}

function safeHostPath(repository?: string): string {
  return (process.env["PATH"] ?? "")
    .split(delimiter)
    .filter(
      (entry) =>
        entry.length > 0 &&
        isAbsolute(entry) &&
        !/(?:^|[\\/])node_modules[\\/]\.bin(?:[\\/]|$)/iu.test(entry) &&
        (repository === undefined ||
          relative(repository, resolve(entry)).startsWith(`..${sep}`)),
    )
    .join(delimiter);
}

function suppressAgentsTracing(): () => void {
  if (tracingUsers++ === 0) {
    savedDebugNamespaces = createDebug.disable();
    createDebug.enable(
      [savedDebugNamespaces, "-openai-agents:*"].filter(Boolean).join(","),
    );
    tracingWasDisabled =
      getGlobalTraceProvider().createTrace({
        name: "Codex Security tracing state probe",
      }) instanceof NoopTrace;
    setTracingDisabled(true);
    savedModelLogGuard = process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
    savedToolLogGuard = process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
    savedOpenAILogLevel = process.env["OPENAI_LOG"];
    process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"] = "1";
    process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"] = "1";
    process.env["OPENAI_LOG"] = "warn";
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--tracingUsers !== 0) return;
    createDebug.enable(savedDebugNamespaces);
    setTracingDisabled(tracingWasDisabled);
    restoreEnvironmentValue(
      "OPENAI_AGENTS_DONT_LOG_MODEL_DATA",
      savedModelLogGuard,
    );
    restoreEnvironmentValue(
      "OPENAI_AGENTS_DONT_LOG_TOOL_DATA",
      savedToolLogGuard,
    );
    restoreEnvironmentValue("OPENAI_LOG", savedOpenAILogLevel);
  };
}

function suppressReferencedSandboxTimeouts(): () => void {
  if (timeoutUsers++ === 0) {
    const previous = globalThis.setTimeout;
    savedSetTimeout = previous;
    globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
      const timeout = previous(...args);
      if (
        /[\\/]sandbox[\\/]sandboxes[\\/]unixLocal\./.test(
          new Error().stack ?? "",
        )
      ) {
        timeout.unref();
      }
      return timeout;
    }) as typeof setTimeout;
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--timeoutUsers !== 0) return;
    if (savedSetTimeout !== undefined) globalThis.setTimeout = savedSetTimeout;
    savedSetTimeout = undefined;
  };
}

function restoreEnvironmentValue(
  name: string,
  value: string | undefined,
): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

async function createDockerSession(
  client: DockerSandboxClient,
  manifest: Manifest,
  signal: AbortSignal,
): Promise<DockerSandboxSession> {
  if (signal.aborted)
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
  const creation = client.create({ manifest });
  let removeAbort = (): void => undefined;
  const interrupted = new Promise<never>((_, reject) => {
    const abort = (): void => {
      void creation.then((session) => session.close()).catch(() => undefined);
      reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
    removeAbort = () => signal.removeEventListener("abort", abort);
  });
  try {
    return await Promise.race([creation, interrupted]);
  } finally {
    removeAbort();
  }
}

function sanitizeAgentsRuntimeFailure(error: unknown): unknown {
  if (typeof error !== "object" || error === null || !("state" in error)) {
    return error;
  }
  const name =
    "name" in error && typeof error.name === "string"
      ? error.name
      : "runtime error";
  return new IncompleteScanError(
    `Agents SDK scan ended without a complete result (${name}).`,
  );
}

export async function agentsManifest(
  request: Pick<
    AgentsScanRequest,
    "repository" | "scanDir" | "pluginRoot" | "python" | "sandboxInputRoot"
  >,
): Promise<Manifest> {
  const entries: Record<string, ReturnType<typeof mount>> = {
    repository: mount({ source: request.repository, readOnly: true }),
    output: mount({ source: request.scanDir, readOnly: false }),
    "scan-inputs": mount({ source: request.sandboxInputRoot, readOnly: true }),
  };
  for (const name of REQUIRED_PLUGIN_DIRECTORIES) {
    const source = join(request.pluginRoot, name);
    const metadata = await lstat(source).catch(() => null);
    if (metadata?.isDirectory() !== true || metadata.isSymbolicLink()) {
      throw new IncompleteScanError(
        `Selected plugin is missing Agents scan runtime directory: ${name}`,
      );
    }
    entries[`plugin/${name}`] = mount({ source, readOnly: true });
  }
  for (const name of OPTIONAL_PLUGIN_DIRECTORIES) {
    const source = join(request.pluginRoot, name);
    const metadata = await lstat(source).catch(() => null);
    if (metadata === null) continue;
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new IncompleteScanError(
        `Selected plugin has an invalid Agents scan runtime directory: ${name}`,
      );
    }
    entries[`plugin/${name}`] = mount({ source, readOnly: true });
  }
  const skills = join(request.pluginRoot, "skills");
  const scanSkill = await lstat(
    join(skills, "security-scan", "SKILL.md"),
  ).catch(() => null);
  if (scanSkill?.isFile() !== true || scanSkill.isSymbolicLink()) {
    throw new IncompleteScanError(
      "Selected plugin is missing scan skill: security-scan",
    );
  }
  entries["plugin/skills"] = mount({ source: skills, readOnly: true });
  return new Manifest({
    root: "/workspace",
    entries,
    extraPathGrants: [
      { path: request.repository, readOnly: true },
      { path: request.pluginRoot, readOnly: true },
      { path: request.scanDir, readOnly: false },
      { path: request.sandboxInputRoot, readOnly: true },
    ],
    environment: {
      PYTHON: request.python,
      PYTHONUNBUFFERED: "1",
      PYTHONDONTWRITEBYTECODE: "1",
      CODEX_SECURITY_AGENT_RUNTIME: "agents-sdk",
      CODEX_SECURITY_TARGET_PATHS_FILE: "scan-inputs/target-paths.json",
      CODEX_SECURITY_REPOSITORY_IDENTITY_FILE:
        "scan-inputs/repository-identity.json",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "safe.directory",
      GIT_CONFIG_VALUE_0: "/workspace/repository",
    },
  });
}

export function agentsScanPrompt(
  request: Pick<
    AgentsScanRequest,
    "target" | "repositoryRevision" | "repositoryIdentity"
  >,
): string {
  const target =
    request.target.kind === "paths"
      ? [
          "Scan target: the paths listed in scan-inputs/target-paths.json.",
          'Generate one combined inventory with "$PYTHON" plugin/scripts/generate_rank_input.py make-repo-rank-input --repo repository --scopes-file scan-inputs/target-paths.json --out output/artifacts/02_discovery/rank_input.jsonl.',
          'Before finalization, bind every requested scope with "$PYTHON" plugin/scripts/generate_rank_input.py bind-repo-scopes --scopes-file scan-inputs/target-paths.json --manifest output/scan-manifest.json --coverage output/coverage.json.',
        ]
      : ["Scan target: the entire repository."];
  return [
    "Use the $security-scan skill at plugin/skills/security-scan/SKILL.md.",
    "Run a standard, non-interactive repository/path scan with the Agents SDK runtime.",
    "Repository root: repository",
    "Plugin root: plugin",
    "Use this exact scan directory for all output: output",
    request.repositoryRevision === null
      ? "Repository identity: Git-visible directory snapshot; history metadata is unavailable."
      : `Repository revision: ${request.repositoryRevision}`,
    `Repository targetId: ${request.repositoryIdentity}. Use this exact stable targetId in scan-manifest.json.`,
    ...target,
    "Use delegate_security_task for required subagent assignments and preserve phase/coverage receipts.",
    "The Agents runtime provides one ranking-worker slot; create the static rank-worker plan with --usable-worker-slots 1 and do not wait for a Codex capability-preflight result.",
    'Complete and seal the canonical JSON contract with "$PYTHON" plugin/scripts/finalize_scan_contract.py --scan-dir output --source-root repository before returning.',
  ].join("\n");
}

async function stageRepository(
  source: string,
  destination: string,
  signal: AbortSignal,
  target: Pick<NormalizedTarget, "kind" | "paths"> = {
    kind: "repository",
    paths: [],
  },
  state: { entries: number; bytes: number } = { entries: 0, bytes: 0 },
): Promise<void> {
  const gitRoot = await enclosingGitWorktreeRoot(source, signal);
  if (gitRoot === null) {
    if (hasBareGitLayout(await readdir(source))) {
      throw new InvalidTargetError(
        `Bare Git repositories cannot be staged safely: ${source}`,
      );
    }
    await stageTree(
      source,
      destination,
      signal,
      {
        skip: (name) =>
          name.toLowerCase() === ".git" ||
          name === ".env" ||
          name.startsWith(".env.") ||
          name.endsWith(".pem") ||
          name.endsWith(".key"),
      },
      state,
    );
    return;
  }
  const marker = await lstat(join(source, ".git")).catch(() => null);
  if (marker?.isSymbolicLink() === true) {
    throw new InvalidTargetError(
      `Git worktree metadata is not safe to stage: ${join(source, ".git")}`,
    );
  }
  const localGitRoot =
    marker?.isFile() === true || marker?.isDirectory() === true
      ? source
      : gitRoot;
  const bareDirectories = await requireSafeGitInputs(
    source,
    localGitRoot,
    signal,
  );
  const environment = sanitizedGitEnvironment(source);
  const configuredEnvironment = {
    ...environment,
    GIT_CONFIG_GLOBAL: process.env["GIT_CONFIG_GLOBAL"],
    GIT_CONFIG_SYSTEM: process.env["GIT_CONFIG_SYSTEM"],
    GIT_CONFIG_NOSYSTEM: process.env["GIT_CONFIG_NOSYSTEM"],
  };
  const configuredFiles = [
    process.env["GIT_CONFIG_GLOBAL"] ?? join(homedir(), ".gitconfig"),
    join(
      process.env["XDG_CONFIG_HOME"] ?? join(homedir(), ".config"),
      "git",
      "config",
    ),
    ...(process.env["GIT_CONFIG_NOSYSTEM"] === "1"
      ? []
      : [process.env["GIT_CONFIG_SYSTEM"] ?? "/etc/gitconfig"]),
  ];
  for (const config of configuredFiles.filter(
    (value) => value !== "/dev/null",
  )) {
    await requireSafeGitConfig(config, new Set<string>(), false);
  }
  let configuredExcludes = "";
  try {
    ({ stdout: configuredExcludes } = await execFile(
      "git",
      [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        `safe.directory=${localGitRoot}`,
        "config",
        "--null",
        "--path",
        "--get-all",
        "core.excludesFile",
      ],
      {
        cwd: source,
        encoding: "utf8",
        env: configuredEnvironment,
        signal,
        timeout: 30_000,
      },
    ));
  } catch (error) {
    if ((error as { code?: unknown }).code !== 1) {
      throw new InvalidTargetError(
        `Unable to inspect Git ignore configuration: ${source}`,
        { cause: error },
      );
    }
  }
  for (const value of configuredExcludes.split("\0").filter(Boolean)) {
    await requireRegularGitInput(resolve(source, value));
  }
  const excludeFiles = configuredExcludes
    .split("\0")
    .filter(Boolean)
    .map((value) => `--exclude-from=${resolve(source, value)}`);
  let stdout: Buffer;
  try {
    ({ stdout } = await execFile(
      "git",
      [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        `safe.directory=${localGitRoot}`,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        ...excludeFiles,
        "--deduplicate",
        "-z",
        "--",
        ".",
      ],
      {
        cwd: source,
        encoding: "buffer",
        env: environment,
        signal,
        timeout: 60_000,
        maxBuffer: 64 * 1024 * 1024,
      },
    ));
  } catch (error) {
    throw new InvalidTargetError(
      `Unable to enumerate non-ignored repository files: ${source}`,
      { cause: error },
    );
  }
  await mkdir(destination, { recursive: true, mode: 0o700 });
  let listedPaths: string;
  try {
    listedPaths = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch (error) {
    throw new InvalidTargetError(
      `Git returned a non-UTF-8 repository path: ${source}`,
      { cause: error },
    );
  }
  for (const value of listedPaths.split("\0")) {
    if (value.length === 0) continue;
    const path = value.endsWith("/") ? value.slice(0, -1) : value;
    const parts = path.split("/");
    if (
      path.startsWith("/") ||
      path.includes("\\") ||
      parts.some((part) => part === "" || part === "." || part === "..")
    ) {
      throw new InvalidTargetError(
        `Git returned an unsafe repository path: ${path}`,
      );
    }
    if (parts.some((part) => part.toLowerCase() === ".git")) {
      continue;
    }
    if (
      bareDirectories.some(
        (directory) => path === directory || path.startsWith(`${directory}/`),
      )
    ) {
      continue;
    }
    throwIfAborted(signal);
    const entry = join(source, path);
    const metadata = await repositoryEntryMetadata(source, parts);
    const target = join(destination, path);
    if (metadata?.isDirectory() === true && !metadata.isSymbolicLink()) {
      await stageRepository(entry, target, signal, undefined, state);
    } else if (metadata?.isFile() === true && !metadata.isSymbolicLink()) {
      await stageInputFile(entry, target, metadata, state, signal);
    }
  }
  for (const scope of target.kind === "paths" ? target.paths : []) {
    const entry = join(source, scope);
    const output = join(destination, scope);
    const metadata = await repositoryEntryMetadata(source, scope.split("/"));
    if (metadata?.isFile() === true && !metadata.isSymbolicLink()) {
      if ((await lstat(output).catch(() => null)) === null) {
        await stageInputFile(entry, output, metadata, state, signal);
      }
    } else if (metadata?.isDirectory() === true && !metadata.isSymbolicLink()) {
      await stageTree(
        entry,
        output,
        signal,
        {
          skip: (name) => name.toLowerCase() === ".git",
          skipExisting: true,
        },
        state,
      );
    }
  }
}

async function repositoryEntryMetadata(
  root: string,
  parts: string[],
): Promise<Stats | null> {
  let entry = root;
  for (const [index, part] of parts.entries()) {
    entry = join(entry, part);
    const metadata = await lstat(entry).catch(() => null);
    if (metadata === null || metadata.isSymbolicLink()) return null;
    if (index < parts.length - 1 && !metadata.isDirectory()) return null;
    if (index === parts.length - 1) return metadata;
  }
  return null;
}

async function requireUnchangedDirectory(
  path: string,
  expected: Pick<Stats, "dev" | "ino">,
): Promise<void> {
  const metadata = await lstat(path).catch(() => null);
  if (
    metadata === null ||
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.dev !== expected.dev ||
    metadata.ino !== expected.ino
  ) {
    throw new InvalidTargetError(`Repository changed before staging: ${path}`);
  }
}

async function requireUnchangedOutputDirectory(
  path: string,
  expected: Pick<Stats, "dev" | "ino">,
): Promise<void> {
  const metadata = await lstat(path).catch(() => null);
  if (
    metadata === null ||
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.dev !== expected.dev ||
    metadata.ino !== expected.ino
  ) {
    throw new OutputDirectoryError(
      `Scan output directory changed before artifact handoff: ${path}`,
    );
  }
}

async function requireSafeGitInputs(
  source: string,
  gitRoot: string,
  signal: AbortSignal,
): Promise<string[]> {
  const marker = join(gitRoot, ".git");
  const markerMetadata = await lstat(marker).catch(() => null);
  if (
    markerMetadata === null ||
    markerMetadata.isSymbolicLink() ||
    (!markerMetadata.isFile() && !markerMetadata.isDirectory())
  ) {
    throw new InvalidTargetError(
      `Git worktree metadata is not safe to stage: ${marker}`,
    );
  }
  let gitDirectory = marker;
  if (markerMetadata.isFile()) {
    if (markerMetadata.size > 64 * 1024) {
      throw new InvalidTargetError(
        `Git worktree metadata is too large: ${marker}`,
      );
    }
    const pointer = await readFile(marker, "utf8");
    const match = /^gitdir:\s*(.+?)\s*$/u.exec(pointer);
    if (match === null) {
      throw new InvalidTargetError(
        `Git worktree metadata is invalid: ${marker}`,
      );
    }
    gitDirectory = resolve(gitRoot, match[1]!);
  }
  const commonPointer = join(gitDirectory, "commondir");
  const commonMetadata = await lstat(commonPointer).catch(() => null);
  let commonDirectory = gitDirectory;
  if (commonMetadata !== null) {
    await requireRegularGitInput(commonPointer);
    commonDirectory = resolve(
      gitDirectory,
      (await readFile(commonPointer, "utf8")).trim(),
    );
  }
  await requireSafeGitConfig(join(commonDirectory, "config"));
  await requireRegularGitInput(join(gitDirectory, "HEAD"));
  await requireRegularGitInput(join(gitDirectory, "index"));
  await requireRegularGitInput(join(commonDirectory, "info", "exclude"));

  const pending = [source];
  const bareDirectories: string[] = [];
  let entries = 0;
  while (pending.length > 0) {
    throwIfAborted(signal);
    const directory = pending.pop()!;
    const children = await readdir(directory, { withFileTypes: true });
    entries += children.length;
    if (entries > MAX_INPUT_ENTRIES) {
      throw new InvalidTargetError(
        `Repository contains too many entries to stage safely: ${source}`,
      );
    }
    if (hasBareGitLayout(children.map((child) => child.name))) {
      if (directory === source) {
        throw new InvalidTargetError(
          `Bare Git repositories cannot be staged safely: ${source}`,
        );
      }
      bareDirectories.push(relative(source, directory).split(sep).join("/"));
      continue;
    }
    for (const child of children) {
      if (child.name.toLowerCase() === ".git") continue;
      const path = join(directory, child.name);
      if (child.name === ".gitignore") await requireRegularGitInput(path);
      if (child.isDirectory() && !child.isSymbolicLink()) pending.push(path);
    }
  }
  let ancestor = dirname(source);
  while (source !== gitRoot && ancestor.startsWith(gitRoot)) {
    await requireRegularGitInput(join(ancestor, ".gitignore"));
    if (ancestor === gitRoot) break;
    ancestor = dirname(ancestor);
  }
  return bareDirectories;
}

async function requireSafeGitConfig(
  config: string,
  seen = new Set<string>(),
  required = true,
): Promise<void> {
  const path = resolve(config);
  if (seen.has(path)) return;
  if (seen.size >= MAX_GIT_CONFIG_FILES) {
    throw new InvalidTargetError(
      "Git configuration contains too many includes.",
    );
  }
  seen.add(path);
  const metadata = await lstat(path).catch(() => null);
  if (metadata === null && !required) return;
  if (
    metadata === null ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_GIT_CONFIG_BYTES
  ) {
    throw new InvalidTargetError(
      `Git configuration input must be a bounded regular file: ${path}`,
    );
  }
  const input = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  );
  let content: string;
  try {
    const opened = await input.stat();
    if (
      !opened.isFile() ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino ||
      opened.size !== metadata.size
    ) {
      throw new InvalidTargetError(
        `Git configuration changed while staging: ${path}`,
      );
    }
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(
        await input.readFile(),
      );
    } catch (error) {
      throw new InvalidTargetError(
        `Git configuration contains invalid UTF-8: ${path}`,
        { cause: error },
      );
    }
    const final = await input.stat();
    if (
      final.dev !== opened.dev ||
      final.ino !== opened.ino ||
      final.size !== opened.size ||
      final.mtimeMs !== opened.mtimeMs
    ) {
      throw new InvalidTargetError(
        `Git configuration changed while staging: ${path}`,
      );
    }
  } finally {
    await input.close();
  }
  let includeSection = false;
  for (const line of content.split(/\r?\n/u)) {
    const section = /^\s*\[\s*([^\s"\]]+)/u.exec(line);
    if (section !== null) {
      includeSection = /^include(?:if)?$/iu.test(section[1]!);
      continue;
    }
    if (!includeSection) continue;
    const include = /^\s*path\s*=\s*(?:"((?:\\.|[^"])*)"|([^#;]+))/iu.exec(
      line,
    );
    if (include === null) continue;
    let value: string;
    try {
      value =
        include[1] === undefined
          ? (include[2] ?? "").trim()
          : (JSON.parse(`"${include[1]}"`) as string);
    } catch (error) {
      throw new InvalidTargetError(
        `Git configuration contains an unsupported include path: ${path}`,
        { cause: error },
      );
    }
    if (
      value.length === 0 ||
      (value.startsWith("~") && !value.startsWith("~/"))
    ) {
      throw new InvalidTargetError(
        `Git configuration contains an unsupported include path: ${path}`,
      );
    }
    const included = value.startsWith("~/")
      ? join(homedir(), value.slice(2))
      : resolve(dirname(path), value);
    await requireSafeGitConfig(included, seen, false);
  }
}

function hasBareGitLayout(names: string[]): boolean {
  return ["HEAD", "config", "objects", "refs"].every((name) =>
    names.includes(name),
  );
}

async function stableRepositoryIdentity(
  repository: string,
  signal: AbortSignal,
): Promise<string> {
  let identity = repository.normalize("NFC");
  const gitRoot = await enclosingGitWorktreeRoot(repository, signal);
  if (gitRoot !== null) {
    try {
      const { stdout } = await execFile(
        "git",
        [
          "-c",
          "core.fsmonitor=false",
          "-c",
          "core.hooksPath=/dev/null",
          "-c",
          `safe.directory=${gitRoot}`,
          "config",
          "--get",
          "remote.origin.url",
        ],
        {
          cwd: repository,
          encoding: "utf8",
          signal,
          timeout: 30_000,
          env: sanitizedGitEnvironment(repository),
        },
      );
      identity = canonicalRemoteIdentity(stdout.trim()) ?? identity;
    } catch {
      throwIfAborted(signal);
    }
  }
  return `codex-security-target/v1:sha256:${createHash("sha256")
    .update(identity)
    .digest("hex")}`;
}

function sanitizedGitEnvironment(repository?: string): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
    ),
    OPENAI_API_KEY: undefined,
    CODEX_API_KEY: undefined,
    PATH: safeHostPath(repository),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
  };
}

function canonicalRemoteIdentity(value: string): string | null {
  const scp = value.includes("://")
    ? null
    : /^(?:[^@\s/:]+@)?([^/\s:]+):(.+)$/u.exec(value);
  try {
    const remote = new URL(scp === null ? value : `ssh://${scp[1]}/${scp[2]}`);
    if (!["http:", "https:", "ssh:", "git:"].includes(remote.protocol)) {
      return null;
    }
    const path = remote.pathname
      .replace(/(?:\.git)?\/+$/u, "")
      .replace(/\.git$/u, "");
    return `${remote.protocol}//${remote.host.toLowerCase()}${path}`;
  } catch {
    return null;
  }
}

async function requireRegularGitInput(path: string): Promise<void> {
  const metadata = await lstat(path).catch(() => null);
  if (metadata === null) return;
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new InvalidTargetError(
      `Git input must be a regular file before staging: ${path}`,
    );
  }
}

async function stageInputFile(
  source: string,
  destination: string,
  metadata: Stats,
  state: { entries: number; bytes: number },
  signal: AbortSignal,
): Promise<void> {
  state.entries += 1;
  state.bytes += metadata.size;
  if (state.entries > MAX_INPUT_ENTRIES || state.bytes > MAX_INPUT_BYTES) {
    throw new InvalidTargetError(
      `Repository inputs exceed the staging limit: ${source}`,
    );
  }
  if (metadata.size > MAX_INPUT_FILE_BYTES) {
    throw new InvalidTargetError(
      `Repository input file is too large to stage safely: ${source}`,
    );
  }
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const input = await open(
    source,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
  );
  let output;
  try {
    const opened = await input.stat();
    if (
      !opened.isFile() ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino ||
      opened.size !== metadata.size
    ) {
      throw new InvalidTargetError(
        `Repository input changed while staging: ${source}`,
      );
    }
    output = await open(
      destination,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      metadata.mode & 0o777,
    );
    const buffer = new Uint8Array(1024 * 1024);
    let offset = 0;
    while (offset < opened.size) {
      throwIfAborted(signal);
      const { bytesRead } = await input.read(
        buffer,
        0,
        Math.min(buffer.byteLength, opened.size - offset),
        offset,
      );
      if (bytesRead === 0) {
        throw new InvalidTargetError(
          `Repository input changed while staging: ${source}`,
        );
      }
      let written = 0;
      while (written < bytesRead) {
        const { bytesWritten } = await output.write(
          buffer,
          written,
          bytesRead - written,
          offset + written,
        );
        if (bytesWritten === 0) {
          throw new InvalidTargetError(
            `Unable to stage repository input: ${source}`,
          );
        }
        written += bytesWritten;
      }
      offset += bytesRead;
    }
    const final = await input.stat();
    if (
      final.dev !== opened.dev ||
      final.ino !== opened.ino ||
      final.size !== opened.size ||
      final.mtimeMs !== opened.mtimeMs
    ) {
      throw new InvalidTargetError(
        `Repository input changed while staging: ${source}`,
      );
    }
  } catch (error) {
    await output?.close();
    output = undefined;
    await rm(destination, { force: true });
    throw error;
  } finally {
    await output?.close();
    await input.close();
  }
}

async function stageTree(
  source: string,
  destination: string,
  signal: AbortSignal,
  options: { skip?: (name: string) => boolean; skipExisting?: boolean } = {},
  state: { entries: number; bytes: number } = { entries: 0, bytes: 0 },
): Promise<void> {
  throwIfAborted(signal);
  await mkdir(destination, { recursive: true, mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  if (hasBareGitLayout(entries.map((entry) => entry.name))) return;
  for (const entry of entries) {
    if (options.skip?.(entry.name) === true) continue;
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    const metadata = await lstat(from);
    if (!metadata.isFile() && ++state.entries > MAX_INPUT_ENTRIES) {
      throw new InvalidTargetError(
        `Repository contains too many entries to stage safely: ${source}`,
      );
    }
    if (metadata.isSymbolicLink()) continue;
    if (metadata.isDirectory()) {
      await stageTree(from, to, signal, options, state);
      continue;
    }
    if (!metadata.isFile()) continue;
    if (
      options.skipExisting === true &&
      (await lstat(to).catch(() => null)) !== null
    ) {
      continue;
    }
    throwIfAborted(signal);
    await stageInputFile(from, to, metadata, state, signal);
  }
}

async function copyStagedOutput(
  source: string,
  destination: string,
): Promise<void> {
  let entries = 0;
  let bytes = 0;
  const copy = async (
    from: string,
    to: string,
    depth: number,
  ): Promise<void> => {
    if (depth > 128 || ++entries > MAX_OUTPUT_ENTRIES) {
      throw new OutputDirectoryError(
        "Agents SDK scan output exceeds the entry limit.",
      );
    }
    const metadata = await lstat(from);
    if (metadata.isDirectory()) {
      await mkdir(to, { recursive: true, mode: 0o700 });
      for (const entry of await readdir(from, { withFileTypes: true })) {
        await copy(join(from, entry.name), join(to, entry.name), depth + 1);
      }
      return;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new OutputDirectoryError(
        "Agents SDK scan output contains a non-regular file.",
      );
    }
    if (metadata.size > MAX_OUTPUT_FILE_BYTES) {
      throw new OutputDirectoryError(
        "Agents SDK scan output contains an oversized file.",
      );
    }
    bytes += metadata.size;
    if (bytes > MAX_OUTPUT_BYTES) {
      throw new OutputDirectoryError(
        "Agents SDK scan output exceeds the total size limit.",
      );
    }
    const input = await open(
      from,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    let output;
    try {
      const opened = await input.stat();
      if (
        !opened.isFile() ||
        opened.dev !== metadata.dev ||
        opened.ino !== metadata.ino ||
        opened.size !== metadata.size
      ) {
        throw new OutputDirectoryError(
          "Agents SDK scan output changed during artifact handoff.",
        );
      }
      output = await open(
        to,
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          fsConstants.O_NOFOLLOW,
        0o600,
      );
      await output.writeFile(await input.readFile());
      const final = await input.stat();
      if (
        final.dev !== opened.dev ||
        final.ino !== opened.ino ||
        final.size !== opened.size ||
        final.mtimeMs !== opened.mtimeMs
      ) {
        throw new OutputDirectoryError(
          "Agents SDK scan output changed during artifact handoff.",
        );
      }
    } finally {
      await output?.close();
      await input.close();
    }
  };
  await copy(source, destination, 0);
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted)
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
}

async function isolateDockerSession(
  session: DockerSandboxSession,
): Promise<void> {
  try {
    const networks = async (): Promise<string[]> => {
      const { stdout } = await execFile(
        "docker",
        [
          "inspect",
          "--type",
          "container",
          "--format",
          "{{json .NetworkSettings.Networks}}",
          session.state.containerId,
        ],
        { encoding: "utf8", timeout: 10_000 },
      );
      return Object.keys(
        (JSON.parse(stdout) as Record<string, unknown> | null) ?? {},
      );
    };
    for (const network of await networks()) {
      await execFile(
        "docker",
        ["network", "disconnect", "-f", network, session.state.containerId],
        { encoding: "utf8", timeout: 10_000 },
      );
    }
    if ((await networks()).length > 0)
      throw new Error("network still attached");
  } catch (error) {
    throw new IncompleteScanError(
      "Unable to disable Docker sandbox network access before scanning.",
      { cause: error },
    );
  }
}

async function collectAgentsResult(
  scanDir: string,
  pluginRoot: string,
  expectation: ScanExpectation,
  summary: AgentsScanSummary,
  signal: AbortSignal,
): Promise<ScanResult> {
  const required = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const missing: string[] = [];
  for (const name of required) {
    try {
      await requireScanFile(scanDir, name, name, signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason ?? error;
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `Agents SDK scan completed without required artifacts: ${missing.join(", ")}`,
    );
  }
  const { manifest, findings, coverage } = await loadContract(scanDir, {
    pluginRoot,
    expectation,
    signal,
  });
  let sarifPath: string | null = null;
  try {
    sarifPath = await requireScanFile(
      scanDir,
      "exports/results.sarif",
      "exports/results.sarif",
      signal,
    );
  } catch (error) {
    if (signal.aborted) throw signal.reason ?? error;
  }
  const turnResult: TurnResultMetadata = {
    id: summary.responseId ?? `agents_${manifest.scan.id}`,
    engine: "agents",
    status: "completed",
    finalResponse: summary.finalResponse,
    usage: summary.usage,
  };
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    sarifPath,
    threadId: summary.responseId ?? `agents_${manifest.scan.id}`,
    turnResult,
  });
}

async function dockerWorkspaceRoot(
  environment: ProcessEnvironment,
  protectedRoot: string,
): Promise<string> {
  const configured = environmentValue(
    environment,
    "CODEX_SECURITY_DOCKER_WORKSPACE_ROOT",
  );
  const candidate = resolve(
    configured ?? join(homedir(), ".cache", "codex-security", "sandboxes"),
  );
  requireOutsideRepository(protectedRoot, candidate);
  await mkdir(candidate, { recursive: true, mode: 0o700 });
  const root = await realpath(candidate);
  requireOutsideRepository(protectedRoot, root);
  return root;
}

function environmentApiKey(environment: ProcessEnvironment): string | null {
  for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY"]) {
    const value = environmentValue(environment, name);
    if (value !== undefined) return value;
  }
  return null;
}

function environmentValue(
  environment: ProcessEnvironment,
  name: string,
): string | undefined {
  const value = environment[name];
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function requireOutsideRepository(repository: string, candidate: string): void {
  if (candidate === repository || candidate.startsWith(`${repository}${sep}`)) {
    throw new OutputDirectoryError(
      `Scan output and Agents runtime directories must be outside the repository: ${candidate}`,
    );
  }
}

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CodexSecurityError(
      "Agents SDK turn limits must be positive integers.",
    );
  }
  return value;
}

function nonEmpty(value: string | undefined, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (value.trim().length === 0) {
    throw new CodexSecurityError(`Agents SDK ${name} must not be empty.`);
  }
  return value;
}

function forwardAbort(
  signal: AbortSignal | undefined,
  controller: AbortController,
): () => void {
  if (signal === undefined) return () => undefined;
  const abort = (): void => controller.abort(signal.reason);
  if (signal.aborted) abort();
  else signal.addEventListener("abort", abort, { once: true });
  return () => signal.removeEventListener("abort", abort);
}
