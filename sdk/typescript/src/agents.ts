import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import { promisify } from "node:util";
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
  dir,
  file,
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
  repositoryRevision,
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
let tracingUsers = 0;
let tracingWasDisabled = false;

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
  target: NormalizedTarget;
  scanDir: string;
  pluginRoot: string;
  python: string;
  sandboxBaseDir: string;
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
  repositoryRevision?: typeof repositoryRevision;
}

const DEFAULT_DEPENDENCIES: ClientDependencies = { environment: process.env };

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
      const revision = await (
        this.#dependencies.repositoryRevision ?? repositoryRevision
      )(repo, controller.signal);
      const repositoryIdentity = `codex-security-target/v1:sha256:${createHash(
        "sha256",
      )
        .update(repo.normalize("NFC"))
        .digest("hex")}`;
      const summary = await (this.#dependencies.runAgents ?? runAgentsScan)({
        repository: repo,
        target,
        scanDir,
        pluginRoot,
        python: this.config.pythonPath ?? "python3",
        sandboxBaseDir: staging,
        repositoryRevision: revision,
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
      const currentRevision = await (
        this.#dependencies.repositoryRevision ?? repositoryRevision
      )(repo, controller.signal);
      if (revision !== currentRevision) {
        throw new InvalidTargetError(
          `Repository revision changed during scan: ${repo}`,
        );
      }
      return await collectAgentsResult(
        scanDir,
        pluginRoot,
        {
          repository: repo,
          repositoryRevision: revision,
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
          { cause: error },
        );
      }
      throw error;
    } finally {
      removeAbort();
      this.#controllers.delete(controller);
      this.#runs.delete(running);
      finish();
      if (staging !== undefined) {
        await rm(staging, { recursive: true, force: true });
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
  const manifest = await agentsManifest(request);
  const session = await new DockerSandboxClient({
    image: DEFAULT_DOCKER_IMAGE,
    workspaceBaseDir: request.sandboxBaseDir,
  }).create({ manifest });
  const releaseTracing = suppressAgentsTracing();
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
        };
      },
    });
    const coordinator = new SandboxAgent({
      name: "Codex Security scan coordinator",
      model: request.model,
      modelSettings: {
        reasoning: { effort: request.reasoningEffort },
        parallelToolCalls: true,
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
  } finally {
    try {
      await session.close().catch(() => undefined);
      await ownedProvider?.close().catch(() => undefined);
    } finally {
      releaseTracing();
    }
  }
}

function suppressAgentsTracing(): () => void {
  if (tracingUsers++ === 0) {
    tracingWasDisabled =
      getGlobalTraceProvider().createTrace({
        name: "Codex Security tracing state probe",
      }) instanceof NoopTrace;
    setTracingDisabled(true);
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--tracingUsers === 0) setTracingDisabled(tracingWasDisabled);
  };
}

export async function agentsManifest(
  request: Pick<
    AgentsScanRequest,
    | "repository"
    | "target"
    | "scanDir"
    | "pluginRoot"
    | "python"
    | "repositoryIdentity"
  >,
): Promise<Manifest> {
  const entries: Record<
    string,
    ReturnType<typeof mount> | ReturnType<typeof dir>
  > = {
    repository: mount({ source: request.repository, readOnly: true }),
    output: mount({ source: request.scanDir, readOnly: false }),
    "scan-inputs": dir({
      children: {
        "target-paths.json": file({
          permissions: 0o400,
          content: `${JSON.stringify(
            request.target.kind === "paths" ? request.target.paths : ["."],
          )}\n`,
        }),
        "repository-identity.json": file({
          permissions: 0o400,
          content: `${JSON.stringify({ targetId: request.repositoryIdentity })}\n`,
        }),
      },
    }),
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
      ? "Repository identity: unversioned directory snapshot."
      : `Repository revision: ${request.repositoryRevision}`,
    `Repository targetId: ${request.repositoryIdentity}. Use this exact stable targetId in scan-manifest.json.`,
    ...target,
    "Use delegate_security_task for required subagent assignments and preserve phase/coverage receipts.",
    "The Agents runtime provides one ranking-worker slot; create the static rank-worker plan with --usable-worker-slots 1 and do not wait for a Codex capability-preflight result.",
    'Complete and seal the canonical JSON contract with "$PYTHON" plugin/scripts/finalize_scan_contract.py --scan-dir output --source-root repository before returning.',
  ].join("\n");
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
  } catch {}
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
  const candidate =
    configured ?? join(homedir(), ".cache", "codex-security", "sandboxes");
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
