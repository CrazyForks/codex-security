import { randomUUID } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, join, relative, resolve, sep } from "node:path";
import { homedir, tmpdir } from "node:os";
import { promisify } from "node:util";
import createDebug from "debug";
import {
  NoopTrace,
  OpenAIProvider,
  Runner,
  getGlobalTraceProvider,
  setTracingDisabled,
  tool,
  type ModelProvider,
} from "@openai/agents";
import { z } from "zod";
import {
  Capabilities,
  Manifest,
  SandboxAgent,
  dir,
  file,
  localDir,
  mount,
  skills,
  type SandboxSessionLike,
} from "@openai/agents/sandbox";
import {
  DockerSandboxClient,
  type DockerSandboxSession,
  UnixLocalSandboxClient,
  localDirLazySkillSource,
} from "@openai/agents/sandbox/local";
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
  resolvePluginPython,
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

const DEFAULT_MODEL = "gpt-5.6";
const DEFAULT_DOCKER_IMAGE = "node:22-bookworm";
const DEFAULT_REASONING_EFFORT: AgentsReasoningEffort = "high";
const DEFAULT_MAX_TURNS = 200;
const DEFAULT_WORKER_MAX_TURNS = 100;
const MAX_OUTPUT_ENTRIES = 20_000;
const MAX_OUTPUT_DEPTH = 128;
const MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 512 * 1024 * 1024;
const MAX_GIT_SUBMODULES = 256;
const execFile = promisify(execFileCallback);
const REQUIRED_PLUGIN_DIRECTORIES = [
  "references",
  "schemas",
  "scripts",
] as const;
const OPTIONAL_PLUGIN_DIRECTORIES = [
  ".codex-plugin",
  "examples",
  "preflight",
] as const;

let sensitiveTelemetryUsers = 0;
let savedDebugNamespaces = "";
let savedDontLogModelData: string | undefined;
let savedDontLogToolData: string | undefined;
let savedOpenAILogLevel: string | undefined;
let savedTracingDisabled = false;
let sandboxTimeoutUsers = 0;
let savedSetTimeout: typeof setTimeout | undefined;

export type AgentsReasoningEffort =
  | "none"
  | "minimal"
  | "low"
  | "medium"
  | "high"
  | "xhigh"
  | "max";

export type AgentsSandbox = "docker" | "unsafe-local";

export interface AgentsSecurityConfig {
  pluginPath?: string;
  pythonPath?: string;
  model?: string;
  reasoningEffort?: AgentsReasoningEffort;
  maxTurns?: number;
  workerMaxTurns?: number;
  sandbox?: AgentsSandbox;
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
  sandbox: AgentsSandbox;
  sandboxBaseDir: string;
  repositoryRevision: string | null;
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
  resolvePluginPython?: typeof resolvePluginPython;
  prepareOutputDir?: typeof prepareOutputDir;
  repositoryRevision?: typeof repositoryRevision;
}

const DEFAULT_DEPENDENCIES: ClientDependencies = {
  environment: process.env,
};

export class AgentsSecurity {
  public readonly config: Readonly<AgentsSecurityConfig>;
  readonly #dependencies: ClientDependencies;
  readonly #controllers = new Set<AbortController>();
  readonly #runs = new Set<Promise<void>>();
  #closed = false;
  #closePromise: Promise<void> | null = null;

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
    const removeExternalAbort = forwardAbort(options.signal, controller);
    this.#controllers.add(controller);
    let finish!: () => void;
    const running = new Promise<void>((resolve) => {
      finish = resolve;
    });
    this.#runs.add(running);
    let staging: string | null = null;
    let scanDir = "";
    try {
      const check = (): void => {
        this.#requireOpen();
        throwIfAborted(controller.signal, scanDir);
      };
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
      if (process.platform === "win32") {
        throw new CodexSecurityError(
          "The Agents SDK sandbox does not support native Windows host paths; use the Codex engine or run the Agents engine from WSL.",
        );
      }
      const protectedRoot =
        (await enclosingGitWorktreeRoot(repo, controller.signal)) ?? repo;
      const repositoryMetadata = await lstat(repo);
      const targetMetadata =
        target.kind === "paths"
          ? await Promise.all(
              target.paths.map((path) => lstat(join(repo, path))),
            )
          : [];
      const requestedOutput = await validateOutputDir(options.outputDir);
      const temporaryRoot = await realpath(tmpdir());
      requireOutsideRepository(protectedRoot, temporaryRoot);
      if (requestedOutput !== null) {
        requireOutsideRepository(protectedRoot, requestedOutput);
      }
      check();

      const apiKey = environmentApiKey(this.#dependencies.environment);
      if (apiKey === null) {
        throw new AuthenticationRequiredError(
          "Agents SDK scans require OPENAI_API_KEY or CODEX_API_KEY. File-backed Codex authentication is available only with the Codex engine.",
        );
      }
      const sandbox = this.config.sandbox ?? "docker";
      if (sandbox !== "docker" && sandbox !== "unsafe-local") {
        throw new CodexSecurityError(
          "Agents SDK sandbox must be docker or unsafe-local.",
        );
      }
      const stagingRoot =
        sandbox === "docker"
          ? await dockerWorkspaceRoot(
              this.#dependencies.environment,
              protectedRoot,
            )
          : temporaryRoot;
      staging = await mkdtemp(
        join(stagingRoot, "codex-security-agents-runtime-"),
      );
      const pluginRoot = await resolvePluginPath(
        this.config.pluginPath,
        staging,
        controller.signal,
      );
      const plugin = await pluginMetadata(pluginRoot);
      const python =
        sandbox === "docker"
          ? nonEmpty(this.config.pythonPath, "pythonPath") ?? "python3"
          : await (
              this.#dependencies.resolvePluginPython ?? resolvePluginPython
            )({
              configuredPath: this.config.pythonPath,
              environment: withoutApiKeys(this.#dependencies.environment),
              signal: controller.signal,
            });
      check();
      const currentRepository = await normalizeRepository(
        repositoryPath,
        controller.signal,
      );
      const currentRepositoryMetadata = await lstat(currentRepository);
      const currentTarget = await normalizeTarget(
        repo,
        target.kind === "paths" ? target.paths : "repository",
        controller.signal,
      );
      const currentTargetMetadata =
        currentTarget.kind === "paths"
          ? await Promise.all(
              currentTarget.paths.map((path) => lstat(join(repo, path))),
            )
          : [];
      if (
        currentRepository !== repo ||
        currentRepositoryMetadata.dev !== repositoryMetadata.dev ||
        currentRepositoryMetadata.ino !== repositoryMetadata.ino ||
        currentTarget.kind !== target.kind ||
        (target.kind === "paths" &&
          currentTarget.kind === "paths" &&
          (currentTarget.paths.length !== target.paths.length ||
            currentTarget.paths.some(
              (path, index) => path !== target.paths[index],
            ) ||
            currentTargetMetadata.some(
              (metadata, index) =>
                metadata.dev !== targetMetadata[index]?.dev ||
                metadata.ino !== targetMetadata[index]?.ino,
            )))
      ) {
        throw new InvalidTargetError(
          `Repository or path target changed during scan preparation: ${repo}`,
        );
      }
      scanDir = await (this.#dependencies.prepareOutputDir ?? prepareOutputDir)(
        requestedOutput ?? undefined,
        basename(repo),
        temporaryRoot,
        (path) => requireOutsideRepository(protectedRoot, path),
      );
      requireOutsideRepository(protectedRoot, scanDir);
      requireModelSafeOutputDir(scanDir);
      const scanDirectoryMetadata = await lstat(scanDir);
      options.onOutputDirReady?.(scanDir);
      scanDir = await validatePreparedOutputDir(
        scanDir,
        (path) => requireOutsideRepository(protectedRoot, path),
        scanDirectoryMetadata,
      );
      check();

      const sourceRevision = await (
        this.#dependencies.repositoryRevision ?? repositoryRevision
      )(repo, controller.signal);
      const expectedRevision = protectedRoot === repo ? sourceRevision : null;
      const stagedRepository = await stageRepositoryWithoutSymbolicLinks(
        repo,
        staging,
        controller.signal,
        sandbox === "docker",
        expectedRevision,
        target,
        protectedRoot !== repo,
      );
      const stagedPlugin =
        sandbox === "docker"
          ? await stageTreeWithoutSymbolicLinks(
              pluginRoot,
              join(staging, "plugin-input"),
              controller.signal,
            )
          : pluginRoot;
      const currentRevision = await (
        this.#dependencies.repositoryRevision ?? repositoryRevision
      )(repo, controller.signal);
      if (currentRevision !== sourceRevision) {
        throw new InvalidTargetError(
          `Repository revision changed during scan preparation: ${repo}`,
        );
      }
      check();

      const summary = await (this.#dependencies.runAgents ?? runAgentsScan)({
        repository: stagedRepository,
        target,
        scanDir,
        pluginRoot: stagedPlugin,
        python,
        sandbox,
        sandboxBaseDir: staging,
        repositoryRevision: expectedRevision,
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
      check();
      const expectation: ScanExpectation = {
        repository: repo,
        repositoryRevision: expectedRevision,
        target,
        mode: "standard",
        pluginVersion: plugin.version,
      };
      return await collectAgentsResult(
        scanDir,
        pluginRoot,
        expectation,
        summary,
        controller.signal,
      );
    } catch (error) {
      if (
        controller.signal.aborted &&
        !(error instanceof ScanInterruptedError)
      ) {
        throw new ScanInterruptedError(
          `Codex Security scan was interrupted${scanDir ? `; partial output remains at ${scanDir}` : ""}.`,
          scanDir,
          { cause: error },
        );
      }
      throw error;
    } finally {
      removeExternalAbort();
      this.#controllers.delete(controller);
      try {
        if (staging !== null) {
          await rm(staging, { recursive: true, force: true });
        }
      } finally {
        this.#runs.delete(running);
        finish();
      }
    }
  }

  public async close(): Promise<void> {
    if (this.#closePromise !== null) return await this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#finishClose();
    await this.#closePromise;
  }

  async #finishClose(): Promise<void> {
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
  const client =
    request.sandbox === "docker"
      ? new DockerSandboxClient({
          image: DEFAULT_DOCKER_IMAGE,
          workspaceBaseDir: request.sandboxBaseDir,
        })
      : new UnixLocalSandboxClient({
          workspaceBaseDir: request.sandboxBaseDir,
        });
  const session = await client.create({ manifest });
  const releaseTelemetry = suppressSensitiveAgentsTelemetry();
  const releaseSandboxTimeouts = suppressReferencedSandboxTimeouts();
  let ownedProvider: OpenAIProvider | undefined;
  let summary: AgentsScanSummary | undefined;
  let failure: unknown;
  try {
    if (request.sandbox === "docker") {
      await isolateDockerSession(session as DockerSandboxSession);
    }
    const provider =
      dependencies.modelProvider ??
      (ownedProvider = new OpenAIProvider({
        apiKey: request.apiKey,
        baseURL: request.baseURL,
        organization: request.organization,
        project: request.project,
      }));
    const preflight = await session.exec({
      cmd: [
        'command -v "$PYTHON" >/dev/null',
        ...(request.sandbox === "unsafe-local"
          ? [
              '"$PYTHON" -c \'import json,os,stat; root=os.path.realpath("repository"); entries=json.load(open("repository-executables.json",encoding="utf-8")); [(lambda p,m: os.chmod(p,(os.lstat(p).st_mode & 0o666) | m) if stat.S_ISREG(os.lstat(p).st_mode) and os.path.commonpath((root,os.path.realpath(p))) == root else (_ for _ in ()).throw(RuntimeError("unsafe executable entry")))(os.path.join(root,*path.split("/")),mode) for path,mode in entries]\'',
            ]
          : []),
        "command -v git >/dev/null",
        "command -v grep >/dev/null",
        "command -v find >/dev/null",
        "test -f plugin/scripts/finalize_scan_contract.py",
        "test -f plugin/scripts/generate_rank_input.py",
        "test -r target-paths.json",
        "test -r repository-executables.json",
      ].join(" && "),
      workdir: "/workspace",
      login: false,
    });
    if (preflight.exitCode !== 0) {
      throw new IncompleteScanError(
        `Agents SDK sandbox is missing required scan tools or inputs: ${preflight.stderr.trim() || preflight.stdout.trim() || `exit ${preflight.exitCode}`}`,
      );
    }
    const runnerConfig = {
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
        "You are a bounded Codex Security scan worker running inside an Agents SDK sandbox.",
        "Follow the exact assignment from the coordinator and the referenced phase skill under plugin/skills.",
        "Use repository, plugin, output, and target-paths.json as workspace-relative paths. Never edit repository files.",
        "The Agents runtime verifies one usable ranking-worker slot; process an assigned ranking slot completely before returning its exact receipt.",
        "Write only the requested worker-local artifacts and receipts, then return a concise evidence-backed summary.",
      ].join("\n"),
      capabilities: Capabilities.default(),
    });
    const delegate = worker.asTool({
      toolName: "delegate_security_task",
      toolDescription:
        "Run one bounded Codex Security ranking, file-review, validation, attack-path, write-up, or hardening assignment in the shared scan sandbox. Provide exact ownership, source paths, artifact paths, and expected receipt/output.",
      runConfig: runnerConfig,
      runOptions: {
        sandbox: { session },
        maxTurns: request.workerMaxTurns,
      },
    });
    const skillSource = localDirLazySkillSource({
      src: join(request.pluginRoot, "skills"),
      baseDir: request.pluginRoot,
    });
    const skillIndex = skillSource.getIndex?.(manifest, "plugin/skills") ?? [];
    const loadMountedSkill = tool({
      name: "load_skill",
      description:
        "Load a bundled Codex Security phase skill from the read-only Docker plugin mount.",
      parameters: z.object({ skill_name: z.string().min(1) }),
      execute: async ({ skill_name }) => {
        const matches = skillIndex.filter((entry) => entry.name === skill_name);
        if (matches.length !== 1) {
          throw new IncompleteScanError(
            `Unknown or ambiguous Agents scan skill: ${skill_name}`,
          );
        }
        const match = matches[0]!;
        return {
          status: "already_loaded",
          skill_name: match.name,
          path: `plugin/skills/${match.path ?? match.name}`,
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
        "You coordinate a non-interactive Codex Security standard scan inside an Agents SDK sandbox.",
        "The host repository has been copied to repository; never edit it. Write every scan artifact below output.",
        'Use "$PYTHON" for every plugin helper invocation; its value is supplied by the trusted host environment.',
        "The full plugin helper/reference tree is under plugin and all phase skills are under plugin/skills.",
        "When the scan skill calls for a subagent, call delegate_security_task with one bounded assignment; the tool shares this sandbox and cannot recursively delegate.",
        "For repository ranking, the Agents runtime verifies one usable worker slot. Set usable_worker_slots to 1 when creating the static rank-worker plan; the Codex capability-preflight result is not available in this runtime.",
        "The Agents host has no Codex app, MCP workbench, goals, native fanout, or config-preflight tools. Use the terminal/chat workflow and do not wait for UI or invoke Codex-only tools.",
        "Complete all required phase, coverage, and candidate-ledger receipts, then run the terminal finalizer exactly once. Never claim complete coverage when a required worker or receipt is missing.",
      ].join("\n"),
      tools: [
        delegate,
        ...(request.sandbox === "docker" ? [loadMountedSkill] : []),
      ],
      capabilities: [
        ...Capabilities.default(),
        ...(request.sandbox === "unsafe-local"
          ? [
              skills({
                lazyFrom: skillSource,
                skillsPath: "plugin/skills",
              }),
            ]
          : []),
      ],
    });
    const runner = new Runner(runnerConfig);
    const stream = await runner.run(coordinator, agentsScanPrompt(request), {
      stream: true,
      signal: request.signal,
      sandbox: { session },
      maxTurns: request.maxTurns,
    });
    for await (const _event of stream) {
      // Consuming the stream keeps tool execution and cancellation responsive.
    }
    await stream.completed;
    if (stream.error !== undefined && stream.error !== null) throw stream.error;
    if (stream.cancelled || request.signal.aborted) {
      throw new DOMException("Agents SDK scan was aborted.", "AbortError");
    }
    const usage = stream.runContext.usage;
    summary = {
      responseId: stream.lastResponseId,
      finalResponse:
        typeof stream.finalOutput === "string" ? stream.finalOutput : undefined,
      usage: {
        requests: usage.requests,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        totalTokens: usage.totalTokens,
        inputTokensDetails: usage.inputTokensDetails,
        outputTokensDetails: usage.outputTokensDetails,
      },
    };
  } catch (error) {
    failure = error;
  }
  try {
    await copySandboxOutput(session, request.scanDir);
  } catch (error) {
    if (failure === undefined) failure = error;
  } finally {
    await session.close().catch(() => undefined);
    await ownedProvider?.close().catch(() => undefined);
    releaseSandboxTimeouts();
    releaseTelemetry();
  }
  if (failure !== undefined) throw failure;
  if (summary === undefined) {
    throw new IncompleteScanError("Agents SDK scan ended without a result.");
  }
  return summary;
}

export async function agentsManifest(
  request: Pick<
    AgentsScanRequest,
    "repository" | "target" | "pluginRoot" | "python"
  > & { sandbox?: AgentsSandbox },
): Promise<Manifest> {
  const entries: Record<
    string,
    | ReturnType<typeof localDir>
    | ReturnType<typeof mount>
    | ReturnType<typeof dir>
    | ReturnType<typeof file>
  > = {
    repository:
      request.sandbox === "docker"
        ? mount({ source: request.repository, readOnly: true })
        : localDir({ src: request.repository }),
    output: dir(),
    "target-paths.json": file({
      permissions: 0o400,
      content: `${JSON.stringify(
        request.target.kind === "paths" ? request.target.paths : ["."],
      )}\n`,
    }),
    "repository-executables.json": file({
      permissions: 0o400,
      content: `${JSON.stringify(await repositoryExecutablePaths(request.repository))}\n`,
    }),
  };
  for (const name of REQUIRED_PLUGIN_DIRECTORIES) {
    const source = join(request.pluginRoot, name);
    const metadata = await lstat(source).catch(() => null);
    if (
      metadata === null ||
      !metadata.isDirectory() ||
      metadata.isSymbolicLink()
    ) {
      throw new IncompleteScanError(
        `Selected plugin is missing Agents scan runtime directory: ${name}`,
      );
    }
    entries[`plugin/${name}`] =
      request.sandbox === "docker"
        ? mount({ source, readOnly: true })
        : localDir({ src: source });
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
    entries[`plugin/${name}`] =
      request.sandbox === "docker"
        ? mount({ source, readOnly: true })
        : localDir({ src: source });
  }
  const scanSkill = join(
    request.pluginRoot,
    "skills",
    "security-scan",
    "SKILL.md",
  );
  const scanSkillMetadata = await lstat(scanSkill).catch(() => null);
  if (
    scanSkillMetadata === null ||
    !scanSkillMetadata.isFile() ||
    scanSkillMetadata.isSymbolicLink()
  ) {
    throw new IncompleteScanError(
      "Selected plugin is missing scan skill: security-scan",
    );
  }
  if (request.sandbox === "docker") {
    entries["plugin/skills"] = mount({
      source: join(request.pluginRoot, "skills"),
      readOnly: true,
    });
  }
  return new Manifest({
    root: "/workspace",
    entries,
    extraPathGrants: [
      {
        path: request.repository,
        readOnly: true,
        description: "Source repository staged into the scan sandbox.",
      },
      {
        path: request.pluginRoot,
        readOnly: true,
        description: "Codex Security scan skills and helpers.",
      },
    ],
    environment: {
      PYTHON: request.python,
      PYTHONUNBUFFERED: "1",
      PYTHONDONTWRITEBYTECODE: "1",
      CODEX_SECURITY_AGENT_RUNTIME: "agents-sdk",
      CODEX_SECURITY_TARGET_PATHS_FILE: "target-paths.json",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "safe.directory",
      GIT_CONFIG_VALUE_0: "/workspace/repository",
    },
  });
}

export function agentsScanPrompt(
  request: Pick<AgentsScanRequest, "target" | "repositoryRevision">,
): string {
  const targetInstruction =
    request.target.kind === "paths"
      ? [
          "Scan target: the paths listed in target-paths.json.",
          'Generate one combined inventory with "$PYTHON" plugin/scripts/generate_rank_input.py make-repo-rank-input --repo repository --scopes-file target-paths.json --out output/artifacts/02_discovery/rank_input.jsonl.',
          'Before finalization, bind every requested scope with "$PYTHON" plugin/scripts/generate_rank_input.py bind-repo-scopes --scopes-file target-paths.json --manifest output/scan-manifest.json --coverage output/coverage.json.',
          "Do not print, evaluate, or modify target-paths.json.",
        ].join(" ")
      : "Scan target: the entire repository.";
  return [
    "Use the $security-scan skill at plugin/skills/security-scan/SKILL.md.",
    "Run a standard, non-interactive repository/path scan with the Agents SDK CLI runtime.",
    "Repository root: repository",
    "Plugin root: plugin",
    "Use this exact scan directory for all output: output",
    request.repositoryRevision === null
      ? "Repository identity: unversioned directory snapshot."
      : `Repository revision: ${request.repositoryRevision}`,
    targetInstruction,
    "Use delegate_security_task for every required subagent assignment and preserve all phase/coverage receipts.",
    "For partial repository ranking, the Agents runtime has verified one usable worker slot; create the static rank-worker plan with --usable-worker-slots 1 and do not wait for a Codex capability-preflight result.",
    'Complete and seal the canonical JSON contract with "$PYTHON" plugin/scripts/finalize_scan_contract.py --scan-dir output --source-root repository before returning.',
  ].join("\n");
}

export async function copySandboxOutput(
  session: Pick<SandboxSessionLike, "listDir" | "readFile">,
  destination: string,
  signal?: AbortSignal,
): Promise<void> {
  if (session.listDir === undefined || session.readFile === undefined) {
    throw new IncompleteScanError(
      "Agents SDK sandbox cannot return generated scan artifacts.",
    );
  }
  let entriesSeen = 0;
  let bytes = 0;
  const destinationMetadata = await lstat(destination).catch(() => null);
  if (
    destinationMetadata === null ||
    !destinationMetadata.isDirectory() ||
    destinationMetadata.isSymbolicLink()
  ) {
    throw new OutputDirectoryError(
      `Agents SDK scan output directory is not a regular directory: ${destination}`,
    );
  }
  const directoryMetadata = new Map([
    [
      destination,
      { dev: destinationMetadata.dev, ino: destinationMetadata.ino },
    ],
  ]);
  const requireUnchangedDirectories = async (target: string): Promise<void> => {
    let currentPath = target;
    while (true) {
      const expected = directoryMetadata.get(currentPath);
      const current = await lstat(currentPath).catch(() => null);
      if (
        expected === undefined ||
        current === null ||
        !current.isDirectory() ||
        current.isSymbolicLink() ||
        current.dev !== expected.dev ||
        current.ino !== expected.ino
      ) {
        throw new OutputDirectoryError(
          `Agents SDK scan output directory changed while copying artifacts: ${currentPath}`,
        );
      }
      if (currentPath === destination) break;
      currentPath = resolve(currentPath, "..");
    }
  };
  const visit = async (
    source: string,
    target: string,
    depth: number,
  ): Promise<void> => {
    throwIfAborted(signal, destination);
    if (depth > MAX_OUTPUT_DEPTH) {
      throw new OutputDirectoryError(
        "Agents SDK sandbox produced excessively nested scan output.",
      );
    }
    await requireUnchangedDirectories(target);
    const entries = await session.listDir!({ path: source });
    entriesSeen += entries.length;
    if (entriesSeen > MAX_OUTPUT_ENTRIES) {
      throw new OutputDirectoryError(
        "Agents SDK sandbox produced too many scan output entries.",
      );
    }
    for (const entry of entries) {
      throwIfAborted(signal, destination);
      if (
        entry.name.length === 0 ||
        entry.name === "." ||
        entry.name === ".." ||
        entry.name.includes("/") ||
        entry.name.includes("\\")
      ) {
        throw new OutputDirectoryError(
          `Agents SDK sandbox returned an unsafe output entry: ${entry.name}`,
        );
      }
      const childSource = `${source}/${entry.name}`;
      const childTarget = join(target, entry.name);
      if (entry.type === "dir") {
        await requireUnchangedDirectories(target);
        await mkdir(childTarget, { recursive: false, mode: 0o700 });
        const childMetadata = await lstat(childTarget).catch(() => null);
        if (
          childMetadata === null ||
          !childMetadata.isDirectory() ||
          childMetadata.isSymbolicLink()
        ) {
          throw new OutputDirectoryError(
            `Agents SDK scan output directory changed while copying artifacts: ${childTarget}`,
          );
        }
        directoryMetadata.set(childTarget, {
          dev: childMetadata.dev,
          ino: childMetadata.ino,
        });
        await visit(childSource, childTarget, depth + 1);
      } else if (entry.type === "file") {
        const content = await session.readFile!({
          path: childSource,
          maxBytes: MAX_OUTPUT_FILE_BYTES + 1,
        });
        const data =
          typeof content === "string"
            ? new TextEncoder().encode(content)
            : content;
        if (data.byteLength > MAX_OUTPUT_FILE_BYTES) {
          throw new OutputDirectoryError(
            `Agents SDK sandbox output file is too large: ${childSource}`,
          );
        }
        bytes += data.byteLength;
        if (bytes > MAX_OUTPUT_BYTES) {
          throw new OutputDirectoryError(
            "Agents SDK sandbox produced too much scan output.",
          );
        }
        await requireUnchangedDirectories(target);
        await writeFile(childTarget, data, { flag: "wx", mode: 0o600 });
      } else {
        throw new OutputDirectoryError(
          `Agents SDK sandbox output is not a regular file or directory: ${childSource}`,
        );
      }
    }
  };
  await visit("output", destination, 0);
}

async function stageRepositoryWithoutSymbolicLinks(
  repository: string,
  staging: string,
  signal: AbortSignal,
  forceSnapshot = false,
  expectedRevision: string | null = null,
  target: NormalizedTarget = { kind: "repository", paths: [] },
  withinGitWorktree = false,
): Promise<string> {
  const containsSymbolicLink = async (directory: string): Promise<boolean> => {
    throwIfAborted(signal, staging);
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      throwIfAborted(signal, staging);
      if (entry.isSymbolicLink()) return true;
      if (
        entry.isDirectory() &&
        (await containsSymbolicLink(join(directory, entry.name)))
      ) {
        return true;
      }
    }
    return false;
  };

  const gitMetadata = await lstat(join(repository, ".git")).catch(() => null);
  const gitBacked =
    gitMetadata?.isFile() === true || gitMetadata?.isDirectory() === true;
  const stageFilter =
    gitBacked || withinGitWorktree
      ? {
          includedPaths: await gitIncludedPaths(repository, signal),
          explicitScopes: target.kind === "paths" ? target.paths : [],
        }
      : undefined;
  if (
    !forceSnapshot &&
    !gitBacked &&
    !withinGitWorktree &&
    !(await containsSymbolicLink(repository))
  ) {
    return repository;
  }
  const snapshot = join(staging, "repository-input");
  await stageTreeWithoutSymbolicLinks(
    repository,
    snapshot,
    signal,
    gitBacked ? join(repository, ".git") : undefined,
    stageFilter,
  );
  if (gitBacked && expectedRevision !== null) {
    await makeSelfContainedWorktreeSnapshot(
      repository,
      snapshot,
      expectedRevision,
      signal,
    );
  }
  return snapshot;
}

async function stageTreeWithoutSymbolicLinks(
  sourceRoot: string,
  destination: string,
  signal: AbortSignal,
  omittedPath?: string,
  stageFilter?: {
    includedPaths: ReadonlySet<string>;
    explicitScopes: readonly string[];
  },
): Promise<string> {
  await cp(sourceRoot, destination, {
    recursive: true,
    filter: async (source) => {
      if (source === omittedPath || basename(source) === ".git") return false;
      if (stageFilter !== undefined) {
        const path = relative(sourceRoot, source).split(sep).join("/");
        const explicitlyRequested = stageFilter.explicitScopes.some(
          (scope) =>
            scope === "." ||
            path === scope ||
            path.startsWith(`${scope}/`) ||
            scope.startsWith(`${path}/`),
        );
        if (
          path.length > 0 &&
          !stageFilter.includedPaths.has(path) &&
          !explicitlyRequested
        ) {
          return false;
        }
      }
      const metadata = await lstat(source);
      return metadata.isFile() || metadata.isDirectory();
    },
  });
  throwIfAborted(signal, destination);
  return destination;
}

async function gitIncludedPaths(
  repository: string,
  signal: AbortSignal,
): Promise<Set<string>> {
  const paths = new Set<string>();
  const pending = [{ repository, prefix: "" }];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const current = pending.pop()!;
    const canonical = await realpath(current.repository);
    if (visited.has(canonical)) continue;
    visited.add(canonical);
    if (visited.size > MAX_GIT_SUBMODULES + 1) {
      throw new InvalidTargetError(
        `Repository contains too many initialized Git submodules: ${repository}`,
      );
    }
    const files = await gitListFiles(
      current.repository,
      ["--cached", "--others", "--exclude-standard"],
      signal,
      repository,
    );
    for (const value of files.split("\0")) {
      if (value.length === 0) continue;
      addGitIncludedPath(paths, current.prefix, value, repository);
    }
    const staged = await gitListFiles(
      current.repository,
      ["--stage"],
      signal,
      repository,
    );
    for (const record of staged.split("\0")) {
      if (!record.startsWith("160000 ")) continue;
      const separator = record.indexOf("\t");
      if (separator < 0) {
        throw new InvalidTargetError(
          `Git returned an invalid submodule entry while staging: ${repository}`,
        );
      }
      const value = record.slice(separator + 1);
      addGitIncludedPath(paths, current.prefix, value, repository);
      const nestedRepository = join(current.repository, value);
      const metadata = await lstat(nestedRepository).catch(() => null);
      const gitMetadata = await lstat(join(nestedRepository, ".git")).catch(
        () => null,
      );
      if (metadata?.isDirectory() !== true || gitMetadata === null) continue;
      pending.push({
        repository: nestedRepository,
        prefix: current.prefix ? `${current.prefix}/${value}` : value,
      });
    }
  }
  return paths;
}

async function gitListFiles(
  repository: string,
  options: readonly string[],
  signal: AbortSignal,
  root: string,
): Promise<string> {
  try {
    const { stdout } = await execFile(
      "git",
      [
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "ls-files",
        ...options,
        "-z",
        "--",
        ".",
      ],
      {
        cwd: repository,
        encoding: "utf8",
        env: sanitizedGitEnvironment(),
        signal,
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    return stdout;
  } catch (error) {
    throwIfAborted(signal, root);
    throw new InvalidTargetError(
      `Unable to enumerate non-ignored repository files: ${repository}`,
      { cause: error },
    );
  }
}

function addGitIncludedPath(
  paths: Set<string>,
  prefix: string,
  value: string,
  repository: string,
): void {
  const parts = value.split("/");
  if (
    parts.some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new InvalidTargetError(
      `Git returned an invalid repository path while staging: ${repository}`,
    );
  }
  const relative = prefix ? `${prefix}/${value}` : value;
  const relativeParts = relative.split("/");
  for (let index = 1; index <= relativeParts.length; index += 1) {
    paths.add(relativeParts.slice(0, index).join("/"));
  }
}

async function repositoryExecutablePaths(
  repository: string,
): Promise<Array<[string, number]>> {
  const result: Array<[string, number]> = [];
  const visit = async (directory: string, relative = ""): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      const child = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(child, childRelative);
      } else if (entry.isFile()) {
        const executeBits = (await lstat(child)).mode & 0o111;
        if (executeBits !== 0) result.push([childRelative, executeBits]);
      }
    }
  };
  await visit(repository);
  return result;
}

async function makeSelfContainedWorktreeSnapshot(
  repository: string,
  snapshot: string,
  revision: string,
  signal: AbortSignal,
): Promise<void> {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu.test(revision)) {
    throw new InvalidTargetError(
      `Cannot stage an invalid Git worktree revision: ${revision}`,
    );
  }
  const environment = sanitizedGitEnvironment();
  const runGit = async (args: string[]): Promise<void> => {
    await execFile("git", args, {
      cwd: snapshot,
      encoding: "utf8",
      env: environment,
      signal,
    });
  };
  const objectFormat = revision.length === 64 ? "sha256" : "sha1";
  await runGit(["init", "--quiet", `--object-format=${objectFormat}`]);
  await runGit([
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "uploadpack.packObjectsHook=",
    "-c",
    "protocol.file.allow=always",
    "fetch",
    "--quiet",
    "--depth=1",
    "--no-tags",
    "--no-recurse-submodules",
    repository,
    revision,
  ]);
  await runGit([
    "update-ref",
    "refs/heads/codex-security-snapshot",
    "FETCH_HEAD",
  ]);
  await runGit(["symbolic-ref", "HEAD", "refs/heads/codex-security-snapshot"]);
  await runGit(["reset", "--quiet", "--mixed", "HEAD"]);
  await rm(join(snapshot, ".git", "FETCH_HEAD"), { force: true });
}

function sanitizedGitEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
  ]) {
    delete environment[name];
  }
  environment["GIT_CONFIG_NOSYSTEM"] = "1";
  environment["GIT_CONFIG_GLOBAL"] = "/dev/null";
  environment["GIT_TERMINAL_PROMPT"] = "0";
  environment["GIT_ALLOW_PROTOCOL"] = "file";
  environment["GIT_LFS_SKIP_SMUDGE"] = "1";
  return environment;
}

async function isolateDockerSession(
  session: DockerSandboxSession,
): Promise<void> {
  const inspectNetworks = async (): Promise<string[]> => {
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
    const parsed = JSON.parse(stdout) as unknown;
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new Error("Docker returned invalid container network metadata.");
    }
    return Object.keys(parsed);
  };
  try {
    for (const network of await inspectNetworks()) {
      await execFile(
        "docker",
        ["network", "disconnect", "-f", network, session.state.containerId],
        { encoding: "utf8", timeout: 10_000 },
      );
    }
    const remaining = await inspectNetworks();
    if (remaining.length > 0) {
      throw new Error(
        `Docker networks still attached: ${remaining.join(", ")}`,
      );
    }
  } catch (error) {
    throw new IncompleteScanError(
      "Unable to disable Docker sandbox network access before scanning.",
      { cause: error },
    );
  }
}

function suppressSensitiveAgentsTelemetry(): () => void {
  if (sensitiveTelemetryUsers++ === 0) {
    savedDebugNamespaces = createDebug.disable();
    createDebug.enable(
      [savedDebugNamespaces, "-openai-agents:*"].filter(Boolean).join(","),
    );
    savedDontLogModelData = process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"];
    savedDontLogToolData = process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"];
    savedOpenAILogLevel = process.env["OPENAI_LOG"];
    process.env["OPENAI_AGENTS_DONT_LOG_MODEL_DATA"] = "1";
    process.env["OPENAI_AGENTS_DONT_LOG_TOOL_DATA"] = "1";
    process.env["OPENAI_LOG"] = "warn";
    savedTracingDisabled =
      getGlobalTraceProvider().createTrace({
        name: "Codex Security tracing state probe",
      }) instanceof NoopTrace;
    setTracingDisabled(true);
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--sensitiveTelemetryUsers !== 0) return;
    createDebug.enable(savedDebugNamespaces);
    restoreEnvironmentValue(
      "OPENAI_AGENTS_DONT_LOG_MODEL_DATA",
      savedDontLogModelData,
    );
    restoreEnvironmentValue(
      "OPENAI_AGENTS_DONT_LOG_TOOL_DATA",
      savedDontLogToolData,
    );
    restoreEnvironmentValue("OPENAI_LOG", savedOpenAILogLevel);
    setTracingDisabled(savedTracingDisabled);
  };
}

export function suppressReferencedSandboxTimeouts(): () => void {
  if (sandboxTimeoutUsers++ === 0) {
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
    if (--sandboxTimeoutUsers !== 0) return;
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
    id: summary.responseId,
    status: "completed",
    finalResponse: summary.finalResponse,
    usage: summary.usage,
    engine: "agents",
  };
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId: summary.responseId ?? `agents-${randomUUID()}`,
    turnResult,
    sarifPath,
  });
}

function environmentApiKey(environment: ProcessEnvironment): string | null {
  return (
    environmentValue(environment, "OPENAI_API_KEY") ??
    environmentValue(environment, "CODEX_API_KEY") ??
    null
  );
}

function environmentValue(
  environment: ProcessEnvironment,
  name: string,
): string | undefined {
  const key = Object.keys(environment).find(
    (candidate) => candidate.toUpperCase() === name,
  );
  const value = key === undefined ? undefined : environment[key];
  return typeof value === "string" && value.trim().length > 0
    ? value
    : undefined;
}

function withoutApiKeys(environment: ProcessEnvironment): ProcessEnvironment {
  return Object.fromEntries(
    Object.entries(environment).filter(([name]) => {
      const upper = name.toUpperCase();
      return upper !== "OPENAI_API_KEY" && upper !== "CODEX_API_KEY";
    }),
  );
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

function throwIfAborted(
  signal: AbortSignal | undefined,
  scanDir: string,
): void {
  if (signal?.aborted !== true) return;
  throw new ScanInterruptedError(
    `Codex Security scan was interrupted${scanDir ? `; partial output remains at ${scanDir}` : ""}.`,
    scanDir,
  );
}

function forwardAbort(
  source: AbortSignal | undefined,
  target: AbortController,
): () => void {
  if (source === undefined) return () => undefined;
  const listener = (): void => target.abort(source.reason);
  if (source.aborted) listener();
  else source.addEventListener("abort", listener, { once: true });
  return () => source.removeEventListener("abort", listener);
}
