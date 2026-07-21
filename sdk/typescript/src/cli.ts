#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpathSync, statSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join, parse, resolve } from "node:path";
import { cwd } from "node:process";
import { pathToFileURL } from "node:url";
import { parse as parseToml } from "smol-toml";
import {
  AgentsSecurity,
  type AgentsReasoningEffort,
  type AgentsSecurityConfig,
} from "./agents.js";
import { CodexSecurity, type ScanOptions } from "./api.js";
import type { CodexSecurityConfig, JsonObject, JsonValue } from "./config.js";
import { CodexSecurityError, ScanInterruptedError } from "./errors.js";
import type { ScanResult } from "./result.js";
import {
  environmentApiKey,
  expandHome,
  resolveCodexCommand,
} from "./runtime.js";
import { DiffTarget, type ScanMode, type ScanTarget } from "./targets.js";
import { BUNDLED_PLUGIN_VERSION, VERSION } from "./version.js";

const PROGRESS_REFRESH_MILLISECONDS = 1_000;
const MAX_CODEX_OVERRIDE_KEY_LENGTH = 1_024;
const MAX_CODEX_OVERRIDE_VALUE_LENGTH = 64 * 1_024;
const MAX_CODEX_OVERRIDE_DEPTH = 64;
const ROOT_LONG_OPTIONS = ["--help", "--version"];
const SCAN_LONG_OPTIONS = [
  "--help",
  "--path",
  "--codex",
  "--diff",
  "--head",
  "--base",
  "--output-dir",
  "--plugin-path",
  "--python",
  "--mode",
  "--engine",
  "--model",
  "--reasoning-effort",
  "--max-turns",
  "--worker-max-turns",
  "--working-tree",
  "--json",
];
const HIDE_CURSOR = "\u001B[?25l";
const SHOW_CURSOR = "\u001B[?25h";

type Writable = Pick<NodeJS.WriteStream, "write"> &
  Partial<Pick<NodeJS.WriteStream, "isTTY">> & { readonly fd?: number };
type SignalName = "SIGINT" | "SIGTERM";
type ScanEngine = "agents" | "codex";

export interface ParsedScanArguments {
  repository: string;
  paths: string[];
  diff?: string;
  workingTree: boolean;
  head?: string;
  base?: string;
  mode: ScanMode;
  outputDir?: string;
  pluginPath?: string;
  pythonPath?: string;
  engine?: ScanEngine;
  model?: string;
  reasoningEffort?: AgentsReasoningEffort;
  maxTurns?: number;
  workerMaxTurns?: number;
  codex: string[];
  json: boolean;
}

interface CliDependencies {
  createSecurity(
    config: CodexSecurityConfig | AgentsSecurityConfig,
    engine: ScanEngine,
  ): Pick<CodexSecurity, "run" | "close">;
  currentDirectory(): string;
  platform(): NodeJS.Platform;
  now(): number;
  setInterval(callback: () => void, milliseconds: number): NodeJS.Timeout;
  clearInterval(timer: NodeJS.Timeout): void;
  addSignalListener(signal: SignalName, listener: () => void): void;
  removeSignalListener(signal: SignalName, listener: () => void): void;
  writeSynchronously(stream: Writable, value: string): void;
  forceExit(signal: SignalName): void;
  hasReusableCodexSignIn(): boolean;
  runCodex(args: readonly string[]): Promise<number>;
}

const DEFAULT_DEPENDENCIES: CliDependencies = {
  createSecurity: (config, engine) =>
    engine === "agents"
      ? new AgentsSecurity(config as AgentsSecurityConfig)
      : new CodexSecurity(config as CodexSecurityConfig),
  currentDirectory: cwd,
  platform: () => process.platform,
  now: Date.now,
  setInterval: (callback, milliseconds) => setInterval(callback, milliseconds),
  clearInterval: (timer) => clearInterval(timer),
  addSignalListener: (signal, listener) => process.on(signal, listener),
  removeSignalListener: (signal, listener) => process.off(signal, listener),
  writeSynchronously: (stream, value) => {
    if (stream.fd === undefined) {
      throw new CodexSecurityError(
        "Cannot restore terminal state without a writable file descriptor.",
      );
    }
    writeSync(stream.fd, value);
  },
  forceExit: (signal) => process.kill(process.pid, signal),
  hasReusableCodexSignIn: () => hasReusableCodexSignIn(),
  runCodex: async (args) => {
    const command = resolveCodexCommand();
    const configuredHome = process.env["CODEX_HOME"];
    const environment = { ...process.env };
    if (configuredHome?.trim()) {
      environment["CODEX_HOME"] = resolve(expandHome(configuredHome));
    } else {
      delete environment["CODEX_HOME"];
    }
    const invocation = spawn(
      command.command,
      [...command.prefixArgs, ...args],
      {
        env: environment,
        cwd: parse(process.execPath).root,
        stdio: "inherit",
        windowsHide: true,
      },
    );
    let requestedSignal: SignalName | null = null;
    const onInterrupt = (): void => {
      requestedSignal = "SIGINT";
      invocation.kill("SIGINT");
    };
    const onTerminate = (): void => {
      requestedSignal = "SIGTERM";
      invocation.kill("SIGTERM");
    };
    process.on("SIGINT", onInterrupt);
    process.on("SIGTERM", onTerminate);
    try {
      return await new Promise<number>((resolve, reject) => {
        invocation.once("error", reject);
        invocation.once("exit", (status, signal) => {
          resolve(
            requestedSignal === "SIGINT" || signal === "SIGINT"
              ? 130
              : requestedSignal === "SIGTERM" || signal === "SIGTERM"
                ? 143
                : status ?? 1,
          );
        });
      });
    } finally {
      process.off("SIGINT", onInterrupt);
      process.off("SIGTERM", onTerminate);
    }
  },
};

export function rootHelp(): string {
  return [
    "usage: codex-security [-h] [--version] {scan,login,logout} ...",
    "",
    "commands:",
    "  {scan,login,logout}",
    "    scan      Run a Codex Security scan.",
    "    login     Sign in with ChatGPT or store credentials.",
    "    logout    Remove the stored sign-in.",
    "",
    "options:",
    "  -h, --help  show this help message and exit",
    "  --version   Print the SDK and bundled plugin versions, then exit.",
  ].join("\n");
}

export function scanHelp(): string {
  return [
    "usage: codex-security scan [-h] [--path PATH | --diff BASE | --working-tree]",
    "                           [--head HEAD] [--base BASE]",
    "                           [--mode {standard,deep}] [--output-dir DIR]",
    "                           [--plugin-path PATH] [--python PATH]",
    "                           [--engine {agents,codex}] [--model MODEL]",
    "                           [--reasoning-effort EFFORT] [--max-turns N]",
    "                           [--worker-max-turns N]",
    "                           [--codex KEY=VALUE]",
    "                           [--json] [repository]",
    "",
    "positional arguments:",
    "  repository            Repository root to scan (default: current directory).",
    "",
    "options:",
    "  -h, --help            show this help message and exit",
    "  --path PATH           Scan only PATH relative to the repository; repeat for",
    "                        multiple paths. Agents requires tracked files.",
    "  --diff BASE           Scan Git changes from BASE to --head (default: HEAD).",
    "  --working-tree        Scan staged and unstaged changes against --base",
    "                        (default: HEAD).",
    "  --head HEAD           Git head ref for --diff (default: HEAD).",
    "  --base BASE           Git base ref for --working-tree (default: HEAD).",
    "  --mode {standard,deep}",
    "                        Scan mode; deep mode supports repository and path",
    "                        targets only.",
    "  --output-dir DIR      Write scan artifacts to an empty DIR outside the",
    "                        repository (default: a temporary directory); SARIF,",
    "                        when produced, is written to <scan-dir>/exports/results.sarif.",
    "  --plugin-path PATH    Use a Codex Security plugin directory or ZIP instead",
    "                        of the bundled plugin.",
    "  --python PATH         Plugin Python interpreter (in-container for Docker).",
    "  --engine {agents,codex}",
    "                        Execution engine. Repository/path standard scans",
    "                        default to Agents SDK with an API key. Stored sign-in,",
    "                        diff/deep, --codex, and native Windows scans use Codex.",
    "                        Agents stages tracked files only.",
    "  --model MODEL         Agents SDK model (default: gpt-5.6).",
    "  --reasoning-effort EFFORT",
    "                        Agents SDK reasoning effort: none, minimal, low,",
    "                        medium, high, xhigh, or max (default: high).",
    "  --max-turns N         Maximum Agents SDK coordinator turns (default: 200).",
    "  --worker-max-turns N  Maximum turns for one delegated Agents SDK scan",
    "                        worker (default: 100).",
    "  --codex KEY=VALUE     Override isolated Codex config with a TOML KEY=VALUE;",
    "                        repeat as needed.",
    "  --json                Print manifest, findings, coverage, output paths, and",
    "                        turn metadata as JSON instead of the human summary.",
  ].join("\n");
}

export function versionText(): string {
  return [
    `codex-security ${VERSION}`,
    `codex-security plugin ${BUNDLED_PLUGIN_VERSION} (bundled)`,
  ].join("\n");
}

export async function main(
  argv: readonly string[] = process.argv.slice(2),
  output: Writable = process.stdout,
  errorOutput: Writable = process.stderr,
  dependencies: CliDependencies = DEFAULT_DEPENDENCIES,
): Promise<number> {
  const rootOption =
    argv[0] === undefined ? undefined : normalizeRootOption(argv[0]);
  const [rootFlag, rootInline] = splitOption(rootOption ?? "");
  if (
    argv.length === 0 ||
    (rootFlag.startsWith("-h") &&
      !rootFlag.startsWith("-h-") &&
      (rootFlag !== "-h" || rootInline === undefined)) ||
    rootOption === "--help"
  ) {
    output.write(`${rootHelp()}\n`);
    return 0;
  }
  if (rootOption === "--version") {
    output.write(`${versionText()}\n`);
    return 0;
  }
  if (argv[0] === "login" || argv[0] === "logout") {
    return await dependencies.runCodex([
      argv[0],
      ...argv.slice(1),
      "-c",
      'cli_auth_credentials_store="file"',
    ]);
  }
  if (argv[0] !== "scan") {
    return usageError(`invalid choice: ${argv[0]}`, rootHelp(), errorOutput);
  }
  const scanTokens = argv.slice(1);
  const optionTerminator = scanTokens.indexOf("--");
  const optionTokens =
    optionTerminator < 0 ? scanTokens : scanTokens.slice(0, optionTerminator);
  const helpIndex = optionTokens.findIndex((value) => {
    const [option, inline] = splitOption(value);
    const matches = SCAN_LONG_OPTIONS.filter((candidate) =>
      candidate.startsWith(option),
    );
    return (
      (option.startsWith("-h") &&
        !option.startsWith("-h-") &&
        (option !== "-h" || inline === undefined)) ||
      (inline === undefined &&
        (option === "--help" ||
          (option.startsWith("--") &&
            matches.length === 1 &&
            matches[0] === "--help")))
    );
  });
  if (
    helpIndex >= 0 &&
    (optionTerminator < 0 || helpIndex < optionTerminator)
  ) {
    try {
      parseScanArguments(scanTokens.slice(0, helpIndex), ".", true, true);
    } catch (error) {
      if (error instanceof CliUsageError) {
        return usageError(error.message, scanHelp(), errorOutput);
      }
      throw error;
    }
    output.write(`${scanHelp()}\n`);
    return 0;
  }

  let arguments_: ParsedScanArguments;
  try {
    arguments_ = parseScanArguments(
      argv.slice(1),
      dependencies.currentDirectory(),
    );
  } catch (error) {
    if (error instanceof CliUsageError) {
      return usageError(error.message, scanHelp(), errorOutput);
    }
    throw error;
  }
  return await runScan(arguments_, output, errorOutput, dependencies);
}

async function runScan(
  arguments_: ParsedScanArguments,
  output: Writable,
  errorOutput: Writable,
  dependencies: CliDependencies,
): Promise<number> {
  let scanDir: string | null = null;
  let requestedSignal: SignalName | null = null;
  let firstSignalAt = 0;
  let progress: Progress | null = null;
  const preparationAbortController = new AbortController();
  const signalListener = (signal: SignalName) => () => {
    if (requestedSignal !== null) {
      // Launchers and terminals can deliver the same initial signal twice.
      // A later repeated signal intentionally restores the conventional escape hatch.
      if (
        signal === requestedSignal &&
        dependencies.now() - firstSignalAt < 500
      ) {
        return;
      }
      requestedSignal = signal;
      progress?.stopTimer();
      if (errorOutput.isTTY === true) {
        try {
          dependencies.writeSynchronously(errorOutput, SHOW_CURSOR);
        } catch {
          // Terminal restoration is best-effort; the escape signal must still win.
        }
      }
      removeSignalListeners();
      dependencies.forceExit(signal);
      return;
    }
    requestedSignal = signal;
    firstSignalAt = dependencies.now();
    preparationAbortController.abort(signal);
  };
  const onInterrupt = signalListener("SIGINT");
  const onTerminate = signalListener("SIGTERM");
  const removeSignalListeners = (): void => {
    dependencies.removeSignalListener("SIGINT", onInterrupt);
    dependencies.removeSignalListener("SIGTERM", onTerminate);
  };
  dependencies.addSignalListener("SIGINT", onInterrupt);
  dependencies.addSignalListener("SIGTERM", onTerminate);

  let security: Pick<CodexSecurity, "run" | "close"> | null = null;
  let result: ScanResult | null = null;
  let failed = false;
  let failure: unknown;
  try {
    const target = targetFromArguments(arguments_);
    const engine = scanEngineFor(
      arguments_,
      dependencies.platform(),
      dependencies.hasReusableCodexSignIn,
    );
    const config: CodexSecurityConfig | AgentsSecurityConfig =
      engine === "agents"
        ? {
            pluginPath: arguments_.pluginPath,
            pythonPath: arguments_.pythonPath,
            model: arguments_.model,
            reasoningEffort: arguments_.reasoningEffort,
            maxTurns: arguments_.maxTurns,
            workerMaxTurns: arguments_.workerMaxTurns,
          }
        : {
            pluginPath: arguments_.pluginPath,
            pythonPath: arguments_.pythonPath,
            codexOverrides: parseCodexOverrides(arguments_.codex),
          };
    progress = new Progress(errorOutput, dependencies);
    progress.stage("Preparing scan");
    security = dependencies.createSecurity(config, engine);
    const options: ScanOptions = {
      target,
      mode: arguments_.mode,
      outputDir: arguments_.outputDir,
      signal: preparationAbortController.signal,
      onOutputDirReady: (path) => {
        scanDir = path;
      },
    };
    progress.startTimer("Running scan");
    result = await security.run(arguments_.repository, options);
    scanDir = result.scanDir;
    progress.stopTimer();
  } catch (error) {
    failed = true;
    failure = error;
  } finally {
    progress?.stopTimer();
    await security?.close().catch((error: unknown) => {
      if (!failed) {
        failed = true;
        failure = error;
      }
    });
    removeSignalListeners();
  }

  if (requestedSignal !== null) {
    return interruptedExit(requestedSignal, scanDir, errorOutput);
  }
  if (failed) {
    if (failure instanceof ScanInterruptedError) {
      errorOutput.write(`codex-security: ${failure.message}\n`);
      return 1;
    }
    const message =
      failure instanceof Error ? failure.message : String(failure);
    errorOutput.write(`codex-security: ${message}\n`);
    if (scanDir !== null) {
      errorOutput.write(
        `codex-security: Partial output was kept at ${scanDir}.\n`,
      );
    }
    return 1;
  }
  if (result === null) {
    errorOutput.write("codex-security: scan completed without a result\n");
    return 1;
  }
  progress?.stage("Scan complete");
  if (arguments_.json) {
    output.write(`${JSON.stringify(resultJson(result), null, 2)}\n`);
  } else {
    output.write(`Scan: ${result.scanDir}\n`);
    output.write(`Report: ${result.reportPath}\n`);
    output.write(`Plugin: ${result.pluginVersion}\n`);
    output.write(`Findings: ${result.findings.findings.length}\n`);
  }
  return 0;
}

export function parseScanArguments(
  values: readonly string[],
  currentDirectory = cwd(),
  ignoreUnrecognized = false,
  allowEmptyRevisions = false,
): ParsedScanArguments {
  const parsed: ParsedScanArguments = {
    repository: currentDirectory,
    paths: [],
    workingTree: false,
    mode: "standard",
    codex: [],
    json: false,
  };
  let repositorySeen = false;
  let optionsEnabled = true;
  let optionAfterRepository = false;
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index]!;
    if (optionsEnabled && token === "--") {
      if (repositorySeen && optionAfterRepository) {
        throw new CliUsageError("unrecognized argument: --");
      }
      optionsEnabled = false;
      continue;
    }
    if (optionsEnabled && token.startsWith("-") && !isPositionalValue(token)) {
      optionAfterRepository ||= repositorySeen;
      const [rawOption, inline] = splitOption(token);
      const option = normalizeScanOption(rawOption);
      if (option === "-h" || option === "--help") {
        throw new CliUsageError("--help must be used immediately after scan");
      }
      if (option === "--working-tree") {
        rejectInline(option, inline);
        parsed.workingTree = true;
      } else if (option === "--json") {
        rejectInline(option, inline);
        parsed.json = true;
      } else if (option === "--path") {
        parsed.paths.push(optionValue(values, index, option, inline));
        if (inline === undefined) index += 1;
      } else if (option === "--codex") {
        parsed.codex.push(optionValue(values, index, option, inline));
        if (inline === undefined) index += 1;
      } else if (option === "--diff") {
        parsed.diff = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--head") {
        parsed.head = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--base") {
        parsed.base = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--output-dir") {
        parsed.outputDir = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--plugin-path") {
        parsed.pluginPath = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--python") {
        parsed.pythonPath = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--mode") {
        const mode = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
        if (mode !== "standard" && mode !== "deep") {
          throw new CliUsageError(`argument --mode: invalid choice: ${mode}`);
        }
        parsed.mode = mode;
      } else if (option === "--engine") {
        const engine = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
        if (engine !== "agents" && engine !== "codex") {
          throw new CliUsageError(
            `argument --engine: invalid choice: ${engine}`,
          );
        }
        parsed.engine = engine;
      } else if (option === "--model") {
        parsed.model = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
      } else if (option === "--reasoning-effort") {
        const effort = optionValue(values, index, option, inline);
        if (inline === undefined) index += 1;
        if (
          effort !== "none" &&
          effort !== "minimal" &&
          effort !== "low" &&
          effort !== "medium" &&
          effort !== "high" &&
          effort !== "xhigh" &&
          effort !== "max"
        ) {
          throw new CliUsageError(
            `argument --reasoning-effort: invalid choice: ${effort}`,
          );
        }
        parsed.reasoningEffort = effort;
      } else if (option === "--max-turns") {
        parsed.maxTurns = positiveOptionValue(
          optionValue(values, index, option, inline),
          option,
        );
        if (inline === undefined) index += 1;
      } else if (option === "--worker-max-turns") {
        parsed.workerMaxTurns = positiveOptionValue(
          optionValue(values, index, option, inline),
          option,
        );
        if (inline === undefined) index += 1;
      } else {
        if (ignoreUnrecognized && !option.startsWith("-h-")) continue;
        throw new CliUsageError(`unrecognized argument: ${token}`);
      }
      continue;
    }
    if (repositorySeen) {
      if (ignoreUnrecognized) continue;
      throw new CliUsageError(`unrecognized argument: ${token}`);
    }
    parsed.repository = token;
    repositorySeen = true;
  }
  if (!allowEmptyRevisions) {
    for (const [option, value] of [
      ["--diff", parsed.diff],
      ["--head", parsed.head],
      ["--base", parsed.base],
    ] as const) {
      if (value?.length === 0) {
        throw new CliUsageError(`argument ${option}: expected one argument`);
      }
    }
  }
  const targetCount =
    Number(parsed.paths.length > 0) +
    Number(parsed.diff !== undefined) +
    Number(parsed.workingTree);
  if (targetCount > 1) {
    throw new CliUsageError(
      "--path, --diff, and --working-tree are mutually exclusive",
    );
  }
  return parsed;
}

export function targetFromArguments(
  arguments_: ParsedScanArguments,
): ScanTarget {
  if (arguments_.head !== undefined && arguments_.diff === undefined) {
    throw new CodexSecurityError("--head requires --diff.");
  }
  if (arguments_.base !== undefined && !arguments_.workingTree) {
    throw new CodexSecurityError("--base requires --working-tree.");
  }
  if (arguments_.paths.some((path) => path.length === 0)) {
    throw new CodexSecurityError("--path must not be empty.");
  }
  if (arguments_.paths.length > 0) return arguments_.paths;
  if (arguments_.diff !== undefined) {
    return DiffTarget.refs({
      base: arguments_.diff,
      head: arguments_.head ?? "HEAD",
    });
  }
  if (arguments_.workingTree) {
    return DiffTarget.workingTree({ base: arguments_.base ?? "HEAD" });
  }
  return "repository";
}

function scanEngineFor(
  arguments_: ParsedScanArguments,
  platform: NodeJS.Platform,
  hasReusableCodexSignIn: () => boolean,
): ScanEngine {
  const implicitCodex =
    arguments_.mode === "deep" ||
    arguments_.diff !== undefined ||
    arguments_.workingTree ||
    arguments_.codex.length > 0;
  const engine =
    arguments_.engine ??
    (implicitCodex || platform === "win32" || hasReusableCodexSignIn()
      ? "codex"
      : "agents");
  if (engine === "agents" && platform === "win32") {
    throw new CodexSecurityError(
      "The Agents SDK sandbox does not support native Windows host paths; use --engine codex or run the Agents engine from WSL.",
    );
  }
  if (engine === "agents" && implicitCodex) {
    throw new CodexSecurityError(
      "The Agents SDK engine supports standard repository/path scans only and cannot be combined with diff, working-tree, deep mode, or --codex overrides.",
    );
  }
  if (
    engine === "codex" &&
    (arguments_.model !== undefined ||
      arguments_.reasoningEffort !== undefined ||
      arguments_.maxTurns !== undefined ||
      arguments_.workerMaxTurns !== undefined)
  ) {
    throw new CodexSecurityError(
      "--model, --reasoning-effort, --max-turns, and --worker-max-turns require the Agents SDK engine.",
    );
  }
  return engine;
}

export function hasReusableCodexSignIn(
  environment: NodeJS.ProcessEnv = process.env,
): boolean {
  if (environmentApiKey(environment) !== null) {
    return false;
  }
  const configuredHome = environment["CODEX_HOME"];
  try {
    return statSync(
      join(
        expandHome(
          configuredHome?.trim() ? configuredHome : join(homedir(), ".codex"),
        ),
        "auth.json",
      ),
    ).isFile();
  } catch {
    return false;
  }
}

function positiveOptionValue(value: string, option: string): number {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new CliUsageError(`argument ${option}: expected a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new CliUsageError(`argument ${option}: expected a positive integer`);
  }
  return parsed;
}

export function parseCodexOverrides(values: readonly string[]): JsonObject {
  const result = Object.create(null) as JsonObject;
  for (const value of values) {
    const separator = value.indexOf("=");
    const key = separator < 0 ? "" : value.slice(0, separator);
    const literal = separator < 0 ? "" : value.slice(separator + 1);
    if (key.length === 0 || literal.length === 0) {
      throw new CodexSecurityError("--codex expects KEY=VALUE.");
    }
    if (
      Buffer.byteLength(key, "utf8") > MAX_CODEX_OVERRIDE_KEY_LENGTH ||
      Buffer.byteLength(literal, "utf8") > MAX_CODEX_OVERRIDE_VALUE_LENGTH
    ) {
      throw new CodexSecurityError("--codex key or value exceeds the limit.");
    }
    const parts = key.split(".");
    if (
      parts.length > MAX_CODEX_OVERRIDE_DEPTH ||
      parts.some(
        (part) =>
          part.length === 0 ||
          part === "__proto__" ||
          part === "prototype" ||
          part === "constructor",
      )
    ) {
      throw new CodexSecurityError("Invalid --codex key.");
    }
    let parsed: JsonValue;
    try {
      parsed = parseToml(`value = ${literal}`)["value"] as JsonValue;
    } catch {
      throw new CodexSecurityError("Invalid --codex TOML value.");
    }
    let cursor = result;
    for (const part of parts.slice(0, -1)) {
      const existing = Object.hasOwn(cursor, part) ? cursor[part] : undefined;
      if (existing === undefined) {
        const nested = Object.create(null) as JsonObject;
        cursor[part] = nested;
        cursor = nested;
      } else if (isJsonObject(existing)) {
        cursor = existing;
      } else {
        throw new CodexSecurityError("Conflicting --codex key.");
      }
    }
    const final = parts.at(-1)!;
    if (Object.hasOwn(cursor, final)) {
      throw new CodexSecurityError("Duplicate --codex key.");
    }
    cursor[final] = parsed;
  }
  return result;
}

export function resultJson(result: ScanResult): Record<string, unknown> {
  return {
    manifest: result.manifest,
    findings: result.findings,
    coverage: result.coverage,
    scanDir: result.scanDir,
    threadId: result.threadId,
    paths: {
      report: result.reportPath,
      artifacts: result.artifactsDir,
      sarif: result.sarifPath,
    },
    turn: {
      id: result.turnResult.id ?? null,
      status: result.turnResult.status ?? null,
      durationMs: result.turnResult.durationMs ?? null,
      finalResponse: result.turnResult.finalResponse ?? null,
      usage: result.turnResult.usage ?? null,
    },
  };
}

export class Progress {
  readonly #stream: Writable;
  readonly #dependencies: Pick<
    CliDependencies,
    "now" | "setInterval" | "clearInterval"
  >;
  readonly #startedAt: number;
  #timer: NodeJS.Timeout | null = null;
  #timerLineActive = false;
  #cursorHidden = false;

  public constructor(
    stream: Writable = process.stderr,
    dependencies: Pick<
      CliDependencies,
      "now" | "setInterval" | "clearInterval"
    > = DEFAULT_DEPENDENCIES,
  ) {
    this.#stream = stream;
    this.#dependencies = dependencies;
    this.#startedAt = dependencies.now();
  }

  public stage(message: string): void {
    this.#stream.write(`${this.#line(message)}\n`);
  }

  public startTimer(message: string): void {
    if (this.#stream.isTTY === true) {
      this.#stream.write(HIDE_CURSOR);
      this.#cursorHidden = true;
    }
    this.#renderTimer(message);
    this.#timer = this.#dependencies.setInterval(
      () => this.#renderTimer(message),
      PROGRESS_REFRESH_MILLISECONDS,
    );
  }

  public stopTimer(): void {
    if (this.#timer !== null) {
      this.#dependencies.clearInterval(this.#timer);
      this.#timer = null;
    }
    if (this.#timerLineActive) {
      this.#stream.write("\n");
      this.#timerLineActive = false;
    }
    if (this.#cursorHidden) {
      this.#stream.write(SHOW_CURSOR);
      this.#cursorHidden = false;
    }
  }

  #line(message: string): string {
    const elapsedSeconds = Math.max(
      0,
      Math.floor((this.#dependencies.now() - this.#startedAt) / 1_000),
    );
    const minutes = Math.floor(elapsedSeconds / 60);
    const seconds = elapsedSeconds % 60;
    return `[${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}] ${message}`;
  }

  #renderTimer(message: string): void {
    this.#stream.write(
      `${this.#timerLineActive ? "\r" : ""}${this.#line(message)}`,
    );
    this.#timerLineActive = true;
  }
}

class CliUsageError extends Error {}

function splitOption(token: string): [string, string | undefined] {
  const separator = token.indexOf("=");
  return separator < 0
    ? [token, undefined]
    : [token.slice(0, separator), token.slice(separator + 1)];
}

function optionValue(
  values: readonly string[],
  index: number,
  option: string,
  inline: string | undefined,
): string {
  if (inline !== undefined) return inline;
  const value = values[index + 1];
  if (
    value === undefined ||
    (value.startsWith("-") && !isPositionalValue(value))
  ) {
    throw new CliUsageError(`argument ${option}: expected one argument`);
  }
  return value;
}

function isPositionalValue(value: string): boolean {
  const [option] = splitOption(value);
  const isScanOption =
    option.startsWith("-h") ||
    (option.startsWith("--") &&
      SCAN_LONG_OPTIONS.some((candidate) => candidate.startsWith(option)));
  return (
    value === "-" ||
    (!isScanOption && value.includes(" ")) ||
    /^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)$/u.test(
      value,
    )
  );
}

function rejectInline(option: string, inline: string | undefined): void {
  if (inline !== undefined)
    throw new CliUsageError(`argument ${option}: ignored explicit argument`);
}

function normalizeScanOption(option: string): string {
  if (!option.startsWith("--") || SCAN_LONG_OPTIONS.includes(option)) {
    return option;
  }
  const matches = SCAN_LONG_OPTIONS.filter((candidate) =>
    candidate.startsWith(option),
  );
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) {
    throw new CliUsageError(`ambiguous option: ${option}`);
  }
  return option;
}

function normalizeRootOption(option: string): string {
  if (!option.startsWith("--") || ROOT_LONG_OPTIONS.includes(option)) {
    return option;
  }
  const matches = ROOT_LONG_OPTIONS.filter((candidate) =>
    candidate.startsWith(option),
  );
  return matches.length === 1 ? matches[0]! : option;
}

function usageError(message: string, help: string, errorOutput: Writable): 2 {
  errorOutput.write(`${help.split("\n", 1)[0]}\n`);
  errorOutput.write(`codex-security: error: ${message}\n`);
  return 2;
}

function interruptedExit(
  signal: SignalName,
  scanDir: string | null,
  errorOutput: Writable,
): number {
  const ctrlC = signal === "SIGINT";
  errorOutput.write(
    `codex-security: Scan ${ctrlC ? "canceled by Ctrl-C" : "terminated by SIGTERM"}.\n`,
  );
  errorOutput.write(
    scanDir === null
      ? "codex-security: No partial output was kept.\n"
      : `codex-security: Partial output was kept at ${scanDir}.\n`,
  );
  return ctrlC ? 130 : 143;
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invokedAsMain(): boolean {
  const entrypoint = process.argv[1];
  if (entrypoint === undefined) return false;
  if (import.meta.url === pathToFileURL(entrypoint).href) return true;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entrypoint)).href;
  } catch {
    return false;
  }
}

if (invokedAsMain()) {
  void main().then(
    (exitCode) => {
      process.exitCode = exitCode;
    },
    (error: unknown) => {
      process.stderr.write(
        `codex-security: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      process.exitCode = 1;
    },
  );
}
