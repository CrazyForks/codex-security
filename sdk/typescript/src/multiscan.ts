import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  type FileHandle,
  copyFile,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { Transform } from "node:stream";
import { promisify } from "node:util";
import Papa from "papaparse";
import type { CodexSecurity } from "./api.js";
import {
  bulkScanRepositoryLimitError,
  MAX_BULK_SCAN_INVENTORY_BYTES,
  MAX_BULK_SCAN_REPOSITORIES,
} from "./bulk-scan-limits.js";
import type { CodexSecurityConfig } from "./config.js";
import { loadContract } from "./contract.js";
import type { ScanCost } from "./cost.js";
import { resolvePluginPath } from "./runtime.js";
import type { ScanMode } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const REQUIRED_ARTIFACTS = [
  "scan-manifest.json",
  "findings.json",
  "coverage.json",
  "report.md",
];
const MAX_LOCK_OWNER_BYTES = 4 * 1024;
const MAX_RECEIPT_LEDGER_BYTES = 64 * 1024 * 1024;
const MAX_RECEIPT_LINE_BYTES = 1024 * 1024;
const MAX_RECEIPT_ERROR_BYTES = 64 * 1024;
const pendingReceiptAppends = new Map<string, Promise<void>>();

interface MultiscanLockOwner {
  pid: number;
  token?: string;
}

interface MultiscanTask {
  id: string;
  repository: string;
  revision: string;
  mode: ScanMode;
  scope?: string;
}

interface MultiscanReceipt extends MultiscanTask {
  status: "completed" | "failed";
  attempt: number;
  outputDir: string;
  cost?: ScanCost;
  error?: string;
}

export interface MultiscanOptions {
  inputPath: string;
  outputDir: string;
  githubHost?: string;
  workers: number;
  mode: ScanMode;
  maxAttempts: number;
  config: CodexSecurityConfig;
  createSecurity(
    config: CodexSecurityConfig,
  ): Pick<CodexSecurity, "run" | "close">;
  signal?: AbortSignal;
  onProgress?(event: {
    repository: string;
    status: "started" | "completed" | "failed";
    attempt: number;
    error?: string;
  }): void;
}

export interface MultiscanResult {
  total: number;
  completed: number;
  failed: number;
  skipped: number;
  resultsPath: string;
}

export async function runMultiscan(
  options: MultiscanOptions,
): Promise<MultiscanResult> {
  options.signal?.throwIfAborted();
  if (!Number.isSafeInteger(options.workers) || options.workers < 1) {
    throw new Error("Multiscan workers must be a positive integer.");
  }
  if (!Number.isSafeInteger(options.maxAttempts) || options.maxAttempts < 1) {
    throw new Error("Multiscan max attempts must be a positive integer.");
  }
  const tasks = await parseInventory(
    options.inputPath,
    dirname(resolve(options.inputPath)),
    options.mode,
    options.signal,
  );
  const output = resolve(options.outputDir);
  await ensureOutputDirectory(output);
  const unlock = await acquireLock(output);
  let pluginWorkspace: string | null = null;
  let pluginRoot: Promise<string> | null = null;
  const resumePluginRoot = (): Promise<string> =>
    (pluginRoot ??= (async () => {
      if (options.config.pluginPath !== undefined) {
        pluginWorkspace = await mkdirTemporaryPluginWorkspace(output);
      }
      return await resolvePluginPath(
        options.config.pluginPath,
        pluginWorkspace ?? output,
        options.signal,
      );
    })());
  try {
    return await runCampaign(options, tasks, output, resumePluginRoot);
  } finally {
    await Promise.all([
      unlock(),
      pluginWorkspace === null
        ? undefined
        : rm(pluginWorkspace, { recursive: true, force: true }),
    ]);
  }
}

async function runCampaign(
  options: MultiscanOptions,
  tasks: MultiscanTask[],
  output: string,
  resumePluginRoot: () => Promise<string>,
): Promise<MultiscanResult> {
  const ledger = join(output, "results.jsonl");
  await ensureOutputDirectory(join(output, "checkouts"));
  await ensureOutputDirectory(join(output, "artifacts"));
  await ensureManifest(join(output, "manifest.json"), tasks);
  const receipts = await readReceipts(ledger, options.signal);
  const pending: Array<{ task: MultiscanTask; attempt: number }> = [];
  let completed = 0;
  let failed = 0;
  for (const task of tasks) {
    const recorded = receipts.get(task.id.toLowerCase());
    const receipt =
      recorded !== undefined && sameMultiscanTask(recorded, task)
        ? recorded
        : undefined;
    if (receipt?.status === "completed") {
      if (
        receipt.outputDir ===
          join(output, "artifacts", task.id, `attempt-${receipt.attempt}`) &&
        (await hasArtifacts(
          receipt.outputDir,
          await resumePluginRoot(),
          task,
          options.signal,
        ))
      ) {
        completed += 1;
      } else {
        pending.push({
          task,
          attempt:
            receipt.attempt >= options.maxAttempts
              ? Math.max(0, receipt.attempt - 1)
              : receipt.attempt,
        });
      }
    } else if ((receipt?.attempt ?? 0) >= options.maxAttempts) {
      failed += 1;
    } else {
      pending.push({ task, attempt: receipt?.attempt ?? 0 });
    }
  }
  const skipped = completed;
  if (pending.length === 0) {
    return {
      total: tasks.length,
      completed,
      failed,
      skipped,
      resultsPath: ledger,
    };
  }

  let next = 0;
  const worker = async (
    security: Pick<CodexSecurity, "run" | "close">,
  ): Promise<void> => {
    for (;;) {
      options.signal?.throwIfAborted();
      const pendingTask = pending[next++];
      if (pendingTask === undefined) return;
      const { task } = pendingTask;
      let { attempt } = pendingTask;
      while (attempt < options.maxAttempts) {
        options.signal?.throwIfAborted();
        attempt += 1;
        const checkout = join(output, "checkouts", task.id);
        const scanDir = join(
          output,
          "artifacts",
          task.id,
          `attempt-${attempt}`,
        );
        const progress = { repository: task.id, attempt };
        options.onProgress?.({ ...progress, status: "started" });
        let failure: string | undefined;
        let cost: Readonly<ScanCost> | null = null;
        try {
          await mkdir(dirname(scanDir), { recursive: true, mode: 0o700 });
          await rm(checkout, { recursive: true, force: true });
          await mkdir(checkout, { mode: 0o700 });
          await checkoutRevision(
            task,
            checkout,
            options.signal,
            options.githubHost,
          );
          if (task.scope !== undefined) {
            const scoped = await realpath(join(checkout, task.scope));
            const outside = relative(await realpath(checkout), scoped);
            if (
              outside === ".." ||
              outside.startsWith(`..${sep}`) ||
              isAbsolute(outside)
            ) {
              throw new Error("Multiscan scope escapes its repository.");
            }
          }
          const result = await security.run(checkout, {
            ...(task.scope === undefined ? {} : { target: [task.scope] }),
            mode: task.mode,
            outputDir: scanDir,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          cost = result.cost;
          if (result.coverage.completeness !== "complete") {
            throw new Error("Multiscan repository coverage is incomplete.");
          }
        } catch (error) {
          if (options.signal?.aborted === true) options.signal.throwIfAborted();
          failure = redactError(error);
        } finally {
          await rm(checkout, { recursive: true, force: true });
        }
        const status = failure === undefined ? "completed" : "failed";
        await appendReceipt(
          ledger,
          `${JSON.stringify({
            ...task,
            status,
            attempt,
            outputDir: scanDir,
            ...(cost === null ? {} : { cost }),
            ...(failure === undefined ? {} : { error: failure }),
          })}\n`,
        );
        options.onProgress?.({
          ...progress,
          status,
          ...(failure === undefined ? {} : { error: failure }),
        });
        if (failure === undefined) {
          completed += 1;
          break;
        }
        if (attempt === options.maxAttempts) failed += 1;
      }
    }
  };
  const results = await Promise.allSettled(
    Array.from(
      { length: Math.min(options.workers, pending.length) },
      async () => {
        const security = options.createSecurity(options.config);
        try {
          await worker(security);
        } finally {
          await security.close();
        }
      },
    ),
  );
  const rejection = results.find((result) => result.status === "rejected");
  if (rejection?.status === "rejected") throw rejection.reason;
  return {
    total: tasks.length,
    completed,
    failed,
    skipped,
    resultsPath: ledger,
  };
}

async function ensureOutputDirectory(path: string): Promise<void> {
  const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
  if (metadata?.isSymbolicLink()) {
    throw new Error("Multiscan output directories must not be symbolic links.");
  }
  await mkdir(path, { recursive: true, mode: 0o700 });
}

async function appendReceipt(path: string, receipt: string): Promise<void> {
  const receiptBytes = Buffer.byteLength(receipt);
  if (receiptBytes > MAX_RECEIPT_LINE_BYTES) {
    throw new Error("Multiscan receipt exceeds the 1 MiB safety limit.");
  }
  const preceding = pendingReceiptAppends.get(path) ?? Promise.resolve();
  const append = preceding
    .catch(() => undefined)
    .then(async () => {
      const file = await openReceiptLedger(
        path,
        constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT,
      );
      try {
        if (
          (await file.stat()).size + receiptBytes >
          MAX_RECEIPT_LEDGER_BYTES
        ) {
          throw new Error(
            "Multiscan receipt ledger exceeds the 64 MiB safety limit.",
          );
        }
        await file.writeFile(receipt, "utf8");
        await file.sync();
      } finally {
        await file.close();
      }
    });
  pendingReceiptAppends.set(path, append);
  try {
    await append;
  } finally {
    if (pendingReceiptAppends.get(path) === append) {
      pendingReceiptAppends.delete(path);
    }
  }
}

function sameMultiscanTask(
  receipt: MultiscanReceipt,
  task: MultiscanTask,
): boolean {
  return (
    receipt.id.toLowerCase() === task.id.toLowerCase() &&
    receipt.repository === task.repository &&
    receipt.revision === task.revision &&
    receipt.mode === task.mode &&
    receipt.scope === task.scope
  );
}

async function openReceiptLedger(
  path: string,
  flags: number,
): Promise<FileHandle> {
  const parentPath = dirname(path);
  const parent = await lstat(parentPath);
  const expected = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (expected !== undefined &&
      (!expected.isFile() || expected.isSymbolicLink() || expected.nlink !== 1))
  ) {
    throw new Error(
      "Multiscan results ledger must be a regular, single-link, non-symbolic-link file.",
    );
  }

  let file: FileHandle | undefined;
  try {
    file = await open(
      path,
      flags |
        (process.platform === "win32"
          ? 0
          : constants.O_NOFOLLOW | constants.O_NONBLOCK),
      0o600,
    );
    const [opened, currentParent, current] = await Promise.all([
      file.stat(),
      lstat(parentPath),
      lstat(path),
    ]);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      !currentParent.isDirectory() ||
      currentParent.isSymbolicLink() ||
      currentParent.dev !== parent.dev ||
      currentParent.ino !== parent.ino ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.nlink !== 1 ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino ||
      (expected !== undefined &&
        (opened.dev !== expected.dev || opened.ino !== expected.ino))
    ) {
      throw new Error(
        "Multiscan results ledger must be a regular, single-link, non-symbolic-link file.",
      );
    }
    return file;
  } catch (error) {
    await file?.close();
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(
        "Multiscan results ledger must be a regular, single-link, non-symbolic-link file.",
        { cause: error },
      );
    }
    throw error;
  }
}

async function acquireLock(output: string): Promise<() => Promise<void>> {
  const path = join(output, ".lock");
  const recovery = join(output, ".lock.recovery");
  const token = randomUUID();
  const pending = join(output, `.lock.pending-${token}`);
  const owner = `${JSON.stringify({ pid: process.pid, token })}\n`;
  const file = await open(pending, "wx", 0o600);
  try {
    await file.writeFile(owner, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }

  try {
    for (;;) {
      try {
        await publishLock(pending, path, owner);
        const recovering = await readLockOwner(recovery);
        if (
          recovering !== null &&
          recovering.token !== token &&
          processIsRunning(recovering.pid)
        ) {
          await releaseLock(path, token);
          throw new Error("A multiscan supervisor is already running.");
        }
        return async () => await releaseLock(path, token);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }

      const existing = await readLockOwner(path);
      if (existing !== null && processIsRunning(existing.pid)) {
        const current = await readLockOwner(path);
        if (
          current !== null &&
          current.pid === existing.pid &&
          current.token === existing.token
        ) {
          throw new Error("A multiscan supervisor is already running.");
        }
        continue;
      }
      if (existing === null && (await hasCompetingPendingLock(output, token))) {
        throw new Error("A multiscan supervisor is already running.");
      }

      try {
        await publishLock(pending, recovery, owner);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const recovering = await readLockOwner(recovery);
        if (recovering !== null && processIsRunning(recovering.pid)) {
          throw new Error("A multiscan supervisor is already running.");
        }
        const stale = join(output, `.lock.recovery.stale-${randomUUID()}`);
        try {
          await rename(recovery, stale);
        } catch (renameError) {
          if ((renameError as NodeJS.ErrnoException).code === "ENOENT") {
            continue;
          }
          throw renameError;
        }
        try {
          const moved = await readLockOwner(stale);
          if (moved !== null && processIsRunning(moved.pid)) {
            try {
              await publishLock(stale, recovery, `${JSON.stringify(moved)}\n`);
            } catch (restoreError) {
              if ((restoreError as NodeJS.ErrnoException).code !== "EEXIST") {
                throw restoreError;
              }
            }
            throw new Error("A multiscan supervisor is already running.");
          }
        } finally {
          await rm(stale, { force: true });
        }
        continue;
      }
      try {
        if ((await readLockOwner(recovery))?.token !== token) {
          throw new Error("A multiscan supervisor is already running.");
        }
        const current = await readLockOwner(path);
        if (current !== null && processIsRunning(current.pid)) {
          throw new Error("A multiscan supervisor is already running.");
        }
        const metadata = await lstat(path).catch((error: unknown) => {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
          throw error;
        });
        if (metadata === null) continue;
        if (metadata.isDirectory()) {
          const stale = join(output, `.lock.stale-${randomUUID()}`);
          await rename(path, stale);
          try {
            await rename(pending, path);
          } finally {
            await rm(stale, { recursive: true, force: true });
          }
        } else {
          // Replace the stale regular lock atomically: the occupied lock name
          // is never absent while another supervisor may be running.
          await rename(pending, path);
        }
        if ((await readLockOwner(recovery))?.token !== token) {
          await releaseLock(path, token);
          throw new Error("A multiscan supervisor is already running.");
        }
        return async () => await releaseLock(path, token);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      } finally {
        await releaseLock(recovery, token);
      }
    }
  } finally {
    await rm(pending, { force: true });
  }
}

async function hasCompetingPendingLock(
  output: string,
  ownToken: string,
): Promise<boolean> {
  for (const name of await readdir(output)) {
    if (
      !name.startsWith(".lock.pending-") ||
      name === `.lock.pending-${ownToken}`
    ) {
      continue;
    }
    const owner = await readLockOwner(join(output, name));
    if (owner !== null && processIsRunning(owner.pid)) return true;
  }
  return false;
}

async function publishLock(
  pending: string,
  destination: string,
  owner: string,
): Promise<void> {
  try {
    await link(pending, destination);
    return;
  } catch (error) {
    if (
      !["EPERM", "EOPNOTSUPP", "ENOTSUP", "EXDEV"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      )
    ) {
      throw error;
    }
  }

  const file = await open(destination, "wx", 0o600);
  try {
    await file.writeFile(owner, "utf8");
    await file.sync();
  } catch (error) {
    await file.close();
    await rm(destination, { force: true });
    throw error;
  }
  await file.close();
}

async function readLockOwner(path: string): Promise<MultiscanLockOwner | null> {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  let ownerPath = path;
  if (metadata.isDirectory()) {
    ownerPath = join(path, "owner.json");
    try {
      metadata = await lstat(ownerPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_LOCK_OWNER_BYTES
  ) {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(await readFile(ownerPath, "utf8"));
  } catch (error) {
    if (
      error instanceof SyntaxError ||
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }
    throw error;
  }
  if (
    typeof value !== "object" ||
    value === null ||
    !("pid" in value) ||
    !Number.isSafeInteger(value.pid) ||
    (value.pid as number) <= 0 ||
    ("token" in value && typeof value.token !== "string")
  ) {
    return null;
  }
  return {
    pid: value.pid as number,
    ...("token" in value ? { token: value.token as string } : {}),
  };
}

function processIsRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    if (code === "EPERM") return true;
    throw error;
  }
}

async function releaseLock(path: string, token: string): Promise<void> {
  const owner = await readLockOwner(path);
  if (owner?.token === token) {
    await rm(path, { force: true });
  }
}

async function ensureManifest(
  path: string,
  tasks: MultiscanTask[],
): Promise<void> {
  const expected = `${JSON.stringify({ version: 1, tasks }, null, 2)}\n`;
  try {
    await writeFile(path, expected, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    if ((await readFile(path, "utf8")) !== expected) {
      throw new Error(
        "Multiscan manifest does not match existing output directory.",
      );
    }
  }
}

async function readReceipts(
  path: string,
  signal?: AbortSignal,
): Promise<Map<string, MultiscanReceipt>> {
  signal?.throwIfAborted();
  await recoverInterruptedReceiptRepair(path, signal);
  let file: FileHandle;
  try {
    file = await openReceiptLedger(path, constants.O_RDONLY);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    throw error;
  }
  let opened: FileHandle | undefined = file;
  try {
    signal?.throwIfAborted();
    const metadata = await file.stat();
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(
        "Multiscan receipt ledger must be a regular file. Move results.jsonl aside before resuming.",
      );
    }
    if (metadata.size > MAX_RECEIPT_LEDGER_BYTES) {
      await file.close();
      opened = undefined;
      await replaceCorruptReceiptLedger(path, async () => {});
      return new Map();
    }

    const receipts = new Map<string, MultiscanReceipt>();
    const initial = await readReceiptLines(file, signal, async (receipt) => {
      receipts.set(receipt.id.toLowerCase(), receipt);
    });
    if (!initial.corrupted) return receipts;

    const replacement = receiptRepairPath(path);
    let repaired: FileHandle | undefined;
    let publishing = false;
    try {
      repaired = await open(replacement, "wx", 0o600);
      if (!initial.discardAll) {
        await readReceiptLines(file, signal, async (_receipt, bytes) => {
          await repaired!.write(bytes);
          await repaired!.write("\n");
        });
      } else {
        receipts.clear();
      }
      await repaired.sync();
      await repaired.close();
      repaired = undefined;
      await file.close();
      opened = undefined;
      publishing = true;
      await publishReceiptRepair(path, replacement);
    } catch (error) {
      await repaired?.close();
      if (!publishing) await rm(replacement, { force: true });
      throw error;
    }
    return receipts;
  } finally {
    await opened?.close();
  }
}

async function recoverInterruptedReceiptRepair(
  path: string,
  signal?: AbortSignal,
): Promise<void> {
  const candidates = (await readdir(dirname(path))).filter(
    (name) => name.startsWith(".results.repair-") && name.endsWith(".jsonl"),
  );
  if (candidates.length === 0) return;
  if (candidates.length !== 1) {
    throw new Error(
      "Multiple interrupted multiscan receipt repairs were found.",
    );
  }
  const replacement = join(dirname(path), candidates[0]!);
  const candidate = await openReceiptLedger(replacement, constants.O_RDONLY);
  let replacementBytes: Buffer;
  try {
    if ((await candidate.stat()).size > MAX_RECEIPT_LEDGER_BYTES) {
      throw new Error(
        "Interrupted multiscan receipt repair exceeds its size limit.",
      );
    }
    replacementBytes = await candidate.readFile();
    const inspection = await readReceiptLines(
      candidate,
      signal,
      async () => {},
    );
    if (inspection.corrupted) {
      throw new Error("Interrupted multiscan receipt repair is invalid.");
    }
  } finally {
    await candidate.close();
  }

  let existing: FileHandle;
  try {
    existing = await openReceiptLedger(path, constants.O_RDONLY);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await rename(replacement, path);
    return;
  }
  let complete = false;
  try {
    if ((await existing.stat()).size <= MAX_RECEIPT_LEDGER_BYTES) {
      const bytes = await existing.readFile();
      const inspection = await readReceiptLines(
        existing,
        signal,
        async () => {},
      );
      complete =
        !inspection.corrupted &&
        bytes.length >= replacementBytes.length &&
        bytes.subarray(0, replacementBytes.length).equals(replacementBytes);
    }
  } finally {
    await existing.close();
  }
  if (complete) {
    await rm(replacement, { force: true });
    return;
  }
  await publishReceiptRepair(path, replacement);
}

async function readReceiptLines(
  file: FileHandle,
  signal: AbortSignal | undefined,
  accept: (receipt: MultiscanReceipt, bytes: Buffer) => Promise<void>,
): Promise<{ corrupted: boolean; discardAll: boolean }> {
  const pending = Buffer.alloc(MAX_RECEIPT_LINE_BYTES);
  let pendingBytes = 0;
  let discardingLine = false;
  let totalBytes = 0;
  let corrupted = false;
  let discardAll = false;
  const input = file.createReadStream({
    autoClose: false,
    start: 0,
    highWaterMark: 64 * 1024,
    ...(signal === undefined ? {} : { signal }),
  });
  for await (const rawChunk of input) {
    signal?.throwIfAborted();
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    totalBytes += chunk.length;
    if (totalBytes > MAX_RECEIPT_LEDGER_BYTES) {
      corrupted = true;
      discardAll = true;
      break;
    }

    let start = 0;
    while (start < chunk.length) {
      signal?.throwIfAborted();
      const newline = chunk.indexOf(0x0a, start);
      const end = newline === -1 ? chunk.length : newline;
      const segment = chunk.subarray(start, end);
      if (!discardingLine) {
        if (pendingBytes + segment.length > MAX_RECEIPT_LINE_BYTES) {
          corrupted = true;
          discardingLine = true;
          pendingBytes = 0;
        } else if (segment.length > 0) {
          segment.copy(pending, pendingBytes);
          pendingBytes += segment.length;
        }
      }
      if (newline === -1) break;
      if (!discardingLine && pendingBytes > 0) {
        const bytes = pending.subarray(0, pendingBytes);
        const receipt = parseMultiscanReceipt(bytes);
        if (receipt === null) corrupted = true;
        else await accept(receipt, bytes);
      }
      pendingBytes = 0;
      discardingLine = false;
      start = newline + 1;
    }
  }
  signal?.throwIfAborted();
  if (discardingLine || pendingBytes > 0) corrupted = true;
  return { corrupted, discardAll };
}

function parseMultiscanReceipt(bytes: Buffer): MultiscanReceipt | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!isRecord(value)) return null;
  const scope = value["scope"];
  const cost = value["cost"];
  const error = value["error"];
  if (
    typeof value["id"] !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value["id"]) ||
    typeof value["repository"] !== "string" ||
    value["repository"].length === 0 ||
    value["repository"].length > 4096 ||
    value["repository"].includes("\0") ||
    typeof value["revision"] !== "string" ||
    !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value["revision"]) ||
    (value["mode"] !== "standard" && value["mode"] !== "deep") ||
    (scope !== undefined &&
      (typeof scope !== "string" ||
        scope.length > 4096 ||
        isAbsolute(scope) ||
        scope.includes("\\") ||
        scope.split("/").includes("..") ||
        scope.includes("\0"))) ||
    (value["status"] !== "completed" && value["status"] !== "failed") ||
    !Number.isSafeInteger(value["attempt"]) ||
    (value["attempt"] as number) < 1 ||
    typeof value["outputDir"] !== "string" ||
    value["outputDir"].length === 0 ||
    value["outputDir"].length > 4096 ||
    !isAbsolute(value["outputDir"]) ||
    value["outputDir"].includes("\0") ||
    (cost !== undefined && !isScanCost(cost)) ||
    (error !== undefined && typeof error !== "string")
  ) {
    return null;
  }
  return value as unknown as MultiscanReceipt;
}

function isScanCost(value: unknown): value is ScanCost {
  if (
    !isRecord(value) ||
    typeof value["model"] !== "string" ||
    value["model"].length === 0 ||
    value["model"].length > 256
  ) {
    return false;
  }
  for (const name of [
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
  ]) {
    const count = value[name];
    if (!Number.isSafeInteger(count) || (count as number) < 0) return false;
  }
  return (
    typeof value["estimatedUsd"] === "number" &&
    Number.isFinite(value["estimatedUsd"]) &&
    value["estimatedUsd"] >= 0
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function receiptRepairPath(path: string): string {
  return join(dirname(path), `.results.repair-${randomUUID()}.jsonl`);
}

async function replaceCorruptReceiptLedger(
  path: string,
  writeReplacement: (file: Awaited<ReturnType<typeof open>>) => Promise<void>,
): Promise<void> {
  const replacement = receiptRepairPath(path);
  const file = await open(replacement, "wx", 0o600);
  try {
    await writeReplacement(file);
    await file.sync();
  } catch (error) {
    await file.close();
    await rm(replacement, { force: true });
    throw error;
  }
  await file.close();
  await publishReceiptRepair(path, replacement);
}

async function publishReceiptRepair(
  path: string,
  replacement: string,
): Promise<void> {
  const quarantine = join(
    dirname(path),
    `results.corrupt-${randomUUID()}.jsonl`,
  );
  await copyFile(path, quarantine, constants.COPYFILE_EXCL);
  try {
    await rename(replacement, path);
  } catch (error) {
    if (
      process.platform !== "win32" ||
      !["EPERM", "EACCES", "EEXIST"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      )
    ) {
      throw error;
    }
    const destination = await openReceiptLedger(path, constants.O_RDWR);
    try {
      const source = await open(replacement, constants.O_RDONLY);
      try {
        await destination.truncate(0);
        for await (const chunk of source.createReadStream({
          autoClose: false,
          highWaterMark: 64 * 1024,
        })) {
          await destination.writeFile(chunk);
        }
        await destination.sync();
      } finally {
        await source.close();
      }
    } finally {
      await destination.close();
    }
    await rm(replacement, { force: true });
  }
}

async function hasArtifacts(
  path: string,
  pluginRoot: string,
  task: MultiscanTask,
  signal?: AbortSignal,
): Promise<boolean> {
  try {
    signal?.throwIfAborted();
    if (!(await lstat(path)).isDirectory()) return false;
    for (const artifact of REQUIRED_ARTIFACTS) {
      if (!(await lstat(join(path, artifact))).isFile()) return false;
    }
    const plugin = JSON.parse(
      await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
    ) as { version?: unknown };
    if (typeof plugin.version !== "string") return false;
    const contract = await loadContract(path, {
      pluginRoot,
      signal,
      expectation: {
        repository: task.repository,
        repositoryRevision: task.revision,
        target:
          task.scope === undefined
            ? { kind: "repository", paths: [] }
            : { kind: "paths", paths: [task.scope] },
        mode: task.mode,
        pluginVersion: plugin.version,
      },
    });
    return (
      contract.coverage.completeness === "complete" &&
      contract.manifest.scan.target.kind !== "directory_snapshot"
    );
  } catch (error) {
    if (signal?.aborted === true) signal.throwIfAborted();
    return false;
  }
}

async function mkdirTemporaryPluginWorkspace(output: string): Promise<string> {
  for (;;) {
    const path = join(output, `.resume-plugin-${randomUUID()}`);
    try {
      await mkdir(path, { mode: 0o700 });
      return path;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
}

async function parseInventory(
  inputPath: string,
  directory: string,
  defaultMode: ScanMode,
  signal?: AbortSignal,
): Promise<MultiscanTask[]> {
  signal?.throwIfAborted();
  const metadata = await stat(inputPath);
  signal?.throwIfAborted();
  if (!metadata.isFile()) {
    throw new Error("Multiscan inventory must be a regular CSV file.");
  }
  if (metadata.size > MAX_BULK_SCAN_INVENTORY_BYTES) {
    throw new Error("Multiscan CSV must not exceed 8 MiB.");
  }

  const tasks: MultiscanTask[] = [];
  const seen = new Set<string>();
  let headers: string[] | undefined;
  let bytesRead = 0;
  const input = createReadStream(inputPath, {
    highWaterMark: 64 * 1_024,
    ...(signal === undefined ? {} : { signal }),
  });
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const bounded = new Transform({
    readableObjectMode: true,
    transform(chunk: Buffer, _encoding, callback) {
      bytesRead += chunk.length;
      if (bytesRead > MAX_BULK_SCAN_INVENTORY_BYTES) {
        callback(new Error("Multiscan CSV must not exceed 8 MiB."));
        return;
      }
      try {
        callback(null, decoder.decode(chunk, { stream: true }));
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
      }
    },
    flush(callback) {
      try {
        callback(null, decoder.decode());
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
      }
    },
  });
  input.pipe(bounded);

  return await new Promise<MultiscanTask[]>((resolveTasks, rejectTasks) => {
    let settled = false;
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      const failure = error instanceof Error ? error : new Error(String(error));
      input.destroy();
      bounded.destroy();
      rejectTasks(failure);
    };
    input.once("error", fail);
    bounded.once("error", fail);

    Papa.parse<string[]>(bounded as unknown as Papa.LocalFile, {
      delimiter: ",",
      skipEmptyLines: "greedy",
      beforeFirstChunk: (chunk) =>
        chunk.charCodeAt(0) === 0xfeff ? chunk.slice(1) : chunk,
      step: ({ data: fields, errors }) => {
        try {
          signal?.throwIfAborted();
          if (errors.length > 0) {
            throw new Error(
              `Multiscan CSV could not be parsed: ${errors[0]!.message}`,
            );
          }
          if (headers === undefined) {
            headers = fields;
            validateInventoryHeaders(headers);
            return;
          }
          if (tasks.length >= MAX_BULK_SCAN_REPOSITORIES) {
            throw bulkScanRepositoryLimitError();
          }
          tasks.push(
            parseInventoryRow(fields, headers, directory, defaultMode, seen),
          );
        } catch (error) {
          fail(error);
        }
      },
      complete: () => {
        if (settled) return;
        try {
          signal?.throwIfAborted();
          if (headers === undefined) validateInventoryHeaders(undefined);
          if (tasks.length === 0) {
            throw new Error(
              "Multiscan CSV must contain at least one repository.",
            );
          }
          settled = true;
          resolveTasks(tasks);
        } catch (error) {
          fail(error);
        }
      },
      error: fail,
    });
  });
}

function validateInventoryHeaders(headers: string[] | undefined): void {
  if (
    headers === undefined ||
    !["id", "repository", "revision"].every((name) => headers.includes(name)) ||
    new Set(headers).size !== headers.length
  ) {
    throw new Error(
      "Multiscan CSV requires id, repository, and revision columns.",
    );
  }
}

function parseInventoryRow(
  fields: string[],
  headers: string[],
  directory: string,
  defaultMode: ScanMode,
  seen: Set<string>,
): MultiscanTask {
  if (fields.length !== headers.length) {
    throw new Error("Multiscan CSV rows must match their header columns.");
  }
  const get = (name: string): string =>
    fields[headers.indexOf(name)]?.trim() ?? "";
  const id = get("id");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(id)) {
    throw new Error("Multiscan task IDs must be safe, unique path names.");
  }
  if (seen.has(id.toLowerCase()))
    throw new Error("Multiscan task IDs must be unique.");
  seen.add(id.toLowerCase());
  const revision = get("revision").toLowerCase();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(revision)) {
    throw new Error("Multiscan revisions must be full immutable Git SHAs.");
  }
  const mode = get("mode") || defaultMode;
  if (mode !== "standard" && mode !== "deep") {
    throw new Error("Multiscan mode must be standard or deep.");
  }
  const scope = get("scope");
  if (
    scope &&
    (scope.length > 4096 ||
      isAbsolute(scope) ||
      scope.includes("\\") ||
      scope.split("/").includes("..") ||
      scope.includes("\0"))
  ) {
    throw new Error("Multiscan scope must stay inside its repository.");
  }
  const normalizedScope = scope
    .split("/")
    .filter((segment) => segment !== "" && segment !== ".")
    .join("/");
  return {
    id,
    repository: normalizeRepository(get("repository"), directory),
    revision,
    mode,
    ...(normalizedScope ? { scope: normalizedScope } : {}),
  };
}

function normalizeRepository(repository: string, directory: string): string {
  if (!repository || repository.length > 4096 || repository.includes("\0")) {
    throw new Error(
      "Multiscan repositories must be safe local paths or Git URLs.",
    );
  }
  if (/^[^@\s/:]+@[^:\s/]+:.+$/u.test(repository)) return repository;
  if (!repository.includes("://")) return resolve(directory, repository);
  let url: URL;
  try {
    url = new URL(repository);
  } catch {
    throw new Error("Multiscan repository URL is invalid.");
  }
  if (url.protocol !== "https:" && url.protocol !== "ssh:") {
    throw new Error("Multiscan repository URL protocol is unsupported.");
  }
  if (
    url.password ||
    (url.protocol === "https:" && url.username) ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "Repository URLs must not contain embedded credentials, query strings, or fragments.",
    );
  }
  return repository;
}

async function checkoutRevision(
  task: MultiscanTask,
  path: string,
  signal?: AbortSignal,
  githubHost?: string,
): Promise<void> {
  const environment = { ...process.env };
  for (const name of [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  ]) {
    delete environment[name];
  }
  environment["GIT_TERMINAL_PROMPT"] = "0";
  environment["GIT_LFS_SKIP_SMUDGE"] = "1";
  const command = await resolveTrustedExecutable(
    "git",
    environment,
    resolve(process.cwd()),
  );
  if (command === null) {
    throw new Error("Git is not available on a trusted PATH.");
  }
  const git = async (...args: string[]): Promise<string> => {
    // Use the resolved absolute path so Windows PATHEXT cannot prefer a
    // .bat/.cmd shim over the trusted executable selected above.
    const result = await execFile(
      command.executable,
      [
        "-c",
        "core.hooksPath=/dev/null",
        ...buildGitHubCredentialArgs(githubHost),
        "-C",
        path,
        ...args,
      ],
      { env: command.environment, signal },
    );
    return result.stdout.trim();
  };
  await git("init", "--quiet");
  await git(
    "fetch",
    "--quiet",
    "--no-tags",
    "--depth=1",
    "--",
    task.repository,
    task.revision,
  );
  await git("checkout", "--quiet", "--detach", "FETCH_HEAD");
  if ((await git("rev-parse", "HEAD")).toLowerCase() !== task.revision) {
    throw new Error("Git checkout revision did not match the pinned SHA.");
  }
}

export function buildGitHubCredentialArgs(host: string | undefined): string[] {
  if (host === undefined) return [];
  let url: URL;
  try {
    url = new URL(`https://${host}`);
  } catch {
    throw new Error("GitHub credential host is invalid.");
  }
  if (
    url.host !== host.toLowerCase() ||
    url.pathname !== "/" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("GitHub credential host is invalid.");
  }
  const key = `credential.${url.origin}.helper`;
  return ["-c", `${key}=`, "-c", `${key}=!gh auth git-credential`];
}

function redactError(error: unknown): string {
  const redacted = (error instanceof Error ? error.message : String(error))
    .replaceAll(
      /((?:api[_-]?key|token|secret|credential|password)[A-Za-z0-9_-]*\s*[:=]\s*)[^\s,;]+/giu,
      "$1[redacted]",
    )
    .replaceAll(
      /\b(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|npm_)[A-Za-z0-9_*=-]{8,}/gu,
      "[redacted]",
    )
    .replaceAll(/\b(Bearer|Basic|Token)\s+[^\s,;]+/giu, "$1 [redacted]");
  const bytes = Buffer.from(redacted);
  return bytes.length <= MAX_RECEIPT_ERROR_BYTES
    ? redacted
    : `${bytes.subarray(0, MAX_RECEIPT_ERROR_BYTES).toString("utf8")}[truncated]`;
}
