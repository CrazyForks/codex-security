#!/usr/bin/env node
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  statSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";

const MAX_INPUT_ENTRIES = 2_000_000;
const MAX_INPUT_FILE_BYTES = 256 * 1024 * 1024;
const MAX_INPUT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_OUTPUT_ENTRIES = 20_000;
const MAX_OUTPUT_FILE_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 512 * 1024 * 1024;

const job = JSON.parse(readFileSync(0, "utf8"));
const input = job.kind !== "output";
const state = job.state ?? { entries: 0, bytes: 0, files: 0 };
const sourceRoot = anchor(job.source);
mkdirSync(job.destination, { recursive: true, mode: 0o700 });
const destinationRoot = anchor(job.destination);

try {
  if (job.kind === "tracked") {
    const seen = new Set();
    const directoryEntries = new Map();
    for (const path of job.paths ?? []) {
      if (seen.has(path)) continue;
      seen.add(path);
      let source = join(job.source, path);
      let metadata;
      try {
        source = resolveSourcePath(
          path,
          directoryEntries,
          job.ignoreCase === true,
        );
        if (source === null) continue;
        metadata = metadataAt(sourceRoot, source);
      } catch (error) {
        fail(
          `Tracked repository input is missing or non-regular: ${JSON.stringify(path)}`,
        );
      }
      if (metadata === null || metadata.isDirectory()) continue;
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        fail(
          `Tracked repository input is missing or non-regular: ${JSON.stringify(path)}`,
        );
      }
      const actualPath = job.ignoreCase
        ? relative(job.source, realpathSync.native(source)).split(sep).join("/")
        : path;
      if (
        actualPath.startsWith("../") ||
        actualPath === ".." ||
        isAbsolute(actualPath)
      ) {
        fail(
          `Tracked repository input escaped the source root: ${JSON.stringify(path)}`,
        );
      }
      if (job.scopes && !include(actualPath, job.scopes)) continue;
      const destinationPath =
        job.ignoreCase && gitCaseFold(basename(actualPath)) === "security.md"
          ? join(dirname(actualPath), "SECURITY.md")
          : actualPath;
      copyFile(source, join(job.destination, destinationPath), metadata);
    }
  } else {
    copyTree(job.source, job.destination, "", 0);
  }
  process.stdout.write(`${JSON.stringify(state)}\n`);
} catch (error) {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}

function copyTree(source, destination, prefix, depth) {
  if (!input && depth > 128) {
    fail("Agents SDK scan output exceeds the entry limit.");
  }
  const sourceMetadata = metadataAt(sourceRoot, source);
  if (sourceMetadata === null) {
    fail(
      input
        ? `Repository input changed while staging: ${JSON.stringify(source)}`
        : "Agents SDK scan output changed during artifact handoff.",
    );
  }
  if (!sourceMetadata.isDirectory() || sourceMetadata.isSymbolicLink()) {
    fail(
      input
        ? `Repository input is not a directory: ${JSON.stringify(source)}`
        : "Agents SDK scan output contains a non-regular file.",
    );
  }
  ensureDirectory(destination);
  const entries = readDirectory(sourceRoot, source);
  if (
    input &&
    ["head", "config", "objects", "refs"].every((name) =>
      entries.some((entry) => gitCaseFold(entry.name) === name),
    )
  ) {
    fail(
      `Bare Git-like directory cannot be staged safely: ${JSON.stringify(source)}`,
    );
  }
  for (const entry of entries) {
    if (input && skip(entry.name, job.kind)) continue;
    const path = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
    if (input && job.scopes && !include(path, job.scopes)) continue;
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    const metadata = metadataAt(sourceRoot, from);
    if (metadata === null) {
      fail(`Repository input changed while staging: ${JSON.stringify(from)}`);
    }
    if (metadata.isSymbolicLink()) {
      if (input) continue;
      fail("Agents SDK scan output contains a non-regular file.");
    }
    if (metadata.isDirectory()) {
      copyTree(from, to, path, depth + 1);
      continue;
    }
    if (!metadata.isFile()) {
      if (input) continue;
      fail("Agents SDK scan output contains a non-regular file.");
    }
    copyFile(from, to, metadata);
  }
}

function copyFile(source, destination, expected) {
  state.entries += 1;
  state.bytes += expected.size;
  state.files += 1;
  if (
    state.entries > (input ? MAX_INPUT_ENTRIES : MAX_OUTPUT_ENTRIES) ||
    state.bytes > (input ? MAX_INPUT_BYTES : MAX_OUTPUT_BYTES)
  ) {
    fail(
      input
        ? `Repository inputs exceed the staging limit: ${JSON.stringify(source)}`
        : "Agents SDK scan output exceeds the staging limit.",
    );
  }
  if (expected.size > (input ? MAX_INPUT_FILE_BYTES : MAX_OUTPUT_FILE_BYTES)) {
    fail(
      input
        ? `Repository input file is too large to stage safely: ${JSON.stringify(source)}`
        : "Agents SDK scan output contains an oversized file.",
    );
  }
  if (input && job.rejectHardlinks !== false && expected.nlink !== 1) {
    fail(`Repository input has an unsafe hard link: ${JSON.stringify(source)}`);
  }
  ensureDirectory(dirname(destination));
  let sourceHandle;
  let destinationHandle;
  try {
    sourceHandle = openAt(
      sourceRoot,
      source,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = fstatSync(sourceHandle);
    if (
      !opened.isFile() ||
      opened.dev !== expected.dev ||
      opened.ino !== expected.ino ||
      opened.size !== expected.size ||
      (input && job.rejectHardlinks !== false && opened.nlink !== 1)
    ) {
      fail(
        input
          ? `Repository input changed while staging: ${JSON.stringify(source)}`
          : "Agents SDK scan output changed during artifact handoff.",
      );
    }
    destinationHandle = openAt(
      destinationRoot,
      destination,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      input ? expected.mode & 0o777 : 0o600,
    );
    const buffer = new Uint8Array(1024 * 1024);
    let offset = 0;
    while (offset < opened.size) {
      const bytesRead = readSync(
        sourceHandle,
        buffer,
        0,
        Math.min(buffer.byteLength, opened.size - offset),
        offset,
      );
      if (bytesRead === 0) fail("Staged file changed during artifact handoff.");
      let written = 0;
      while (written < bytesRead) {
        const bytesWritten = writeSync(
          destinationHandle,
          buffer,
          written,
          bytesRead - written,
          offset + written,
        );
        if (bytesWritten === 0) fail("Unable to copy staged file.");
        written += bytesWritten;
      }
      offset += bytesRead;
    }
    const final = fstatSync(sourceHandle);
    if (
      final.dev !== opened.dev ||
      final.ino !== opened.ino ||
      final.size !== opened.size ||
      final.mtimeMs !== opened.mtimeMs
    ) {
      fail("Staged file changed during artifact handoff.");
    }
    if (input) fchmodSync(destinationHandle, expected.mode & 0o7777);
  } finally {
    if (destinationHandle !== undefined) closeSync(destinationHandle);
    if (sourceHandle !== undefined) closeSync(sourceHandle);
  }
}

function anchor(path) {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`Unable to bind a safe staging directory: ${JSON.stringify(path)}`);
  }
  return { path, dev: metadata.dev, ino: metadata.ino };
}

function inDirectory(root, directory, callback) {
  const path = relative(root.path, directory);
  if (isAbsolute(path) || path === ".." || path.startsWith(`..${sep}`)) {
    fail("Staging path escaped its directory boundary.");
  }
  const previous = process.cwd();
  try {
    const initial = lstatSync(root.path);
    if (
      !initial.isDirectory() ||
      initial.isSymbolicLink() ||
      initial.dev !== root.dev ||
      initial.ino !== root.ino
    ) {
      fail("A staging directory changed or contained a symbolic link.");
    }
    process.chdir(root.path);
    let opened = statSync(".");
    if (opened.dev !== initial.dev || opened.ino !== initial.ino) {
      fail("A staging directory changed while opening.");
    }
    for (const part of path.length === 0 ? [] : path.split(sep)) {
      if (part.length === 0 || part === "." || part === "..") {
        fail("Staging path contains an invalid directory component.");
      }
      const metadata = lstatSync(part);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail("A staging directory changed or contained a symbolic link.");
      }
      process.chdir(part);
      opened = statSync(".");
      if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) {
        fail("A staging directory changed while opening.");
      }
    }
    return callback();
  } finally {
    process.chdir(previous);
  }
}

function metadataAt(root, path) {
  try {
    return path === root.path
      ? inDirectory(root, path, () => lstatSync("."))
      : inDirectory(
          root,
          dirname(path),
          () => lstatSync(basename(path), { throwIfNoEntry: false }) ?? null,
        );
  } catch (error) {
    if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
      return null;
    }
    throw error;
  }
}

function readDirectory(root, path) {
  return inDirectory(root, path, () =>
    readdirSync(".", { withFileTypes: true }),
  );
}

function resolveSourcePath(path, cache, ignoreCase) {
  let current = job.source;
  for (const part of path.split("/")) {
    let entries = cache.get(current);
    if (entries === undefined) {
      try {
        entries = readDirectory(sourceRoot, current).map((entry) => entry.name);
      } catch (error) {
        if (!error || (error.code !== "ENOENT" && error.code !== "ENOTDIR")) {
          throw error;
        }
        entries = null;
      }
      cache.set(current, entries);
    }
    if (entries === null) return null;
    const name =
      entries.find((entry) => entry === part) ??
      (ignoreCase
        ? entries.find((entry) => gitCaseFold(entry) === gitCaseFold(part))
        : undefined);
    if (name === undefined) return null;
    current = join(current, name);
  }
  return current;
}

function gitCaseFold(value) {
  return value.replace(/[A-Z]/gu, (character) => character.toLowerCase());
}

function openAt(root, path, flags, mode) {
  return inDirectory(root, dirname(path), () =>
    openSync(basename(path), flags, mode),
  );
}

function ensureDirectory(path) {
  const relativePath = relative(destinationRoot.path, path);
  if (
    isAbsolute(relativePath) ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`)
  ) {
    fail("Staging path escaped its directory boundary.");
  }
  let current = destinationRoot.path;
  for (const part of relativePath.length === 0 ? [] : relativePath.split(sep)) {
    const next = join(current, part);
    const metadata = metadataAt(destinationRoot, next);
    if (metadata === null) {
      state.entries += 1;
      if (state.entries > (input ? MAX_INPUT_ENTRIES : MAX_OUTPUT_ENTRIES)) {
        fail(
          input
            ? `Repository contains too many entries to stage safely: ${JSON.stringify(job.source)}`
            : "Agents SDK scan output exceeds the entry limit.",
        );
      }
      inDirectory(destinationRoot, current, () =>
        mkdirSync(part, { mode: 0o700 }),
      );
    } else if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail(
        input
          ? "A staging directory changed or contained a symbolic link."
          : "Agents SDK scan output destination contains a non-directory entry.",
      );
    }
    current = next;
  }
}

function skip(name, kind) {
  const lower = name.toLowerCase();
  if (
    lower === ".git" ||
    lower === ".git-credentials" ||
    lower === ".gitmodules" ||
    lower === ".env" ||
    lower.startsWith(".env.") ||
    lower.endsWith(".pem") ||
    lower.endsWith(".key")
  ) {
    return true;
  }
  return (
    kind === "plugin" &&
    (lower.endsWith(".git") || name === "__pycache__" || name.endsWith(".pyc"))
  );
}

function include(path, scopes) {
  if (
    scopes.some(
      (scope) =>
        scope === "." ||
        path === scope ||
        path.startsWith(`${scope}/`) ||
        scope.startsWith(`${path}/`),
    )
  ) {
    return true;
  }
  if (gitCaseFold(basename(path)) !== "security.md") return false;
  const parent = dirname(path).split(sep).join("/");
  return scopes.some(
    (scope) =>
      parent === "." || scope === parent || scope.startsWith(`${parent}/`),
  );
}

function fail(message) {
  throw new Error(message);
}
