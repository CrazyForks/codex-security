import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  open,
  opendir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { inflateSync } from "node:zlib";
import { unzipSync } from "fflate";

const SUPPORTED_EXTENSIONS = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".pdf",
  ".docx",
]);
const MAX_DOCUMENTS = 128;
const MAX_DIRECTORY_DEPTH = 16;
const MAX_DISCOVERY_ENTRIES = 4_096;
const MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;
const MAX_INPUT_BYTES = 32 * 1024 * 1024;
const MAX_EXTRACTED_DOCUMENT_BYTES = 8 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 32 * 1024 * 1024;
const MAX_PDF_PAGES = 512;
const READ_CHUNK_BYTES = 64 * 1024;

interface DiscoveryState {
  documents: Map<string, string>;
  entries: number;
  inputBytes: number;
}

class KnowledgeBaseLimitError extends Error {}

export interface PreparedKnowledgeBase {
  path: string;
  sources: string[];
  cleanup(): Promise<void>;
}

export async function prepareKnowledgeBase(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<PreparedKnowledgeBase> {
  const sources = new Set<string>();
  const discovery: DiscoveryState = {
    documents: new Map(),
    entries: 0,
    inputBytes: 0,
  };

  for (const requested of paths) {
    signal?.throwIfAborted();
    if (!requested.trim())
      throw new Error("Knowledge base paths cannot be empty.");
    const path = resolve(requested);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`Knowledge base paths cannot be symbolic links: ${path}`);
    }
    if (!metadata.isFile() && !metadata.isDirectory()) {
      throw new Error(
        `Knowledge base path is not a file or directory: ${path}`,
      );
    }

    const source = await realpath(path);
    signal?.throwIfAborted();
    if (sources.has(source)) continue;
    let selected = false;
    if (metadata.isDirectory()) {
      selected = await discover(source, source, 0, discovery, signal);
    } else {
      if (!SUPPORTED_EXTENSIONS.has(extname(source).toLowerCase())) {
        throw new Error(`Unsupported knowledge base document: ${source}`);
      }
      await addDocument(source, source, await lstat(source), discovery, signal);
      selected = true;
    }
    if (!selected) {
      throw new Error(
        `Knowledge base directory contains no supported documents: ${path}`,
      );
    }
    sources.add(source);
  }

  signal?.throwIfAborted();
  const path = await mkdtemp(join(tmpdir(), "codex-security-knowledge-"));
  try {
    let index = 0;
    let inputBytes = 0;
    let extractedBytes = 0;
    for (const [document, sourceRoot] of discovery.documents) {
      signal?.throwIfAborted();
      const bytes = await readDocument(
        document,
        sourceRoot,
        inputBytes,
        signal,
      );
      inputBytes += bytes.byteLength;
      const extension = extname(document).toLowerCase();
      const text =
        extension === ".pdf"
          ? await extractPdf(document, bytes, signal)
          : extension === ".docx"
            ? extractDocx(document, bytes, signal)
            : decodeText(document, bytes);
      signal?.throwIfAborted();
      if ((extension === ".pdf" || extension === ".docx") && !text.trim()) {
        throw new Error(
          `Knowledge base document contains no extractable text: ${document}`,
        );
      }
      const textBytes = Buffer.byteLength(text, "utf8");
      if (textBytes > MAX_EXTRACTED_DOCUMENT_BYTES) {
        throw new KnowledgeBaseLimitError(
          `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${document}`,
        );
      }
      if (extractedBytes + textBytes > MAX_EXTRACTED_BYTES) {
        throw new KnowledgeBaseLimitError(
          `Knowledge base extracted text exceeds the ${MAX_EXTRACTED_BYTES}-byte aggregate limit.`,
        );
      }
      extractedBytes += textBytes;
      await writeFile(
        join(path, `${index++}-${basename(document)}.txt`),
        text,
        {
          encoding: "utf8",
          mode: 0o600,
          signal,
        },
      );
    }
  } catch (error) {
    await rm(path, { recursive: true, force: true });
    throw error;
  }

  return {
    path,
    sources: [...sources],
    cleanup: () => rm(path, { recursive: true, force: true }),
  };
}

async function discover(
  directory: string,
  sourceRoot: string,
  depth: number,
  state: DiscoveryState,
  signal?: AbortSignal,
): Promise<boolean> {
  signal?.throwIfAborted();
  if (depth > MAX_DIRECTORY_DEPTH) {
    throw new KnowledgeBaseLimitError(
      `Knowledge base directory exceeds the ${MAX_DIRECTORY_DEPTH}-level nesting limit: ${directory}`,
    );
  }
  let selected = false;
  const initial = await lstat(directory);
  const canonicalDirectory = await requireContainedSource(
    directory,
    sourceRoot,
  );
  if (!initial.isDirectory() || initial.isSymbolicLink()) {
    throw new Error(
      `Knowledge base directory changed during discovery: ${directory}`,
    );
  }
  const entries = await opendir(directory);
  for await (const entry of entries) {
    signal?.throwIfAborted();
    const currentDirectory = await requireContainedSource(
      directory,
      sourceRoot,
    );
    const current = await lstat(currentDirectory);
    if (
      currentDirectory !== canonicalDirectory ||
      current.dev !== initial.dev ||
      current.ino !== initial.ino
    ) {
      throw new Error(
        `Knowledge base directory changed during discovery: ${directory}`,
      );
    }
    state.entries += 1;
    if (state.entries > MAX_DISCOVERY_ENTRIES) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base discovery exceeds the ${MAX_DISCOVERY_ENTRIES}-entry limit.`,
      );
    }
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (await discover(path, sourceRoot, depth + 1, state, signal)) {
        selected = true;
      }
    } else if (
      entry.isFile() &&
      SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase())
    ) {
      const metadata = await lstat(path);
      signal?.throwIfAborted();
      if (metadata.isSymbolicLink() || !metadata.isFile()) continue;
      selected = true;
      await addDocument(path, sourceRoot, metadata, state, signal);
    }
  }
  signal?.throwIfAborted();
  return selected;
}

async function addDocument(
  path: string,
  sourceRoot: string,
  metadata: { size: number },
  state: DiscoveryState,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  if (state.documents.has(path)) return;
  if (state.documents.size >= MAX_DOCUMENTS) {
    throw new KnowledgeBaseLimitError(
      `Knowledge base contains more than ${MAX_DOCUMENTS} documents.`,
    );
  }
  if (metadata.size > MAX_DOCUMENT_BYTES) {
    throw new KnowledgeBaseLimitError(
      `Knowledge base document exceeds the ${MAX_DOCUMENT_BYTES}-byte input limit: ${path}`,
    );
  }
  if (state.inputBytes + metadata.size > MAX_INPUT_BYTES) {
    throw new KnowledgeBaseLimitError(
      `Knowledge base input exceeds the ${MAX_INPUT_BYTES}-byte aggregate limit.`,
    );
  }
  await requireContainedSource(path, sourceRoot);
  state.documents.set(path, sourceRoot);
  state.inputBytes += metadata.size;
}

async function requireContainedSource(
  path: string,
  sourceRoot: string,
): Promise<string> {
  const canonical = await realpath(path);
  const remaining = relative(sourceRoot, canonical);
  if (
    remaining === ".." ||
    remaining.startsWith(`..${sep}`) ||
    isAbsolute(remaining)
  ) {
    throw new Error(
      `Knowledge base path escaped the requested source: ${path}`,
    );
  }
  return canonical;
}

async function readDocument(
  path: string,
  sourceRoot: string,
  consumedBytes: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  signal?.throwIfAborted();
  const initialPath = await requireContainedSource(path, sourceRoot);
  const file = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (process.platform === "win32" ? 0 : constants.O_NONBLOCK ?? 0),
  );
  try {
    const metadata = await file.stat();
    signal?.throwIfAborted();
    if (!metadata.isFile()) {
      throw new Error(`Knowledge base document is not a file: ${path}`);
    }
    if (process.platform !== "win32" && (metadata.mode & 0o444) === 0) {
      throw new Error(`Knowledge base document is not readable: ${path}`);
    }
    const currentPath = await requireContainedSource(path, sourceRoot);
    const current = await lstat(currentPath);
    if (
      currentPath !== initialPath ||
      current.dev !== metadata.dev ||
      current.ino !== metadata.ino
    ) {
      throw new Error(`Knowledge base document changed while opening: ${path}`);
    }
    if (metadata.size > MAX_DOCUMENT_BYTES) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base document exceeds the ${MAX_DOCUMENT_BYTES}-byte input limit: ${path}`,
      );
    }
    if (consumedBytes + metadata.size > MAX_INPUT_BYTES) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base input exceeds the ${MAX_INPUT_BYTES}-byte aggregate limit.`,
      );
    }

    const maximum = Math.min(
      MAX_DOCUMENT_BYTES,
      MAX_INPUT_BYTES - consumedBytes,
    );
    const chunks: Buffer[] = [];
    let length = 0;
    while (length <= maximum) {
      signal?.throwIfAborted();
      const chunk = Buffer.allocUnsafe(
        Math.min(READ_CHUNK_BYTES, maximum + 1 - length),
      );
      const { bytesRead } = await file.read(chunk, 0, chunk.byteLength, null);
      signal?.throwIfAborted();
      if (bytesRead === 0) break;
      chunks.push(chunk.subarray(0, bytesRead));
      length += bytesRead;
    }
    if (length > MAX_DOCUMENT_BYTES) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base document exceeds the ${MAX_DOCUMENT_BYTES}-byte input limit: ${path}`,
      );
    }
    if (consumedBytes + length > MAX_INPUT_BYTES) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base input exceeds the ${MAX_INPUT_BYTES}-byte aggregate limit.`,
      );
    }
    return Buffer.concat(chunks, length);
  } finally {
    await file.close();
  }
}

function decodeText(path: string, bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`Knowledge base document is not valid UTF-8: ${path}`, {
      cause: error,
    });
  }
}

function boundCompressedPdfStreams(
  path: string,
  bytes: Uint8Array,
  signal?: AbortSignal,
): void {
  const source = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const contents = source.toString("latin1");
  const filters = /\/(?:FlateDecode|Fl)(?=[\s/>[\]])/gu;
  for (const filter of contents.matchAll(filters)) {
    signal?.throwIfAborted();
    const marker = filter.index;
    const headerEnd = Math.min(contents.length, marker + 64 * 1024);
    const header = contents.slice(marker, headerEnd);
    const stream = /\bstream(?:\r\n|\r|\n)/u.exec(header);
    if (stream?.index === undefined) continue;

    const streamStart = marker + stream.index + stream[0].length;
    const dictionaryStart = contents.lastIndexOf("<<", marker);
    const dictionary = contents.slice(
      Math.max(0, dictionaryStart),
      streamStart,
    );
    const declared = /\/Length\s+(\d+)(?!\s+\d+\s+R)/u.exec(dictionary);
    const length = declared?.[1] === undefined ? NaN : Number(declared[1]);
    let streamEnd = Number.isSafeInteger(length)
      ? streamStart + length
      : contents.indexOf("\nendstream", streamStart);
    if (streamEnd === -1)
      streamEnd = contents.indexOf("\rendstream", streamStart);
    if (streamEnd < streamStart || streamEnd > source.byteLength) continue;

    try {
      inflateSync(source.subarray(streamStart, streamEnd), {
        maxOutputLength: MAX_EXTRACTED_DOCUMENT_BYTES,
      });
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === "ERR_BUFFER_TOO_LARGE"
      ) {
        throw new KnowledgeBaseLimitError(
          `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${path}`,
        );
      }
      throw new Error(
        `Knowledge base PDF compressed stream cannot be safely bounded: ${path}`,
        { cause: error },
      );
    }
  }
}

async function extractPdf(
  path: string,
  bytes: Uint8Array,
  signal?: AbortSignal,
): Promise<string> {
  signal?.throwIfAborted();
  try {
    boundCompressedPdfStreams(path, bytes, signal);
    const { getDocument, VerbosityLevel } = await import(
      "pdfjs-dist/legacy/build/pdf.mjs"
    );
    const loadingTask = getDocument({
      data: new Uint8Array(bytes),
      isEvalSupported: false,
      stopAtErrors: true,
      verbosity: VerbosityLevel.ERRORS,
    });
    let document: Awaited<typeof loadingTask.promise> | undefined;
    let destroying: Promise<void> | null = null;
    const destroy = (): Promise<void> =>
      (destroying ??=
        document === undefined ? loadingTask.destroy() : document.destroy());
    const onAbort = (): void => {
      void destroy().catch(() => {});
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) onAbort();
    try {
      document = await loadingTask.promise;
      signal?.throwIfAborted();
      if (document.numPages > MAX_PDF_PAGES) {
        throw new KnowledgeBaseLimitError(
          `Knowledge base PDF exceeds the ${MAX_PDF_PAGES}-page limit: ${path}`,
        );
      }
      const pages: string[] = [];
      let extractedBytes = 0;
      for (let number = 1; number <= document.numPages; number++) {
        signal?.throwIfAborted();
        const reader = (await document.getPage(number))
          .streamTextContent()
          .getReader();
        const pieces: string[] = [];
        try {
          while (true) {
            signal?.throwIfAborted();
            const chunk = await reader.read();
            signal?.throwIfAborted();
            if (chunk.done) break;
            for (const item of chunk.value.items as Array<{ str?: string }>) {
              const piece = item.str ?? "";
              const separator = pieces.length === 0 ? 0 : 1;
              const pageBreak = pages.length === 0 || pieces.length > 0 ? 0 : 1;
              const pieceBytes =
                Buffer.byteLength(piece, "utf8") + separator + pageBreak;
              if (extractedBytes + pieceBytes > MAX_EXTRACTED_DOCUMENT_BYTES) {
                throw new KnowledgeBaseLimitError(
                  `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${path}`,
                );
              }
              pieces.push(piece);
              extractedBytes += pieceBytes;
            }
          }
        } finally {
          reader.releaseLock();
        }
        if (pieces.length === 0 && pages.length > 0) {
          extractedBytes += 1;
          if (extractedBytes > MAX_EXTRACTED_DOCUMENT_BYTES) {
            throw new KnowledgeBaseLimitError(
              `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${path}`,
            );
          }
        }
        pages.push(pieces.join(" "));
      }
      return pages.join("\n");
    } finally {
      signal?.removeEventListener("abort", onAbort);
      await destroy().catch((error: unknown) => {
        signal?.throwIfAborted();
        throw error;
      });
    }
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof KnowledgeBaseLimitError) throw error;
    throw new Error(`Cannot extract text from knowledge base PDF: ${path}`, {
      cause: error,
    });
  }
}

function extractDocx(
  path: string,
  bytes: Uint8Array,
  signal?: AbortSignal,
): string {
  signal?.throwIfAborted();
  try {
    const files = unzipSync(bytes, {
      filter: (file) => {
        if (file.name !== "word/document.xml") return false;
        if (file.originalSize > MAX_EXTRACTED_DOCUMENT_BYTES) {
          throw new KnowledgeBaseLimitError(
            `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${path}`,
          );
        }
        return true;
      },
    });
    signal?.throwIfAborted();
    const document = files["word/document.xml"];
    if (document === undefined) throw new Error("Missing word/document.xml.");
    const xml = decodeText(path, document);
    if (
      !/<(?:\w+:)?document\b[^>]*>[\s\S]*<\/(?:\w+:)?document\s*>/u.test(xml)
    ) {
      throw new Error("Malformed word/document.xml.");
    }
    const text = decodeXml(
      xml
        .replace(/<\/(?:\w+:)?p\s*>/gu, "\n")
        .replace(/<(?:\w+:)?tab\b[^>]*\/>/gu, "\t")
        .replace(/<[^>]+>/gu, ""),
    );
    signal?.throwIfAborted();
    return text;
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof KnowledgeBaseLimitError) throw error;
    throw new Error(`Cannot extract text from knowledge base DOCX: ${path}`, {
      cause: error,
    });
  }
}

function decodeXml(value: string): string {
  const entities: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
  };
  return value.replace(
    /&(amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);/giu,
    (entity, name: string) => {
      if (!name.startsWith("#")) return entities[name.toLowerCase()] ?? entity;
      const hexadecimal = name[1]?.toLowerCase() === "x";
      return String.fromCodePoint(
        Number.parseInt(name.slice(hexadecimal ? 2 : 1), hexadecimal ? 16 : 10),
      );
    },
  );
}
