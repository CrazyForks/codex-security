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

const MAX_CODE_POINT = 0x10ffff;
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
const MAX_PDF_XREF_OBJECTS = 65_536;
const MAX_PDF_DICTIONARY_SCAN_BYTES = 256 * 1024;
const MAX_PDF_DICTIONARY_WORK_BYTES = 2 * MAX_DOCUMENT_BYTES;
const MAX_PDF_DECODE_WORK_BYTES = 4 * MAX_EXTRACTED_DOCUMENT_BYTES;
const MAX_PDF_LZW_CODES = 1_000_000;
const READ_CHUNK_BYTES = 64 * 1024;

interface DiscoveryState {
  documents: Map<string, string>;
  entries: number;
  inputBytes: number;
}

class KnowledgeBaseLimitError extends Error {}

type PdfCrossReferenceEntry =
  | number
  | { readonly stream: number; readonly index: number }
  | null;

const pdfObjectStreamCache = new WeakMap<
  ReadonlyMap<string, PdfCrossReferenceEntry>,
  {
    streams: Map<
      number,
      ReadonlyArray<{ number: number; value: string | undefined }> | null
    >;
    remaining: number;
  }
>();

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
  const streams =
    />>(?:(?:\s+|%[^\r\n]*(?:\r\n|\r|\n))*)stream(?:\r\n|\r|\n)/gu;
  const indirectObjects = pdfCrossReferenceOffsets(contents, path, signal);
  const objectOffsets = [...(indirectObjects?.entries() ?? [])]
    .filter((entry): entry is [string, number] => typeof entry[1] === "number")
    .sort((left, right) => left[1] - right[1]);
  const pageContentReferences = pdfPageContentReferences(
    contents,
    indirectObjects,
    path,
    signal,
  );
  let inflatedBytes = 0;
  let decodingWorkBytes = 0;
  let streamBodyEnd = 0;
  const dictionaryWork = { remaining: MAX_PDF_DICTIONARY_WORK_BYTES };
  for (const marker of contents.matchAll(streams)) {
    signal?.throwIfAborted();
    if (marker.index < streamBodyEnd) continue;
    const object = pdfObjectBeforeOffset(objectOffsets, marker.index);
    const lexicalPrefix = pdfDictionaryLexicalValues(
      contents.slice(
        object?.[1] ??
          Math.max(0, marker.index - MAX_PDF_DICTIONARY_SCAN_BYTES),
        marker.index + 2,
      ),
      false,
    );
    if (!lexicalPrefix.endsWith(">>")) continue;
    const dictionary = pdfStreamDictionary(
      contents,
      marker.index + 2,
      dictionaryWork,
      path,
      object?.[1],
    );
    if (dictionary === null) continue;
    const streamStart = marker.index + marker[0].length;
    const declared = /\/Length\s+(\d+)(?:\s+(\d+)\s+R)?(?=[\s/>])/u.exec(
      pdfDictionaryLexicalValues(dictionary),
    );
    let length = Number(declared?.[1]);
    if (declared?.[2] !== undefined) {
      const referenced = pdfIndirectValue(
        contents,
        declared[1]!,
        declared[2],
        indirectObjects,
        path,
      );
      if (referenced === undefined) {
        throw new Error(
          "Compressed PDF stream length cannot be resolved safely.",
        );
      }
      length = Number(referenced);
    }
    let streamEnd = Number.isSafeInteger(length)
      ? streamStart + length
      : contents.indexOf("\nendstream", streamStart);
    if (streamEnd === -1)
      streamEnd = contents.indexOf("\rendstream", streamStart);
    if (streamEnd < streamStart || streamEnd > source.byteLength) continue;
    streamBodyEnd = streamEnd;
    const lexicalDictionary = pdfDictionaryLexicalValues(dictionary, false);
    if (pdfTopLevelDictionaryName(lexicalDictionary, "Subtype") === "Image") {
      const pageContent =
        object !== undefined && pageContentReferences.has(object[0]);
      if (!pageContent) continue;
    }
    const filters = pdfStreamFilters(
      contents,
      dictionary,
      indirectObjects,
      path,
    );
    if (filters.length === 0) continue;

    let decoded = source.subarray(streamStart, streamEnd);
    for (const [filterIndex, filter] of filters.entries()) {
      signal?.throwIfAborted();
      if (
        inflatedBytes >= MAX_EXTRACTED_DOCUMENT_BYTES ||
        decodingWorkBytes >= MAX_PDF_DECODE_WORK_BYTES
      ) {
        throw oversizedPdfStream(path);
      }
      const maximumOutput = Math.min(
        MAX_EXTRACTED_DOCUMENT_BYTES,
        MAX_PDF_DECODE_WORK_BYTES - decodingWorkBytes,
      );
      try {
        switch (filter) {
          case "ASCIIHexDecode":
          case "AHx":
            decoded = decodePdfAsciiHex(decoded, maximumOutput);
            break;
          case "ASCII85Decode":
          case "A85":
            decoded = decodePdfAscii85(decoded, maximumOutput);
            break;
          case "RunLengthDecode":
          case "RL":
            decoded = decodePdfRunLength(decoded, maximumOutput);
            break;
          case "LZWDecode":
          case "LZW":
            decoded = decodePdfLzw(
              decoded,
              maximumOutput,
              pdfLzwEarlyChange(
                dictionary,
                filterIndex,
                contents,
                indirectObjects,
                path,
              ),
            );
            break;
          case "FlateDecode":
          case "Fl":
            decoded = inflateSync(decoded, {
              maxOutputLength: maximumOutput,
            });
            break;
          case "DCTDecode":
          case "DCT":
          case "JPXDecode":
          case "JBIG2Decode":
          case "CCITTFaxDecode":
          case "CCF":
            // These image-only codecs are not evaluated while extracting text.
            decoded = Buffer.alloc(0);
            continue;
          default:
            throw new Error(`Unsupported compressed PDF filter: ${filter}`);
        }
      } catch (error) {
        if (error instanceof KnowledgeBaseLimitError) throw error;
        if (
          error instanceof Error &&
          "code" in error &&
          error.code === "ERR_BUFFER_TOO_LARGE"
        ) {
          throw oversizedPdfStream(path);
        }
        throw new Error(
          `Knowledge base PDF compressed stream cannot be safely bounded: ${path}`,
          { cause: error },
        );
      }
      if (["FlateDecode", "Fl", "LZWDecode", "LZW"].includes(filter)) {
        const predictorWork = {
          remaining: MAX_PDF_DECODE_WORK_BYTES - decodingWorkBytes,
        };
        const predicted = pdfApplyPredictor(
          dictionary,
          decoded,
          predictorWork,
          filterIndex,
          contents,
          indirectObjects,
          path,
        );
        if (predicted === null) {
          throw new Error(
            `Knowledge base PDF compressed stream cannot be safely bounded: ${path}`,
          );
        }
        decodingWorkBytes +=
          MAX_PDF_DECODE_WORK_BYTES -
          decodingWorkBytes -
          predictorWork.remaining;
        decoded = predicted;
      }
      decodingWorkBytes += decoded.byteLength;
      if (decodingWorkBytes > MAX_PDF_DECODE_WORK_BYTES) {
        throw oversizedPdfStream(path);
      }
    }
    inflatedBytes += decoded.byteLength;
    if (inflatedBytes > MAX_EXTRACTED_DOCUMENT_BYTES) {
      throw oversizedPdfStream(path);
    }
  }
}

function pdfStreamDictionary(
  contents: string,
  end: number,
  work: { remaining: number },
  path: string,
  objectOffset?: number,
): string | null {
  let depth = 1;
  let minimum = Math.max(0, end - MAX_PDF_DICTIONARY_SCAN_BYTES);
  if (objectOffset !== undefined && objectOffset > minimum) {
    minimum = objectOffset;
  }
  const lexical = pdfDictionaryLexicalValues(
    contents.slice(minimum, end),
    false,
  );
  for (let index = lexical.length - 3; index >= 0; index -= 1) {
    if (--work.remaining < 0) {
      throw new KnowledgeBaseLimitError(
        `Knowledge base PDF exceeds the ${MAX_PDF_DICTIONARY_WORK_BYTES}-byte dictionary scan limit: ${path}`,
      );
    }
    const token = lexical.slice(index, index + 2);
    if (token === ">>") {
      depth += 1;
      index -= 1;
    } else if (token === "<<") {
      depth -= 1;
      if (depth === 0) {
        return contents.slice(minimum + index, end);
      }
      index -= 1;
    }
  }
  if (minimum !== 0) {
    throw new KnowledgeBaseLimitError(
      `Knowledge base PDF exceeds the ${MAX_PDF_DICTIONARY_SCAN_BYTES}-byte dictionary limit: ${path}`,
    );
  }
  return null;
}

function pdfObjectBeforeOffset(
  offsets: ReadonlyArray<readonly [string, number]>,
  selected: number,
): readonly [string, number] | undefined {
  let low = 0;
  let high = offsets.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (offsets[middle]![1] < selected) low = middle + 1;
    else high = middle;
  }
  return offsets[low - 1];
}

function pdfIndirectValue(
  contents: string,
  object: string,
  generation: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
): string | undefined {
  const offset = offsets?.get(`${object}:${generation}`);
  if (offset === null || offset === undefined) return undefined;
  if (typeof offset === "number") {
    const value = new RegExp(
      `^${object}\\s+${generation}\\s+obj(?:\\s+|%[^\\r\\n]*(?:\\r\\n|\\r|\\n))*(<<[\\s\\S]*?>>|\\[[^\\]]*\\]|\\/[^\\s<>[\\]()%/]+|\\d+)`,
      "u",
    ).exec(contents.slice(offset));
    if (value?.[1] === undefined) return undefined;
    const remainder = contents.slice(offset + value[0].length);
    return /^(?:\s+|%[^\r\n]*(?:\r\n|\r|\n))*endobj(?=\s|$)/u.test(remainder)
      ? value[1]
      : undefined;
  }
  if (offsets === null || generation !== "0") return undefined;
  const streamOffset = offsets.get(`${offset.stream}:0`);
  if (typeof streamOffset !== "number") return undefined;
  let cache = pdfObjectStreamCache.get(offsets);
  if (cache === undefined) {
    cache = { streams: new Map(), remaining: MAX_PDF_DECODE_WORK_BYTES };
    pdfObjectStreamCache.set(offsets, cache);
  }
  let objects = cache.streams.get(offset.stream);
  if (objects === null) return undefined;
  if (objects === undefined) {
    cache.streams.set(offset.stream, null);
    const decoded = pdfCrossReferenceStream(
      contents,
      streamOffset,
      offsets,
      path,
      cache,
    );
    if (decoded === null) return undefined;
    const dictionary = pdfDictionaryLexicalValues(decoded.dictionary);
    const count = Number(/\/N\s+(\d+)(?=[\s/>])/u.exec(dictionary)?.[1]);
    const first = Number(/\/First\s+(\d+)(?=[\s/>])/u.exec(dictionary)?.[1]);
    if (
      !Number.isSafeInteger(count) ||
      count > MAX_PDF_XREF_OBJECTS ||
      !Number.isSafeInteger(first) ||
      first > decoded.contents.byteLength
    ) {
      return undefined;
    }
    const stream = decoded.contents;
    const header = stream
      .subarray(0, first)
      .toString("latin1")
      .replace(/%[^\r\n]*/gu, " ")
      .trim()
      .split(/\s+/u);
    if (header.length !== 2 * count) return undefined;
    const parsed: Array<{ number: number; value: string | undefined }> = [];
    for (let index = 0; index < count; index += 1) {
      const number = Number(header[index * 2]);
      const start = Number(header[index * 2 + 1]);
      const next =
        index + 1 < count
          ? Number(header[(index + 1) * 2 + 1])
          : stream.byteLength - first;
      if (
        !Number.isSafeInteger(number) ||
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(next) ||
        number < 0 ||
        start < 0 ||
        next < 0 ||
        start > next ||
        first + next > stream.byteLength
      ) {
        return undefined;
      }
      const raw = stream
        .subarray(first + start, first + next)
        .toString("latin1")
        .trim();
      const lexical = pdfDictionaryLexicalValues(raw, false).trim();
      const primitive = /^(\[[^\]]*\]|\/[^\s<>[\]()%/]+|\d+)$/u.exec(
        lexical,
      )?.[1];
      parsed.push({
        number,
        value:
          primitive ??
          (lexical.startsWith("<<") && lexical.endsWith(">>")
            ? lexical
            : undefined),
      });
    }
    objects = parsed;
    cache.streams.set(offset.stream, objects);
  }
  const selected = objects[offset.index];
  return selected?.number === Number(object) ? selected.value : undefined;
}

function pdfCrossReferenceOffsets(
  contents: string,
  path: string,
  signal?: AbortSignal,
): ReadonlyMap<string, PdfCrossReferenceEntry> | null {
  const marker = /startxref\s+(\d+)\s+%%EOF\s*$/u.exec(contents);
  let offset = Number(marker?.[1]);
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset >= contents.length
  ) {
    return null;
  }
  const entries = new Map<string, PdfCrossReferenceEntry>();
  const visited = new Set<number>();
  const pending = [offset];
  const decodingWork = { remaining: MAX_PDF_DECODE_WORK_BYTES };
  const whitespace = /[\u0000\t\n\f\r ]*/uy;
  const section = /(\d+)[\t ]+(\d+)(?:\r\n|\r|\n)/uy;
  const entry = /(\d+)[\t ]+(\d+)[\t ]+([nf])(?:[\t ]*(?:\r\n|\r|\n)|$)/uy;

  while (pending.length > 0) {
    signal?.throwIfAborted();
    offset = pending.shift()!;
    if (visited.has(offset)) continue;
    visited.add(offset);
    if (contents.slice(offset, offset + 4) !== "xref") {
      const stream = pdfCrossReferenceStream(
        contents,
        offset,
        entries,
        path,
        decodingWork,
      );
      if (stream === null) return null;
      const dictionary = pdfDictionaryLexicalValues(stream.dictionary);
      if (!/\/Type\s*\/XRef(?=[\s/>])/u.test(dictionary)) return null;
      const widths = /\/W\s*\[([^\]]+)\]/u
        .exec(dictionary)?.[1]
        ?.trim()
        .split(/\s+/u)
        .map(Number);
      if (
        widths?.length !== 3 ||
        widths.some(
          (width) => !Number.isSafeInteger(width) || width < 0 || width > 6,
        )
      ) {
        return null;
      }
      const rowSize = widths.reduce((total, width) => total + width, 0);
      if (rowSize === 0) return null;
      const size = Number(/\/Size\s+(\d+)(?=[\s/>])/u.exec(dictionary)?.[1]);
      const indices = /\/Index\s*\[([^\]]+)\]/u
        .exec(dictionary)?.[1]
        ?.trim()
        .split(/\s+/u)
        .map(Number) ?? [0, size];
      if (
        !Number.isSafeInteger(size) ||
        indices.length % 2 !== 0 ||
        indices.some((index) => !Number.isSafeInteger(index) || index < 0)
      ) {
        return null;
      }
      let cursor = 0;
      for (let index = 0; index < indices.length; index += 2) {
        const first = indices[index]!;
        const count = indices[index + 1]!;
        if (count > MAX_PDF_XREF_OBJECTS) return null;
        for (let row = 0; row < count; row += 1) {
          if (cursor + rowSize > stream.contents.byteLength) return null;
          const fields = widths.map((width, field) => {
            let value = field === 0 && width === 0 ? 1 : 0;
            for (let byte = 0; byte < width; byte += 1) {
              value = value * 256 + stream.contents[cursor++]!;
            }
            return value;
          });
          const key = `${first + row}:${fields[0] === 2 ? 0 : fields[2]}`;
          if (entries.has(key)) continue;
          if (entries.size >= MAX_PDF_XREF_OBJECTS) return null;
          entries.set(
            key,
            fields[0] === 0
              ? null
              : fields[0] === 1
                ? fields[1]!
                : fields[0] === 2
                  ? { stream: fields[1]!, index: fields[2]! }
                  : null,
          );
        }
      }
      const previous = /\/Prev\s+(\d+)(?=[\s/>])/u.exec(dictionary)?.[1];
      if (previous !== undefined) {
        const previousOffset = Number(previous);
        if (
          !Number.isSafeInteger(previousOffset) ||
          previousOffset >= contents.length
        ) {
          return null;
        }
        pending.push(previousOffset);
      }
      continue;
    }
    let cursor = offset + 4;
    while (true) {
      whitespace.lastIndex = cursor;
      cursor = whitespace.exec(contents)?.index ?? cursor;
      cursor = whitespace.lastIndex;
      if (contents.startsWith("trailer", cursor)) {
        const trailer = pdfDictionaryLexicalValues(
          contents.slice(cursor + "trailer".length, cursor + 64 * 1024),
        );
        const previous = /\/Prev\s+(\d+)(?=[\s/>])/u.exec(trailer)?.[1];
        const xrefStream = /\/XRefStm\s+(\d+)(?=[\s/>])/u.exec(trailer)?.[1];
        for (const value of [xrefStream, previous]) {
          if (value === undefined) continue;
          const next = Number(value);
          if (!Number.isSafeInteger(next) || next >= contents.length)
            return null;
          pending.push(next);
        }
        break;
      }
      section.lastIndex = cursor;
      const subsection = section.exec(contents);
      if (subsection === null) return null;
      cursor = section.lastIndex;
      const firstObject = Number(subsection[1]);
      const count = Number(subsection[2]);
      if (
        !Number.isSafeInteger(firstObject) ||
        !Number.isSafeInteger(count) ||
        count < 0 ||
        count > MAX_PDF_XREF_OBJECTS
      ) {
        return null;
      }
      for (let index = 0; index < count; index += 1) {
        entry.lastIndex = cursor;
        const value = entry.exec(contents);
        if (value === null) return null;
        cursor = entry.lastIndex;
        const key = `${firstObject + index}:${Number(value[2])}`;
        if (!entries.has(key)) {
          if (entries.size >= MAX_PDF_XREF_OBJECTS) return null;
          entries.set(key, value[3] === "n" ? Number(value[1]) : null);
        }
      }
    }
  }
  return entries;
}

function pdfCrossReferenceStream(
  contents: string,
  offset: number,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry>,
  path: string,
  work: { remaining: number },
): { dictionary: string; contents: Buffer } | null {
  const header = /^\d+\s+\d+\s+obj\s*/u.exec(contents.slice(offset));
  if (header === null) return null;
  const tail = contents.slice(offset + header[0].length);
  const marker =
    />>(?:(?:\s+|%[^\r\n]*(?:\r\n|\r|\n))*)stream(?:\r\n|\r|\n)/u.exec(tail);
  if (marker === null || marker.index > MAX_PDF_DICTIONARY_SCAN_BYTES) {
    return null;
  }
  const dictionary = tail.slice(0, marker.index + 2);
  const length = Number(
    /\/Length\s+(\d+)(?=[\s/>])/u.exec(
      pdfDictionaryLexicalValues(dictionary),
    )?.[1],
  );
  const streamOffset =
    offset + header[0].length + marker.index + marker[0].length;
  if (
    !Number.isSafeInteger(length) ||
    streamOffset + length > contents.length
  ) {
    return null;
  }
  let decoded: Buffer<ArrayBufferLike> = Buffer.from(
    contents.slice(streamOffset, streamOffset + length),
    "latin1",
  );
  for (const [filterIndex, filter] of pdfStreamFilters(
    contents,
    dictionary,
    offsets,
    path,
  ).entries()) {
    try {
      switch (filter) {
        case "FlateDecode":
        case "Fl":
          decoded = inflateSync(decoded, {
            maxOutputLength: Math.min(
              MAX_EXTRACTED_DOCUMENT_BYTES,
              work.remaining,
            ),
          });
          break;
        case "ASCIIHexDecode":
        case "AHx":
          decoded = decodePdfAsciiHex(decoded, work.remaining);
          break;
        case "ASCII85Decode":
        case "A85":
          decoded = decodePdfAscii85(decoded, work.remaining);
          break;
        case "RunLengthDecode":
        case "RL":
          decoded = decodePdfRunLength(decoded, work.remaining);
          break;
        case "LZWDecode":
        case "LZW":
          decoded = decodePdfLzw(
            decoded,
            work.remaining,
            pdfLzwEarlyChange(dictionary, filterIndex, contents, offsets, path),
          );
          break;
        default:
          return null;
      }
    } catch (error) {
      if (error instanceof KnowledgeBaseLimitError) throw error;
      return null;
    }
    work.remaining -= decoded.byteLength;
    if (work.remaining < 0) return null;
    if (["FlateDecode", "Fl", "LZWDecode", "LZW"].includes(filter)) {
      const predicted = pdfApplyPredictor(
        dictionary,
        decoded,
        work,
        filterIndex,
        contents,
        offsets,
        path,
      );
      if (predicted === null) return null;
      decoded = predicted;
    }
  }
  return { dictionary, contents: decoded };
}

function pdfApplyPredictor(
  dictionary: string,
  decoded: Buffer,
  work: { remaining: number },
  filterIndex: number,
  contents: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
): Buffer | null {
  const parameters = pdfFilterDecodeParameters(
    dictionary,
    filterIndex,
    contents,
    offsets,
    path,
  );
  const predictor = Number(
    /\/Predictor\s+(\d+)(?=[\s/>])/u.exec(parameters ?? "")?.[1] ?? "1",
  );
  if (predictor === 1) return decoded;
  const columns = Number(
    /\/Columns\s+(\d+)(?=[\s/>])/u.exec(parameters!)?.[1] ?? "1",
  );
  const colors = Number(
    /\/Colors\s+(\d+)(?=[\s/>])/u.exec(parameters!)?.[1] ?? "1",
  );
  const bits = Number(
    /\/BitsPerComponent\s+(\d+)(?=[\s/>])/u.exec(parameters!)?.[1] ?? "8",
  );
  if (
    (predictor !== 2 && (predictor < 10 || predictor > 15)) ||
    !Number.isSafeInteger(columns) ||
    !Number.isSafeInteger(colors) ||
    !Number.isSafeInteger(bits) ||
    columns <= 0 ||
    colors <= 0 ||
    bits <= 0
  ) {
    return null;
  }
  const rowBytes = Math.ceil((columns * colors * bits) / 8);
  const encodedRowBytes = rowBytes + (predictor === 2 ? 0 : 1);
  if (
    !Number.isSafeInteger(rowBytes) ||
    rowBytes <= 0 ||
    decoded.byteLength % encodedRowBytes !== 0 ||
    (predictor === 2 && ![1, 2, 4, 8, 16].includes(bits))
  ) {
    return null;
  }
  const reconstructed =
    predictor === 2
      ? Buffer.from(decoded)
      : Buffer.alloc((decoded.byteLength / encodedRowBytes) * rowBytes);
  const pixelBytes = Math.max(1, Math.ceil((colors * bits) / 8));
  let input = 0;
  let output = 0;
  if (predictor === 2) {
    const samples = columns * colors;
    const rows = decoded.byteLength / rowBytes;
    const reconstructionWork = rows * Math.max(0, samples - colors);
    if (
      !Number.isSafeInteger(reconstructionWork) ||
      reconstructionWork > work.remaining
    ) {
      return null;
    }
    work.remaining -= reconstructionWork;
    const sampleMask = 2 ** bits - 1;
    for (let row = 0; row < reconstructed.byteLength; row += rowBytes) {
      for (let sample = colors; sample < samples; sample += 1) {
        if (bits === 16) {
          const current = row + sample * 2;
          const previous = row + (sample - colors) * 2;
          reconstructed.writeUInt16BE(
            (reconstructed.readUInt16BE(current) +
              reconstructed.readUInt16BE(previous)) &
              sampleMask,
            current,
          );
        } else {
          const bit = sample * bits;
          const previousBit = (sample - colors) * bits;
          const current = row + Math.floor(bit / 8);
          const previous = row + Math.floor(previousBit / 8);
          const shift = 8 - bits - (bit % 8);
          const previousShift = 8 - bits - (previousBit % 8);
          const next =
            (((reconstructed[current]! >> shift) & sampleMask) +
              ((reconstructed[previous]! >> previousShift) & sampleMask)) &
            sampleMask;
          reconstructed[current] =
            (reconstructed[current]! & ~(sampleMask << shift)) |
            (next << shift);
        }
      }
    }
    return reconstructed;
  }
  while (input < decoded.byteLength) {
    const filter = decoded[input++]!;
    if (filter > 4) return null;
    for (let column = 0; column < rowBytes; column += 1) {
      const left =
        column < pixelBytes ? 0 : reconstructed[output - pixelBytes]!;
      const above = output < rowBytes ? 0 : reconstructed[output - rowBytes]!;
      const upperLeft =
        output < rowBytes || column < pixelBytes
          ? 0
          : reconstructed[output - rowBytes - pixelBytes]!;
      let prediction = 0;
      if (filter === 1) prediction = left;
      else if (filter === 2) prediction = above;
      else if (filter === 3) prediction = Math.floor((left + above) / 2);
      else if (filter === 4) {
        const estimate = left + above - upperLeft;
        const leftDistance = Math.abs(estimate - left);
        const aboveDistance = Math.abs(estimate - above);
        const diagonalDistance = Math.abs(estimate - upperLeft);
        prediction =
          leftDistance <= aboveDistance && leftDistance <= diagonalDistance
            ? left
            : aboveDistance <= diagonalDistance
              ? above
              : upperLeft;
      }
      reconstructed[output++] = (decoded[input++]! + prediction) & 255;
    }
  }
  return reconstructed;
}

function pdfDictionaryLexicalValues(
  dictionary: string,
  normalizeNames = true,
): string {
  let output = "";
  let literalDepth = 0;
  let escaped = false;
  let comment = false;
  let hex = false;
  for (let index = 0; index < dictionary.length; index += 1) {
    const character = dictionary[index]!;
    if (comment) {
      if (character === "\r" || character === "\n") {
        comment = false;
        output += character;
      } else {
        output += " ";
      }
      continue;
    }
    if (literalDepth > 0) {
      output += " ";
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "(") {
        literalDepth += 1;
      } else if (character === ")") {
        literalDepth -= 1;
      }
      continue;
    }
    if (hex) {
      output += " ";
      if (character === ">") hex = false;
      continue;
    }
    if (character === "%") {
      comment = true;
      output += " ";
    } else if (character === "(") {
      literalDepth = 1;
      output += " ";
    } else if (character === "<" && dictionary[index + 1] === "<") {
      output += "<<";
      index += 1;
    } else if (character === "<" && dictionary[index + 1] !== "<") {
      hex = true;
      output += " ";
    } else {
      output += character;
    }
  }
  return normalizeNames
    ? output.replace(
        /\/([^\s<>()\[\]{}/%]+)/gu,
        (_match, name: string) =>
          `/${name.replace(/#([0-9a-f]{2})/giu, (_escape, value: string) =>
            String.fromCharCode(Number.parseInt(value, 16)),
          )}`,
      )
    : output;
}

function pdfTopLevelDictionaryName(
  dictionary: string,
  key: string,
): string | undefined {
  let dictionaryDepth = 0;
  let arrayDepth = 0;
  for (let index = 0; index < dictionary.length; index += 1) {
    if (dictionary.startsWith("<<", index)) {
      dictionaryDepth += 1;
      index += 1;
      continue;
    }
    if (dictionary.startsWith(">>", index)) {
      dictionaryDepth -= 1;
      index += 1;
      continue;
    }
    if (dictionary[index] === "[") {
      arrayDepth += 1;
      continue;
    }
    if (dictionary[index] === "]") {
      arrayDepth -= 1;
      continue;
    }
    if (
      dictionaryDepth !== 1 ||
      arrayDepth !== 0 ||
      dictionary[index] !== "/"
    ) {
      continue;
    }
    const value = /^\/([^\s<>[\]()%/]+)\s*\/([^\s<>[\]()%/]+)(?=[\s/>])/u.exec(
      dictionary.slice(index),
    );
    if (value?.[1] !== undefined && pdfDecodedName(value[1]) === key) {
      return pdfDecodedName(value[2]!);
    }
  }
  return undefined;
}

function pdfDecodedName(value: string): string {
  return value.replace(/#([0-9a-f]{2})/giu, (_match, encoded: string) =>
    String.fromCharCode(Number.parseInt(encoded, 16)),
  );
}

function pdfPageContentReferences(
  contents: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
  signal?: AbortSignal,
): ReadonlySet<string> {
  const references = /\/(?:Contents)\s+(\[[^\]]*\]|\d+\s+\d+\s+R)/gu;
  const pending: string[] = [];
  let remaining = MAX_PDF_XREF_OBJECTS;
  for (const entry of contents.matchAll(references)) {
    signal?.throwIfAborted();
    if (--remaining < 0) throw oversizedPdfStream(path);
    pending.push(entry[1]!);
  }
  for (const [key, offset] of offsets ?? []) {
    if (offset === null || typeof offset === "number") continue;
    signal?.throwIfAborted();
    if (--remaining < 0) throw oversizedPdfStream(path);
    const [object, generation] = key.split(":");
    const dictionary = pdfIndirectValue(
      contents,
      object!,
      generation!,
      offsets,
      path,
    );
    if (dictionary === undefined || !dictionary.startsWith("<<")) continue;
    const lexical = pdfDictionaryLexicalValues(dictionary, false);
    if (pdfTopLevelDictionaryName(lexical, "Type") !== "Page") continue;
    const contentsValue = pdfTopLevelDictionaryReference(lexical, "Contents");
    if (contentsValue !== undefined) pending.push(contentsValue);
  }
  const selected = new Set<string>();
  while (pending.length > 0) {
    signal?.throwIfAborted();
    if (--remaining < 0) throw oversizedPdfStream(path);
    const current = pdfDictionaryLexicalValues(pending.pop()!);
    for (const reference of current.matchAll(/(\d+)\s+(\d+)\s+R/gu)) {
      const key = `${reference[1]}:${reference[2]}`;
      if (selected.has(key)) continue;
      selected.add(key);
      const resolved = pdfIndirectValue(
        contents,
        reference[1]!,
        reference[2]!,
        offsets,
        path,
      );
      if (resolved?.trimStart().startsWith("[") === true) {
        pending.push(resolved);
      }
    }
  }
  return selected;
}

function pdfTopLevelDictionaryReference(
  dictionary: string,
  key: string,
): string | undefined {
  let dictionaryDepth = 0;
  let arrayDepth = 0;
  for (let index = 0; index < dictionary.length; index += 1) {
    if (dictionary.startsWith("<<", index)) {
      dictionaryDepth += 1;
      index += 1;
      continue;
    }
    if (dictionary.startsWith(">>", index)) {
      dictionaryDepth -= 1;
      index += 1;
      continue;
    }
    if (dictionary[index] === "[") {
      arrayDepth += 1;
      continue;
    }
    if (dictionary[index] === "]") {
      arrayDepth -= 1;
      continue;
    }
    if (
      dictionaryDepth !== 1 ||
      arrayDepth !== 0 ||
      dictionary[index] !== "/"
    ) {
      continue;
    }
    const value =
      /^\/([^\s<>[\]()%/]+)\s*(\[[^\]]*\]|\d+\s+\d+\s+R)(?=[\s/>])/u.exec(
        dictionary.slice(index),
      );
    if (value?.[1] !== undefined && pdfDecodedName(value[1]) === key) {
      return value[2];
    }
  }
  return undefined;
}

function pdfStreamFilters(
  contents: string,
  dictionary: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
): string[] {
  const match =
    /\/(?:Filter|F)\s+(\[[^\]]*\]|\/[^\s<>[\]()%/]+|\d+\s+\d+\s+R)(?=[\s/>])/u.exec(
      pdfDictionaryLexicalValues(dictionary),
    );
  if (match?.[1] === undefined) return [];
  let value = match[1];
  const reference = /^(\d+)\s+(\d+)\s+R$/u.exec(value);
  if (reference !== null) {
    const resolved = pdfIndirectValue(
      contents,
      reference[1]!,
      reference[2]!,
      offsets,
      path,
    );
    if (resolved === undefined) {
      throw new Error("Compressed PDF filter cannot be resolved safely.");
    }
    value = pdfDictionaryLexicalValues(resolved);
  }
  const filters: string[] = [];
  for (const filter of value.matchAll(
    /\/([^\s<>[\]()%/]+)|(\d+)\s+(\d+)\s+R/gu,
  )) {
    let name = filter[1];
    if (name === undefined) {
      const resolved = pdfIndirectValue(
        contents,
        filter[2]!,
        filter[3]!,
        offsets,
        path,
      );
      const reference = /^\/([^\s<>[\]()%/]+)$/u.exec(
        pdfDictionaryLexicalValues(resolved ?? "").trim(),
      );
      if (reference?.[1] === undefined) {
        throw new Error("Compressed PDF filter cannot be resolved safely.");
      }
      name = reference[1];
    }
    filters.push(pdfDecodedName(name));
  }
  return filters;
}

function pdfLzwEarlyChange(
  dictionary: string,
  filterIndex: number,
  contents: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
): 0 | 1 {
  const selected = pdfFilterDecodeParameters(
    dictionary,
    filterIndex,
    contents,
    offsets,
    path,
  );
  if (selected === undefined) return 1;
  const value = /\/EarlyChange\s+([01])(?=[\s/>])/u.exec(selected)?.[1];
  return value === "0" ? 0 : 1;
}

function pdfFilterDecodeParameters(
  dictionary: string,
  filterIndex: number,
  contents: string,
  offsets: ReadonlyMap<string, PdfCrossReferenceEntry> | null,
  path: string,
): string | undefined {
  const lexical = pdfDictionaryLexicalValues(dictionary);
  const parameters =
    /\/(?:DecodeParms|DP)\s+(\[[\s\S]*?\]|<<[\s\S]*?>>|\d+\s+\d+\s+R)/u.exec(
      lexical,
    )?.[1];
  if (parameters === undefined) return undefined;
  const selected = parameters.startsWith("[")
    ? [...parameters.matchAll(/null|<<[\s\S]*?>>|\d+\s+\d+\s+R/gu)][
        filterIndex
      ]?.[0]
    : parameters;
  if (selected === undefined || selected === "null") return undefined;
  const reference = /^(\d+)\s+(\d+)\s+R$/u.exec(selected);
  if (reference === null) return selected;
  const resolved = pdfIndirectValue(
    contents,
    reference[1]!,
    reference[2]!,
    offsets,
    path,
  );
  return resolved?.startsWith("<<") && resolved.endsWith(">>")
    ? resolved
    : undefined;
}

function oversizedPdfStream(path: string): KnowledgeBaseLimitError {
  return new KnowledgeBaseLimitError(
    `Knowledge base document exceeds the ${MAX_EXTRACTED_DOCUMENT_BYTES}-byte extracted-text limit: ${path}`,
  );
}

function decodePdfAsciiHex(value: Buffer, maximum: number): Buffer {
  const digits = value.toString("latin1").replace(/[\u0000\t\n\f\r ]/gu, "");
  const end = digits.indexOf(">");
  const hex = end === -1 ? digits : digits.slice(0, end);
  if (!/^[0-9a-f]*$/iu.test(hex)) throw new Error("Invalid PDF ASCIIHex data.");
  if (Math.ceil(hex.length / 2) > maximum) {
    throw Object.assign(new Error("Decoded PDF stream is too large."), {
      code: "ERR_BUFFER_TOO_LARGE",
    });
  }
  return Buffer.from(hex.length % 2 === 0 ? hex : `${hex}0`, "hex");
}

function decodePdfAscii85(value: Buffer, maximum: number): Buffer {
  const encoded = value.toString("latin1").replace(/[\u0000\t\n\f\r ]/gu, "");
  const output = Buffer.allocUnsafe(Math.min(maximum, encoded.length * 4));
  let used = 0;
  let group: number[] = [];
  const append = (word: number, count: number): void => {
    if (used + count > maximum) {
      throw Object.assign(new Error("Decoded PDF stream is too large."), {
        code: "ERR_BUFFER_TOO_LARGE",
      });
    }
    for (let index = 0; index < count; index += 1) {
      output[used++] = Math.floor(word / 256 ** (3 - index)) & 0xff;
    }
  };
  for (let index = 0; index < encoded.length; index += 1) {
    const character = encoded[index]!;
    if (character === "~" && encoded[index + 1] === ">") break;
    if (character === "z" && group.length === 0) {
      append(0, 4);
      continue;
    }
    const digit = character.charCodeAt(0) - 33;
    if (digit < 0 || digit > 84) throw new Error("Invalid PDF ASCII85 data.");
    group.push(digit);
    if (group.length === 5) {
      const word = group.reduce((result, part) => result * 85 + part, 0);
      if (word > 0xffffffff) throw new Error("Invalid PDF ASCII85 group.");
      append(word, 4);
      group = [];
    }
  }
  if (group.length === 1) throw new Error("Invalid partial PDF ASCII85 group.");
  if (group.length > 1) {
    const count = group.length - 1;
    while (group.length < 5) group.push(84);
    append(
      group.reduce((result, part) => result * 85 + part, 0),
      count,
    );
  }
  return output.subarray(0, used);
}

function decodePdfRunLength(value: Buffer, maximum: number): Buffer {
  const output = Buffer.allocUnsafe(Math.min(maximum, value.length * 128));
  let written = 0;
  for (let index = 0; index < value.length; ) {
    const control = value[index++]!;
    if (control === 128) break;
    if (control < 128) {
      const count = control + 1;
      if (index + count > value.length || written + count > maximum) {
        throw Object.assign(new Error("Decoded PDF stream is too large."), {
          code: "ERR_BUFFER_TOO_LARGE",
        });
      }
      value.copy(output, written, index, index + count);
      index += count;
      written += count;
    } else {
      const count = 257 - control;
      if (index >= value.length || written + count > maximum) {
        throw Object.assign(new Error("Decoded PDF stream is too large."), {
          code: "ERR_BUFFER_TOO_LARGE",
        });
      }
      output.fill(value[index++]!, written, written + count);
      written += count;
    }
  }
  return output.subarray(0, written);
}

function decodePdfLzw(
  value: Buffer,
  maximum: number,
  earlyChange: 0 | 1,
): Buffer {
  const dictionary = Array.from({ length: 256 }, (_unused, code) =>
    Buffer.from([code]),
  );
  let nextCode = 258;
  let codeBits = 9;
  let bitOffset = 0;
  let previous: Buffer | undefined;
  const chunks: Buffer[] = [];
  let outputBytes = 0;
  let decodedCodes = 0;
  while (bitOffset + codeBits <= value.byteLength * 8) {
    if (++decodedCodes > MAX_PDF_LZW_CODES) {
      throw Object.assign(new Error("PDF LZW stream requires too much work."), {
        code: "ERR_BUFFER_TOO_LARGE",
      });
    }
    let code = 0;
    for (let bit = 0; bit < codeBits; bit += 1) {
      const offset = bitOffset + bit;
      code =
        (code << 1) |
        ((value[Math.floor(offset / 8)]! >> (7 - (offset % 8))) & 1);
    }
    bitOffset += codeBits;
    if (code === 256) {
      dictionary.length = 256;
      nextCode = 258;
      codeBits = 9;
      previous = undefined;
      continue;
    }
    if (code === 257) break;
    const entry =
      dictionary[code] ??
      (code === nextCode && previous !== undefined
        ? Buffer.concat([previous, previous.subarray(0, 1)])
        : undefined);
    if (entry === undefined) throw new Error("Invalid PDF LZW stream.");
    if (outputBytes + entry.byteLength > maximum) {
      throw Object.assign(new Error("Decoded PDF stream is too large."), {
        code: "ERR_BUFFER_TOO_LARGE",
      });
    }
    chunks.push(entry);
    outputBytes += entry.byteLength;
    if (previous !== undefined && nextCode < 4_096) {
      dictionary[nextCode++] = Buffer.concat([previous, entry.subarray(0, 1)]);
      if (nextCode + earlyChange === 1 << codeBits && codeBits < 12) {
        codeBits += 1;
      }
    }
    previous = entry;
  }
  return Buffer.concat(chunks, outputBytes);
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
    let seenDocument = false;
    const files = unzipSync(bytes, {
      filter: (file) => {
        if (file.name !== "word/document.xml") return false;
        if (seenDocument) {
          throw new KnowledgeBaseLimitError(
            `Knowledge base DOCX contains duplicate word/document.xml entries: ${path}`,
          );
        }
        seenDocument = true;
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
      const codePoint = Number.parseInt(
        name.slice(hexadecimal ? 2 : 1),
        hexadecimal ? 16 : 10,
      );
      // A reference that cannot name a Unicode scalar value is left as literal
      // text, matching the unrecognized-named-entity fallback above. Without the
      // bound String.fromCodePoint throws RangeError, which surfaced as an
      // unextractable document and failed the whole knowledge base. Surrogates
      // are excluded too: XML forbids them and writing one would silently encode
      // as U+FFFD.
      return isUnicodeScalarValue(codePoint)
        ? String.fromCodePoint(codePoint)
        : entity;
    },
  );
}

function isUnicodeScalarValue(codePoint: number): boolean {
  return (
    Number.isInteger(codePoint) &&
    codePoint >= 0 &&
    codePoint <= MAX_CODE_POINT &&
    !(codePoint >= 0xd800 && codePoint <= 0xdfff)
  );
}
