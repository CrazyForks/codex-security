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
const MAX_PDF_LZW_CODES = 1_000_000;
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
  const streams =
    />>(?:(?:\s+|%[^\r\n]*(?:\r\n|\r|\n))*)stream(?:\r\n|\r|\n)/gu;
  const indirectObjects = pdfCrossReferenceOffsets(contents);
  let inflatedBytes = 0;
  const dictionaryWork = { remaining: MAX_PDF_DICTIONARY_WORK_BYTES };
  for (const marker of contents.matchAll(streams)) {
    signal?.throwIfAborted();
    const dictionary = pdfStreamDictionary(
      contents,
      marker.index + 2,
      dictionaryWork,
      path,
      indirectObjects,
    );
    if (dictionary === null) continue;
    const filters = pdfStreamFilters(contents, dictionary, indirectObjects);
    if (filters.length === 0) continue;

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

    let decoded = source.subarray(streamStart, streamEnd);
    for (const [filterIndex, filter] of filters.entries()) {
      signal?.throwIfAborted();
      if (inflatedBytes >= MAX_EXTRACTED_DOCUMENT_BYTES) {
        throw oversizedPdfStream(path);
      }
      try {
        switch (filter) {
          case "ASCIIHexDecode":
          case "AHx":
            decoded = decodePdfAsciiHex(decoded, MAX_EXTRACTED_DOCUMENT_BYTES);
            break;
          case "ASCII85Decode":
          case "A85":
            decoded = decodePdfAscii85(decoded, MAX_EXTRACTED_DOCUMENT_BYTES);
            break;
          case "RunLengthDecode":
          case "RL":
            decoded = decodePdfRunLength(decoded, MAX_EXTRACTED_DOCUMENT_BYTES);
            break;
          case "LZWDecode":
          case "LZW":
            decoded = decodePdfLzw(
              decoded,
              MAX_EXTRACTED_DOCUMENT_BYTES,
              pdfLzwEarlyChange(dictionary, filterIndex),
            );
            break;
          case "FlateDecode":
          case "Fl":
            decoded = inflateSync(decoded, {
              maxOutputLength: MAX_EXTRACTED_DOCUMENT_BYTES,
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
  offsets: ReadonlyMap<string, number | null> | null,
): string | null {
  let depth = 1;
  let minimum = Math.max(0, end - MAX_PDF_DICTIONARY_SCAN_BYTES);
  for (const offset of offsets?.values() ?? []) {
    if (offset !== null && offset < end && offset > minimum) {
      minimum = offset;
    }
  }
  const lexical = pdfDictionaryLexicalValues(contents.slice(minimum, end));
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
        return contents
          .slice(minimum + index, end)
          .replace(
            /\/([^\s<>()\[\]{}/%]+)/gu,
            (_match, name: string) =>
              `/${name.replace(/#([0-9a-f]{2})/giu, (_escape, value: string) =>
                String.fromCharCode(Number.parseInt(value, 16)),
              )}`,
          );
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

function pdfIndirectValue(
  contents: string,
  object: string,
  generation: string,
  offsets: ReadonlyMap<string, number | null> | null,
): string | undefined {
  const offset = offsets?.get(`${object}:${generation}`);
  if (offset === null || offset === undefined) return undefined;
  return new RegExp(
    `^${object}\\s+${generation}\\s+obj\\s*(\\[[^\\]]*\\]|\\/[^\\s<>[\\]()%/]+|\\d+)\\s*endobj`,
    "u",
  ).exec(contents.slice(offset))?.[1];
}

function pdfCrossReferenceOffsets(
  contents: string,
): ReadonlyMap<string, number | null> | null {
  const marker = /startxref\s+(\d+)\s+%%EOF\s*$/u.exec(contents);
  let offset = Number(marker?.[1]);
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset >= contents.length
  ) {
    return null;
  }
  const entries = new Map<string, number | null>();
  const visited = new Set<number>();
  const whitespace = /[\u0000\t\n\f\r ]*/uy;
  const section = /(\d+)[\t ]+(\d+)(?:\r\n|\r|\n)/uy;
  const entry = /(\d+)[\t ]+(\d+)[\t ]+([nf])(?:[\t ]*(?:\r\n|\r|\n)|$)/uy;

  while (!visited.has(offset)) {
    visited.add(offset);
    if (contents.slice(offset, offset + 4) !== "xref") return null;
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
        if (previous === undefined) return entries;
        offset = Number(previous);
        if (
          !Number.isSafeInteger(offset) ||
          offset < 0 ||
          offset >= contents.length
        ) {
          return null;
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
        count > MAX_PDF_XREF_OBJECTS ||
        entries.size + count > MAX_PDF_XREF_OBJECTS
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
          entries.set(key, value[3] === "n" ? Number(value[1]) : null);
        }
      }
    }
  }
  return null;
}

function pdfDictionaryLexicalValues(dictionary: string): string {
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
  return output;
}

function pdfStreamFilters(
  contents: string,
  dictionary: string,
  offsets: ReadonlyMap<string, number | null> | null,
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
    );
    if (resolved === undefined) {
      throw new Error("Compressed PDF filter cannot be resolved safely.");
    }
    value = resolved;
  }
  return [...value.matchAll(/\/([^\s<>[\]()%/]+)/gu)].map((filter) =>
    filter[1]!.replace(/#([0-9a-f]{2})/giu, (_match, encoded: string) =>
      String.fromCharCode(Number.parseInt(encoded, 16)),
    ),
  );
}

function pdfLzwEarlyChange(dictionary: string, filterIndex: number): 0 | 1 {
  const lexical = pdfDictionaryLexicalValues(dictionary);
  const parameters = /\/(?:DecodeParms|DP)\s+(\[[\s\S]*?\]|<<[\s\S]*?>>)/u.exec(
    lexical,
  )?.[1];
  if (parameters === undefined) return 1;
  const selected = parameters.startsWith("[")
    ? [...parameters.matchAll(/null|<<[\s\S]*?>>/gu)][filterIndex]?.[0]
    : parameters;
  if (selected === undefined || selected === "null") return 1;
  const value = /\/EarlyChange\s+([01])(?=[\s/>])/u.exec(selected)?.[1];
  return value === "0" ? 0 : 1;
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
