import { spawnSync } from "node:child_process";
import { renameSync, symlinkSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { afterEach, describe, expect, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import { prepareKnowledgeBase } from "../src/knowledge-base.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-knowledge-test-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function extractedDocuments(path: string): Promise<string[]> {
  return await Promise.all(
    (await readdir(path)).map((name) => readFile(join(path, name), "utf8")),
  );
}

function docx(text: string): Uint8Array {
  return zipSync({
    "word/document.xml": strToU8(
      `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`,
    ),
  });
}

function pdf(
  text: string,
  pages = 1,
  compressed = false,
  streamPrefix = "",
  options: {
    filter?: string;
    encode?: (bytes: Buffer) => Buffer;
    extraStreams?: number;
    indirectLength?: boolean;
    indirectFilter?: boolean;
    indirectFilterArray?: boolean;
    indirectCommentedFilterArray?: boolean;
    indirectContentsArray?: boolean;
    indirectValuePrefix?: string;
    indirectValueComment?: string;
    imageBytes?: Buffer;
    uncompressedImage?: boolean;
    formBytes?: Buffer;
    headerComment?: string;
    dictionaryPrefix?: string;
    streamComment?: string;
  } = {},
): Uint8Array {
  const escaped = text.replace(/[\\()]/gu, "\\$&");
  const chunks = escaped.match(/.{1,512}/gu) ?? [""];
  const stream = `${streamPrefix}BT /F1 12 Tf 72 720 Td ${chunks
    .map((chunk) => `(${chunk}) Tj`)
    .join(" ")} ET`;
  let streamBytes: Buffer = compressed
    ? deflateSync(Buffer.from(stream))
    : Buffer.from(stream);
  if (options.encode !== undefined) streamBytes = options.encode(streamBytes);
  const pageObjects = Array.from({ length: pages }, (_, index) => index + 3);
  const font = pages + 3;
  const content = pages + 4;
  const directFilter =
    options.filter ?? (compressed ? "/FlateDecode" : undefined);
  const extraStreams = options.extraStreams ?? 0;
  let nextObject = content + extraStreams + 1;
  const lengthObject = options.indirectLength ? nextObject++ : undefined;
  const indirectFilter =
    options.indirectFilter ||
    options.indirectFilterArray ||
    options.indirectCommentedFilterArray;
  const filterObject = indirectFilter ? nextObject++ : undefined;
  const filterNameObject = options.indirectCommentedFilterArray
    ? nextObject++
    : undefined;
  const contentsArrayObject = options.indirectContentsArray
    ? nextObject++
    : undefined;
  const imageObject =
    options.imageBytes === undefined ? undefined : nextObject++;
  const formObject = options.formBytes === undefined ? undefined : nextObject++;
  const length =
    lengthObject === undefined
      ? String(streamBytes.byteLength)
      : `${lengthObject} 0 R`;
  const filterReference = `${filterObject} 0 R`;
  const filter = options.indirectFilterArray
    ? `[${filterReference}]`
    : options.indirectFilter || options.indirectCommentedFilterArray
      ? filterReference
      : directFilter;
  const streamObject = `<< ${options.dictionaryPrefix ?? ""}/Length ${length}${filter === undefined ? "" : ` /Filter ${filter}`} >>${options.streamComment === undefined ? "\n" : ` ${options.streamComment}\n`}stream\n${streamBytes.toString("latin1")}\nendstream`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pageObjects.map((number) => `${number} 0 R`).join(" ")}] /Count ${pages} >>`,
    ...pageObjects.map(
      () =>
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 2000000 792] /Resources << /Font << /F1 ${font} 0 R >>${imageObject === undefined && formObject === undefined ? "" : ` /XObject <<${imageObject === undefined ? "" : ` /Im1 ${imageObject} 0 R`}${formObject === undefined ? "" : ` /Fm1 ${formObject} 0 R`} >>`} >> /Contents ${contentsArrayObject ?? content} 0 R >>`,
    ),
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    streamObject,
    ...Array.from({ length: extraStreams }, () => streamObject),
    ...(options.indirectLength
      ? [
          `${options.indirectValuePrefix ?? ""}${streamBytes.byteLength}${options.indirectValueComment ?? ""}`,
        ]
      : []),
    ...(indirectFilter
      ? [
          `${options.indirectValuePrefix ?? ""}${filterNameObject === undefined ? directFilter ?? "/FlateDecode" : `[${filterNameObject} % valid filter comment\n0 R]`}${options.indirectValueComment ?? ""}`,
        ]
      : []),
    ...(filterNameObject === undefined ? [] : [directFilter ?? "/FlateDecode"]),
    ...(contentsArrayObject === undefined ? [] : [`[${content} 0 R]`]),
    ...(options.imageBytes === undefined
      ? []
      : [
          (() => {
            const image = options.uncompressedImage
              ? options.imageBytes!
              : deflateSync(options.imageBytes!);
            return `<< /Type /XObject /Subtype /Image /Width 1024 /Height ${Math.ceil(options.imageBytes!.byteLength / 1024)} /ColorSpace /DeviceGray /BitsPerComponent 8 /Length ${image.byteLength}${options.uncompressedImage ? "" : " /Filter /FlateDecode"} >>\nstream\n${image.toString("latin1")}\nendstream`;
          })(),
        ]),
    ...(options.formBytes === undefined
      ? []
      : [
          `<< /Type /XObject /Foo /#3E#3E /Bar << /Subtype /Image >> /Subtype /Form /BBox [0 0 1 1] /Length ${deflateSync(options.formBytes).byteLength} /Filter /FlateDecode >>\nstream\n${deflateSync(options.formBytes).toString("latin1")}\nendstream`,
        ]),
  ];
  let output = `%PDF-1.4\n${options.headerComment === undefined ? "" : `% ${options.headerComment}\n`}`;
  const offsets = [0];
  for (const [index, object] of objects.entries()) {
    offsets.push(Buffer.byteLength(output, "latin1"));
    output += `${index + 1} 0 obj\n${object}\nendobj\n`;
  }
  const xref = Buffer.byteLength(output, "latin1");
  output += `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) {
    output += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }
  output += `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(output, "latin1");
}

function xrefStreamPdf(
  document: Uint8Array,
  compressIndirectObjects = false,
  objectHeaderPadding = 0,
  options: {
    objectHeaderComments?: boolean;
    tiffPredictor?: boolean;
    compressPageObjects?: boolean;
    compressedPagePrefix?: string;
    compressedPageSuffix?: string;
    compressedPageDictionaryPrefix?: string;
    escapedCompressedPageContents?: boolean;
    compressedPageContentsArray?: boolean;
    objectStreamFilter?: {
      name: string;
      encode: (bytes: Buffer) => Buffer;
    };
  } = {},
): Buffer {
  const original = Buffer.from(document).toString("latin1");
  const table = original.lastIndexOf("\nxref\n");
  if (table < 0)
    throw new Error("PDF fixture does not contain a classic xref.");
  let body = original.slice(0, table + 1).replace("%PDF-1.4", "%PDF-1.5");
  const references = [
    ...new Set(
      [...body.matchAll(/\/(?:Length|Filter)\s+(\d+)\s+0\s+R/gu)].map((match) =>
        Number(match[1]),
      ),
    ),
  ];
  if (options.compressPageObjects) {
    for (const page of body.matchAll(
      /(?:^|\n)(\d+) 0 obj\n<< \/Type \/Page(?=[\s/>])/gu,
    )) {
      references.push(Number(page[1]));
    }
  }
  let maximumObject = Math.max(
    ...[...body.matchAll(/^(\d+)\s+0\s+obj$/gmu)].map((match) =>
      Number(match[1]),
    ),
  );
  const compressed = new Map<number, { stream: number; index: number }>();
  if (compressIndirectObjects && references.length > 0) {
    const streamObject = ++maximumObject;
    const values: string[] = [];
    for (const number of references) {
      const expression = new RegExp(
        `(?:^|\\n)${number} 0 obj\\n([\\s\\S]*?)\\nendobj\\n`,
        "u",
      );
      const match = expression.exec(body);
      if (match?.[1] === undefined) {
        throw new Error("Indirect PDF fixture object is missing.");
      }
      compressed.set(number, { stream: streamObject, index: values.length });
      const page = /<<\s*\/Type\s+\/Page(?=[\s/>])/u.test(match[1]);
      let value = match[1];
      if (page && options.escapedCompressedPageContents === true) {
        value = value.replace("/Contents ", "/Cont#65nts ");
      }
      if (page && options.compressedPageContentsArray === true) {
        value = value.replace(/\/Contents (\d+ \d+ R)/u, "/Contents[$1]");
      }
      if (page && options.compressedPageDictionaryPrefix !== undefined) {
        value = value.replace(
          /^<</u,
          `<< ${options.compressedPageDictionaryPrefix} `,
        );
      }
      if (page) {
        value = `${options.compressedPagePrefix ?? ""}${value}${options.compressedPageSuffix ?? ""}`;
      }
      values.push(value);
      body =
        body.slice(0, match.index + 1) +
        body.slice(match.index + match[0].length);
    }
    let objectBody = "";
    let header = "";
    for (const [index, number] of references.entries()) {
      header += `${number} ${objectBody.length}${options.objectHeaderComments ? " % compressed object\n" : " "}`;
      objectBody += `${values[index]} `;
    }
    header += " ".repeat(objectHeaderPadding);
    const objectStreamFilter = options.objectStreamFilter ?? {
      name: "/FlateDecode",
      encode: deflateSync,
    };
    const encoded = objectStreamFilter.encode(
      Buffer.from(header + objectBody, "latin1"),
    );
    body += `${streamObject} 0 obj\n<< /Type /ObjStm /N ${references.length} /First ${header.length} /Length ${encoded.byteLength} /Filter ${objectStreamFilter.name} >>\nstream\n${encoded.toString("latin1")}\nendstream\nendobj\n`;
  }
  const xrefObject = ++maximumObject;
  const xrefOffset = Buffer.byteLength(body, "latin1");
  const objects = new Map<number, number>();
  for (const match of body.matchAll(/^(\d+)\s+0\s+obj$/gmu)) {
    objects.set(Number(match[1]), match.index!);
  }
  objects.set(xrefObject, xrefOffset);
  const records = Buffer.alloc((xrefObject + 1) * 7);
  for (let number = 0; number <= xrefObject; number += 1) {
    const position = number * 7;
    const compact = compressed.get(number);
    if (compact !== undefined) {
      records[position] = 2;
      records.writeUInt32BE(compact.stream, position + 1);
      records.writeUInt16BE(compact.index, position + 5);
    } else if (objects.has(number)) {
      records[position] = 1;
      records.writeUInt32BE(objects.get(number)!, position + 1);
    } else {
      records.writeUInt16BE(65535, position + 5);
    }
  }
  const predicted = Buffer.from(records);
  if (options.tiffPredictor) {
    for (let position = 0; position < predicted.byteLength; position += 7) {
      for (let column = 6; column >= 1; column -= 1) {
        predicted[position + column] =
          (records[position + column]! - records[position + column - 1]!) & 255;
      }
    }
  }
  const encoded = deflateSync(predicted);
  body += `${xrefObject} 0 obj\n<< /Type /XRef /Size ${xrefObject + 1} /Root 1 0 R /W [1 4 2] /Length ${encoded.byteLength} /Filter /FlateDecode${options.tiffPredictor ? " /DecodeParms << /Predictor 2 /Columns 7 /Colors 1 /BitsPerComponent 8 >>" : ""} >>\nstream\n${encoded.toString("latin1")}\nendstream\nendobj\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(body, "latin1");
}

function incrementallyUpdatedPdf(document: Uint8Array): Buffer {
  const original = Buffer.from(document).toString("latin1");
  const table = original.lastIndexOf("\nxref\n");
  if (table < 0)
    throw new Error("PDF fixture does not contain a classic xref.");
  let body = original.slice(0, table + 1);
  const objects = new Map<number, number>();
  for (const match of body.matchAll(/^(\d+)\s+0\s+obj$/gmu)) {
    objects.set(Number(match[1]), match.index!);
  }
  const size = 40_000;
  const entries = Array.from({ length: size }, (_unused, number) =>
    objects.has(number)
      ? `${String(objects.get(number)).padStart(10, "0")} 00000 n \n`
      : "0000000000 65535 f \n",
  ).join("");
  const previous = Buffer.byteLength(body, "latin1");
  body += `xref\n0 ${size}\n${entries}trailer\n<< /Size ${size} /Root 1 0 R >>\n`;
  const latest = Buffer.byteLength(body, "latin1");
  body += `xref\n0 ${size}\n${entries}trailer\n<< /Size ${size} /Root 1 0 R /Prev ${previous} >>\nstartxref\n${latest}\n%%EOF\n`;
  return Buffer.from(body, "latin1");
}

function encodeAscii85(bytes: Buffer): Buffer {
  let encoded = "";
  for (let index = 0; index < bytes.length; index += 4) {
    const group = bytes.subarray(index, index + 4);
    let value = 0;
    for (let position = 0; position < 4; position += 1) {
      value = value * 256 + (group[position] ?? 0);
    }
    if (value === 0 && group.length === 4) {
      encoded += "z";
      continue;
    }
    let word = "";
    for (let digit = 0; digit < 5; digit += 1) {
      word = String.fromCharCode((value % 85) + 33) + word;
      value = Math.floor(value / 85);
    }
    encoded += word.slice(0, group.length + 1);
  }
  return Buffer.from(`${encoded}~>`, "latin1");
}

function encodeRunLength(bytes: Buffer): Buffer {
  const encoded: number[] = [];
  for (let index = 0; index < bytes.length; ) {
    let count = 1;
    while (
      count < 128 &&
      index + count < bytes.length &&
      bytes[index + count] === bytes[index]
    ) {
      count += 1;
    }
    if (count > 1) {
      encoded.push(257 - count, bytes[index]!);
      index += count;
    } else {
      encoded.push(0, bytes[index++]!);
    }
  }
  encoded.push(128);
  return Buffer.from(encoded);
}

function encodePdfLzwLiterals(bytes: Buffer, earlyChange: 0 | 1 = 1): Buffer {
  const codes = [256, ...bytes, 257];
  let bits = "";
  let nextCode = 258;
  let codeBits = 9;
  let previous = false;
  for (const code of codes) {
    bits += code.toString(2).padStart(codeBits, "0");
    if (code === 256) {
      nextCode = 258;
      codeBits = 9;
      previous = false;
    } else if (code !== 257) {
      if (previous && nextCode < 4_096) {
        nextCode += 1;
        if (nextCode + earlyChange === 1 << codeBits && codeBits < 12) {
          codeBits += 1;
        }
      }
      previous = true;
    }
  }
  bits = bits.padEnd(Math.ceil(bits.length / 8) * 8, "0");
  return Buffer.from(
    Array.from({ length: bits.length / 8 }, (_unused, index) =>
      Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2),
    ),
  );
}

describe("scan knowledge bases", () => {
  test("prepares nested supported documents and retains requested source roots", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "architecture", "threats");
    const scope = join(root, "scope.md");
    await mkdir(nested, { recursive: true });
    await writeFile(scope, "Ignore local debug endpoints.");
    await writeFile(join(nested, "deployment.MARKDOWN"), "Public API gateway.");
    await writeFile(join(nested, "notes.txt"), "Prioritize SSRF.");
    await writeFile(join(root, "ignored.json"), "{}");

    const knowledgeBase = await prepareKnowledgeBase([root, scope, scope]);
    temporaryDirectories.push(knowledgeBase.path);

    expect(knowledgeBase.sources).toEqual([root, scope]);
    expect((await readdir(knowledgeBase.path)).length).toBe(3);
    const documents = await extractedDocuments(knowledgeBase.path);
    expect(documents).toContain("Ignore local debug endpoints.");
    expect(documents).toContain("Public API gateway.");
    expect(documents).toContain("Prioritize SSRF.");
    expect(knowledgeBase.path.startsWith(root)).toBe(false);
    if (process.platform !== "win32") {
      expect((await stat(knowledgeBase.path)).mode & 0o777).toBe(0o700);
      for (const name of await readdir(knowledgeBase.path)) {
        expect((await stat(join(knowledgeBase.path, name))).mode & 0o777).toBe(
          0o600,
        );
      }
    }
  });

  test("extracts searchable text from PDFs and DOCX documents", async () => {
    const root = await temporaryDirectory();
    await writeFile(
      join(root, "architecture.pdf"),
      pdf("Payment service boundary"),
    );
    await writeFile(join(root, "threat-model.docx"), docx("SSRF &amp; IDOR"));

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    const documents = await extractedDocuments(knowledgeBase.path);

    expect(documents).toContain("Payment service boundary");
    expect(documents).toContain("SSRF & IDOR\n");
  });

  test("keeps DOCX numeric references that cannot name a code point as literal text", async () => {
    // https://github.com/openai/codex-security/issues/40 -- an out-of-range
    // reference used to raise RangeError out of String.fromCodePoint, which
    // surfaced as an unextractable document and failed the whole knowledge base.
    const cases: Array<[string, string, string]> = [
      [
        "above-max-hex",
        "Boundary &#x110000; case.",
        "Boundary &#x110000; case.",
      ],
      [
        "above-max-decimal",
        "Boundary &#1114112; case.",
        "Boundary &#1114112; case.",
      ],
      [
        "huge-decimal",
        "Huge &#99999999999999; case.",
        "Huge &#99999999999999; case.",
      ],
      [
        "lone-surrogate",
        "Surrogate &#xD800; case.",
        "Surrogate &#xD800; case.",
      ],
      ["valid-ascii", "Valid &#65; case.", "Valid A case."],
      ["valid-astral", "Valid &#128512; case.", "Valid \u{1F600} case."],
      ["max-code-point", "Valid &#x10FFFF; case.", "Valid \u{10FFFF} case."],
    ];

    for (const [name, body, expected] of cases) {
      const root = await temporaryDirectory();
      await writeFile(join(root, `${name}.docx`), docx(body));
      const knowledgeBase = await prepareKnowledgeBase([root]);
      temporaryDirectories.push(knowledgeBase.path);
      const documents = await extractedDocuments(knowledgeBase.path);
      expect(documents).toEqual([`${expected}\n`]);
    }
  });

  test("keeps one unusable reference from failing the other knowledge-base documents", async () => {
    const root = await temporaryDirectory();
    await writeFile(join(root, "notes.md"), "Authentication boundary notes");
    await writeFile(
      join(root, "threat-model.docx"),
      docx("Boundary &#x110000; case."),
    );

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    const documents = await extractedDocuments(knowledgeBase.path);

    expect(documents).toHaveLength(2);
    expect(documents).toContain("Authentication boundary notes");
    expect(documents).toContain("Boundary &#x110000; case.\n");
  });

  test("cleans up documents and rediscovers directory contents on later runs", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    await writeFile(source, "Initial scope");
    const first = await prepareKnowledgeBase([root]);
    await first.cleanup();
    await expect(stat(first.path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(source, "utf8")).toBe("Initial scope");

    await writeFile(source, "Updated scope");
    await writeFile(join(root, "priorities.txt"), "New attack priorities");
    const second = await prepareKnowledgeBase(first.sources);
    temporaryDirectories.push(second.path);
    const documents = await extractedDocuments(second.path);

    expect(documents.sort()).toEqual([
      "New attack priorities",
      "Updated scope",
    ]);
  });

  test("rejects missing and unsupported paths", async () => {
    const root = await temporaryDirectory();
    const unsupported = join(root, "scope.doc");
    await writeFile(unsupported, "legacy document");

    await expect(prepareKnowledgeBase([""])).rejects.toThrow("cannot be empty");
    await expect(
      prepareKnowledgeBase([join(root, "missing.md")]),
    ).rejects.toThrow();
    await expect(prepareKnowledgeBase([unsupported])).rejects.toThrow(
      "Unsupported knowledge base document",
    );
    await expect(prepareKnowledgeBase([root])).rejects.toThrow(
      "contains no supported documents",
    );
  });

  test("rejects invalid UTF-8, malformed PDFs, and malformed DOCX files", async () => {
    const root = await temporaryDirectory();
    const invalidText = join(root, "invalid.md");
    const invalidPdf = join(root, "invalid.pdf");
    const invalidDocx = join(root, "invalid.docx");
    const invalidXml = join(root, "invalid-xml.docx");
    await writeFile(invalidText, new Uint8Array([0xc3, 0x28]));
    await writeFile(invalidPdf, "not a PDF");
    await writeFile(invalidDocx, zipSync({ "README.md": strToU8("not DOCX") }));
    await writeFile(
      invalidXml,
      zipSync({ "word/document.xml": strToU8("not XML") }),
    );

    await expect(prepareKnowledgeBase([invalidText])).rejects.toThrow(
      "not valid UTF-8",
    );
    await expect(prepareKnowledgeBase([invalidPdf])).rejects.toThrow(
      "Cannot extract text from knowledge base PDF",
    );
    await expect(prepareKnowledgeBase([invalidDocx])).rejects.toThrow(
      "Cannot extract text from knowledge base DOCX",
    );
    await expect(prepareKnowledgeBase([invalidXml])).rejects.toThrow(
      "Cannot extract text from knowledge base DOCX",
    );
  });

  test("bounds document count, nesting depth, and individual input size", async () => {
    const countRoot = await temporaryDirectory();
    const documents = Array.from({ length: 129 }, (_, index) =>
      join(countRoot, `${index}.md`),
    );
    await Promise.all(documents.map((path) => writeFile(path, "scope")));
    await expect(prepareKnowledgeBase(documents)).rejects.toThrow(
      "more than 128 documents",
    );

    const depthRoot = await temporaryDirectory();
    let nested = depthRoot;
    for (let depth = 0; depth < 17; depth += 1) {
      nested = join(nested, "nested");
      await mkdir(nested);
    }
    await writeFile(join(nested, "scope.md"), "scope");
    await expect(prepareKnowledgeBase([depthRoot])).rejects.toThrow(
      "16-level nesting limit",
    );

    const sizeRoot = await temporaryDirectory();
    const oversized = join(sizeRoot, "oversized.md");
    await writeFile(oversized, "");
    await truncate(oversized, 8 * 1024 * 1024 + 1);
    await expect(prepareKnowledgeBase([oversized])).rejects.toThrow(
      "8388608-byte input limit",
    );
  });

  test("bounds aggregate input and extracted text", async () => {
    const inputRoot = await temporaryDirectory();
    const inputs = Array.from({ length: 5 }, (_, index) =>
      join(inputRoot, `${index}.md`),
    );
    for (const [index, path] of inputs.entries()) {
      await writeFile(path, "");
      await truncate(path, index === inputs.length - 1 ? 1 : 8 * 1024 * 1024);
    }
    await expect(prepareKnowledgeBase(inputs)).rejects.toThrow(
      "33554432-byte aggregate limit",
    );

    const documentOutputRoot = await temporaryDirectory();
    const oversizedOutput = join(documentOutputRoot, "oversized.docx");
    await writeFile(oversizedOutput, docx("x".repeat(8 * 1024 * 1024)));
    await expect(prepareKnowledgeBase([oversizedOutput])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );

    const outputRoot = await temporaryDirectory();
    const compressedText = "x".repeat(7 * 1024 * 1024);
    for (let index = 0; index < 5; index += 1) {
      await writeFile(join(outputRoot, `${index}.docx`), docx(compressedText));
    }
    await expect(prepareKnowledgeBase([outputRoot])).rejects.toThrow(
      "extracted text exceeds the 33554432-byte aggregate limit",
    );
  });

  test("limits PDF page extraction", async () => {
    const root = await temporaryDirectory();
    const oversized = join(root, "oversized.pdf");
    await writeFile(oversized, pdf("scope", 513));

    await expect(prepareKnowledgeBase([oversized])).rejects.toThrow(
      "512-page limit",
    );
  });

  test("bounds streamed text from a compressed PDF page", async () => {
    const root = await temporaryDirectory();
    const oversized = join(root, "compressed.pdf");
    const compressed = pdf("x".repeat(300 * 1024), 32, true);
    expect(compressed.byteLength).toBeLessThan(8 * 1024 * 1024);
    await writeFile(oversized, compressed);

    await expect(prepareKnowledgeBase([oversized])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("rejects oversized compressed PDF streams before parsing operands", async () => {
    const root = await temporaryDirectory();
    const oversized = join(root, "compressed-operand.pdf");
    const compressed = pdf("reviewable", 1, true, " ".repeat(9 * 1024 * 1024));
    expect(compressed.byteLength).toBeLessThan(8 * 1024 * 1024);
    await writeFile(oversized, compressed);

    await expect(prepareKnowledgeBase([oversized])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("bounds every PDF compression pipeline and cumulative stream output", async () => {
    const root = await temporaryDirectory();
    const runLength = join(root, "run-length.pdf");
    await writeFile(
      runLength,
      pdf("reviewable", 1, false, " ".repeat(9 * 1024 * 1024), {
        filter: "/RunLengthDecode",
        encode: encodeRunLength,
      }),
    );
    await expect(prepareKnowledgeBase([runLength])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );

    const cumulative = join(root, "cumulative.pdf");
    await writeFile(
      cumulative,
      pdf("reviewable", 1, true, " ".repeat(3 * 1024 * 1024), {
        extraStreams: 2,
      }),
    );
    await expect(prepareKnowledgeBase([cumulative])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );

    const intermediate = join(root, "cumulative-intermediate.pdf");
    await writeFile(
      intermediate,
      pdf("reviewable", 1, true, `>${" ".repeat(4 * 1024 * 1024)}`, {
        filter: "[/FlateDecode /ASCIIHexDecode]",
        extraStreams: 8,
      }),
    );
    await expect(prepareKnowledgeBase([intermediate])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("accepts PDF filter chains, indirect lengths, and escaped filter names", async () => {
    const root = await temporaryDirectory();
    const chained = join(root, "chained.pdf");
    const indirect = join(root, "indirect.pdf");
    const indirectFilter = join(root, "indirect-filter.pdf");
    const indirectFilterArray = join(root, "indirect-filter-array.pdf");
    const commentedIndirectFilterArray = join(
      root,
      "commented-indirect-filter-array.pdf",
    );
    const commentedIndirect = join(root, "commented-indirect.pdf");
    const leadingCommentedIndirect = join(root, "leading-comment-indirect.pdf");
    const escaped = join(root, "escaped.pdf");
    const lzw = join(root, "lzw.pdf");
    const earlyChange = join(root, "lzw-early-change.pdf");
    await writeFile(
      chained,
      pdf("ASCII85 then Flate", 1, true, "", {
        filter: "[/ASCII85Decode /FlateDecode]",
        encode: encodeAscii85,
      }),
    );
    await writeFile(
      indirect,
      pdf("Indirect stream length", 1, true, "", { indirectLength: true }),
    );
    await writeFile(
      indirectFilter,
      pdf("Indirect stream filter", 1, true, "", { indirectFilter: true }),
    );
    await writeFile(
      indirectFilterArray,
      pdf("Indirect array stream filter", 1, true, "", {
        indirectFilterArray: true,
      }),
    );
    await writeFile(
      commentedIndirectFilterArray,
      pdf("Commented indirect array filter", 1, true, "", {
        indirectCommentedFilterArray: true,
      }),
    );
    await writeFile(
      commentedIndirect,
      pdf("Commented indirect values", 1, true, "", {
        indirectLength: true,
        indirectFilter: true,
        indirectValueComment: " % valid comment\n",
      }),
    );
    await writeFile(
      leadingCommentedIndirect,
      pdf("Leading commented indirect values", 1, true, "", {
        indirectLength: true,
        indirectFilter: true,
        indirectValuePrefix: "% valid leading comment\n",
      }),
    );
    await writeFile(
      escaped,
      pdf("Escaped PDF filter", 1, true, "", { filter: "/#46lateDecode" }),
    );
    await writeFile(
      lzw,
      pdf("LZW encoded text", 1, false, "", {
        filter: "/LZWDecode",
        encode: encodePdfLzwLiterals,
      }),
    );
    const earlyChangeText = `LZW early change ${"x".repeat(350)}`;
    await writeFile(
      earlyChange,
      pdf(earlyChangeText, 1, false, "", {
        filter: "/LZWDecode",
        dictionaryPrefix: "/DecodeParms << /EarlyChange 0 >> ",
        encode: (bytes) => encodePdfLzwLiterals(bytes, 0),
      }),
    );

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    expect((await extractedDocuments(knowledgeBase.path)).sort()).toEqual(
      [
        "ASCII85 then Flate",
        "Commented indirect array filter",
        "Commented indirect values",
        "Escaped PDF filter",
        "Indirect array stream filter",
        "Indirect stream length",
        "Indirect stream filter",
        "Leading commented indirect values",
        "LZW encoded text",
        earlyChangeText,
      ].sort(),
    );
  });

  test("resolves indirect PDF values from compressed cross-reference and object streams", async () => {
    const root = await temporaryDirectory();
    for (const compressIndirectObjects of [false, true]) {
      const name = compressIndirectObjects
        ? "object-stream.pdf"
        : "xref-stream.pdf";
      await writeFile(
        join(root, name),
        xrefStreamPdf(
          pdf(`PDF ${name}`, 1, true, "", {
            indirectLength: true,
            indirectFilter: true,
          }),
          compressIndirectObjects,
        ),
      );
    }

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    expect((await extractedDocuments(knowledgeBase.path)).sort()).toEqual([
      "PDF object-stream.pdf",
      "PDF xref-stream.pdf",
    ]);
  });

  test("caches large compressed object-stream headers across repeated references", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "large-object-header.pdf");
    await writeFile(
      document,
      xrefStreamPdf(
        pdf("Cached object stream header", 1, true, "", {
          extraStreams: 12,
          indirectLength: true,
          indirectFilter: true,
        }),
        true,
        512 * 1024,
      ),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Cached object stream header",
    ]);
  });

  test("parses comments inside compressed PDF object-stream headers", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "commented-object-header.pdf");
    await writeFile(
      document,
      xrefStreamPdf(
        pdf("Commented object-stream header", 1, true, "", {
          indirectLength: true,
          indirectFilter: true,
        }),
        true,
        0,
        { objectHeaderComments: true },
      ),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Commented object-stream header",
    ]);
  });

  test("decodes TIFF-predicted PDF cross-reference streams", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "tiff-predicted-cross-reference.pdf");
    await writeFile(
      document,
      xrefStreamPdf(
        pdf("TIFF-predicted cross reference", 1, true, "", {
          indirectLength: true,
          indirectFilter: true,
        }),
        false,
        0,
        { tiffPredictor: true },
      ),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "TIFF-predicted cross reference",
    ]);
  });

  test("bounds sample-level work in bit-packed TIFF cross-reference predictors", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "bit-packed-tiff-predictor.pdf");
    const original = xrefStreamPdf(
      pdf("Bound the packed predictor", 1, true, "", {
        indirectLength: true,
        indirectFilter: true,
      }),
      false,
      0,
      { tiffPredictor: true },
    ).toString("latin1");
    const start = original.lastIndexOf("\nstream\n");
    const end = original.indexOf("\nendstream", start);
    const packed = deflateSync(Buffer.alloc(5 * 1024 * 1024));
    const header = original
      .slice(0, start)
      .replace(
        /\/Length \d+(?= \/Filter \/FlateDecode \/DecodeParms)/u,
        `/Length ${packed.byteLength}`,
      )
      .replace(
        "/Columns 7 /Colors 1 /BitsPerComponent 8",
        "/Columns 8 /Colors 1 /BitsPerComponent 1",
      );
    await writeFile(
      document,
      Buffer.concat([
        Buffer.from(`${header}\nstream\n`, "latin1"),
        packed,
        Buffer.from(original.slice(end), "latin1"),
      ]),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "Cannot extract text from knowledge base PDF",
    );
  });

  test("excludes compressed image pixels from the extracted-text budget", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "large-image.pdf");
    await writeFile(
      document,
      pdf("Small document text", 1, true, "/Im1 Do ", {
        imageBytes: Buffer.alloc(9 * 1024 * 1024, 1),
      }),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Small document text",
    ]);
  });

  test("bounds compressed form streams with nested image-subtype decoys", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "nested-image-decoy.pdf");
    await writeFile(
      document,
      pdf("Small document text", 1, true, "/Fm1 Do ", {
        formBytes: Buffer.alloc(9 * 1024 * 1024, 32),
      }),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("bounds cumulative indirect PDF contents references", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "contents-reference-budget.pdf");
    await writeFile(
      document,
      pdf("Bound repeated contents references", 1, true, "", {
        headerComment: "/Contents 5 0 R ".repeat(70_000),
      }),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("indexes cross-reference ownership across many compressed streams", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "many-streams.pdf");
    await writeFile(
      document,
      pdf("Indexed stream ownership", 1, true, "", { extraStreams: 1_024 }),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Indexed stream ownership",
    ]);
  });

  test("bounds image-tagged content streams referenced by compressed page objects", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "compressed-page-content.pdf");
    await writeFile(
      document,
      xrefStreamPdf(
        pdf("reviewable", 1, true, " ".repeat(9 * 1024 * 1024), {
          dictionaryPrefix: "/Subtype /Image ",
        }),
        true,
        0,
        { compressPageObjects: true },
      ),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("bounds compressed page contents behind PDF comments and escaped dictionary names", async () => {
    for (const [name, options] of [
      [
        "comments",
        {
          compressedPagePrefix: "% valid leading page comment\n",
          compressedPageSuffix: " % valid trailing page comment\n",
        },
      ],
      ["escaped-contents", { escapedCompressedPageContents: true }],
      [
        "escaped-structural-name",
        { compressedPageDictionaryPrefix: "/Foo /#3C#3C" },
      ],
      ["delimiter-adjacent-array", { compressedPageContentsArray: true }],
    ] as const) {
      const root = await temporaryDirectory();
      const document = join(root, `${name}.pdf`);
      await writeFile(
        document,
        xrefStreamPdf(
          pdf("reviewable", 1, true, " ".repeat(9 * 1024 * 1024), {
            dictionaryPrefix: "/Subtype /Image ",
          }),
          true,
          0,
          { compressPageObjects: true, ...options },
        ),
      );

      await expect(prepareKnowledgeBase([document])).rejects.toThrow(
        "8388608-byte extracted-text limit",
      );
    }
  });

  test("bounds page contents in LZW- and run-length-compressed object streams", async () => {
    for (const [name, encode] of [
      ["/LZWDecode", encodePdfLzwLiterals],
      ["/RunLengthDecode", encodeRunLength],
    ] as const) {
      const root = await temporaryDirectory();
      const document = join(root, `${name.slice(1)}.pdf`);
      await writeFile(
        document,
        xrefStreamPdf(
          pdf("reviewable", 1, true, " ".repeat(9 * 1024 * 1024), {
            dictionaryPrefix: "/Subtype /Image ",
          }),
          true,
          0,
          {
            compressPageObjects: true,
            objectStreamFilter: { name, encode },
          },
        ),
      );

      await expect(prepareKnowledgeBase([document])).rejects.toThrow(
        "8388608-byte extracted-text limit",
      );
    }
  });

  test("applies an LZW predictor before the next compressed object-stream filter", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "predicted-lzw-object-stream.pdf");
    await writeFile(
      document,
      xrefStreamPdf(pdf("Predicted compressed page", 1, true), true, 0, {
        compressPageObjects: true,
        objectStreamFilter: {
          name: "[/LZWDecode /ASCII85Decode] /DecodeParms [<< /Predictor 12 /Columns 1 >> null]",
          encode: (contents) =>
            encodePdfLzwLiterals(
              Buffer.from(
                [...encodeAscii85(contents)].flatMap((byte) => [0, byte]),
              ),
            ),
        },
      }),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Predicted compressed page",
    ]);
  });

  test("ignores stream-shaped bytes inside declared uncompressed image data", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "stream-shaped-image-data.pdf");
    const pixels = Buffer.alloc(1024);
    pixels.write(
      "<< /Length 1 /Filter /FlateDecode >>\nstream\nX\nendstream\n",
      "latin1",
    );
    await writeFile(
      document,
      pdf("Image payload remains data", 1, false, "", {
        imageBytes: pixels,
        uncompressedImage: true,
      }),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Image payload remains data",
    ]);
  });

  test("rejects negative cross-reference stream field widths", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "negative-xref-width.pdf");
    const malformed = xrefStreamPdf(
      pdf("Malformed cross-reference", 1, true, "", {
        indirectLength: true,
        indirectFilter: true,
      }),
      true,
    )
      .toString("latin1")
      .replace("/W [1 4 2]", "/W [-1 0 0]");
    await writeFile(document, Buffer.from(malformed, "latin1"));

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "Cannot extract text from knowledge base PDF",
    );
  });

  test("counts unique objects across overlapping incremental cross-reference tables", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "incremental.pdf");
    await writeFile(
      document,
      incrementallyUpdatedPdf(
        pdf("Incremental cross-reference tables", 1, true, "", {
          indirectFilter: true,
        }),
      ),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Incremental cross-reference tables",
    ]);
  });

  test("does not mistake a PDF comment for a stream compression filter", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "comment.pdf");
    await writeFile(
      document,
      pdf("Uncompressed PDF", 1, false, "", {
        headerComment: "This metadata mentions /FlateDecode.",
      }),
    );

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "Uncompressed PDF",
    ]);
  });

  test("bounds compressed streams after PDF comments and ignores fake literal lengths", async () => {
    const root = await temporaryDirectory();
    for (const [name, options] of [
      ["comment-before-stream", { streamComment: "% comment before stream" }],
      [
        "literal-length-token",
        { dictionaryPrefix: "/Note (/Length 999999999) " },
      ],
      [
        "literal-filter-token",
        { dictionaryPrefix: "/Note (/Filter /DCTDecode) " },
      ],
      ["literal-dictionary-close", { dictionaryPrefix: "/Note (>>) " }],
      ["literal-dictionary-open", { dictionaryPrefix: "/Note (<<) " }],
      [
        "escaped-literal-dictionary-close",
        { dictionaryPrefix: "/Note (/A#29 /Filter /DCTDecode) " },
      ],
      [
        "comment-dictionary-delimiters",
        { dictionaryPrefix: "% << >> ignored\n" },
      ],
      [
        "decoy-indirect-filter",
        {
          indirectFilter: true,
          headerComment: "6 0 obj /DCTDecode endobj",
        },
      ],
      [
        "decoy-indirect-length",
        {
          indirectLength: true,
          headerComment: "6 0 obj 0 endobj",
        },
      ],
      ["indirect-filter-array", { indirectFilterArray: true }],
      [
        "commented-indirect-filter-array",
        { indirectCommentedFilterArray: true },
      ],
      [
        "page-content-marked-as-image",
        { dictionaryPrefix: "/Subtype /Image " },
      ],
      [
        "indirect-page-content-marked-as-image",
        {
          dictionaryPrefix: "/Subtype /Image ",
          indirectContentsArray: true,
        },
      ],
    ] as const) {
      const document = join(root, `${name}.pdf`);
      await writeFile(
        document,
        pdf("reviewable", 1, true, " ".repeat(9 * 1024 * 1024), options),
      );
      await expect(prepareKnowledgeBase([document])).rejects.toThrow(
        "8388608-byte extracted-text limit",
      );
    }
  });

  test("counts only the final output of chained PDF compression filters", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "multi-stage-limit.pdf");
    const noise = Buffer.allocUnsafe(5 * 1024 * 1024);
    let state = 1;
    for (let index = 0; index < noise.length; index += 1) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      noise[index] = 33 + ((state >>> 16) % 90);
    }
    const compressed = pdf(
      "A bounded multi-stage PDF stream",
      1,
      true,
      `%${noise.toString("latin1")}\n`,
      {
        filter: "[/ASCII85Decode /FlateDecode]",
        encode: encodeAscii85,
      },
    );
    expect(compressed.byteLength).toBeLessThan(8 * 1024 * 1024);
    await writeFile(document, compressed);

    const knowledgeBase = await prepareKnowledgeBase([document]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "A bounded multi-stage PDF stream",
    ]);
  });

  test("bounds repeated PDF LZW clear codes without allocating fresh dictionaries", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "lzw-clears.pdf");
    const clearCodes = 1_000_001;
    const encoded = Buffer.alloc(Math.ceil(((clearCodes + 1) * 9) / 8));
    let offset = 0;
    for (let index = 0; index <= clearCodes; index += 1) {
      const code = index === clearCodes ? 257 : 256;
      for (let bit = 8; bit >= 0; bit -= 1) {
        encoded[Math.floor(offset / 8)]! |=
          ((code >> bit) & 1) << (7 - (offset % 8));
        offset += 1;
      }
    }
    await writeFile(
      document,
      pdf("reviewable", 1, false, "", {
        filter: "/LZWDecode",
        encode: () => encoded,
      }),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "8388608-byte extracted-text limit",
    );
  });

  test("bounds adversarial backward PDF stream-dictionary scans", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "dictionary-work.pdf");
    await writeFile(
      document,
      pdf("reviewable", 1, false, "", {
        headerComment: ">>stream\n".repeat(6_000),
      }),
    );

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "dictionary scan limit",
    );
  });

  test("rejects duplicate DOCX document entries before repeated inflation", async () => {
    const root = await temporaryDirectory();
    const document = join(root, "duplicate.docx");
    const alternate = "word/decument.xml";
    const archive = Buffer.from(
      zipSync({
        "word/document.xml": strToU8("<w:document>safe</w:document>"),
        [alternate]: strToU8("<w:document>duplicate</w:document>"),
      }),
    );
    const replacement = Buffer.from("word/document.xml");
    for (let offset = 0; ; offset += replacement.length) {
      offset = archive.indexOf(alternate, offset);
      if (offset < 0) break;
      replacement.copy(archive, offset);
    }
    await writeFile(document, archive);

    await expect(prepareKnowledgeBase([document])).rejects.toThrow(
      "duplicate word/document.xml entries",
    );
  });

  test("observes cancellation while discovering directories", async () => {
    const root = await temporaryDirectory();
    const nested = join(root, "one", "two");
    await mkdir(nested, { recursive: true });
    await writeFile(join(nested, "scope.md"), "scope");
    const controller = new AbortController();
    const reason = new DOMException("cancel discovery", "AbortError");
    const throwIfAborted = controller.signal.throwIfAborted.bind(
      controller.signal,
    );
    let checks = 0;
    controller.signal.throwIfAborted = (): void => {
      checks += 1;
      if (checks === 5) controller.abort(reason);
      throwIfAborted();
    };

    await expect(prepareKnowledgeBase([root], controller.signal)).rejects.toBe(
      reason,
    );
    expect(checks).toBe(5);
  });

  testPosix("does not follow symbolic links", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    const linked = join(root, "linked.md");
    await writeFile(source, "External APIs");
    await symlink(source, linked);

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    expect(await extractedDocuments(knowledgeBase.path)).toEqual([
      "External APIs",
    ]);
    await expect(prepareKnowledgeBase([linked])).rejects.toThrow(
      "cannot be symbolic links",
    );
  });

  testPosix(
    "rejects a directory replaced with an escaping symbolic link",
    async () => {
      const source = await temporaryDirectory();
      const nested = join(source, "nested");
      const outside = await temporaryDirectory();
      await mkdir(nested);
      await writeFile(join(nested, "scope.md"), "Internal scope");
      await writeFile(
        join(outside, "external.md"),
        "Never ingest this document",
      );
      const controller = new AbortController();
      let checks = 0;
      controller.signal.throwIfAborted = (): void => {
        checks += 1;
        if (checks === 5) {
          renameSync(nested, join(source, "replaced"));
          symlinkSync(outside, nested);
        }
      };

      await expect(
        prepareKnowledgeBase([source], controller.signal),
      ).rejects.toThrow(
        /escaped the requested source|changed during discovery/u,
      );
    },
  );

  testPosix(
    "does not block when a discovered document becomes a FIFO",
    async () => {
      const root = await temporaryDirectory();
      const document = join(root, "scope.md");
      await writeFile(document, "Internal scope");
      const controller = new AbortController();
      let checks = 0;
      controller.signal.throwIfAborted = (): void => {
        checks += 1;
        if (checks === 6) {
          renameSync(document, join(root, "replaced.md"));
          const result = spawnSync("mkfifo", [document], { encoding: "utf8" });
          expect(result.status, result.stderr).toBe(0);
        }
      };

      await expect(
        prepareKnowledgeBase([document], controller.signal),
      ).rejects.toThrow("not a file");
    },
  );

  testPosix("rejects unreadable source documents", async () => {
    const root = await temporaryDirectory();
    const source = join(root, "scope.md");
    await writeFile(source, "External APIs");
    await chmod(source, 0o000);

    try {
      await expect(prepareKnowledgeBase([source])).rejects.toThrow();
    } finally {
      await chmod(source, 0o600);
    }
  });
});
