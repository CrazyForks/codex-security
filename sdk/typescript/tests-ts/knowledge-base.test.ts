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
    headerComment?: string;
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
  const filter = options.filter ?? (compressed ? "/FlateDecode" : undefined);
  const extraStreams = options.extraStreams ?? 0;
  const length = options.indirectLength
    ? `${content + extraStreams + 1} 0 R`
    : String(streamBytes.byteLength);
  const streamObject = `<< /Length ${length}${filter === undefined ? "" : ` /Filter ${filter}`} >>\nstream\n${streamBytes.toString("latin1")}\nendstream`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pageObjects.map((number) => `${number} 0 R`).join(" ")}] /Count ${pages} >>`,
    ...pageObjects.map(
      () =>
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 2000000 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`,
    ),
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    streamObject,
    ...Array.from({ length: extraStreams }, () => streamObject),
    ...(options.indirectLength ? [String(streamBytes.byteLength)] : []),
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
  });

  test("accepts PDF filter chains, indirect lengths, and escaped filter names", async () => {
    const root = await temporaryDirectory();
    const chained = join(root, "chained.pdf");
    const indirect = join(root, "indirect.pdf");
    const escaped = join(root, "escaped.pdf");
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
      escaped,
      pdf("Escaped PDF filter", 1, true, "", { filter: "/#46lateDecode" }),
    );

    const knowledgeBase = await prepareKnowledgeBase([root]);
    temporaryDirectories.push(knowledgeBase.path);
    expect((await extractedDocuments(knowledgeBase.path)).sort()).toEqual(
      [
        "ASCII85 then Flate",
        "Escaped PDF filter",
        "Indirect stream length",
      ].sort(),
    );
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
