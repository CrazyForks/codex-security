import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";

const pluginRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "_bundled_plugin",
);

function usablePython(): string | null {
  for (const candidate of [process.env["PYTHON"], "python3", "python"]) {
    if (candidate === undefined) continue;
    const probe = spawnSync(
      candidate,
      [
        "-c",
        "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)",
      ],
      { encoding: "utf8" },
    );
    if (probe.status === 0) return candidate;
  }
  return null;
}

const python = usablePython();

/** Render report.md through the bundled projection with each finding forced to `level`. */
function renderReport(python: string, levels: readonly string[]): string {
  const script = `
import copy, json, sys
sys.path.insert(0, ${JSON.stringify(join(pluginRoot, "scripts"))})
import report_projection

base = ${JSON.stringify(join(pluginRoot, "examples", "completed-scan"))}
def load(name):
    with open(base + "/" + name, encoding="utf-8") as handle:
        return json.load(handle)

manifest, coverage, findings = load("scan-manifest.json"), load("coverage.json"), load("findings.json")
levels = json.loads(${JSON.stringify(JSON.stringify(levels))})
template = copy.deepcopy(findings["findings"][0])
findings["findings"] = []
for index, level in enumerate(levels):
    entry = copy.deepcopy(template)
    entry["severity"]["level"] = level
    entry["title"] = "Finding %d" % index
    entry["findingId"] = "%s-%d" % (entry.get("findingId", "finding"), index)
    if index > 0:
        entry.pop("writeup", None)
    findings["findings"].append(entry)

sys.stdout.write(report_projection.build_report_markdown(manifest, findings, coverage))
`;
  const result = spawnSync(python, ["-I", "-B", "-c", script], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`report projection failed: ${result.stderr}`);
  }
  return result.stdout;
}

describe("report projection severity gate", () => {
  test.skipIf(python === null)(
    "records findings held back by the reportable severity gate",
    () => {
      const text = renderReport(python!, ["informational"]);
      expect(text).toContain("### No findings");
      expect(text).toContain(
        "1 finding is outside the reportable severity set",
      );
      expect(text).toContain("(informational: 1)");
      expect(text).toContain("`findings.json`");
      expect(text).not.toContain("Finding 0");
    },
  );

  test.skipIf(python === null)(
    "records held-back findings alongside reportable ones",
    () => {
      const text = renderReport(python!, [
        "high",
        "informational",
        "informational",
      ]);
      expect(text).not.toContain("### No findings");
      expect(text).toContain("Finding 0");
      expect(text).toContain(
        "2 findings are outside the reportable severity set",
      );
      expect(text).toContain("(informational: 2)");
    },
  );

  test.skipIf(python === null)(
    "stays silent when every finding is reportable",
    () => {
      const text = renderReport(python!, ["high", "low"]);
      expect(text).not.toContain("outside the reportable severity set");
      expect(text).not.toContain("### No findings");
    },
  );

  test.skipIf(python === null)(
    "keeps the rendered report valid for the format validator",
    () => {
      const reportDirectory = mkdtempSync(
        join(tmpdir(), "codex-security-report-projection-"),
      );
      const reportPath = join(reportDirectory, "report.md");
      try {
        for (const levels of [["informational"], ["high", "informational"]]) {
          writeFileSync(reportPath, renderReport(python!, levels), "utf8");
          const validation = spawnSync(
            python!,
            [
              "-I",
              "-B",
              join(pluginRoot, "scripts", "validate_report_format.py"),
              "--report-md",
              reportPath,
            ],
            { encoding: "utf8" },
          );
          expect(validation.status).toBe(0);
        }
      } finally {
        rmSync(reportDirectory, { recursive: true, force: true });
      }
    },
  );

  test("documents the exclusion in the final-report reference", () => {
    const reference = readFileSync(
      join(pluginRoot, "references", "final-report.md"),
      "utf8",
    );
    expect(reference).toContain(
      "`informational` is outside the reportable severity set",
    );
  });
});
