import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type Finding = Record<string, unknown> & {
  ruleId: string;
  identity: { anchor: string; instance?: string };
  summary: string;
  severity: { level: string };
  confidence: { level: string };
  locations: Array<{ path: string }>;
  codeEvidence?: Array<{
    id: string;
    label: string;
    path: string;
    startLine: number;
    code: string;
    explanation: string;
  }>;
  writeup?: unknown;
  remediationTests?: unknown;
  preventiveControls?: unknown;
};

type FindingsDocument = {
  scanId: string;
  findings: Array<Finding | null>;
};

type CoverageSurface = Record<string, unknown> & {
  id: string;
  label: string;
  disposition: string;
  receiptRefs: unknown[];
};

type CoverageDocument = Record<string, unknown> & {
  scanId: string;
  completeness: string;
  inventoryStrategy: string;
  surfaces: CoverageSurface[] | Record<string, unknown>;
  explicitExclusions: unknown;
  deferred: unknown;
};

type ScanSummary = {
  findingCount: number;
  progress: { status: string };
  warnings: string[];
};

type SarifDocument = {
  runs: Array<{
    properties: { codexSecurityCoverageCompleteness?: string };
    results: Array<{ properties: { severity: string } }>;
    invocations?: Array<{
      executionSuccessful: boolean;
      toolExecutionNotifications: Array<{
        level: string;
        message: { text: string };
      }>;
    }>;
  }>;
};

type ScanFixture = {
  python: string;
  repository: string;
  stateDir: string;
  scanDir: string;
  scanId: string;
  registration: Record<string, unknown>;
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function workbench(fixture: ScanFixture, args: readonly string[]) {
  return runWorkbench(
    {
      python: fixture.python,
      pluginRoot: PLUGIN_ROOT,
      environment: {
        PATH: process.env["PATH"],
        CODEX_SECURITY_STATE_DIR: fixture.stateDir,
      },
    },
    args,
  );
}

async function startDraftScan(
  repositoryKind: "directory" | "clean" | "dirty" | "nested" = "directory",
  emptyScope = false,
  symlinkScope = false,
  configure?: (repository: string) => Promise<void>,
): Promise<ScanFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scan-recovery-")),
  );
  temporaryDirectories.push(root);
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const target = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(join(target, "src"), { recursive: true });
  if (!emptyScope) {
    await writeFile(join(target, "src", "extract.py"), "# fixture\n");
  }
  if (symlinkScope) {
    const external = join(root, "external.py");
    await writeFile(external, "# outside the scanned repository\n");
    await symlink(external, join(target, "src", "external.py"));
  }
  await mkdir(scanDir, { mode: 0o700 });

  if (repositoryKind !== "directory") {
    for (const args of [
      ["init", "--quiet", target],
      ["-C", target, "add", "--", "src/extract.py"],
      [
        "-C",
        target,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    if (repositoryKind === "dirty") {
      await writeFile(join(target, "src", "extract.py"), "# changed fixture\n");
    }
    if (repositoryKind === "nested") {
      const nested = join(target, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "source.py"), "# nested fixture\n");
      const initialized = spawnSync("git", ["init", "--quiet", nested], {
        encoding: "utf8",
      });
      expect(initialized.status, initialized.stderr).toBe(0);
    }
  }

  await configure?.(target);

  const fixture: ScanFixture = {
    python: python!,
    repository: target,
    stateDir: join(root, "state"),
    scanDir,
    scanId: "",
    registration: {},
  };
  const registration = await workbench(fixture, [
    "register-cli-scan",
    "--repository",
    target,
    "--scan-dir",
    scanDir,
    "--recipe-json",
    JSON.stringify({
      config: {},
      mode: "standard",
      repository: target,
      target: { kind: "repository", paths: [] },
    }),
  ]);
  fixture.scanId = String(registration["scanId"]);
  fixture.registration = registration;

  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = await readJson<{
    scan: {
      id: string;
      target: { kind: string };
      sealedAt?: string;
      artifacts?: unknown[];
    };
  }>(manifestPath);
  manifest.scan.id = fixture.scanId;
  manifest.scan.target.kind =
    repositoryKind === "directory"
      ? "directory_snapshot"
      : repositoryKind === "clean"
        ? "git_revision"
        : "git_worktree";
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeJson(manifestPath, manifest);

  for (const name of ["findings.json", "coverage.json"] as const) {
    const path = join(scanDir, name);
    const document = await readJson<{ scanId: string }>(path);
    document.scanId = fixture.scanId;
    await writeJson(path, document);
  }
  await writeFile(join(scanDir, "report.md"), "# Draft report\n");
  return fixture;
}

async function completeScan(fixture: ScanFixture): Promise<ScanSummary> {
  const result = await workbench(fixture, [
    "complete-scan",
    "--scan-id",
    fixture.scanId,
  ]);
  return result["scan"] as unknown as ScanSummary;
}

async function prepareStandardNoFindingReview(
  fixture: ScanFixture,
  inventory: string[],
): Promise<void> {
  const findingsPath = join(fixture.scanDir, "findings.json");
  const coveragePath = join(fixture.scanDir, "coverage.json");
  const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
  await mkdir(discovery, { recursive: true });
  const findings = await readJson<FindingsDocument>(findingsPath);
  const coverage = await readJson<CoverageDocument>(coveragePath);
  findings.findings = [];
  const surface = (coverage.surfaces as CoverageSurface[])[0]!;
  surface.disposition = "no_issue_found";
  surface.receiptRefs = [];
  await Promise.all([
    writeJson(findingsPath, findings),
    writeJson(coveragePath, coverage),
    writeFile(
      join(discovery, "in_scope_files.txt"),
      `${inventory.join("\n")}\n`,
    ),
    writeFile(join(discovery, "candidate_ledger.jsonl"), ""),
    workbench(fixture, [
      "update-progress",
      "--scan-id",
      fixture.scanId,
      "--review-items-total",
      String(inventory.length),
      "--review-items-completed",
      String(inventory.length),
    ]),
  ]);
}

describe("malformed scan artifact recovery", () => {
  test("seals a host-proven empty scope inventory into the completed scan", async () => {
    const fixture = await startDraftScan("directory", true);
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    coverage.surfaces = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
    ]);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
    const manifest = await readJson<{
      scan: {
        artifacts: Array<{ path: string; mediaType: string; sha256: string }>;
      };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts).toContainEqual({
      path: "artifacts/02_discovery/scope_inventory.jsonl",
      mediaType: "application/octet-stream",
      sha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });
    await expect(
      workbench(fixture, [
        "export-findings",
        "--scan-id",
        fixture.scanId,
        "--format",
        "json",
      ]),
    ).resolves.toMatchObject({
      export: { path: join(fixture.scanDir, "findings.json") },
    });
    await expect(
      workbench(fixture, [
        "export-findings",
        "--scan-id",
        fixture.scanId,
        "--format",
        "sarif",
      ]),
    ).resolves.toMatchObject({
      export: { path: join(fixture.scanDir, "exports", "results.sarif") },
    });
    await expect(
      readFile(join(fixture.scanDir, "exports", "results.sarif"), "utf8"),
    ).resolves.toContain('"version": "2.1.0"');
  });

  test("does not treat a symlink-only repository snapshot as empty", async () => {
    const fixture = await startDraftScan("directory", true, true);
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    coverage.surfaces = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
    ]);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
  });

  test("rejects receiptless producer claims that nonempty coverage was fully reviewed", async () => {
    for (const disposition of ["no_issue_found", "rejected"] as const) {
      const fixture = await startDraftScan();
      const findingsPath = join(fixture.scanDir, "findings.json");
      const coveragePath = join(fixture.scanDir, "coverage.json");
      const findings = await readJson<FindingsDocument>(findingsPath);
      const coverage = await readJson<CoverageDocument>(coveragePath);
      findings.findings = [];
      const surface = (coverage.surfaces as CoverageSurface[])[0]!;
      surface.disposition = disposition;
      surface.receiptRefs = [];
      await Promise.all([
        writeJson(findingsPath, findings),
        writeJson(coveragePath, coverage),
      ]);

      await expect(completeScan(fixture)).rejects.toThrow(
        "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
      );
    }
  });

  test("completes standard no-finding scans with authoritative compact review evidence", async () => {
    const fixture = await startDraftScan();
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    const surface = (coverage.surfaces as CoverageSurface[])[0]!;
    surface.disposition = "no_issue_found";
    surface.receiptRefs = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
      writeFile(join(discovery, "in_scope_files.txt"), "src/extract.py\n"),
      writeFile(join(discovery, "candidate_ledger.jsonl"), ""),
      workbench(fixture, [
        "update-progress",
        "--scan-id",
        fixture.scanId,
        "--review-items-total",
        "1",
        "--review-items-completed",
        "1",
      ]),
    ]);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(0);
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toEqual(
      expect.arrayContaining([
        "artifacts/02_discovery/candidate_ledger.jsonl",
        "artifacts/02_discovery/in_scope_files.txt",
      ]),
    );
    expect(
      (
        (await readJson<CoverageDocument>(coveragePath))
          .surfaces as CoverageSurface[]
      )[0],
    ).toMatchObject({ disposition: "no_issue_found", receiptRefs: [] });
  });

  test("rejects a compact candidate ledger before host-owned review progress is complete", async () => {
    const fixture = await startDraftScan();
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    const surface = (coverage.surfaces as CoverageSurface[])[0]!;
    surface.disposition = "no_issue_found";
    surface.receiptRefs = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
      writeFile(join(discovery, "in_scope_files.txt"), "src/extract.py\n"),
      writeFile(join(discovery, "candidate_ledger.jsonl"), ""),
    ]);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
  });

  test("rejects a same-sized standard inventory that replaces registered files", async () => {
    const fixture = await startDraftScan();
    await prepareStandardNoFindingReview(fixture, ["src/invented.py"]);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
  });

  test("binds standard review progress to the original registered snapshot", async () => {
    const fixture = await startDraftScan(
      "directory",
      false,
      false,
      async (repository) => {
        await writeFile(
          join(repository, "src", "unreviewed.py"),
          "# unreviewed\n",
        );
      },
    );
    await rm(join(fixture.repository, "src", "unreviewed.py"));
    await prepareStandardNoFindingReview(fixture, ["src/extract.py"]);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
  });

  test("applies ripgrep ignore rules to the registered standard inventory", async () => {
    const fixture = await startDraftScan(
      "clean",
      false,
      false,
      async (repository) => {
        await mkdir(join(repository, "dist"));
        await writeFile(join(repository, ".gitignore"), "dist/\n");
        await writeFile(
          join(repository, "dist", "kept.js"),
          "ignored but tracked\n",
        );
        for (const args of [
          [
            "-C",
            repository,
            "add",
            "--force",
            "--",
            ".gitignore",
            "dist/kept.js",
          ],
          [
            "-C",
            repository,
            "-c",
            "user.name=Codex Security",
            "-c",
            "user.email=codex-security@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "add ignored tracked file",
          ],
        ]) {
          const result = spawnSync("git", args, { encoding: "utf8" });
          expect(result.status, result.stderr).toBe(0);
        }
      },
    );
    await prepareStandardNoFindingReview(fixture, [
      ".gitignore",
      "src/extract.py",
    ]);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("preserves authoritative standard coverage for all-not-applicable surfaces", async () => {
    const fixture = await startDraftScan();
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    const surface = (coverage.surfaces as CoverageSurface[])[0]!;
    surface.disposition = "not_applicable";
    surface.receiptRefs = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
      writeFile(join(discovery, "in_scope_files.txt"), "src/extract.py\n"),
      writeFile(join(discovery, "candidate_ledger.jsonl"), ""),
      workbench(fixture, [
        "update-progress",
        "--scan-id",
        fixture.scanId,
        "--review-items-total",
        "1",
        "--review-items-completed",
        "1",
      ]),
    ]);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("reconciles regular-file review progress with symlink-inclusive scope counts", async () => {
    const fixture = await startDraftScan("directory", false, true);
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    const surface = (coverage.surfaces as CoverageSurface[])[0]!;
    surface.disposition = "no_issue_found";
    surface.receiptRefs = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
      writeFile(join(discovery, "in_scope_files.txt"), "src/extract.py\n"),
      writeFile(join(discovery, "candidate_ledger.jsonl"), ""),
      workbench(fixture, [
        "update-progress",
        "--scan-id",
        fixture.scanId,
        "--review-items-total",
        "1",
        "--review-items-completed",
        "1",
      ]),
    ]);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("seals the canonical standard ledger when candidates become reported findings", async () => {
    const fixture = await startDraftScan();
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    await Promise.all([
      writeFile(join(discovery, "in_scope_files.txt"), "src/extract.py\n"),
      writeFile(
        join(discovery, "candidate_ledger.jsonl"),
        `${JSON.stringify({
          candidate_id: "candidate-example",
          locations: [{ path: "src/extract.py" }],
          validation: { disposition: "reportable" },
          attack_path: { decision: "reportable" },
        })}\n`,
      ),
      workbench(fixture, [
        "update-progress",
        "--scan-id",
        fixture.scanId,
        "--review-items-total",
        "1",
        "--review-items-completed",
        "1",
      ]),
    ]);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toEqual(
      expect.arrayContaining([
        "artifacts/02_discovery/candidate_ledger.jsonl",
        "artifacts/02_discovery/in_scope_files.txt",
      ]),
    );
  });

  test("exports trusted receiptless legacy scans to SARIF without weakening fresh validation", async () => {
    const fixture = await startDraftScan();
    await completeScan(fixture);
    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    const surface = (coverage.surfaces as CoverageSurface[])[0]!;
    surface.disposition = "no_issue_found";
    surface.receiptRefs = [];
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
    ]);
    const migrateLegacyScan = [
      "import hashlib, json, pathlib, sqlite3, sys",
      "scan = pathlib.Path(sys.argv[1])",
      "manifest_path = scan / 'scan-manifest.json'",
      "manifest = json.loads(manifest_path.read_text())",
      "for artifact in manifest['scan']['artifacts']:",
      "    artifact['sha256'] = hashlib.sha256((scan / artifact['path']).read_bytes()).hexdigest()",
      "encoded = (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + '\\n').encode()",
      "manifest_path.write_bytes(encoded)",
      "database = sqlite3.connect(sys.argv[2])",
      "database.execute('UPDATE scans SET seal_manifest_digest = ? WHERE id = ?', ('sha256:' + hashlib.sha256(encoded).hexdigest(), sys.argv[3]))",
      "database.commit()",
      "database.close()",
    ].join("\n");
    const migrated = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        migrateLegacyScan,
        fixture.scanDir,
        join(fixture.stateDir, "workbench.sqlite3"),
        fixture.scanId,
      ],
      { encoding: "utf8" },
    );
    expect(migrated.status, migrated.stderr).toBe(0);

    await expect(
      workbench(fixture, [
        "export-findings",
        "--scan-id",
        fixture.scanId,
        "--format",
        "sarif",
      ]),
    ).resolves.toMatchObject({
      export: { path: join(fixture.scanDir, "exports", "results.sarif") },
    });
    expect(
      (
        await readJson<SarifDocument>(
          join(fixture.scanDir, "exports", "results.sarif"),
        )
      ).runs[0]?.results,
    ).toEqual([]);
  });

  test("counts symlinks when a Deep Scan starts directly from a target", async () => {
    const fixture = await startDraftScan("directory", true, true);
    const started = await workbench(fixture, [
      "begin-deep-scan",
      "--thread-id",
      "direct-deep-symlink-review",
      "--target-path",
      fixture.repository,
    ]);
    const scanId = String((started["deepScan"] as { scanId: string }).scanId);
    const context = await workbench(fixture, ["get-scan", "--scan-id", scanId]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 1 });
  });

  test("allows empty scoped Git paths beside unrelated working-tree changes", async () => {
    const fixture = await startDraftScan("clean");
    await mkdir(join(fixture.repository, "empty"));
    await writeFile(join(fixture.repository, "src", "extract.py"), "# dirty\n");
    const scanDir = join(fixture.stateDir, "empty-dirty-scope");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "paths", paths: ["empty"] },
      }),
    ]);
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      String(registration["scanId"]),
    ]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 0 });
  });

  test("verifies every requested path when several Git scopes are empty", async () => {
    const fixture = await startDraftScan("clean");
    await Promise.all([
      mkdir(join(fixture.repository, "empty-one")),
      mkdir(join(fixture.repository, "empty-two")),
    ]);
    const scanDir = join(fixture.stateDir, "multiple-empty-scopes");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "paths", paths: ["empty-one", "empty-two"] },
      }),
    ]);
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      String(registration["scanId"]),
    ]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 0 });
  });

  test("counts an initialized empty Git submodule as a scoped review target", async () => {
    const fixture = await startDraftScan("clean");
    const root = join(fixture.repository, "..");
    const child = join(root, "empty-submodule-source");
    await mkdir(child);
    for (const args of [
      ["init", "--quiet", child],
      [
        "-C",
        child,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "empty",
      ],
      [
        "-C",
        fixture.repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "--quiet",
        child,
        "vendor/empty",
      ],
      [
        "-C",
        fixture.repository,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "add empty submodule",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    const scanDir = join(fixture.stateDir, "empty-submodule-scope");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "paths", paths: ["vendor/empty"] },
      }),
    ]);
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      String(registration["scanId"]),
    ]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 1 });
  });

  test("does not certify sparse submodule index contents as an empty scope", async () => {
    const fixture = await startDraftScan("clean");
    const child = join(fixture.repository, "..", "sparse-submodule-source");
    await mkdir(join(child, "secret"), { recursive: true });
    await writeFile(
      join(child, "secret", "token.py"),
      "secret = 'review me'\n",
    );
    await writeFile(join(child, "visible.py"), "print('visible')\n");
    for (const args of [
      ["init", "--quiet", child],
      ["-C", child, "add", "."],
      [
        "-C",
        child,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "tracked secret",
      ],
      [
        "-C",
        fixture.repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "--quiet",
        child,
        "vendor/sub",
      ],
      [
        "-C",
        fixture.repository,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "add sparse submodule",
      ],
      [
        "-C",
        join(fixture.repository, "vendor", "sub"),
        "sparse-checkout",
        "set",
        "--no-cone",
        "/visible.py",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    await mkdir(join(fixture.repository, "vendor", "sub", "secret"), {
      recursive: true,
    });
    const scanDir = join(fixture.stateDir, "sparse-submodule-scope");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });

    await expect(
      workbench(fixture, [
        "register-cli-scan",
        "--repository",
        fixture.repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository: fixture.repository,
          target: { kind: "paths", paths: ["vendor/sub/secret"] },
        }),
      ]),
    ).rejects.toThrow("empty scope was being verified");
  });

  test("rejects an empty scope that changes during snapshot capture", async () => {
    const fixture = await startDraftScan("directory", true);
    const scanDir = join(fixture.stateDir, "racing-scan");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const script = [
      "import sys",
      "from pathlib import Path",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db",
      "repository = Path(sys.argv[2])",
      "original = workbench_db.authoritative_scope_file_count",
      "def racing_count(*args, **kwargs):",
      "    count = original(*args, **kwargs)",
      "    (repository / 'src' / 'new.py').write_text('# appeared\\n')",
      "    return count",
      "workbench_db.authoritative_scope_file_count = racing_count",
      "sys.argv = [workbench_db.__file__, *sys.argv[3:]]",
      "workbench_db.main()",
    ].join("\n");
    const recipe = JSON.stringify({
      config: {},
      mode: "standard",
      repository: fixture.repository,
      target: { kind: "repository", paths: [] },
    });
    const result = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        "register-cli-scan",
        "--repository",
        fixture.repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        recipe,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "The selected scan target changed while its empty scope was being verified.",
    );
  });

  test("rejects files that disappear and return around an empty-scope count", async () => {
    const fixture = await startDraftScan();
    const scanDir = join(fixture.stateDir, "aba-scan");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const script = [
      "import sys",
      "from pathlib import Path",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db",
      "repository = Path(sys.argv[2])",
      "original = workbench_db.authoritative_scope_file_count",
      "def racing_count(*args, **kwargs):",
      "    path = repository / 'src' / 'extract.py'",
      "    original_contents = path.read_bytes()",
      "    path.unlink()",
      "    count = original(*args, **kwargs)",
      "    path.write_bytes(original_contents)",
      "    return count",
      "workbench_db.authoritative_scope_file_count = racing_count",
      "sys.argv = [workbench_db.__file__, *sys.argv[3:]]",
      "workbench_db.main()",
    ].join("\n");
    const result = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        "register-cli-scan",
        "--repository",
        fixture.repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository: fixture.repository,
          target: { kind: "repository", paths: [] },
        }),
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "The selected scan target changed while its empty scope was being verified.",
    );
  });

  test("rejects a self-sealed empty inventory for a nonempty running scan", async () => {
    const fixture = await startDraftScan();
    await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    const findingsPath = join(fixture.scanDir, "findings.json");
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const inventoryPath = join(
      fixture.scanDir,
      "artifacts",
      "02_discovery",
      "scope_inventory.jsonl",
    );
    const findings = await readJson<FindingsDocument>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    findings.findings = [];
    coverage.surfaces = [];
    await mkdir(join(fixture.scanDir, "artifacts", "02_discovery"), {
      recursive: true,
    });
    await Promise.all([
      writeJson(findingsPath, findings),
      writeJson(coveragePath, coverage),
      writeFile(inventoryPath, ""),
    ]);

    const manifestPath = join(fixture.scanDir, "scan-manifest.json");
    const manifest = await readJson<{
      scan: {
        artifacts: Array<{ path: string; mediaType: string; sha256: string }>;
      };
    }>(manifestPath);
    for (const artifact of manifest.scan.artifacts) {
      artifact.sha256 = createHash("sha256")
        .update(await readFile(join(fixture.scanDir, artifact.path)))
        .digest("hex");
    }
    manifest.scan.artifacts.push({
      path: "artifacts/02_discovery/scope_inventory.jsonl",
      mediaType: "application/octet-stream",
      sha256: createHash("sha256").update("").digest("hex"),
    });
    await writeJson(manifestPath, manifest);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
    const running = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((running["scan"] as ScanSummary).progress.status).toBe("running");
  });

  test("returns the authoritative directory snapshot contract at registration", async () => {
    const fixture = await startDraftScan();
    const registration = fixture.registration;
    const contract = registration["contract"] as {
      target: {
        allowedKinds: string[];
        displayName: string;
        targetId: string;
        requiredSnapshotDigest?: string;
      };
    };

    expect(registration["targetRevision"]).toBe("unversioned");
    expect(contract.target).toMatchObject({
      allowedKinds: ["directory_snapshot"],
      displayName: "repository",
      targetId: registration["targetId"],
      requiredSnapshotDigest: expect.stringMatching(
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
      ),
    });
  });

  test("returns authoritative clean, dirty, and nested Git target contracts", async () => {
    for (const kind of ["clean", "dirty", "nested"] as const) {
      const fixture = await startDraftScan(kind);
      const registration = fixture.registration;
      const contract = registration["contract"] as {
        target: {
          allowedKinds: string[];
          targetId: string;
          requiredSnapshotDigest?: string;
        };
      };
      const revision = spawnSync(
        "git",
        ["-C", fixture.repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      );

      expect(revision.status, revision.stderr).toBe(0);
      expect(registration["targetRevision"]).toBe(revision.stdout.trim());
      expect(registration["targetId"]).toBe(contract.target.targetId);
      expect(contract.target.allowedKinds).toEqual([
        kind === "clean" ? "git_revision" : "git_worktree",
      ]);
      if (kind === "clean") {
        expect(contract.target).not.toHaveProperty("requiredSnapshotDigest");
      } else {
        expect(contract.target.requiredSnapshotDigest).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
        );
      }
      if (kind === "nested") {
        const copied = spawnSync(
          fixture.python,
          [
            "-I",
            "-B",
            "-c",
            [
              "import sys",
              "from pathlib import Path",
              "sys.path.insert(0, sys.argv[1])",
              "import workbench_target as target",
              "source = Path(sys.argv[2])",
              "checkout = target.copy_git_worktree_files(source, Path(sys.argv[3]), ())",
              "git_dir = Path(target.git_output(source, 'rev-parse', '--absolute-git-dir'))",
              "assert target.worktree_content_digest_for_context(checkout, '.', git_dir=git_dir, work_tree=checkout) == target.worktree_content_digest(source)",
            ].join("\n"),
            join(PLUGIN_ROOT, "scripts"),
            fixture.repository,
            join(fixture.stateDir, "checkout"),
          ],
          { encoding: "utf8" },
        );
        expect(copied.status, copied.stderr).toBe(0);
      }
    }
  });

  test("counts deleted diff files before minting an empty-scope proof", async () => {
    const fixture = await startDraftScan("clean");
    const git = (args: string[]): string => {
      const result = spawnSync("git", ["-C", fixture.repository, ...args], {
        encoding: "utf8",
      });
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    const base = git(["rev-parse", "HEAD"]);
    git(["rm", "--quiet", "src/extract.py"]);
    git([
      "-c",
      "user.name=Codex Security",
      "-c",
      "user.email=codex-security@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "remove final source file",
    ]);
    const head = git(["rev-parse", "HEAD"]);
    const scanDir = join(fixture.stateDir, "deletion-scan");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "refs", paths: [], base, head },
      }),
    ]);
    fixture.scanDir = scanDir;
    fixture.scanId = String(registration["scanId"]);
    await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
      recursive: true,
    });
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson<{
      scan: {
        id: string;
        target: { kind: string };
        sealedAt?: string;
        artifacts?: unknown[];
      };
    }>(manifestPath);
    manifest.scan.id = fixture.scanId;
    manifest.scan.target.kind = "git_diff";
    delete manifest.scan.sealedAt;
    delete manifest.scan.artifacts;
    await writeJson(manifestPath, manifest);
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    findings.scanId = fixture.scanId;
    findings.findings = [];
    await writeJson(findingsPath, findings);
    const coveragePath = join(scanDir, "coverage.json");
    const coverage = await readJson<CoverageDocument>(coveragePath);
    coverage.scanId = fixture.scanId;
    coverage["mode"] = "branch_diff";
    coverage.surfaces = [];
    await writeJson(coveragePath, coverage);

    await expect(completeScan(fixture)).rejects.toThrow(
      "complete coverage requires a reviewed surface or an authoritatively empty scope inventory",
    );
  });

  test("counts changed submodules even when local Git config ignores them", async () => {
    const fixture = await startDraftScan("clean");
    const git = (args: string[]): string => {
      const result = spawnSync("git", ["-C", fixture.repository, ...args], {
        encoding: "utf8",
      });
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    const base = git(["rev-parse", "HEAD"]);
    git(["config", "diff.ignoreSubmodules", "all"]);
    git(["update-index", "--add", "--cacheinfo", `160000,${base},deps/linked`]);
    git([
      "-c",
      "user.name=Codex Security",
      "-c",
      "user.email=codex-security@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "add linked repository",
    ]);
    const head = git(["rev-parse", "HEAD"]);
    const scanDir = join(fixture.stateDir, "submodule-scan");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });

    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "refs", paths: [], base, head },
      }),
    ]);
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      String(registration["scanId"]),
    ]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 1 });
  });

  test("counts an uninitialized tracked Git submodule as reviewable", async () => {
    const fixture = await startDraftScan("clean");
    const git = (args: string[]): string => {
      const result = spawnSync("git", ["-C", fixture.repository, ...args], {
        encoding: "utf8",
      });
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    const revision = git(["rev-parse", "HEAD"]);
    git(["rm", "--quiet", "src/extract.py"]);
    git([
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${revision},deps/linked`,
    ]);
    git([
      "-c",
      "user.name=Codex Security",
      "-c",
      "user.email=codex-security@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "leave only an uninitialized linked repository",
    ]);
    const scanDir = join(fixture.stateDir, "uninitialized-submodule-scan");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registration = await workbench(fixture, [
      "register-cli-scan",
      "--repository",
      fixture.repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository: fixture.repository,
        target: { kind: "repository", paths: [] },
      }),
    ]);
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      String(registration["scanId"]),
    ]);

    expect(
      (
        context["scan"] as {
          progress: { coverage: { filesTotal: number } };
        }
      ).progress.coverage,
    ).toMatchObject({ filesTotal: 1 });
  });

  test("rejects a working-tree diff that disappears before its empty count", async () => {
    const fixture = await startDraftScan("dirty");
    const scanDir = join(fixture.stateDir, "working-tree-race");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const script = [
      "import sys",
      "from pathlib import Path",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db",
      "repository = Path(sys.argv[2])",
      "original = workbench_db.authoritative_scope_file_count",
      "def racing_count(*args, **kwargs):",
      "    (repository / 'src' / 'extract.py').write_text('# fixture\\n')",
      "    return original(*args, **kwargs)",
      "workbench_db.authoritative_scope_file_count = racing_count",
      "sys.argv = [workbench_db.__file__, *sys.argv[3:]]",
      "workbench_db.main()",
    ].join("\n");
    const result = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        script,
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        "register-cli-scan",
        "--repository",
        fixture.repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository: fixture.repository,
          target: {
            kind: "working_tree",
            paths: [],
            base: "HEAD",
            head: "HEAD",
          },
        }),
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "The selected scan target changed while its empty scope was being verified.",
    );
  });

  test("seals a prepared scan without publishing it before acceptance", async () => {
    const fixture = await startDraftScan();

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    const manifest = await readJson<{
      scan: { sealedAt: string; completedAt: string };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
    const running = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((running["scan"] as ScanSummary).progress.status).toBe("running");
    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("marks rejected prepared scans as failed without publishing completion", async () => {
    const fixture = await startDraftScan();
    await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    await writeFile(join(fixture.scanDir, "findings.json"), "corrupted\n");

    const failed = await workbench(fixture, [
      "fail-scan",
      "--scan-id",
      fixture.scanId,
      "--message",
      "Sealed scan could not be accepted.",
    ]);

    expect((failed["scan"] as ScanSummary).progress.status).toBe("failed");
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((stored["scan"] as ScanSummary).progress.status).toBe("failed");
  });

  test("normalizes finding identities and persists recovery warnings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding.ruleId = "Path Traversal: Archive Extraction";
    finding.identity.anchor = "Archive Entry Write Without Containment";
    finding.identity.instance = "User Input #1";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([
      "Recovered finding 1: normalized rule identifier, semantic anchor, instance.",
    ]);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
    expect(recovered.ruleId).toBe("path-traversal-archive-extraction");
    expect(recovered.identity).toEqual({
      anchor: "archive-entry-write-without-containment",
      instance: "user-input-1",
    });
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as unknown as ScanSummary).warnings).toEqual(
      completed.warnings,
    );
  });

  test("preserves recovery warnings across prepared scan completion", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Archive Entry Without Containment";
    await writeJson(path, document);

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const warning = "Recovered finding 1: normalized semantic anchor.";

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    expect((prepared["scan"] as ScanSummary).warnings).toEqual([warning]);
    const completed = await completeScan(fixture);
    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toEqual([warning]);
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as ScanSummary).warnings).toEqual([warning]);
  });

  test("keeps valid findings and skips malformed or duplicate findings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const missingSummary = structuredClone(valid);
    missingSummary.identity.anchor = "missing-summary";
    missingSummary.summary = "";
    const unsafeLocation = structuredClone(valid);
    unsafeLocation.identity.anchor = "unsafe-location";
    unsafeLocation.locations[0]!.path = "../outside.py";
    const missingIdentity = structuredClone(valid);
    delete (missingIdentity as Partial<Finding>).identity;
    document.findings.push(
      missingSummary,
      unsafeLocation,
      missingIdentity,
      structuredClone(valid),
      null,
    );
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toHaveLength(5);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed finding"),
      ),
    ).toBe(true);
    for (const reason of [
      "summary",
      "safe repository-relative",
      "identity",
      "duplicate logical finding",
      "expected an object",
    ]) {
      expect(
        completed.warnings.some((warning) => warning.includes(reason)),
      ).toBe(true);
    }
    expect((await readJson<FindingsDocument>(path)).findings).toHaveLength(1);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toHaveLength(4);
  });

  test("retains the strongest duplicate finding regardless of input order", async () => {
    const cases = [
      {
        name: "severity ascending",
        candidates: [
          ["informational", "high", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "severity descending",
        candidates: [
          ["critical", "high", 1],
          ["informational", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence ascending",
        candidates: [
          ["critical", "low", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence descending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "low", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "evidence ascending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "high", 2],
        ],
        expected: ["critical", "high", 2],
      },
      {
        name: "evidence descending",
        candidates: [
          ["critical", "high", 2],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 2],
      },
    ] as const;

    for (const { name, candidates, expected } of cases) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "findings.json");
      const document = await readJson<FindingsDocument>(path);
      const baseline = document.findings[0]!;
      document.findings = candidates.map(([severity, confidence, count]) => {
        const finding = structuredClone(baseline);
        finding.severity.level = severity;
        finding.confidence.level = confidence;
        finding.codeEvidence = Array.from({ length: count }, (_, index) => ({
          id: `evidence-${index + 1}`,
          label: "Archive extraction",
          path: "src/extract.py",
          startLine: 1,
          code: "# fixture",
          explanation: "The archive entry reaches a filesystem write.",
        }));
        return finding;
      });
      await writeJson(path, document);

      const completed = await completeScan(fixture);

      expect(completed.progress.status, name).toBe("complete");
      expect(completed.findingCount, name).toBe(1);
      expect(completed.warnings, name).toHaveLength(1);
      expect(completed.warnings[0], name).toContain(
        "duplicate logical finding",
      );
      const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
      expect(
        [
          recovered.severity.level,
          recovered.confidence.level,
          recovered.codeEvidence?.length,
        ],
        name,
      ).toEqual([...expected]);
      const coverage = await readJson<CoverageDocument>(
        join(fixture.scanDir, "coverage.json"),
      );
      expect(coverage.completeness, name).toBe("complete");
      expect(
        await readFile(join(fixture.scanDir, "report.md"), "utf8"),
        name,
      ).not.toContain("### No findings");
      const sarif = await readJson<SarifDocument>(
        join(fixture.scanDir, "exports", "results.sarif"),
      );
      expect(sarif.runs[0]?.results[0]?.properties.severity, name).toBe(
        "critical",
      );
    }
  });

  test("completes scans when every draft finding is malformed", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.summary = "";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(0);
    expect(completed.warnings).toHaveLength(1);
    expect(completed.warnings[0]).toContain("summary");
    expect((await readJson<FindingsDocument>(path)).findings).toEqual([]);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toEqual([
      { id: "discarded-finding-1", reason: completed.warnings[0] },
    ]);
    const report = await readFile(join(fixture.scanDir, "report.md"), "utf8");
    expect(report).toContain("| Coverage | partial |");
    expect(report).toContain("Skipped malformed finding 1");
    const sarif = await readJson<SarifDocument>(
      join(fixture.scanDir, "exports", "results.sarif"),
    );
    expect(sarif.runs[0]?.properties.codexSecurityCoverageCompleteness).toBe(
      "partial",
    );
    expect(sarif.runs[0]?.invocations).toEqual([
      {
        executionSuccessful: true,
        toolExecutionNotifications: [
          { level: "warning", message: { text: completed.warnings[0]! } },
        ],
      },
    ]);
  });

  test("keeps findings while removing invalid or duplicate writeups", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const reportPath = "findings/linked-writeup/linked-writeup.md";
    await mkdir(join(fixture.scanDir, "findings", "linked-writeup"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, reportPath), "# Verified finding\n");

    for (const [anchor, writeup] of [
      ["linked-writeup", { reportPath }],
      ["duplicate-writeup", { reportPath }],
      ["missing-writeup", { reportPath: "findings/missing/missing.md" }],
      ["unsafe-writeup", { reportPath: "../outside.md" }],
      ["invalid-writeup", "not an object"],
    ] as const) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding.writeup = writeup;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(6);
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed writeup for finding"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.md");
    const recovered = (await readJson<FindingsDocument>(path)).findings;
    expect(
      recovered.find((finding) => finding?.identity.anchor === "linked-writeup")
        ?.writeup,
    ).toEqual({ reportPath });
    for (const anchor of [
      "duplicate-writeup",
      "missing-writeup",
      "unsafe-writeup",
      "invalid-writeup",
    ]) {
      expect(
        recovered.find((finding) => finding?.identity.anchor === anchor),
      ).not.toHaveProperty("writeup");
    }
  });

  test("preserves findings while discarding malformed optional remediation guidance", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    for (const [anchor, field, value] of [
      [
        "valid-remediation-tests",
        "remediationTests",
        ["Add a regression test."],
      ],
      ["prose-remediation-tests", "remediationTests", "Add a regression test."],
      [
        "object-remediation-tests",
        "remediationTests",
        [{ description: "Add a regression test." }],
      ],
      ["prose-preventive-controls", "preventiveControls", "Validate paths."],
    ] as const) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding[field] = value;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(5);
    expect(completed.warnings).toHaveLength(3);
    const recovered = (await readJson<FindingsDocument>(path)).findings;
    expect(
      recovered.find(
        (finding) => finding?.identity.anchor === "valid-remediation-tests",
      )?.remediationTests,
    ).toEqual(["Add a regression test."]);
    for (const [anchor, field] of [
      ["prose-remediation-tests", "remediationTests"],
      ["object-remediation-tests", "remediationTests"],
      ["prose-preventive-controls", "preventiveControls"],
    ] as const) {
      expect(
        recovered.find((finding) => finding?.identity.anchor === anchor),
      ).not.toHaveProperty(field);
    }
  });

  test("keeps verified coverage receipts and downgrades invalid coverage", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    const receipt = "artifacts/02_discovery/work_ledger.jsonl";
    await mkdir(join(fixture.scanDir, "artifacts", "02_discovery"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, receipt), '{"status":"reviewed"}\n');
    const surface = (document.surfaces as CoverageSurface[])[0]!;
    surface.receiptRefs = [
      receipt,
      "report.md",
      "../outside.json",
      "artifacts/02_discovery/missing.jsonl",
      null,
    ];
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed coverage receipt"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.json");
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered.completeness).toBe("partial");
    expect((recovered.surfaces as CoverageSurface[])[0]).toMatchObject({
      disposition: "needs_follow_up",
      receiptRefs: [receipt],
    });
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toContain(
      receipt,
    );
  });

  test("downgrades malformed coverage collections without claiming completeness", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.completeness = "finished";
    document.surfaces = { id: "not-an-array" };
    document.explicitExclusions = null;
    document.deferred = "later";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(4);
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered).toMatchObject({
      completeness: "partial",
      surfaces: [
        {
          id: "surface_recovered_reported_findings",
          disposition: "reported",
        },
      ],
      explicitExclusions: [],
      deferred: [],
    });
  });

  test("avoids collisions with existing recovered coverage-surface IDs", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    const surface = (document.surfaces as CoverageSurface[])[0]!;
    surface.id = "surface_recovered_reported_findings";
    surface.disposition = "reviewed";
    await writeJson(path, document);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered.completeness).toBe("partial");
    expect(
      (recovered.surfaces as CoverageSurface[]).map(({ id }) => id),
    ).toEqual([
      "surface_recovered_reported_findings",
      "surface_recovered_reported_findings_2",
    ]);
  });

  test("discards unsafe hardening portfolios without discarding findings", async () => {
    for (const hardening of [
      "not an object",
      { portfolioPath: "../outside.md" },
      { portfolioPath: "hardening/hardening.md" },
    ]) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "scan-manifest.json");
      const manifest = await readJson<{
        scan: { hardening?: unknown };
      }>(path);
      manifest.scan.hardening = hardening;
      await writeJson(path, manifest);

      const completed = await completeScan(fixture);

      expect(completed.progress.status).toBe("complete");
      expect(completed.findingCount).toBe(1);
      expect(completed.warnings).toHaveLength(1);
      expect(completed.warnings[0]).toContain(
        "Skipped malformed hardening portfolio:",
      );
      expect(completed.warnings[0]).not.toContain("../outside.md");
      expect(
        (await readJson<{ scan: { hardening?: unknown } }>(path)).scan,
      ).not.toHaveProperty("hardening");
    }
  });

  test("keeps direct finalization strict unless recovery is explicitly enabled", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Invalid Anchor";
    await writeJson(path, document);

    const strict = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        "--scan-dir",
        fixture.scanDir,
      ],
      { encoding: "utf8" },
    );

    expect(strict.status).not.toBe(0);
    expect(strict.stderr).toContain("stable lowercase semantic slug");
    expect((await completeScan(fixture)).findingCount).toBe(1);
  });

  test("refuses to repair scan-wide coverage contract violations", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.inventoryStrategy = "";
    await writeJson(path, document);
    const original = await readFile(path, "utf8");

    await expect(completeScan(fixture)).rejects.toThrow("inventoryStrategy");
    expect(await readFile(path, "utf8")).toBe(original);
  });
});
