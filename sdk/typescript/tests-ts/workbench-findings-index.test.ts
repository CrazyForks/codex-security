import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "settings = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT, scan_dir TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, updated_at TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?)', [('current-target', '/current/repository'), ('stale-target', '/stale/repository')])",
  "stale_directory = sys.argv[1] if settings.get('coverageFailure') == 'noncanonical' else '/private/tmp/codex-security-findings-index-missing-stale'",
  "connection.executemany('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old', 'current-target', '/current/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/current-old'),",
  "    ('current-new', None, '/current/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new'),",
  "    ('stale-old', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/stale-old'),",
  "    ('stale-new', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', stale_directory),",
  "    ('orphan-old', None, '/orphan/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/orphan-old'),",
  "    ('orphan-new', None, '/orphan/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/orphan-new'),",
  "])",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "    ('orphan-old-occurrence', 'orphan-old-finding', 'orphan-old', 'high', '2026-01-01', 'Older orphan finding', 'Still outside follow-up coverage'),",
  "    ('orphan-new-occurrence', 'orphan-new-finding', 'orphan-new', 'medium', '2026-02-01', 'Latest orphan finding', 'Target row does not exist'),",
  "])",
  "connection.executemany('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'src/old.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/new.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/secondary.py', 'sink', 1),",
  "    ('stale-old-occurrence', 'src/stale.py', 'root_control', 0),",
  "    ('orphan-old-occurrence', 'src/orphan-old.py', 'root_control', 0),",
  "    ('orphan-new-occurrence', 'src/orphan-new.py', 'root_control', 0),",
  "])",
  "coverage_reads = []",
  "def coverage(scan):",
  "    coverage_reads.append(scan['id'])",
  "    if scan['id'] == 'stale-new':",
  "        if settings.get('coverageFailure') == 'tampered':",
  "            raise SystemExit('The sealed scan manifest changed after completion.')",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    if scan['id'] == 'orphan-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/orphan-new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "args = argparse.Namespace(query=settings.get('query'), severity=None, status=None, target_id=settings.get('targetId'), target_path=settings.get('targetPath'), offset=0, limit=20)",
  "result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "print(json.dumps({'findings': result['findings'], 'coverageReads': coverage_reads}))",
].join("\n");

const nestedDirectoryScanProbe = [
  "import argparse, json, pathlib, sqlite3, subprocess, sys, tempfile",
  "sys.path.insert(0, sys.argv[1])",
  "from workbench_db import apply_migrations",
  "from workbench_scan_history import list_scans",
  "from workbench_target_state import ensure_security_target",
  "with tempfile.TemporaryDirectory(prefix='codex-security-unversioned-scan-') as directory:",
  "    root = (pathlib.Path(directory) / 'plain-directory').resolve()",
  "    nested = root / 'src' / 'nested'",
  "    nested.mkdir(parents=True)",
  "    independent = root / 'independent-git'",
  "    independent_nested = independent / 'src'",
  "    independent_nested.mkdir(parents=True)",
  "    subprocess.run(['git', 'init', '-q', str(independent)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    service = root / 'independent-service'",
  "    nested_service = service / 'src'",
  "    nested_service.mkdir(parents=True)",
  "    connection = sqlite3.connect(':memory:')",
  "    connection.row_factory = sqlite3.Row",
  "    apply_migrations(connection)",
  "    timestamp = '2026-08-03T12:00:00Z'",
  "    for scan_id, path in [('scan', root), ('independent-service-scan', service)]:",
  "        target = ensure_security_target(connection, str(path))",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(path), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(path), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    connection.commit()",
  "    output = {}",
  "    for label, path in [('root', root), ('nested', nested), ('independentGit', independent), ('nestedIndependentGit', independent_nested), ('independentService', service), ('nestedIndependentService', nested_service)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    print(json.dumps(output))",
].join("\n");

const findingDetailProbe = [
  "import json, sys",
  "sys.path.insert(0, sys.argv[1])",
  "from finding_preview import bounded_finding_details",
  "finding = {'rootCause': {'summary': 'Missing authorization'}, 'remediationTests': ['Reject a cross-account request.'], 'preventiveControls': ['Centralize account authorization.']}",
  "print(json.dumps({'preview': bounded_finding_details(finding), 'detail': bounded_finding_details(finding, include_remediation=True)}))",
].join("\n");

function runFindingsIndex(
  targetId: string | null,
  settings: {
    targetPath?: string;
    query?: string;
    coverageFailure?: "tampered" | "noncanonical";
  } = {},
) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for findings-index tests.",
    );
  }
  return Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      findingsIndexProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify({ targetId, ...settings }),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
}

function probeFindingsIndex(
  targetId: string | null,
  settings: { targetPath?: string; query?: string } = {},
): {
  findings: Array<{
    occurrenceId: string;
    scanId: string;
    targetId: string | null;
    targetPath: string;
  }>;
  coverageReads: string[];
} {
  const result = runFindingsIndex(targetId, settings);
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout));
}

describe("workbench findings index", () => {
  test("includes CLI scans without target IDs and scopes coverage reads", () => {
    const result = probeFindingsIndex("current-target");

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        scanId: "current-new",
        targetId: "current-target",
      }),
    ]);
    expect(result.coverageReads).toEqual(["current-new"]);
  });

  test("keeps earlier findings when follow-up coverage is unavailable", () => {
    const result = probeFindingsIndex(null);

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "orphan-old-occurrence" }),
      expect.objectContaining({ occurrenceId: "orphan-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual([
      "current-new",
      "orphan-new",
      "stale-new",
    ]);
  });

  test("indexes every targetless scan even without a saved target", () => {
    const result = probeFindingsIndex(null, {
      targetPath: "/orphan/repository",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "orphan-old-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
      expect.objectContaining({
        occurrenceId: "orphan-new-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
    ]);
    expect(result.coverageReads).toEqual(["orphan-new"]);
  });

  test("searches secondary finding source locations", () => {
    const result = probeFindingsIndex("current-target", {
      query: "SECONDARY.PY",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
  });

  test("searches repository paths only for cross-repository queries", () => {
    const scoped = probeFindingsIndex("current-target", {
      query: "/CURRENT/REPOSITORY",
    });
    expect(scoped.findings).toEqual([]);

    const unscoped = probeFindingsIndex(null, {
      query: "/ORPHAN/REPOSITORY",
    });
    expect(unscoped.findings.map((finding) => finding.occurrenceId)).toEqual([
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
  });

  test("finds unversioned directory scans from nested subdirectories", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null)
      throw new Error("Python is required for scan-history tests.");
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        "-c",
        nestedDirectoryScanProbe,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      root: ["scan"],
      nested: ["scan"],
      independentGit: [],
      nestedIndependentGit: [],
      independentService: ["independent-service-scan"],
      nestedIndependentService: ["independent-service-scan"],
    });
  });

  test("preserves remediation guidance only in dedicated finding details", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null)
      throw new Error("Python is required for finding-detail tests.");
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        "-c",
        findingDetailProbe,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      preview: { rootCause: { summary: "Missing authorization" } },
      detail: {
        rootCause: { summary: "Missing authorization" },
        remediationTests: ["Reject a cross-account request."],
        preventiveControls: ["Centralize account authorization."],
      },
    });
  });

  test("rejects tampered or noncanonical follow-up scan artifacts", () => {
    for (const coverageFailure of ["tampered", "noncanonical"] as const) {
      const result = runFindingsIndex("stale-target", { coverageFailure });

      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain(
        coverageFailure === "tampered"
          ? "sealed scan manifest changed"
          : "existing canonical non-symlink directory",
      );
    }
  });
});
