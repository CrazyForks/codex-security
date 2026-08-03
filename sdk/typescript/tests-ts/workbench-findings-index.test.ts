import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "target_id = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, updated_at TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?)', [('current-target', '/current/repository'), ('stale-target', '/stale/repository')])",
  "connection.executemany('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old', 'current-target', '/current/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.'),",
  "    ('current-new', None, '/current/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.'),",
  "    ('stale-old', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.'),",
  "    ('stale-new', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.'),",
  "])",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "])",
  "connection.executemany('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'src/old.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/new.py', 'root_control', 0),",
  "    ('stale-old-occurrence', 'src/stale.py', 'root_control', 0),",
  "])",
  "coverage_reads = []",
  "def coverage(scan):",
  "    coverage_reads.append(scan['id'])",
  "    if scan['id'] == 'stale-new':",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "args = argparse.Namespace(query=None, severity=None, status=None, target_id=target_id, offset=0, limit=20)",
  "result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "print(json.dumps({'findings': result['findings'], 'coverageReads': coverage_reads}))",
].join("\n");

function probeFindingsIndex(targetId: string | null): {
  findings: Array<{ occurrenceId: string; scanId: string; targetId: string }>;
  coverageReads: string[];
} {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for findings-index tests.",
    );
  }
  const result = Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      findingsIndexProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(targetId),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
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
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual(["current-new", "stale-new"]);
  });
});
