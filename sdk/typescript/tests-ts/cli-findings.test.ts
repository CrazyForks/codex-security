import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./support/cli.js";

describe("CLI findings history", () => {
  test("lists active findings for the current repository by default", async () => {
    for (const command of [["findings"], ["findings", "list"]]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      const deps = dependencies({
        onWorkbench: (args): JsonObject => {
          calls.push(args);
          if (args[0] === "list-scans") {
            return {
              scans: [
                {
                  scanId: "scan-1",
                  targetId: "target-1",
                  targetPath: "/current/repository",
                },
              ],
            };
          }
          return {
            findings: [
              { occurrenceId: "occ-1", title: "Missing authorization" },
            ],
            limit: 20,
            nextOffset: null,
            offset: 0,
          };
        },
      });
      deps.createSecurity = () => {
        throw new Error("saved findings must not initialize Codex");
      };

      expect(
        await main(
          [...command, "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual([
        ["list-scans", "--repository", "/current/repository"],
        [
          "list-global-findings",
          "--target-id",
          "target-1",
          "--offset",
          "0",
          "--limit",
          "20",
        ],
      ]);
      expect(JSON.parse(stdout.text())).toMatchObject({
        findings: [{ occurrenceId: "occ-1" }],
      });
    }
  });

  test("keeps the current checkout scoped when related scan history is newer", async () => {
    const calls: Array<readonly string[]> = [];
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        return args[0] === "list-scans"
          ? {
              scans: [
                {
                  scanId: "related",
                  targetId: "related-target",
                  targetPath: "/another/checkout",
                },
                {
                  scanId: "current",
                  targetId: "current-target",
                  targetPath: "/current/repository",
                },
              ],
            }
          : { findings: [], limit: 20, nextOffset: null, offset: 0 };
      },
    });

    expect(
      await main(
        ["findings", "list"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls[1]).toContain("current-target");
    expect(calls[1]).not.toContain("related-target");
  });

  test("returns an empty repository page without querying other targets", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["findings", "--offset", "5", "--limit", "10", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return { scans: [] };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", "/current/repository"],
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      findings: [],
      limit: 10,
      nextOffset: null,
      offset: 5,
    });
  });

  test("falls back to a completed scan when legacy history has no target ID", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["findings", "--offset", "20", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "legacy-scan",
                      targetId: null,
                      targetPath: "/current/repository",
                      progress: { status: "complete" },
                    },
                  ],
                }
              : {
                  findingsPage: {
                    findings: [{ occurrenceId: "occ-21" }],
                    limit: 20,
                    nextOffset: null,
                    offset: 20,
                    scanId: "legacy-scan",
                    total: 21,
                  },
                };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", "/current/repository"],
      [
        "list-findings",
        "--scan-id",
        "legacy-scan",
        "--offset",
        "20",
        "--limit",
        "20",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      findings: [{ occurrenceId: "occ-21" }],
      scanId: "legacy-scan",
    });
  });

  test("lists findings across repositories without a target filter", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        [
          "findings",
          "list",
          "--all-repositories",
          "--severity",
          "critical",
          "--status",
          "open",
          "--limit",
          "5",
        ],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return { findings: [], limit: 5, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-global-findings",
        "--severity",
        "critical",
        "--status",
        "open",
        "--offset",
        "0",
        "--limit",
        "5",
      ],
    ]);
  });

  test("paginates and filters findings from a selected historical scan", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        [
          "findings",
          "list",
          "--scan",
          "31107fbe",
          "--query",
          "login injection",
          "--severity",
          "high",
          "--status",
          "open",
          "--offset",
          "20",
          "--limit",
          "5",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return {
              findingsPage: {
                findings: [{ occurrenceId: "occ-25", title: "Historic SQLi" }],
                limit: 5,
                nextOffset: null,
                offset: 20,
                scanId: "31107fbe-full",
                total: 21,
              },
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-findings",
        "--scan-id",
        "31107fbe",
        "--query",
        "login injection",
        "--severity",
        "high",
        "--status",
        "open",
        "--offset",
        "20",
        "--limit",
        "5",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      findings: [{ occurrenceId: "occ-25", title: "Historic SQLi" }],
      limit: 5,
      nextOffset: null,
      offset: 20,
      scanId: "31107fbe-full",
      total: 21,
    });
  });

  test("shows a historical occurrence without exposing unrelated findings", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    const selected: JsonObject = {
      occurrenceId: "occ-25",
      severity: { level: "high" },
      title: "Historic SQL injection",
      matches: [{ scanId: "previous-scan", title: "Previous injection" }],
    };
    expect(
      await main(
        ["findings", "show", "occ-25", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return {
              scan: {
                scanId: "31107fbe-full",
                targetPath: "/current/repository",
                findings: [
                  { occurrenceId: "occ-other", title: "Unrelated finding" },
                  selected,
                ],
              },
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([["get-finding", "--occurrence-id", "occ-25"]]);
    expect(JSON.parse(stdout.text())).toEqual({
      ...selected,
      scanId: "31107fbe-full",
      targetPath: "/current/repository",
    });
    expect(stdout.text()).not.toContain("Unrelated finding");
  });

  test("shows the latest completed scan without requiring its identifier", async () => {
    for (const command of [
      ["scans", "show"],
      ["scans", "show", "latest"],
    ]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      expect(
        await main(
          [...command, "--json"],
          stdout.stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              return args[0] === "list-scans"
                ? {
                    scans: [
                      { scanId: "running", progress: { status: "running" } },
                      { scanId: "latest", progress: { status: "complete" } },
                      { scanId: "older", progress: { status: "complete" } },
                    ],
                  }
                : { scan: { scanId: "latest", findings: [] } };
            },
          }),
        ),
      ).toBe(0);
      expect(calls).toEqual([
        ["list-scans", "--repository", "/current/repository"],
        ["get-scan", "--scan-id", "latest"],
      ]);
      expect(JSON.parse(stdout.text())).toEqual({
        scanId: "latest",
        findings: [],
      });
    }
  });

  test("explains when no completed scan is available", async () => {
    const stderr = capture();
    expect(
      await main(
        ["scans", "show"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: () => ({
            scans: [{ scanId: "running", progress: { status: "running" } }],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("No completed scans found");
    expect(stderr.text()).toContain("codex-security scan .");
  });

  test("rejects invalid filters before querying saved findings", async () => {
    const invalid = [
      ["findings", "list", "--scan", "scan-1", "--all-repositories"],
      ["findings", "list", "--limit", "0"],
      ["findings", "list", "--limit", "21"],
      ["findings", "list", "--offset", "-1"],
      ["findings", "list", "--severity", "urgent"],
      ["findings", "list", "--scan"],
    ];
    for (const command of invalid) {
      let called = false;
      expect(
        await main(
          command,
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: () => {
              called = true;
              return {};
            },
          }),
        ),
      ).toBe(2);
      expect(called).toBe(false);
    }
  });
});
