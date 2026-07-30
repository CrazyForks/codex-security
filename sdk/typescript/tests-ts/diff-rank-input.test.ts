import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type DiffMode = "revisions" | "local-patch";

type RankInputRow = {
  path: string;
  area: string;
  preview: string;
};

type TestRepository = {
  root: string;
  repository: string;
  base: string;
};

type PathSwap = {
  path: string;
  replacement: string;
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

async function writeRepositoryFile(
  repository: string,
  path: string,
  contents: string | Uint8Array,
): Promise<void> {
  const destination = join(repository, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, contents);
}

async function createRepository(): Promise<TestRepository> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-diff-rank-input-")),
  );
  temporaryDirectories.push(root);

  const repository = join(root, "repository");
  await mkdir(repository);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.name", "Codex Security Test");
  git(repository, "config", "user.email", "codex-security@example.invalid");
  git(repository, "config", "commit.gpgsign", "false");

  await Promise.all([
    writeRepositoryFile(repository, ".gitignore", "node_modules/\nvendor/\n"),
    writeRepositoryFile(
      repository,
      "AGENTS.md",
      "Follow the existing policy.\n",
    ),
    writeRepositoryFile(repository, "docker-compose.yml", "services: {}\n"),
    writeRepositoryFile(repository, "src/app.ts", "export const value = 1;\n"),
    writeRepositoryFile(repository, "src/remove.py", "print('remove')\n"),
    writeRepositoryFile(repository, "src/old.py", "print('rename')\n"),
  ]);
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "initial");

  return { root, repository, base: git(repository, "rev-parse", "HEAD") };
}

async function runDiffRankInput(
  fixture: TestRepository,
  mode: DiffMode,
  swap?: PathSwap,
  head = "HEAD",
): Promise<RankInputRow[]> {
  const interpreter =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (interpreter === null) {
    throw new Error(
      "A Python interpreter is required for diff rank input tests.",
    );
  }

  const output = join(
    fixture.root,
    `rank-input-${mode}${swap ? "-swapped" : ""}.jsonl`,
  );
  const command = [
    "make-diff-rank-input",
    "--repo",
    fixture.repository,
    "--base",
    fixture.base,
    "--mode",
    mode,
    "--head",
    head,
    "--out",
    output,
  ];
  const script = join(PLUGIN_ROOT, "scripts", "generate_rank_input.py");
  const swapHook = [
    "from pathlib import Path",
    "import sys",
    "scripts, candidate, replacement = sys.argv[1:4]",
    "sys.path.insert(0, scripts)",
    "import generate_rank_input",
    "original_resolve = Path.resolve",
    "def swap_after_resolve(path, *args, **kwargs):",
    "    resolved = original_resolve(path, *args, **kwargs)",
    "    if path == Path(candidate) and kwargs.get('strict', False):",
    "        path.unlink()",
    "        path.symlink_to(replacement)",
    "    return resolved",
    "Path.resolve = swap_after_resolve",
    "sys.argv = [generate_rank_input.__file__, *sys.argv[4:]]",
    "generate_rank_input.main()",
  ].join("\n");
  const args = swap
    ? [
        "-B",
        "-c",
        swapHook,
        dirname(script),
        join(fixture.repository, swap.path),
        swap.replacement,
        ...command,
      ]
    : ["-B", script, ...command];
  execFileSync(interpreter, args, {
    stdio: "pipe",
    env: { ...process.env, CODEX_SECURITY_GIT: Bun.which("git") ?? undefined },
  });

  const contents = (await readFile(output, "utf8")).trim();
  return contents
    ? contents.split("\n").map((line) => JSON.parse(line) as RankInputRow)
    : [];
}

describe("diff rank input", () => {
  test("previews immutable head blobs even when another revision is checked out", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "export const value = 'reviewed-head';\n",
    );
    git(fixture.repository, "add", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "selected review head");
    const selectedHead = git(fixture.repository, "rev-parse", "HEAD");
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "export const value = 'different-checkout';\n",
    );
    git(fixture.repository, "add", "src/app.ts");
    git(fixture.repository, "commit", "-qm", "different checked out head");

    const rows = await runDiffRankInput(
      fixture,
      "revisions",
      undefined,
      selectedHead,
    );

    expect(rows).toContainEqual({
      path: "src/app.ts",
      area: "diff",
      preview: "export const value = 'reviewed-head';",
    });
    expect(JSON.stringify(rows)).not.toContain("different-checkout");
  });

  test("resolves trusted system Git for direct plugin launches without an SDK override", async () => {
    const fixture = await createRepository();
    const trustedGit = Bun.which("git");
    expect(trustedGit).not.toBeNull();
    const shimDirectory = join(fixture.repository, "node_modules", ".bin");
    const marker = join(fixture.root, "repository-git-ran");
    await mkdir(shimDirectory, { recursive: true });
    await writeFile(
      join(shimDirectory, process.platform === "win32" ? "git.cmd" : "git"),
      process.platform === "win32"
        ? `@echo off\r\n> "${marker}" echo hijacked\r\nexit /b 1\r\n`
        : `#!/bin/sh\nprintf hijacked > '${marker}'\nexit 1\n`,
      { mode: 0o755 },
    );
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const environment = { ...process.env };
    delete environment["CODEX_SECURITY_GIT"];
    environment["PATH"] = [shimDirectory, dirname(trustedGit!)].join(delimiter);
    const result = spawnSync(
      python!,
      [
        "-I",
        "-B",
        "-c",
        [
          "from pathlib import Path",
          "import sys",
          "sys.path.insert(0, sys.argv[1])",
          "from workbench_constants import trusted_git_executable",
          "print(trusted_git_executable(Path(sys.argv[2])))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
      ],
      { encoding: "utf8", env: environment },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(await realpath(trustedGit!));
    await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });

    const nested = join(fixture.repository, "vendor", "nested");
    await mkdir(nested, { recursive: true });
    git(nested, "init", "-q");
    const nestedResult = spawnSync(
      python!,
      [
        "-I",
        "-B",
        "-c",
        [
          "from pathlib import Path",
          "import sys",
          "sys.path.insert(0, sys.argv[1])",
          "from workbench_constants import trusted_git_executable",
          "print(trusted_git_executable(Path(sys.argv[2])))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        nested,
      ],
      { encoding: "utf8", env: environment },
    );
    expect(nestedResult.status, nestedResult.stderr).toBe(0);
    expect(nestedResult.stdout.trim()).toBe(await realpath(trustedGit!));
    await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test.skipIf(process.platform === "win32")(
    "treats metacharacters in immutable Git paths as literal names",
    async () => {
      const fixture = await createRepository();
      const path = "src/[security]*.ts";
      await writeRepositoryFile(
        fixture.repository,
        path,
        "export const literal = 'immutable';\n",
      );
      git(fixture.repository, "add", path);
      git(fixture.repository, "commit", "-qm", "add literal Git path");

      expect(await runDiffRankInput(fixture, "revisions")).toContainEqual({
        path,
        area: "diff",
        preview: "export const literal = 'immutable';",
      });
    },
  );

  test("includes ignored Git submodule changes and their recorded commits", async () => {
    const fixture = await createRepository();
    const revision = fixture.base;
    await writeRepositoryFile(
      fixture.repository,
      ".gitmodules",
      '[submodule "security"]\n\tpath = dependencies/security\n\turl = https://example.invalid/security.git\n',
    );
    git(fixture.repository, "config", "diff.ignoreSubmodules", "all");
    git(fixture.repository, "add", ".gitmodules");
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${revision},dependencies/security`,
    );
    git(fixture.repository, "commit", "-qm", "add pinned security dependency");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows).toContainEqual({
      path: "dependencies/security",
      area: "diff",
      preview: `Git submodule pinned to commit ${revision}`,
    });
    expect(rows.map((row) => row.path)).toContain(".gitmodules");
  });

  test("includes ignored paths that change from regular files into Git submodules", async () => {
    const fixture = await createRepository();
    const path = "vendor/dep";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "previous dependency\n",
    );
    git(fixture.repository, "add", "--force", path);
    git(fixture.repository, "commit", "-qm", "track the previous dependency");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "rm", "--quiet", path);
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},${path}`,
    );
    git(fixture.repository, "commit", "-qm", "replace dependency with gitlink");

    expect(await runDiffRankInput(fixture, "revisions")).toContainEqual({
      path,
      area: "diff",
      preview: `Git submodule pinned to commit ${fixture.base}`,
    });
  });

  test("includes ignored Git submodules replaced by regular files", async () => {
    const fixture = await createRepository();
    const path = "vendor/dep";
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},${path}`,
    );
    git(fixture.repository, "commit", "-qm", "add gitlink dependency");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "rm", "--cached", "--quiet", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      "replacement dependency\n",
    );
    git(fixture.repository, "add", "--force", path);
    git(
      fixture.repository,
      "commit",
      "-qm",
      "replace gitlink with regular file",
    );

    expect(await runDiffRankInput(fixture, "revisions")).toContainEqual({
      path,
      area: "diff",
      preview: "replacement dependency",
    });
  });

  test("includes staged gitlinks before their working trees are checked out", async () => {
    const fixture = await createRepository();
    const path = "vendor/index-only-dependency";
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},${path}`,
    );

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview: `Git submodule pinned to commit ${fixture.base}`,
    });
  });

  test("includes staged deletions of ignored Git submodules", async () => {
    const fixture = await createRepository();
    const path = "vendor/dep";
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},${path}`,
    );
    git(fixture.repository, "commit", "-qm", "add gitlink dependency");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "rm", "--cached", "--quiet", path);

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview: "",
    });
  });

  test("includes ignored Git submodules staged as regular files", async () => {
    const fixture = await createRepository();
    const path = "vendor/dep";
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${fixture.base},${path}`,
    );
    git(fixture.repository, "commit", "-qm", "add gitlink dependency");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "rm", "--cached", "--quiet", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      "replacement dependency\n",
    );
    git(fixture.repository, "add", "--force", path);

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview: "replacement dependency",
    });
    await rm(join(fixture.repository, path));
    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview: "replacement dependency",
    });
  });

  test("previews local dirty Git submodules from their pinned index commit", async () => {
    const fixture = await createRepository();
    const submodule = join(fixture.repository, ".github", "actions", "sub");
    await mkdir(submodule, { recursive: true });
    git(submodule, "init", "-q", "-b", "main");
    git(submodule, "config", "user.name", "Codex Security Test");
    git(submodule, "config", "user.email", "codex-security@example.invalid");
    await writeRepositoryFile(submodule, "action.yml", "name: original\n");
    git(submodule, "add", ".");
    git(submodule, "commit", "-qm", "original action");
    const revision = git(submodule, "rev-parse", "HEAD");
    git(
      fixture.repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${revision},.github/actions/sub`,
    );
    git(fixture.repository, "commit", "-qm", "pin workflow action");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    git(fixture.repository, "config", "diff.ignoreSubmodules", "all");
    await writeRepositoryFile(submodule, "action.yml", "name: dirty\n");

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path: ".github/actions/sub",
      area: "diff",
      preview: `Git submodule pinned to commit ${revision}`,
    });
  });

  test("inventories committed security-sensitive workflows, containers, and agent instructions", async () => {
    const fixture = await createRepository();
    const files: Record<string, string> = {
      ".dockerignore": "node_modules\nvendor\n",
      ".github/actions/build/action.yml": "runs:\n  using: composite\n",
      ".github/actions/vendor/checkout/action.yml":
        "runs:\n  using: composite\n",
      ".github/actions/security/action.yml": "runs:\n  using: composite\n",
      ".github/actions/security/index.js": "export const secure = true;\n",
      ".github/actions/security/script.py": "print('review action')\n",
      ".github/actions/test/action.yml": "runs:\n  using: composite\n",
      ".github/CODEOWNERS": "* @security-reviewers\n",
      ".github/copilot-instructions.md":
        "Review changes before running code.\n",
      ".github/dependabot.yml": "version: 2\nupdates: []\n",
      ".github/instructions/security.instructions.md":
        "Review every authentication boundary.\n",
      ".github/ISSUE_TEMPLATE/bug.yml": "name: Bug report\n",
      ".github/scripts/ci/check.py": "print('review CI helper')\n",
      ".github/scripts/security.py": "print('review first-party changes')\n",
      ".github/workflows/security.yml": "name: Security\non: pull_request\n",
      ".github/workflows/scripts/check.py": "print('check workflow')\n",
      ".env.example": "AUTH_PROVIDER=example\n",
      "AGENTS.md": "Require authorization before exposing credentials.\n",
      "CLAUDE.md": "Keep repository credentials private.\n",
      CODEOWNERS: "* @repository-owners\n",
      Containerfile: "FROM scratch\n",
      Dockerfile: "FROM node:24-alpine\n",
      "build/Dockerfile": "FROM node:24-alpine\n",
      "compose.yaml": "services:\n  app:\n    image: app\n",
      "config/nginx.conf": "server { listen 443 ssl; }\n",
      "docker-compose.yml": "services:\n  app:\n    image: app\n",
      "docs/example.py": "print('documentation example')\n",
      "docs/AGENTS.md":
        "Example instructions, not executable repository scope.\n",
      "infra/main.tf": 'resource "example" "service" {}\n',
      "infra/variables.hcl": 'environment = "production"\n',
      "node_modules/AGENTS.md": "External dependency instructions.\n",
      "node_modules/dependency.py": "print('external dependency')\n",
      "policy/security.rego": "package security\ndefault allow = false\n",
      "services/api/AGENTS.md": "Do not read files outside this service.\n",
      "services/api/CLAUDE.md": "Review authentication changes.\n",
      "services/api/Dockerfile.production": "FROM node:24-alpine\n",
      "services/api/app.Dockerfile": "FROM node:24-alpine\n",
      "src/app.ts": "export const value = 2;\n",
      "src/auth.cjs": "module.exports = { authenticated: true };\n",
      "vendor/Dockerfile": "FROM external-vendor\n",
      "vendor/dependency.py": "print('vendored dependency')\n",
    };

    await Promise.all(
      Object.entries(files).map(([path, contents]) =>
        writeRepositoryFile(fixture.repository, path, contents),
      ),
    );
    git(fixture.repository, "add", "-A");
    git(
      fixture.repository,
      "add",
      "-f",
      ".github/actions/vendor/checkout/action.yml",
      "node_modules/AGENTS.md",
      "node_modules/dependency.py",
      "vendor/Dockerfile",
      "vendor/dependency.py",
    );
    git(fixture.repository, "commit", "-qm", "change security-sensitive files");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows.map((row) => row.path)).toEqual(
      [
        ".dockerignore",
        ".github/actions/build/action.yml",
        ".github/actions/security/action.yml",
        ".github/actions/security/index.js",
        ".github/actions/security/script.py",
        ".github/actions/test/action.yml",
        ".github/actions/vendor/checkout/action.yml",
        ".github/CODEOWNERS",
        ".github/copilot-instructions.md",
        ".github/dependabot.yml",
        ".github/instructions/security.instructions.md",
        ".github/scripts/ci/check.py",
        ".github/scripts/security.py",
        ".github/workflows/security.yml",
        ".github/workflows/scripts/check.py",
        ".env.example",
        "AGENTS.md",
        "CLAUDE.md",
        "CODEOWNERS",
        "Containerfile",
        "Dockerfile",
        "build/Dockerfile",
        "compose.yaml",
        "config/nginx.conf",
        "docker-compose.yml",
        "infra/main.tf",
        "infra/variables.hcl",
        "policy/security.rego",
        "services/api/AGENTS.md",
        "services/api/CLAUDE.md",
        "services/api/Dockerfile.production",
        "services/api/app.Dockerfile",
        "src/app.ts",
        "src/auth.cjs",
      ].sort(),
    );
    expect(rows.every((row) => row.area === "diff")).toBe(true);
    expect(rows.every((row) => row.preview.length > 0)).toBe(true);
  });

  test("inventories both staged and unstaged security-sensitive changes", async () => {
    const fixture = await createRepository();

    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        ".github/workflows/staged.yml",
        "name: Staged security workflow\n",
      ),
      writeRepositoryFile(fixture.repository, "Dockerfile", "FROM scratch\n"),
    ]);
    git(
      fixture.repository,
      "add",
      ".github/workflows/staged.yml",
      "Dockerfile",
    );

    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "AGENTS.md",
        "Review the staged changes.\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "docker-compose.yml",
        "services:\n  app:\n    image: changed\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      ),
    ]);

    const rows = await runDiffRankInput(fixture, "local-patch");

    expect(rows.map((row) => row.path)).toEqual(
      [
        ".github/workflows/staged.yml",
        "AGENTS.md",
        "Dockerfile",
        "docker-compose.yml",
        "src/app.ts",
      ].sort(),
    );
    expect(rows.every((row) => row.preview.length > 0)).toBe(true);
  });

  test("reads staged-only additions from their immutable Git index blobs", async () => {
    const fixture = await createRepository();
    const path = "src/staged-only.ts";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const staged = 'review this exact blob';\n",
    );
    git(fixture.repository, "add", path);
    await rm(join(fixture.repository, path));

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview: "export const staged = 'review this exact blob';",
    });
  });

  test("reviews both staged and restored working-tree versions of modified files", async () => {
    const fixture = await createRepository();
    const path = "src/app.ts";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const dangerous = 'staged vulnerable content';\n",
    );
    git(fixture.repository, "add", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const value = 1;\n",
    );

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview:
        "Staged Git index:\nexport const dangerous = 'staged vulnerable content';\nWorking tree:\nexport const value = 1;",
    });
  });

  test("distinguishes staged blobs even when both structural previews match", async () => {
    const fixture = await createRepository();
    const path = "src/handler.py";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "def handler(user):\n    return eval(user)\n",
    );
    git(fixture.repository, "add", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      "def handler(user):\n    return user\n",
    );

    const row = (await runDiffRankInput(fixture, "local-patch")).find(
      (candidate) => candidate.path === path,
    );

    expect(row?.preview).toContain("Staged Git index:");
    expect(row?.preview).toContain("Working tree:");
    expect(
      await readFile(
        join(PLUGIN_ROOT, "skills", "security-diff-scan", "SKILL.md"),
        "utf8",
      ),
    ).toContain("read every staged Git index blob in full");
  });

  test("reviews every available stage of an unresolved Git merge conflict", async () => {
    const fixture = await createRepository();
    const path = "src/app.ts";
    git(fixture.repository, "branch", "conflicting");
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const ours = 'review our side';\n",
    );
    git(fixture.repository, "add", path);
    git(fixture.repository, "commit", "-qm", "ours");
    git(fixture.repository, "checkout", "-q", "conflicting");
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const theirs = 'review their side';\n",
    );
    git(fixture.repository, "add", path);
    git(fixture.repository, "commit", "-qm", "theirs");
    git(fixture.repository, "checkout", "-q", "main");
    expect(
      spawnSync("git", ["merge", "--no-edit", "conflicting"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).status,
    ).toBe(1);

    const row = (await runDiffRankInput(fixture, "local-patch")).find(
      (candidate) => candidate.path === path,
    );

    expect(row?.preview).toContain("Merge base (stage 1):");
    expect(row?.preview).toContain("Ours (stage 2):");
    expect(row?.preview).toContain("Theirs (stage 3):");
    expect(row?.preview).toContain("Working tree:");
  });

  test("reviews immutable symlink targets across all unresolved merge stages", async () => {
    const fixture = await createRepository();
    const path = "src/app.ts";
    const hashes = ["base-target.ts", "ours-target.ts", "theirs-target.ts"].map(
      (target) => {
        const hashed = spawnSync("git", ["hash-object", "-w", "--stdin"], {
          cwd: fixture.repository,
          encoding: "utf8",
          input: target,
        });
        expect(hashed.status, hashed.stderr).toBe(0);
        return hashed.stdout.trim();
      },
    );
    const index = [
      `0 ${"0".repeat(40)}\t${path}`,
      ...hashes.map((hash, index) => `120000 ${hash} ${index + 1}\t${path}`),
    ].join("\n");
    const updated = spawnSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      encoding: "utf8",
      input: `${index}\n`,
    });
    expect(updated.status, updated.stderr).toBe(0);

    const row = (await runDiffRankInput(fixture, "local-patch")).find(
      (candidate) => candidate.path === path,
    );

    expect(row?.preview).toContain("Merge base (stage 1):");
    expect(row?.preview).toContain("Symlink target: base-target.ts");
    expect(row?.preview).toContain("Symlink target: ours-target.ts");
    expect(row?.preview).toContain("Symlink target: theirs-target.ts");
  });

  test("preserves pinned submodule revisions across unresolved merge stages", async () => {
    const fixture = await createRepository();
    const path = ".github/actions/security";
    const index = [
      `0 ${"0".repeat(40)}\t${path}`,
      ...[1, 2, 3].map((stage) => `160000 ${fixture.base} ${stage}\t${path}`),
    ].join("\n");
    const updated = spawnSync("git", ["update-index", "--index-info"], {
      cwd: fixture.repository,
      encoding: "utf8",
      input: `${index}\n`,
    });
    expect(updated.status, updated.stderr).toBe(0);

    const row = (await runDiffRankInput(fixture, "local-patch")).find(
      (candidate) => candidate.path === path,
    );

    expect(row?.preview).toContain("Merge base (stage 1):");
    expect(row?.preview).toContain("Ours (stage 2):");
    expect(row?.preview).toContain("Theirs (stage 3):");
    expect(row?.preview).toContain(
      `Git submodule pinned to commit ${fixture.base}`,
    );
  });

  test("retains reviewable staged text when the working-tree version is binary", async () => {
    const fixture = await createRepository();
    const path = "src/app.ts";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const staged = 'review the staged version';\n",
    );
    git(fixture.repository, "add", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      new Uint8Array([0, 255, 0, 255]),
    );

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview:
        "Staged Git index (working tree is binary):\nexport const staged = 'review the staged version';",
    });
  });

  test("retains reviewable working-tree text when the staged version is binary", async () => {
    const fixture = await createRepository();
    const path = "src/app.ts";
    await writeRepositoryFile(
      fixture.repository,
      path,
      new Uint8Array([0, 255, 0, 255]),
    );
    git(fixture.repository, "add", path);
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const working = 'review the working tree';\n",
    );

    expect(await runDiffRankInput(fixture, "local-patch")).toContainEqual({
      path,
      area: "diff",
      preview:
        "Working tree (staged Git index is binary):\nexport const working = 'review the working tree';",
    });
  });

  test.skipIf(process.platform === "win32")(
    "inventories Git paths containing non-UTF-8 filesystem bytes",
    async () => {
      const fixture = await createRepository();
      await writeRepositoryFile(
        fixture.repository,
        "src/normal.py",
        "print('ordinary path')\n",
      );
      const python =
        Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
      expect(python).not.toBeNull();
      const probe = [
        "from pathlib import Path",
        "from types import SimpleNamespace",
        "import json, sys",
        "sys.path.insert(0, sys.argv[1])",
        "import generate_rank_input",
        "generate_rank_input.subprocess.run = lambda *args, **kwargs: SimpleNamespace(stdout=b'src/\\xff.py\\x00src/normal.py\\x00')",
        "paths = generate_rank_input.git_untracked_paths(Path(sys.argv[2]))",
        "print(json.dumps([str(path.relative_to(sys.argv[2])) for path, _ in paths], ensure_ascii=True))",
      ].join("\n");
      const decoded = JSON.parse(
        execFileSync(
          python!,
          ["-B", "-c", probe, join(PLUGIN_ROOT, "scripts"), fixture.repository],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              CODEX_SECURITY_GIT: Bun.which("git") ?? undefined,
            },
          },
        ),
      ) as string[];

      const rows = await runDiffRankInput(fixture, "local-patch");

      expect(rows.some((row) => row.path === "src/normal.py")).toBe(true);
      expect(decoded).toEqual(["src/\udcff.py", "src/normal.py"]);
    },
  );

  test("inventories untracked security-sensitive files without including ignored files", async () => {
    const fixture = await createRepository();
    const workflow = ".github/workflows/deploy.yml";
    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        workflow,
        "name: Untracked deploy\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "node_modules/ignored.ts",
        "export const ignored = true;\n",
      ),
    ]);

    expect(await runDiffRankInput(fixture, "local-patch")).toEqual([
      {
        path: workflow,
        area: "diff",
        preview: "key name",
      },
    ]);
  });

  test.skipIf(process.platform === "win32")(
    "never previews committed symlinks or repository paths escaping through a symlinked parent",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_EXTERNAL_SECRET_7e98526d";
      const externalFile = join(fixture.root, "external-canary.py");
      const externalDirectory = join(fixture.root, "external-directory");
      await mkdir(externalDirectory);
      await Promise.all([
        writeFile(externalFile, `secret = '${canary}'\n`),
        writeFile(
          join(externalDirectory, "escaped.py"),
          `secret = '${canary}'\n`,
        ),
        writeRepositoryFile(
          fixture.repository,
          "src/parent/escaped.py",
          "print('safe committed source')\n",
        ),
        writeRepositoryFile(
          fixture.repository,
          "src/app.ts",
          "export const value = 2;\n",
        ),
        mkdir(join(fixture.repository, ".github", "workflows"), {
          recursive: true,
        }),
      ]);
      await Promise.all([
        symlink(externalFile, join(fixture.repository, "src", "linked.py")),
        symlink(
          externalFile,
          join(fixture.repository, ".github", "workflows", "linked.yml"),
        ),
      ]);
      git(fixture.repository, "add", "-A");
      git(fixture.repository, "commit", "-qm", "add changed symlinks");

      await rm(join(fixture.repository, "src", "parent"), {
        recursive: true,
        force: true,
      });
      await symlink(
        externalDirectory,
        join(fixture.repository, "src", "parent"),
        "dir",
      );

      await expect(runDiffRankInput(fixture, "revisions")).rejects.toThrow(
        /unsafe changed repository path/iu,
      );
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "never previews staged symlinks in a local patch",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_LOCAL_PATCH_SECRET_ef9b01d2";
      const externalFile = join(fixture.root, "external-canary.py");
      await writeFile(externalFile, `secret = '${canary}'\n`);
      await symlink(externalFile, join(fixture.repository, "src", "linked.py"));
      git(fixture.repository, "add", "src/linked.py");
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );

      await expect(runDiffRankInput(fixture, "local-patch")).rejects.toThrow(
        /unsafe changed repository path/iu,
      );
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "inventories tracked files replaced with symlinks in committed and local diffs",
    async () => {
      for (const mode of ["revisions", "local-patch"] as const) {
        const fixture = await createRepository();
        const canary = `CODEX_SECURITY_SYNTHETIC_TYPE_CHANGE_${mode}`;
        const externalFile = join(fixture.root, "external-canary.py");
        await writeFile(externalFile, `secret = '${canary}'\n`);

        const trackedFile = join(fixture.repository, "src", "app.ts");
        await rm(trackedFile);
        await symlink(externalFile, trackedFile);
        git(fixture.repository, "add", "src/app.ts");
        if (mode === "revisions") {
          git(
            fixture.repository,
            "commit",
            "-qm",
            "replace source with symlink",
          );
        }

        await expect(runDiffRankInput(fixture, mode)).rejects.toThrow(
          /unsafe changed repository path/iu,
        );
        expect(await readFile(externalFile, "utf8")).toContain(canary);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a deterministic symlink swap after canonical containment is checked",
    async () => {
      const fixture = await createRepository();
      const canary = "CODEX_SECURITY_SYNTHETIC_POST_CHECK_SECRET_c326a1f4";
      const externalFile = join(fixture.root, "external-canary.py");
      await writeFile(externalFile, `secret = '${canary}'\n`);
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      git(fixture.repository, "add", "src/app.ts");
      git(fixture.repository, "commit", "-qm", "update reviewed source");
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 3;\n",
      );

      await expect(
        runDiffRankInput(fixture, "local-patch", {
          path: "src/app.ts",
          replacement: externalFile,
        }),
      ).rejects.toThrow(/unsafe changed repository path/iu);
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "reviews immutable Git blobs without opening a replacement FIFO",
    async () => {
      const fixture = await createRepository();
      await writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      );
      git(fixture.repository, "add", "src/app.ts");
      git(fixture.repository, "commit", "-qm", "update reviewed source");

      const trackedFile = join(fixture.repository, "src", "app.ts");
      await rm(trackedFile);
      execFileSync("mkfifo", [trackedFile], { stdio: "pipe" });

      expect(await runDiffRankInput(fixture, "revisions")).toContainEqual({
        path: "src/app.ts",
        area: "diff",
        preview: "export const value = 2;",
      });
    },
  );

  test("preserves deleted and renamed source files without following deleted paths", async () => {
    const fixture = await createRepository();
    await rm(join(fixture.repository, "src", "remove.py"));
    await rename(
      join(fixture.repository, "src", "old.py"),
      join(fixture.repository, "src", "renamed.py"),
    );
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "delete and rename source");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows).toEqual([
      { path: "src/old.py", area: "diff", preview: "" },
      { path: "src/remove.py", area: "diff", preview: "" },
      {
        path: "src/renamed.py",
        area: "diff",
        preview: "print('rename')",
      },
    ]);
  });

  test("retains security-relevant rename sources when destinations are excluded", async () => {
    const fixture = await createRepository();
    const source = ".github/workflows/deploy.yml";
    await writeRepositoryFile(
      fixture.repository,
      source,
      "name: deploy\non: push\n",
    );
    git(fixture.repository, "add", source);
    git(fixture.repository, "commit", "-qm", "add deployment workflow");
    fixture.base = git(fixture.repository, "rev-parse", "HEAD");
    await mkdir(join(fixture.repository, "docs"), { recursive: true });
    await rename(
      join(fixture.repository, source),
      join(fixture.repository, "docs/deploy.yml"),
    );
    git(fixture.repository, "add", "-A");
    git(
      fixture.repository,
      "commit",
      "-qm",
      "move deployment workflow to docs",
    );

    expect(await runDiffRankInput(fixture, "revisions")).toEqual([
      { path: source, area: "diff", preview: "" },
    ]);
  });

  test("binds staged-only Git index blobs into local-patch snapshot digests", async () => {
    const fixture = await createRepository();
    const path = "src/staged-only.ts";
    await writeRepositoryFile(
      fixture.repository,
      path,
      "export const secret = 1;\n",
    );
    git(fixture.repository, "add", path);
    await rm(join(fixture.repository, path));
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const digest = (): string =>
      execFileSync(
        python!,
        [
          "-I",
          "-B",
          "-c",
          "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from workbench_target import worktree_content_digest; print(worktree_content_digest(Path(sys.argv[2])))",
          join(PLUGIN_ROOT, "scripts"),
          fixture.repository,
        ],
        { encoding: "utf8" },
      ).trim();
    const previous = digest();
    const replacement = execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: fixture.repository,
      input: "export const secret = 2;\n",
      encoding: "utf8",
    }).trim();
    git(
      fixture.repository,
      "update-index",
      "--cacheinfo",
      `100644,${replacement},${path}`,
    );

    expect(digest()).not.toBe(previous);
  });

  test("preserves legacy working-tree snapshots while binding new index digests", async () => {
    const fixture = await createRepository();
    await writeRepositoryFile(
      fixture.repository,
      "src/app.ts",
      "export const value = 2;\n",
    );
    git(fixture.repository, "add", "src/app.ts");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const result = execFileSync(
      python!,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sqlite3, sys",
          "from pathlib import Path",
          "sys.path.insert(0, sys.argv[1])",
          "from filesystem_identity import serialize_filesystem_identity",
          "from workbench_db import require_diff_target",
          "from workbench_target import scan_target_warning, worktree_content_digest",
          "target = Path(sys.argv[2])",
          "revision = sys.argv[3]",
          "modern = worktree_content_digest(target)",
          "legacy = worktree_content_digest(target, legacy=True)",
          "selected = require_diff_target(target, 'working_tree', revision, revision, legacy)",
          "connection = sqlite3.connect(':memory:')",
          "connection.row_factory = sqlite3.Row",
          "metadata = target.stat()",
          "scan = connection.execute('SELECT ? AS diff_target_kind, ? AS target_snapshot_digest, ? AS target_path, ? AS target_device, ? AS target_inode, ? AS target_revision, ? AS diff_head_revision, ? AS diff_content_digest, ? AS scan_dir', ('working_tree', legacy, str(target), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), revision, revision, legacy, str(target.parent / 'scan'))).fetchone()",
          "print(json.dumps({'modern': modern, 'legacy': legacy, 'selected': selected['contentDigest'], 'warning': scan_target_warning(scan)}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        fixture.base,
      ],
      { encoding: "utf8" },
    );
    const snapshot = JSON.parse(result) as {
      modern: string;
      legacy: string;
      selected: string;
      warning: string | null;
    };

    expect(snapshot.modern).not.toBe(snapshot.legacy);
    expect(snapshot.selected).toBe(snapshot.modern);
    expect(snapshot.warning).toBeNull();
  });

  test("continues to exclude binary files and ignored dependency directories", async () => {
    const fixture = await createRepository();
    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "src/binary.py",
        Buffer.from([0x00, 0x01, 0x02, 0x03]),
      ),
      writeRepositoryFile(
        fixture.repository,
        "node_modules/dependency.py",
        "print('external dependency')\n",
      ),
      writeRepositoryFile(
        fixture.repository,
        "vendor/dependency.py",
        "print('vendored dependency')\n",
      ),
    ]);
    git(fixture.repository, "add", "-A");
    git(
      fixture.repository,
      "add",
      "-f",
      "node_modules/dependency.py",
      "vendor/dependency.py",
    );
    git(fixture.repository, "commit", "-qm", "change source and dependencies");

    const rows = await runDiffRankInput(fixture, "revisions");

    expect(rows.map((row) => row.path)).toEqual(["src/app.ts"]);
    expect(rows[0]?.preview).toContain("value = 2");
  });

  test("excludes changed and deleted non-source binary assets", async () => {
    const fixture = await createRepository();
    await Promise.all([
      writeRepositoryFile(
        fixture.repository,
        "assets/deleted.png",
        Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      ),
      writeRepositoryFile(
        fixture.repository,
        "assets/changed.png",
        Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      ),
    ]);
    git(fixture.repository, "add", "assets");
    git(fixture.repository, "commit", "-qm", "add image assets");
    const base = git(fixture.repository, "rev-parse", "HEAD");
    await Promise.all([
      rm(join(fixture.repository, "assets", "deleted.png")),
      writeRepositoryFile(
        fixture.repository,
        "assets/changed.png",
        Buffer.from([0x89, 0x50, 0x4e, 0x48]),
      ),
      writeRepositoryFile(
        fixture.repository,
        "src/app.ts",
        "export const value = 2;\n",
      ),
    ]);
    git(fixture.repository, "add", "-A");
    git(fixture.repository, "commit", "-qm", "change source and image assets");

    const rows = await runDiffRankInput({ ...fixture, base }, "revisions");

    expect(rows.map((row) => row.path)).toEqual(["src/app.ts"]);
  });
});
