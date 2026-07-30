import { execFileSync } from "node:child_process";
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
import { dirname, join } from "node:path";
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
    "HEAD",
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
  execFileSync(interpreter, args, { stdio: "pipe" });

  const contents = (await readFile(output, "utf8")).trim();
  return contents
    ? contents.split("\n").map((line) => JSON.parse(line) as RankInputRow)
    : [];
}

describe("diff rank input", () => {
  test("inventories committed security-sensitive workflows, containers, and agent instructions", async () => {
    const fixture = await createRepository();
    const files: Record<string, string> = {
      ".dockerignore": "node_modules\nvendor\n",
      ".github/actions/build/action.yml": "runs:\n  using: composite\n",
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

      await expect(
        runDiffRankInput(fixture, "revisions", {
          path: "src/app.ts",
          replacement: externalFile,
        }),
      ).rejects.toThrow(/unsafe changed repository path/iu);
      expect(await readFile(externalFile, "utf8")).toContain(canary);
    },
  );

  test.skipIf(process.platform === "win32")(
    "inventories a changed FIFO without blocking or reading it",
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

      await expect(runDiffRankInput(fixture, "revisions")).rejects.toThrow(
        /unsafe changed repository path/iu,
      );
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
      { path: "src/remove.py", area: "diff", preview: "" },
      {
        path: "src/renamed.py",
        area: "diff",
        preview: "print('rename')",
      },
    ]);
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
