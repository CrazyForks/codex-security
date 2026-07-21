# `@openai/codex-security`

TypeScript SDK and CLI for running Codex Security scans. The package is
ESM-only, includes TypeScript declarations, and installs the `codex-security`
executable. On macOS and Linux, standard repository/path scans use OpenAI
Agents SDK with an API key and the aligned `@openai/codex` runtime with a
stored sign-in. Codex also handles diff, working-tree, deep, `--codex`, and
native Windows scans.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Install

```bash
npm install @openai/codex-security@beta
npx codex-security --version
```

Node.js 22 or later is required. Standard Agents scans require a running Docker
daemon and a host Python 3 interpreter for the SDK PTY bridge; the default
sandbox image includes Python for the bundled scan helpers.
`--python` and `pythonPath` select an in-container interpreter for Agents
scans or a host interpreter for Codex scans.

## Authentication

For local use, sign in with ChatGPT:

```bash
npx codex-security login
npx codex-security scan .
```

On a remote or headless machine, use device authentication:

```bash
npx codex-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To store an API key or
enterprise access token instead, pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx codex-security login --with-api-key
printenv CODEX_ACCESS_TOKEN | npx codex-security login --with-access-token
```

Check or remove the stored sign-in with `npx codex-security login status` and
`npx codex-security logout`. Codex Security reuses an existing file-based Codex
sign-in. If Codex stores credentials in the system keyring, run
`npx codex-security login` once before scanning.

An environment API key takes precedence over a stored sign-in. On macOS and
Linux, standard repository/path scans use Agents with an API key and Codex with
a stored sign-in. Unset both `OPENAI_API_KEY` and `CODEX_API_KEY` to use your
ChatGPT sign-in.

## CLI

```bash
npx codex-security scan /path/to/repository
npx codex-security scan /path/to/repository --path src --path tests
# With OPENAI_API_KEY or CODEX_API_KEY set (Agents):
npx codex-security scan /path/to/repository --path src --model gpt-5.6 --reasoning-effort high
npx codex-security scan /path/to/repository --diff origin/main --json
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx codex-security scan /path/to/repository --engine codex
```

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets. The output directory must be outside the scanned
repository. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`.

The Agents engine stages tracked, regular files and bundled scan helpers, then
mounts them read-only in a network-disabled Docker workspace. Local edits to
tracked files are included; untracked or ignored files, submodules, symlinks,
Git history, and common credential stores are excluded. Path scans include
applicable ancestor `SECURITY.md` files. Unsafe or ambiguous targets fail
before a scan starts, and repository instructions such as `AGENTS.md` remain
untrusted input.

The scan shell does not receive ambient API keys or Docker proxy credentials.
Host Git, staging, and Docker subprocesses use a minimal credential-free
environment. Git-backed targets are directory snapshots, so history and
advisory lookup are unavailable; staged content remains trusted local input.
Use `--engine codex` when a path contains only untracked or ignored files, or
when Docker is unavailable. `--model`,
`--reasoning-effort`, `--max-turns`, and `--worker-max-turns` control the
Agents workflow.

The sandbox uses a writable temporary home/cache without exposing host home
directories. Docker workspaces default to `~/.cache/codex-security/sandboxes`, which works with
Docker Desktop and Colima's default shared-user-directory mount. Set
`CODEX_SECURITY_DOCKER_WORKSPACE_ROOT` to another Docker-shared directory when a
custom daemon or mount policy requires it.

Use `--engine codex` for an explicit Codex-backed standard scan. Diff,
working-tree, deep, `--codex`, and native Windows scans automatically retain
the Codex engine; the Agents migration intentionally does not change those
skills. Run from WSL to use the Agents engine on a Windows host.

Run `npx codex-security scan --help` for the complete CLI reference.

## SDK

```ts
import { AgentsSecurity } from "@openai/codex-security";

const security = new AgentsSecurity({
  model: "gpt-5.6",
  reasoningEffort: "high",
});
try {
  const result = await security.run("/path/to/repository");
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

`AgentsSecurity` supports standard repository/path targets, cancellation, and
typed scan results. `CodexSecurity` remains available for the Codex-backed
standard, diff, and deep workflows, streaming, and Codex sign-in flows. See the
[SDK and CLI reference](https://github.com/openai/codex-security/blob/main/sdk/typescript/compatibility/PARITY_MATRIX.md) for supported methods,
options, output, and exit behavior.

Product documentation is available in the
[Codex Security guide](https://developers.openai.com/codex/security). Please
report bugs using [GitHub issues](https://github.com/openai/codex-security/issues)
and vulnerabilities using the repository security policy.
