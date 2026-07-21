# Codex Security

Run Codex Security scans from the command line or a TypeScript application.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Requirements

The SDK and CLI require Node.js 22 or later. Standard Agents scans require a
running Docker daemon and a host Python 3 interpreter for the SDK PTY bridge;
the default sandbox image includes Python for the bundled scan helpers. Codex
scans also require a host Python interpreter. Docker and Python are not needed
to install the package or run `--help` and `--version`.

On macOS and Linux, standard repository and path scans use OpenAI Agents SDK
with an API key and Codex with a stored sign-in. Diff, working-tree, deep,
`--codex`, and native Windows scans use Codex.

## Install and scan

```bash
npm install @openai/codex-security@beta
npx codex-security login
npx codex-security scan /path/to/repo
```

On a remote or headless machine, use `npx codex-security login --device-auth`.
For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. See the
[authentication guide](sdk/typescript/README.md#authentication) for stored API
keys, enterprise access tokens, and login status.

Scan a subset of a repository or write machine-readable results:

```bash
npx codex-security scan /path/to/repo --path src --path tests
# With OPENAI_API_KEY or CODEX_API_KEY set (Agents):
npx codex-security scan /path/to/repo --path src --model gpt-5.6 --reasoning-effort high
npx codex-security scan /path/to/repo --diff origin/main --json
npx codex-security scan /path/to/repo --output-dir /path/outside/repo/results
npx codex-security scan /path/to/repo --engine codex
```

The output directory must be outside the scanned repository. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`. Use `npx codex-security scan --help` for all
target, output, and runtime options.

The Agents engine stages tracked, regular files and bundled scan helpers, then
mounts them read-only in a network-disabled Docker workspace. Local edits to
tracked files are included; untracked or ignored files, submodules, symlinks,
Git history, and common credential stores are excluded. Path scans include
applicable ancestor `SECURITY.md` files. Unsafe or ambiguous targets fail
before a scan starts, and repository instructions such as `AGENTS.md` remain
untrusted input.

The scan shell does not receive ambient API keys or Docker proxy credentials.
Host Git, staging, and Docker subprocesses use a minimal credential-free
environment. Staged content remains trusted local input. Use `--engine codex`
when a path contains only untracked or ignored files, or when Docker is
unavailable.

## TypeScript SDK

```ts
import { AgentsSecurity } from "@openai/codex-security";

const security = new AgentsSecurity({
  model: "gpt-5.6",
  reasoningEffort: "high",
});
try {
  const result = await security.run("/path/to/repo");
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

See the [TypeScript SDK and CLI reference](sdk/typescript/README.md) for
authentication, targets, output, and API details. `CodexSecurity` remains
available for the Codex-backed standard, diff, and deep workflows. Product documentation is
available in the [Codex Security guide](https://developers.openai.com/codex/security).

## Support and security

Please use [GitHub issues](https://github.com/openai/codex-security/issues) for
bugs and feature requests. Report vulnerabilities privately using the
[security policy](SECURITY.md).

This project is licensed under the [Apache-2.0 License](LICENSE).
