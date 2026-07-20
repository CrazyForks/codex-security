# Codex Security

Run Codex Security scans from the command line or a TypeScript application.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Requirements

The SDK and CLI require Node.js 22 or later. Standard Agents scans require a
running Docker daemon; the default sandbox image includes Python for the
bundled scan helpers. Codex scans require a host Python interpreter. Docker and
Python are not needed to install the package or run
`--help` and `--version`.

Standard repository and path scans run through the OpenAI Agents SDK by
default. Set `OPENAI_API_KEY` or `CODEX_API_KEY` before scanning. Diff and deep
scans continue to use Codex and can also reuse an existing file-backed Codex
sign-in.

## Install and scan

```bash
npm install @openai/codex-security@beta
npx codex-security scan /path/to/repo
```

Scan a subset of a repository or write machine-readable results:

```bash
npx codex-security scan /path/to/repo --path src --path tests
npx codex-security scan /path/to/repo --path src --model gpt-5.6 --reasoning-effort high
npx codex-security scan /path/to/repo --diff origin/main --json
npx codex-security scan /path/to/repo --output-dir /path/outside/repo/results
npx codex-security scan /path/to/repo --engine codex
```

The output directory must be outside the scanned repository. When SARIF is produced, it is written to
`<scan-dir>/exports/results.sarif`. Use `npx codex-security scan --help` for all
target, output, and runtime options.

The Agents engine stages the requested tracked, regular-file scope and the
bundled scan skills/helpers into a network-disabled `node:22-bookworm` Docker
workspace, mounts them read-only, and delegates bounded scan workers through
Agents SDK. Path scans include applicable ancestor `SECURITY.md` files while
excluding unrelated source files. Local edits to tracked files are included; untracked/ignored files,
submodule contents, symlinks, unstaged deletions, sparse-checkout paths absent
from the worktree, and Git credentials/history are excluded. Empty and
Git-shaped unversioned targets fail closed; use the Codex engine when a path
contains only untracked or ignored files. Ambient OpenAI/Codex API keys are
not forwarded to Docker subprocesses. A sanitized,
one-way-hashed remote and relative-scope identity keeps finding fingerprints
stable across checkouts without colliding across monorepo services; bounded
results are copied to the requested output directory. SDK tracing and sensitive
debug logging are suppressed, and repository instruction files such as
`AGENTS.md` are treated as untrusted scan input.
Docker must be running for the default Agents engine. Use
`--engine codex` to run the existing Codex-backed standard scan when needed;
diff, working-tree, deep, `--codex`, and native Windows scans select it
automatically.

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
