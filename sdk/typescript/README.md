# `@openai/codex-security`

TypeScript SDK and CLI for running Codex Security scans. The package is
ESM-only, includes TypeScript declarations, and installs the `codex-security`
executable. Standard repository/path scans use OpenAI Agents SDK by default;
the aligned `@openai/codex` runtime remains available for diff, deep, and
explicit Codex-backed scans.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Install

```bash
npm install @openai/codex-security@beta
npx codex-security --version
```

Node.js 22 or later is required. Running a scan also requires Python for the
bundled scan helpers; configure its interpreter with `--python`, `pythonPath`,
or `PYTHON` when automatic discovery is not appropriate.

Before a standard repository/path scan, set `OPENAI_API_KEY` or
`CODEX_API_KEY`. File-backed Codex sign-in remains available for
`--engine codex`, diff, and deep scans.

## CLI

```bash
npx codex-security scan /path/to/repository
npx codex-security scan /path/to/repository --path src --path tests
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

The default Agents engine stages a copy of the repository plus the scan
skills/helpers in a local sandbox, runs the standard `security-scan` workflow
with bounded delegated workers, and transfers generated scan artifacts back to
the output directory. The shell environment does not receive model API keys,
and source/tool traces are disabled. `--model`, `--reasoning-effort`,
`--max-turns`, and `--worker-max-turns` control the Agents workflow.

Use `--engine codex` for an explicit Codex-backed standard scan. Diff,
working-tree, deep, and `--codex` scans automatically retain the Codex engine;
the Agents migration intentionally does not change those skills.

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
