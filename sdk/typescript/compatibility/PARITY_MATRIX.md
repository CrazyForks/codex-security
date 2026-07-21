# TypeScript SDK and CLI reference

This reference describes the supported TypeScript SDK, CLI, and observable scan
contracts. The SDK is asynchronous and uses camelCase option and result names.

## Public SDK surface

| Historical surface                           | Supported behavior                                  | TypeScript contract                                                                               |
| -------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `CodexSecurity(config)`                      | Eager isolated-runtime preparation; context manager | `new CodexSecurity(config)` with lazy async preparation; `await close()` / async disposal         |
| `AgentsSecurity(config)`                     | n/a                                                 | Standard repository/path scans using OpenAI Agents SDK with Docker sandbox and delegated workers. |
| `AsyncCodexSecurity(config)`                 | Async mirror of the synchronous client              | Folded into the single async `CodexSecurity` class                                                |
| `.metadata`                                  | Codex SDK runtime metadata                          | Exact aligned npm SDK/executable package names and versions                                       |
| `.run(repository, target, mode, output_dir)` | Start, await, validate, and return a scan           | `await run(repository, options)`                                                                  |
| `.turn(...)`                                 | Return a controllable scan handle                   | `await turn(repository, options)`                                                                 |
| `.close()`                                   | Close Codex and remove isolated runtime             | `await close()`; idempotent cleanup                                                               |
| `.login_api_key(key)`                        | Materialize API-key authentication                  | `await loginApiKey(key)` without persisting the key in metadata                                   |
| `.login_chatgpt()`                           | Browser login handle                                | `await loginChatGPT()` child-process handle around the exact public Codex CLI                     |
| `.login_chatgpt_device_code()`               | Device-code login handle                            | `await loginChatGPTDeviceCode()` child-process handle around `--device-auth`                      |
| `.account(refresh_token=False)`              | Return Codex account state                          | `await account()` from `codex login status`; refresh-token metadata is explicitly unsupported     |
| `.logout()`                                  | Clear isolated authentication                       | `await logout()` through the exact public Codex CLI                                               |
| `ScanHandle.id`                              | Turn identifier                                     | Always `null`; the public JavaScript SDK event stream has no turn identifier                      |
| `ScanHandle.thread_id`                       | Thread identifier                                   | `threadId`, populated from `thread.started`                                                       |
| `ScanHandle.scan_dir`                        | Persistent partial/final output directory           | `scanDir`                                                                                         |
| `ScanHandle.stream()`                        | Stream Codex events                                 | Async iterable `stream()`                                                                         |
| `ScanHandle.run()`                           | Collect final result                                | `await run()`                                                                                     |
| `ScanHandle.interrupt()`                     | Interrupt running turn                              | `interrupt()` via the supported `AbortSignal` boundary                                            |
| `ScanHandle.steer(input)`                    | Send input to the active turn                       | Requires a reusable public JS SDK capability; `0.142.0` has no steering API                       |
| `DiffTarget.refs(base, head)`                | Committed ref diff                                  | `DiffTarget.refs({base, head})`                                                                   |
| `DiffTarget.working_tree(base)`              | Staged and unstaged diff                            | `DiffTarget.workingTree({base})`                                                                  |
| `CodexSecurityConfig.plugin_path`            | Directory/ZIP override                              | `pluginPath`                                                                                      |
| `CodexSecurityConfig.codex_overrides`        | Deep-merged isolated Codex config                   | `codexOverrides`                                                                                  |
| `AgentsSecurityConfig.model`                 | n/a                                                 | Agents model, default `gpt-5.6`                                                                   |
| `AgentsSecurityConfig.reasoningEffort`       | n/a                                                 | Agents reasoning effort, default `high`                                                           |
| `AgentsSecurityConfig.maxTurns`              | n/a                                                 | Coordinator turn limit, default `200`                                                             |
| `AgentsSecurityConfig.workerMaxTurns`        | n/a                                                 | Per-worker turn limit, default `100`                                                              |
| n/a                                          | Explicit plugin Python interpreter                  | `pythonPath` and CLI `--python`                                                                   |
| `ScanResult` paths/properties                | Canonical contract plus paths and turn result       | Readonly camelCase fields and path getters                                                        |
| Contract Pydantic models                     | Typed nested documents; unknown fields retained     | TypeScript interfaces plus Ajv 2020 validation; parsed JSON objects retain unknown fields         |
| Error hierarchy                              | Typed SDK failures                                  | Same class names in TypeScript, plus a plugin-Python diagnostic subtype if needed                 |

## CLI flags and arguments

| Surface                        | CLI behavior                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------- |
| no arguments                   | Print root help to stdout and exit 0                                          |
| `-h`, `--help`                 | Print root help and exit 0                                                    |
| `--version`                    | Print SDK version and bundled plugin version to stdout; exit 0 without Python |
| `login [OPTIONS]`              | Delegate ChatGPT, device, API-key, and access-token login to bundled Codex    |
| `login status`                 | Show the stored sign-in available to Codex Security                           |
| `logout`                       | Remove the stored sign-in available to Codex Security                         |
| `scan [repository]`            | Repository defaults to the current directory                                  |
| repeatable `--path PATH`       | Path-only scan; mutually exclusive with diff/working-tree                     |
| `--diff BASE`                  | Ref diff using `--head` or `HEAD`                                             |
| `--working-tree`               | Staged and unstaged changes using `--base` or `HEAD`                          |
| `--head REF`                   | Valid only with `--diff`                                                      |
| `--base REF`                   | Valid only with `--working-tree`                                              |
| `--mode standard\|deep`        | Deep rejects diff targets                                                     |
| `--engine agents\|codex`       | Repo/path: Agents with key; sign-in/diff/working-tree/deep/Windows: Codex     |
| `--model MODEL`                | Agents model, default `gpt-5.6`                                               |
| `--reasoning-effort EFFORT`    | Agents reasoning effort, default `high`                                       |
| `--max-turns N`                | Agents coordinator turn limit, default `200`                                  |
| `--worker-max-turns N`         | Agents per-worker turn limit, default `100`                                   |
| `--output-dir DIR`             | Must be absent or empty and outside the repository; preserved on interruption |
| `--plugin-path PATH`           | Plugin directory or safe ZIP override                                         |
| repeatable `--codex KEY=VALUE` | Parse TOML literals, reject duplicate/conflicting/owned keys                  |
| `--json`                       | Machine JSON only on stdout; progress/errors on stderr                        |
| `--python PATH`                | Intentional additive v0 option for the explicit plugin runtime boundary       |

## Output, exit, and signal contract

| Condition                      | stdout                                                     | stderr                                   | exit |
| ------------------------------ | ---------------------------------------------------------- | ---------------------------------------- | ---- |
| successful human scan          | Scan, report, plugin, finding-count lines                  | timed progress stages                    | 0    |
| successful JSON scan           | manifest/findings/coverage, scan/thread/path/turn metadata | timed progress stages                    | 0    |
| SDK/validation/bootstrap error | empty                                                      | `codex-security: <message>`              | 1    |
| parser/usage error             | empty                                                      | usage plus error                         | 2    |
| Ctrl-C                         | empty                                                      | cancellation and partial-output location | 130  |
| SIGTERM                        | empty                                                      | termination and partial-output location  | 143  |

Standard repository/path CLI scans use `@openai/agents@0.13.5`. The thin Agents
adapter stages the requested tracked regular-file scope and the plugin with a credential-free
subprocess into a network-disabled `node:22-bookworm` Docker sandbox, exposes the SDK shell tool with context
compaction, and delegates one bounded worker. Local edits to tracked files are included;
untracked/ignored files, submodule contents, symlinks, hard-linked source/custom-plugin files, intent-to-add files, unstaged deletions,
sparse-checkout paths absent from the worktree, common local credential stores/key material (including `.config`, shell profiles/histories/caches, alternate-VCS metadata, `.envrc`, Composer/Bundler/Gradle credentials, Terraform CLI/state, Databricks, dbt, Snowflake/SnowSQL, gsutil, common client RC files, and bounded credential-shaped and nested Docker/AWS/Azure/OAuth/service-account JSON, exported token/kubeconfig/CSV files, and extensionless SSH keys), and Git credentials/history (including incomplete/headless tracked nested repositories)
are excluded. Path scans include applicable ancestor `SECURITY.md` files and
exclude unrelated source files. Credential-directory roots/descendants, empty targets, Git-config includes, Git-shaped unversioned targets, and unversioned directories containing `.gitignore` files or nested Git worktrees fail
closed; bundled content-addressable installs are supported. Use Codex for paths containing only untracked or ignored files. Inputs
are mounted read-only, ambient API keys and Docker-configured proxy credentials
are not forwarded to the scan shell; host Git, staging, and Docker subprocesses receive a minimal credential-free environment, target-controlled Docker configuration, path-shaped Docker helper names, and Docker/PTY helpers resolving into the target are rejected, unsafe PTY loader overrides are suppressed, and the sandbox has a writable temporary home/cache. Bounded
output is copied to the requested directory. It runs the `security-scan` skill
with one delegated ranking worker and validates the canonical output contract
against a stable repository and relative-scope identity. SDK tracing and
sensitive debug logging are suppressed. Repository instruction files such as
`AGENTS.md` are treated as untrusted scan input. It requires an API key and
does not consume file-backed Codex authentication.

Git-backed targets are deliberately treated as directory snapshots, so history
and advisory lookup is unavailable; staged targets omit common local
credential files and directories but remain trusted-local input. Docker-host limits and the SDK's host Python 3 PTY-bridge requirement apply. Native
Windows paths route to Codex; WSL can be used for Agents execution. Docker
workspaces default to
`~/.cache/codex-security/sandboxes`; set
`CODEX_SECURITY_DOCKER_WORKSPACE_ROOT` when a custom Docker mount policy needs a
different shared directory.

`@openai/codex-sdk@0.142.0` provides run, streaming, and `AbortSignal`
cancellation. The aligned public Codex executable provides login, account-status, and
logout commands. Neither surface exposes steering, stable login/turn IDs, refresh-token
metadata, structured skill input, or turn duration. Those missing reusable capabilities
are the optional prerequisite boundary; the security package does not invent a private
transport.
