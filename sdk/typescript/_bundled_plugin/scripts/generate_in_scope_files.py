#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


def resolve_repository(value: str) -> Path:
    """Resolve the repository once so every scope is bound to its real root."""
    try:
        repository = Path(value).expanduser().resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--repo: cannot resolve repository: {value}") from error
    if not repository.is_dir():
        raise InventoryError(f"--repo: expected a directory: {repository}")
    return repository


def resolve_scope(repository: Path, value: str) -> str:
    """Preserve ripgrep's relative path spelling while rejecting escaped scopes."""
    if not value or "\0" in value:
        raise InventoryError("--scope: expected a non-empty file or directory")

    requested = Path(value).expanduser()
    scope = requested if requested.is_absolute() else repository / requested
    try:
        resolved = scope.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--scope: path does not exist: {value}") from error

    try:
        relative = resolved.relative_to(repository)
    except ValueError as error:
        raise InventoryError(f"--scope: path must remain inside --repo: {value}") from error

    if not resolved.is_dir() and not resolved.is_file():
        raise InventoryError(f"--scope: expected a file or directory: {value}")

    if requested.is_absolute():
        return relative.as_posix() if relative.parts else "."
    return value


def resolve_output(value: str) -> Path:
    """Reject direct symlink outputs without constraining the artifact root."""
    if not value or "\0" in value:
        raise InventoryError("--out: expected an inventory file path")
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise InventoryError("--out: refusing to replace a symbolic link")
    try:
        output = requested.resolve(strict=False)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--out: cannot resolve inventory path: {value}") from error
    if output.exists() and not output.is_file():
        raise InventoryError(f"--out: expected a regular file path: {output}")
    return output


def generate_in_scope_files(repository: Path, scope: str, output: Path) -> int:
    """Atomically write the exact ripgrep inventory sorted as ``LC_ALL=C``."""
    scopes = [scope]
    if scopes_file := os.environ.get("CODEX_SECURITY_TARGET_PATHS_FILE"):
        try:
            requested_scopes = json.loads(Path(scopes_file).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise InventoryError(f"cannot read target paths file: {scopes_file}") from error
        if (
            not isinstance(requested_scopes, list)
            or not requested_scopes
            or any(not isinstance(path, str) or not path for path in requested_scopes)
        ):
            raise InventoryError("target paths file must contain a non-empty JSON string array")
        scopes = [resolve_scope(repository, path) for path in requested_scopes]

    command = ["rg", "--files", "--hidden", "--glob", "!.git/**", "--", *scopes]
    with tempfile.TemporaryFile(mode="w+b") as inventory:
        try:
            result = subprocess.run(
                command,
                cwd=repository,
                stdout=inventory,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as error:
            raise InventoryError(f"could not run ripgrep: {error}") from error

        if result.returncode not in (0, 1):
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            message = f"ripgrep exited with status {result.returncode}"
            if detail:
                message = f"{message}: {detail}"
            raise InventoryError(message)

        inventory.seek(0)
        rows = sorted(set(inventory))

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.writelines(rows)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--scope", required=True, help="File or directory within the repository.")
    parser.add_argument("--out", required=True, help="Destination for the file inventory.")
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        count = generate_in_scope_files(repository, scope, output)
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()
