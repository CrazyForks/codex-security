"""Shared scan-start helpers for the Codex Security workbench."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import serialize_filesystem_identity
from finalize_scan_contract import write_scan_local_bytes
from workbench_feedback import get_scan_feedback
from workbench_target import (
    clean_worktree_content_digest,
    directory_content_digest,
    directory_snapshot_digest_and_reviewable_count,
    git_bytes,
    git_revision,
    git_submodule_entries,
    worktree_content_digest,
)


def safe_segment(value: str) -> str:
    segment = "".join(
        character if character.isalnum() or character in "._-" else "-" for character in value
    )
    return segment.strip("-") or "scan"


def compact_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def scan_target_identity(
    target: Path,
    diff_target: dict[str, str] | None,
    *,
    metadata: os.stat_result | None = None,
) -> tuple[str, str | None, int | str, int | str]:
    if metadata is None:
        metadata = target.stat()
    revision = diff_target["headRevision"] if diff_target else git_revision(target)
    snapshot_digest = None
    if diff_target is None:
        snapshot_digest = (
            directory_content_digest(target)
            if revision == "unversioned"
            else worktree_content_digest(target)
        )
    return (
        revision,
        snapshot_digest,
        serialize_filesystem_identity(metadata.st_dev),
        serialize_filesystem_identity(metadata.st_ino),
    )


def verify_empty_scope_identity(
    target: Path,
    diff_target: dict[str, str] | None,
    scope_file_count: int,
    target_identity: tuple[str, str | None, int | str, int | str],
    *,
    scope: str = ".",
    scopes: tuple[str, ...] | None = None,
) -> None:
    if scope_file_count != 0:
        return
    changed_message = (
        "The selected scan target changed while its empty scope was being verified."
    )
    if scan_target_identity(target, diff_target) != target_identity:
        raise SystemExit(changed_message)
    if diff_target is not None:
        if diff_target["kind"] == "working_tree" and (
            diff_target.get("contentDigest") != clean_worktree_content_digest()
            or worktree_content_digest(target) != diff_target.get("contentDigest")
        ):
            raise SystemExit(changed_message)
        return

    snapshot_digest, captured_count = directory_snapshot_digest_and_reviewable_count(
        target,
        count_scopes=tuple(target / path for path in scopes)
        if scopes
        else (target if scope == "." else target / scope,),
    )
    if captured_count != 0:
        raise SystemExit(changed_message)
    revision, recorded_digest, _, _ = target_identity
    if revision == "unversioned":
        if snapshot_digest != recorded_digest:
            raise SystemExit(changed_message)
        return
    tracked_scope = git_bytes(
        target,
        "ls-files",
        "--cached",
        "-z",
        "--",
        *(scopes if scopes else (scope,)),
    )
    if tracked_scope is None or tracked_scope:
        raise SystemExit(changed_message)
    requested = scopes if scopes else (scope,)
    verify_nested_empty_scopes(target, requested, changed_message)


def verify_nested_empty_scopes(
    repository: Path, scopes: tuple[str, ...], changed_message: str
) -> None:
    for submodule, _revision in git_submodule_entries(repository):
        nested_scopes = []
        for scope in scopes:
            try:
                nested_scope = (repository / scope).relative_to(submodule)
            except ValueError:
                continue
            nested_scopes.append(nested_scope.as_posix())
        if not nested_scopes:
            continue
        if not submodule.exists() or not (submodule / ".git").exists():
            raise SystemExit(changed_message)
        tracked = git_bytes(
            submodule,
            "ls-files",
            "--cached",
            "-z",
            "--",
            *nested_scopes,
        )
        if tracked is None or tracked:
            raise SystemExit(changed_message)
        verify_nested_empty_scopes(submodule, tuple(nested_scopes), changed_message)


def scan_diff_identity(
    diff_target: dict[str, str] | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    if diff_target is None:
        return (None, None, None, None)
    return (
        diff_target["kind"],
        diff_target["baseRevision"],
        diff_target["headRevision"],
        diff_target.get("contentDigest"),
    )


def stored_diff_target(row: sqlite3.Row) -> dict[str, str] | None:
    if not row["diff_target_kind"]:
        return None
    target = {
        "baseRevision": row["diff_base_revision"],
        "headRevision": row["diff_head_revision"],
        "kind": row["diff_target_kind"],
    }
    if row["diff_content_digest"]:
        target["contentDigest"] = row["diff_content_digest"]
    return target


def archive_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    scan_dir: Path,
    timestamp: str,
    canonical_directory: Callable[[Path], Path],
) -> None:
    archived_scan_dir = (
        canonical_directory(Path(args.archived_scan_dir).expanduser())
        if args.archived_scan_dir is not None
        else None
    )
    if archived_scan_dir is not None and (
        not args.archive_existing
        or archived_scan_dir.parent != scan_dir.parent
        or not archived_scan_dir.name.startswith(f"{scan_dir.name}.previous-")
    ):
        raise SystemExit("The archived scan must be a previous sibling of the scan directory.")

    previous_scan = connection.execute(
        "SELECT id, status FROM scans WHERE scan_dir = ?", (str(scan_dir),)
    ).fetchone()
    if previous_scan is None:
        return
    if not args.archive_existing:
        raise SystemExit(
            "The scan artifact directory belongs to an existing scan. "
            "Use --archive-existing to preserve that scan and start a new one."
        )
    if previous_scan["status"] == "running":
        raise SystemExit("Cannot archive the output of a running scan.")
    artifacts = connection.execute(
        "SELECT kind, path FROM scan_artifacts WHERE scan_id = ?",
        (previous_scan["id"],),
    ).fetchall()
    if archived_scan_dir is None:
        if artifacts:
            raise SystemExit(
                "The archived scan directory is required to preserve existing scan artifacts."
            )
        archived_scan_dir = Path(
            tempfile.mkdtemp(prefix=f"{scan_dir.name}.previous-", dir=scan_dir.parent)
        ).resolve()
    connection.execute(
        "UPDATE scans SET scan_dir = ?, updated_at = ? WHERE id = ?",
        (str(archived_scan_dir), timestamp, previous_scan["id"]),
    )
    for artifact in artifacts:
        try:
            relative_path = Path(artifact["path"]).relative_to(scan_dir)
        except ValueError:
            continue
        connection.execute(
            "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
            (
                str(archived_scan_dir / relative_path),
                previous_scan["id"],
                artifact["kind"],
            ),
        )


def insert_running_scan(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    workspace: sqlite3.Row,
    target: Path,
    scope: str,
    diff_target: dict[str, str] | None,
    target_identity: tuple[str, str | None, int | str, int | str],
    target_root: Path,
    target_summary: str | None,
    scope_file_count: int,
    timestamp: str,
    handoff_status: str = "pending",
    scan_dir: Path | None = None,
    standard_review_scopes: tuple[str, ...] | None = None,
) -> str:
    revision = target_identity[0]
    standard_review_inventory = None
    if workspace["default_mode"] == "standard":
        standard_review_inventory = registered_standard_review_inventory(
            target, standard_review_scopes or (scope,)
        )
        if scan_target_identity(target, diff_target) != target_identity:
            raise SystemExit("The selected scan target changed while its scope inventory was captured.")
    native_scan = scan_dir is None
    if scan_dir is None:
        scan_dir = Path(
            tempfile.mkdtemp(
                prefix=f"{safe_segment(revision)}_{compact_timestamp()}_",
                dir=target_root,
            )
        ).resolve()
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
            target_device, target_inode, scope, mode, user_context,
            deep_scan_owner_thread_id, diff_target_kind, diff_base_revision,
            diff_head_revision, diff_content_digest, target_summary, scan_dir, status, phase,
            handoff_status, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 'preflight',
            ?, ?, ?, ?)
        """,
        (
            scan_id,
            workspace["id"],
            workspace["target_id"],
            str(target),
            *target_identity,
            scope,
            workspace["default_mode"],
            workspace["user_context"],
            workspace["thread_id"] if workspace["default_mode"] == "deep" else None,
            diff_target["kind"] if diff_target else None,
            diff_target["baseRevision"] if diff_target else None,
            diff_target["headRevision"] if diff_target else None,
            diff_target.get("contentDigest") if diff_target else None,
            target_summary,
            str(scan_dir),
            handoff_status,
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO scan_progress (
            scan_id, scope_file_count, review_items_total, review_items_completed,
            reportable_findings_count, updated_at, standard_review_inventory_json
        ) VALUES (?, ?, 0, 0, 0, ?, ?)
        """,
        (
            scan_id,
            scope_file_count,
            timestamp,
            json.dumps(standard_review_inventory, ensure_ascii=True, separators=(",", ":"))
            if standard_review_inventory is not None
            else None,
        ),
    )
    connection.execute(
        "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
        (scan_id, timestamp, workspace["id"]),
    )
    if native_scan:
        scan = next(connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)))
        false_positives = get_scan_feedback(connection, scan)["falsePositives"]
        if false_positives:
            write_scan_local_bytes(
                scan_dir,
                "artifacts/01_context/false_positive_feedback.json",
                (json.dumps(false_positives, allow_nan=False) + "\n").encode(),
            )
    return scan_id


def registered_standard_review_inventory(target: Path, scopes: tuple[str, ...]) -> tuple[str, ...]:
    executable = shutil.which("rg")
    if executable is None:
        raise SystemExit("Standard scans require ripgrep to capture their registered file inventory.")
    resolved_executable = Path(executable).resolve()
    if target == resolved_executable or target in resolved_executable.parents:
        raise SystemExit("Standard scan inventory cannot use a repository-controlled executable.")
    try:
        listed = subprocess.run(
            [
                str(resolved_executable),
                "--files",
                "--hidden",
                "--null",
                "--glob",
                "!.git/**",
                "--",
                *scopes,
            ],
            cwd=target,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise SystemExit("Could not capture the registered standard scan inventory.") from error
    if listed.returncode not in {0, 1}:
        raise SystemExit("Could not capture the registered standard scan inventory.")
    paths: set[str] = set()
    for raw in (path for path in listed.stdout.split(b"\0") if path):
        try:
            decoded = raw.decode("utf-8")
            relative = PurePosixPath(decoded)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe repository-relative path")
            path = target / relative.as_posix()
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            path.resolve(strict=True).relative_to(target)
        except (OSError, UnicodeError, ValueError) as error:
            raise SystemExit("Could not capture the registered standard scan inventory.") from error
        paths.add(relative.as_posix())
    return tuple(sorted(paths))


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
