"""Unprivileged subprocess worker (``docs/tools.md`` §4, ADR-008).

Protocol: ``python -s -m artemis.tools.worker <worker-name>``, one JSON request
object on ``stdin``, exactly one JSON response object on ``stdout``.

The child receives **only** the validated canonical arguments plus the
authorization scope (allowed roots, caps).  It never receives the auth token,
the database path, config secrets or an :class:`Authorization` object: authority
was already decided in the parent, and the worker's job is to perform the I/O
and to re-verify the target by handle at the moment of use.

The worker is a leaf: it imports the path module and the filesystem primitives
and nothing else from ARTEMIS.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Callable

from ..policy.paths import CanonicalPath, PathPolicy, PathRejected
from . import fsops


def _policy(request: dict[str, Any]) -> PathPolicy:
    scope = request.get("scope") or {}
    roots = scope.get("allow_roots") or []
    return PathPolicy(roots, allow_unc=bool(scope.get("allow_unc", False)))


def _canonical(policy: PathPolicy, raw: Any, *, must_exist: bool = False) -> CanonicalPath:
    if not isinstance(raw, str) or not raw:
        raise fsops.FsError("PATH_INVALID", "A path argument was missing.")
    return policy.canonicalize(raw, must_exist=must_exist)


# --------------------------------------------------------------------------
# Workers
# --------------------------------------------------------------------------


def worker_list_directory(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    target = _canonical(policy, args.get("path"), must_exist=True)
    limit = int(args.get("limit") or fsops.LIST_MAX_ENTRIES)
    return fsops.list_directory(policy, target, limit=min(limit, fsops.LIST_MAX_ENTRIES))


def worker_search_files(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    root = _canonical(policy, args.get("root"), must_exist=True)
    return fsops.search_files(
        policy,
        root,
        pattern=str(args.get("pattern") or "*"),
        recursive=bool(args.get("recursive", True)),
        max_results=min(int(args.get("limit") or fsops.SEARCH_MAX_RESULTS), fsops.SEARCH_MAX_RESULTS),
    )


def worker_read_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    scope = request.get("scope") or {}
    target = _canonical(policy, args.get("path"), must_exist=True)
    return fsops.read_file(
        policy,
        target,
        max_bytes=min(int(scope.get("max_read_bytes") or fsops.READ_MAX_BYTES), fsops.READ_MAX_BYTES),
    )


def worker_write_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    target = _canonical(policy, args.get("path"))
    return fsops.write_file(
        policy,
        target,
        content=str(args.get("content") or ""),
        overwrite=bool(args.get("overwrite", False)),
        encoding=str(args.get("encoding") or "utf-8"),
    )


def worker_create_directory(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    target = _canonical(policy, args.get("path"))
    return fsops.create_directory(policy, target)


def worker_copy_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    source = _canonical(policy, args.get("source"), must_exist=True)
    destination = _canonical(policy, args.get("destination"))
    return fsops.copy_file(
        policy, source, destination, overwrite=bool(args.get("overwrite", False))
    )


def worker_move_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    source = _canonical(policy, args.get("source"), must_exist=True)
    destination = _canonical(policy, args.get("destination"))
    result = fsops.move_file(
        policy, source, destination, overwrite=bool(args.get("overwrite", False))
    )
    result["undo"] = {"kind": "move_manifest", "from": result["destination"], "to": result["source"]}
    return result


def worker_rename_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    source = _canonical(policy, args.get("path"), must_exist=True)
    result = fsops.rename_file(
        policy,
        source,
        new_name=str(args.get("new_name") or ""),
        overwrite=bool(args.get("overwrite", False)),
    )
    result["undo"] = {"kind": "move_manifest", "from": result["destination"], "to": result["source"]}
    return result


def worker_delete_file(request: dict[str, Any]) -> dict[str, Any]:
    policy = _policy(request)
    args = request.get("args") or {}
    raw_paths = args.get("paths")
    if isinstance(raw_paths, str):
        raw_paths = [raw_paths]
    if not isinstance(raw_paths, list) or not raw_paths:
        raise fsops.FsError("PATH_INVALID", "No target was supplied.")
    targets = [_canonical(policy, item, must_exist=True) for item in raw_paths]
    result = fsops.delete_to_recycle_bin(policy, targets)
    result["undo"] = {"kind": "recycle_bin", "paths": result["deleted"]}
    return result


def worker_restore_deleted(request: dict[str, Any]) -> dict[str, Any]:
    args = request.get("args") or {}
    paths = args.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    return fsops.restore_from_recycle_bin(paths)


def worker_selftest_sleep(request: dict[str, Any]) -> dict[str, Any]:
    """Blocking worker used only by the runtime's cancellation tests.

    Not a registered :class:`~artemis.tools.contract.ToolSpec`, therefore not
    reachable by the model, and additionally gated behind ``ARTEMIS_SELFTEST``
    which the runtime never sets.
    """
    if os.environ.get("ARTEMIS_SELFTEST") != "1":
        raise fsops.FsError("FS_DENIED", "self-test workers are disabled")
    args = request.get("args") or {}
    seconds = float(args.get("seconds") or 30.0)
    marker = args.get("child_marker")
    if marker:
        import subprocess

        subprocess.Popen(  # noqa: S603 - constant argv, self-test only
            [
                sys.executable,
                "-c",
                "import time,sys;open(sys.argv[1],'w').write(str(__import__('os').getpid()));"
                "time.sleep(120)",
                str(marker),
            ],
            shell=False,
        )
    time.sleep(seconds)
    return {"slept": seconds}


WORKERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "fs.list_directory": worker_list_directory,
    "fs.search_files": worker_search_files,
    "fs.read_file": worker_read_file,
    "fs.write_file": worker_write_file,
    "fs.create_directory": worker_create_directory,
    "fs.copy_file": worker_copy_file,
    "fs.move_file": worker_move_file,
    "fs.rename_file": worker_rename_file,
    "fs.delete_file": worker_delete_file,
    "fs.restore_deleted": worker_restore_deleted,
    "selftest.sleep": worker_selftest_sleep,
}


def run(worker_name: str, request: dict[str, Any]) -> dict[str, Any]:
    handler = WORKERS.get(worker_name)
    if handler is None:
        return {"ok": False, "error_code": "WORKER_UNKNOWN", "message": "unknown worker"}
    try:
        return {"ok": True, "data": handler(request)}
    except fsops.FsError as exc:
        return {"ok": False, "error_code": exc.code, "message": exc.message}
    except PathRejected as exc:
        return {"ok": False, "error_code": exc.code, "message": exc.reason}
    except MemoryError:  # pragma: no cover - resource guard
        return {"ok": False, "error_code": "WORKER_OOM", "message": "out of memory"}
    except Exception as exc:  # noqa: BLE001 - normalised, never re-raised
        return {"ok": False, "error_code": "TOOL_ERROR", "message": type(exc).__name__}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        sys.stdout.write(json.dumps({"ok": False, "error_code": "WORKER_USAGE"}))
        return 2
    worker_name = argv[0]
    raw = sys.stdin.read()
    try:
        request = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        sys.stdout.write(json.dumps({"ok": False, "error_code": "WORKER_PROTOCOL"}))
        return 2
    if not isinstance(request, dict):
        sys.stdout.write(json.dumps({"ok": False, "error_code": "WORKER_PROTOCOL"}))
        return 2
    response = run(worker_name, request)
    sys.stdout.write(json.dumps(response, ensure_ascii=False, default=str))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
