"""Filesystem primitives for the Phase 5 tools.

This module performs I/O only.  It makes **no** policy decisions: every function
receives an already-canonicalized :class:`~artemis.policy.paths.CanonicalPath`
plus the :class:`~artemis.policy.paths.PathPolicy` that produced it, and uses
handle-based verification immediately before touching the object
(``docs/security.md`` §5 step 11).

It runs in the ``SUBPROCESS`` tier (``docs/tools.md`` §6 "Files"), which is why
it is a plain synchronous module with no imports from the API, the agent or the
policy *engine*: the worker process is unprivileged and holds no tokens.
"""

from __future__ import annotations

import fnmatch
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any, Iterable, Iterator, Optional

from ..policy.paths import (
    CREATE_ALWAYS,
    CREATE_NEW,
    OPEN_EXISTING,
    CanonicalPath,
    PathPolicy,
    PathRejected,
    comparison_key,
)

#: ``docs/security.md`` §5 Reads: 512 KB cap.
READ_MAX_BYTES: int = 512 * 1024

#: ``docs/tools.md`` §6: search results capped at 500.
SEARCH_MAX_RESULTS: int = 500

#: ``docs/tools.md`` §8: batch operations capped.
MAX_BATCH_ITEMS: int = 200

#: Directory listing cap — a 5 000-file listing must never enter the prompt.
LIST_MAX_ENTRIES: int = 1000

#: Bytes inspected when deciding whether a file is binary.
_SNIFF_BYTES: int = 8192

_TEMP_PREFIX = ".artemis-tmp-"


class FsError(Exception):
    """A filesystem operation failed with a stable, user-safe code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _strip_control(text: str) -> str:
    """Filenames are untrusted content: strip control and bidi characters."""
    cleaned = re.sub("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]", "", text)
    return "".join(ch for ch in cleaned if unicodedata.category(ch) != "Cc")


def is_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    text_chars = bytes(range(0x20, 0x7F)) + b"\r\n\t\f\b"
    nontext = sum(1 for byte in sample if byte not in text_chars and byte < 0x80)
    return nontext / len(sample) > 0.30


def decode_text(raw: bytes) -> tuple[str, str]:
    """Decode with a small, deterministic encoding ladder."""
    for bom, encoding in (
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    ):
        if raw.startswith(bom):
            return raw.decode(encoding, "replace"), encoding
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), "utf-8/replace"


def validate_leaf_name(name: str) -> str:
    """Validate a new file/folder name supplied for a rename or create."""
    if not name or name.strip() != name:
        raise FsError("FS_INVALID_NAME", "The name is empty or has surrounding whitespace.")
    if any(sep in name for sep in ("\\", "/", ":")):
        raise FsError("FS_INVALID_NAME", "The name may not contain a path separator.")
    if name in (".", ".."):
        raise FsError("FS_INVALID_NAME", "The name is not a valid file name.")
    if name != name.rstrip(" ."):
        raise FsError("FS_INVALID_NAME", "The name may not end with a space or a dot.")
    if any(ch in name for ch in '<>"|?*'):
        raise FsError("FS_INVALID_NAME", "The name contains characters Windows forbids.")
    from ..policy import baseline

    stem = name.split(".")[0].strip().lower()
    if stem in baseline.RESERVED_DEVICE_NAMES:
        raise FsError("FS_INVALID_NAME", "The name is a reserved Windows device name.")
    if baseline.is_secret_shaped_name(name):
        raise FsError("FS_DENIED", "The name looks like credential material.")
    return name


def _rejected(exc: PathRejected) -> FsError:
    return FsError(exc.code, exc.reason)


# --------------------------------------------------------------------------
# Read-only operations
# --------------------------------------------------------------------------


@dataclass(slots=True)
class DirEntryInfo:
    name: str
    is_dir: bool
    size: int
    modified: float
    is_link: bool


def list_directory(
    policy: PathPolicy, target: CanonicalPath, *, limit: int = LIST_MAX_ENTRIES
) -> dict[str, Any]:
    """List a directory.  Names are untrusted content and are sanitised."""
    if not target.exists:
        raise FsError("PATH_NOT_FOUND", "The folder does not exist.")
    try:
        handle = policy.open_verified(target, directory=True)
    except PathRejected as exc:
        raise _rejected(exc) from exc
    try:
        entries: list[DirEntryInfo] = []
        truncated = False
        with os.scandir(handle.final_path) as scanner:
            for index, entry in enumerate(scanner):
                if index >= limit:
                    truncated = True
                    break
                try:
                    stat = entry.stat(follow_symlinks=False)
                    entries.append(
                        DirEntryInfo(
                            name=_strip_control(entry.name),
                            is_dir=entry.is_dir(follow_symlinks=False),
                            size=int(stat.st_size),
                            modified=float(stat.st_mtime),
                            is_link=bool(stat.st_file_attributes & 0x400)
                            if hasattr(stat, "st_file_attributes")
                            else entry.is_symlink(),
                        )
                    )
                except OSError:
                    continue
    finally:
        handle.close()

    entries.sort(key=lambda item: (not item.is_dir, item.name.casefold()))
    return {
        "path": target.path,
        "truncated": truncated,
        "entry_count": len(entries),
        "entries": [
            {
                "name": entry.name,
                "kind": "dir" if entry.is_dir else "file",
                "size": entry.size,
                "modified": entry.modified,
                "link": entry.is_link,
            }
            for entry in entries
        ],
    }


def search_files(
    policy: PathPolicy,
    root: CanonicalPath,
    *,
    pattern: str,
    recursive: bool = True,
    max_results: int = SEARCH_MAX_RESULTS,
) -> dict[str, Any]:
    """Name-glob search inside one allowed root.  No content grep."""
    if not root.exists or not root.is_dir:
        raise FsError("PATH_NOT_FOUND", "The folder does not exist.")
    if not pattern or len(pattern) > 260:
        raise FsError("FS_INVALID_NAME", "The search pattern is invalid.")
    if any(sep in pattern for sep in ("\\", "/", ":")):
        raise FsError("FS_INVALID_NAME", "The search pattern may not contain a path.")
    try:
        handle = policy.open_verified(root, directory=True)
        base = handle.final_path
        handle.close()
    except PathRejected as exc:
        raise _rejected(exc) from exc

    matches: list[dict[str, Any]] = []
    truncated = False
    lowered = pattern.casefold()
    for current_dir, dir_names, file_names in os.walk(base):
        # Never follow reparse points out of the root.
        dir_names[:] = [
            name
            for name in dir_names
            if not _is_reparse(os.path.join(current_dir, name))
        ]
        for name in list(dir_names) + file_names:
            if not fnmatch.fnmatch(name.casefold(), lowered):
                continue
            full = os.path.join(current_dir, name)
            if policy.match_root(_segments(full)) is None:
                continue
            if policy.denial_reason(full, _segments(full)) is not None:
                continue
            if len(matches) >= max_results:
                truncated = True
                break
            try:
                stat = os.stat(full, follow_symlinks=False)
                size = int(stat.st_size)
                modified = float(stat.st_mtime)
            except OSError:
                size, modified = 0, 0.0
            matches.append(
                {
                    "path": full,
                    "name": _strip_control(name),
                    "kind": "dir" if os.path.isdir(full) else "file",
                    "size": size,
                    "modified": modified,
                }
            )
        if truncated or not recursive:
            break
    return {
        "root": root.path,
        "pattern": pattern,
        "match_count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }


def _segments(path: str) -> tuple[str, ...]:
    from ..policy.paths import segments_of

    return segments_of(path.rstrip("\\"))


def _is_reparse(path: str) -> bool:
    try:
        stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return True
    attrs = getattr(stat, "st_file_attributes", 0)
    return bool(attrs & 0x400)


def read_file(
    policy: PathPolicy, target: CanonicalPath, *, max_bytes: int = READ_MAX_BYTES
) -> dict[str, Any]:
    """Read a text file through a verified handle.  Binary is refused."""
    if not target.exists:
        raise FsError("PATH_NOT_FOUND", "The file does not exist.")
    try:
        handle = policy.open_verified(target)
    except PathRejected as exc:
        raise _rejected(exc) from exc
    try:
        if handle.identity.is_dir:
            raise FsError("FS_IS_DIRECTORY", "The target is a folder, not a file.")
        size = handle.identity.size
        if size > max_bytes:
            raise FsError(
                "FS_TOO_LARGE",
                f"The file is {size / 1024 / 1024:.1f} MB; the limit is "
                f"{max_bytes // 1024} KB.",
            )
        fd = handle.fd(os.O_RDONLY)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
    finally:
        handle.close()

    if len(raw) > max_bytes:
        raise FsError("FS_TOO_LARGE", "The file exceeds the read limit.")
    if is_binary(raw[:_SNIFF_BYTES]):
        raise FsError("FS_BINARY", "The file is binary and cannot be read as text.")
    text, encoding = decode_text(raw)
    return {
        "path": target.path,
        "encoding": encoding,
        "bytes": len(raw),
        "line_count": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        "text": text,
    }


# --------------------------------------------------------------------------
# Mutating operations
# --------------------------------------------------------------------------


def _verified_parent(policy: PathPolicy, target: CanonicalPath) -> str:
    parent = target.parent
    try:
        parent_canonical = policy.canonicalize(parent, must_exist=True)
        handle = policy.open_verified(parent_canonical, directory=True)
    except PathRejected as exc:
        raise _rejected(exc) from exc
    try:
        if not handle.identity.is_dir:
            raise FsError("FS_NOT_A_DIRECTORY", "The parent path is not a folder.")
        return handle.final_path
    finally:
        handle.close()


def _assert_replaceable(policy: PathPolicy, target: CanonicalPath) -> None:
    """If the destination exists it must be a plain file, not a link."""
    if not os.path.lexists(target.path):
        return
    try:
        policy.assert_not_reparse_point(target)
    except PathRejected as exc:
        raise _rejected(exc) from exc


def write_file(
    policy: PathPolicy,
    target: CanonicalPath,
    *,
    content: str,
    overwrite: bool = False,
    encoding: str = "utf-8",
) -> dict[str, Any]:
    """Atomic write: temp file in the verified parent, then ``os.replace``.

    A partially-written file is never observable (``docs/roadmap.md`` Phase 5
    write safety).  Collision handling is explicit: without ``overwrite`` an
    existing destination is an error, never a silent clobber.
    """
    if encoding.lower() not in ("utf-8", "utf-8-sig", "utf-16", "cp1252", "ascii"):
        raise FsError("FS_INVALID_ENCODING", f"Unsupported encoding '{encoding}'.")
    validate_leaf_name(PureWindowsPath(target.path).name)
    existed = os.path.lexists(target.path)
    if existed and not overwrite:
        raise FsError("FS_COLLISION", "The file already exists.")
    if existed:
        _assert_replaceable(policy, target)
        try:
            previous_size = os.stat(target.path, follow_symlinks=False).st_size
        except OSError:
            previous_size = 0
    else:
        previous_size = 0

    parent = _verified_parent(policy, target)
    temp_path = os.path.join(parent, f"{_TEMP_PREFIX}{uuid.uuid4().hex[:12]}")
    data = content.encode(encoding)
    try:
        with open(temp_path, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target.path)
    except OSError as exc:
        _quiet_unlink(temp_path)
        raise FsError("FS_WRITE_FAILED", _os_message(exc)) from exc
    return {
        "path": target.path,
        "bytes_written": len(data),
        "created": not existed,
        "previous_bytes": previous_size,
        "encoding": encoding,
    }


def create_directory(policy: PathPolicy, target: CanonicalPath) -> dict[str, Any]:
    validate_leaf_name(PureWindowsPath(target.path).name)
    if os.path.lexists(target.path):
        if os.path.isdir(target.path):
            return {"path": target.path, "created": False}
        raise FsError("FS_COLLISION", "A file with that name already exists.")
    _verified_parent(policy, target)
    try:
        os.mkdir(target.path)
    except OSError as exc:
        raise FsError("FS_WRITE_FAILED", _os_message(exc)) from exc
    return {"path": target.path, "created": True}


def copy_file(
    policy: PathPolicy,
    source: CanonicalPath,
    destination: CanonicalPath,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    return _transfer(policy, source, destination, overwrite=overwrite, move=False)


def move_file(
    policy: PathPolicy,
    source: CanonicalPath,
    destination: CanonicalPath,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    return _transfer(policy, source, destination, overwrite=overwrite, move=True)


def rename_file(
    policy: PathPolicy, source: CanonicalPath, *, new_name: str, overwrite: bool = False
) -> dict[str, Any]:
    validate_leaf_name(new_name)
    destination_raw = str(PureWindowsPath(source.parent, new_name))
    try:
        destination = policy.canonicalize(destination_raw)
    except PathRejected as exc:
        raise _rejected(exc) from exc
    return _transfer(policy, source, destination, overwrite=overwrite, move=True)


def _transfer(
    policy: PathPolicy,
    source: CanonicalPath,
    destination: CanonicalPath,
    *,
    overwrite: bool,
    move: bool,
) -> dict[str, Any]:
    import shutil

    if not source.exists:
        raise FsError("PATH_NOT_FOUND", "The source does not exist.")
    if comparison_key(source.path) == comparison_key(destination.path):
        raise FsError("FS_SAME_PATH", "The source and destination are the same.")
    try:
        source_identity = policy.assert_not_reparse_point(source)
    except PathRejected as exc:
        raise _rejected(exc) from exc
    if source_identity.is_dir and not move:
        raise FsError("FS_IS_DIRECTORY", "Copying folders is not supported.")

    existed = os.path.lexists(destination.path)
    if existed and not overwrite:
        raise FsError("FS_COLLISION", "The destination already exists.")
    if existed:
        _assert_replaceable(policy, destination)
    validate_leaf_name(PureWindowsPath(destination.path).name)
    _verified_parent(policy, destination)

    try:
        if move:
            os.replace(source.path, destination.path)
        else:
            shutil.copy2(source.path, destination.path, follow_symlinks=False)
    except OSError as exc:
        raise FsError("FS_WRITE_FAILED", _os_message(exc)) from exc

    try:
        size = os.stat(destination.path, follow_symlinks=False).st_size
    except OSError:  # pragma: no cover - the object was just created
        size = 0
    return {
        "source": source.path,
        "destination": destination.path,
        "bytes": int(size),
        "replaced": existed,
        "moved": move,
    }


def delete_to_recycle_bin(
    policy: PathPolicy, targets: Iterable[CanonicalPath]
) -> dict[str, Any]:
    """Recoverable deletion via ``IFileOperation`` (ADR-010).

    Permanent deletion is a separate, baseline-denied capability and is not
    implemented: ``FOF_ALLOWUNDO`` is always set, and ``FOF_WANTNUKEWARNING``
    ensures that if Windows *cannot* recycle an item the operation reports an
    abort rather than silently destroying it.
    """
    import pythoncom
    from win32com.shell import shell, shellcon

    resolved: list[CanonicalPath] = list(targets)
    if not resolved:
        raise FsError("FS_NOTHING_TO_DO", "No target was supplied.")
    if len(resolved) > MAX_BATCH_ITEMS:
        raise FsError("FS_BATCH_TOO_LARGE", f"More than {MAX_BATCH_ITEMS} items.")

    for target in resolved:
        if not target.exists:
            raise FsError("PATH_NOT_FOUND", "The target does not exist.")
        try:
            policy.assert_not_reparse_point(target)
        except PathRejected as exc:
            raise _rejected(exc) from exc

    pythoncom.CoInitialize()
    try:
        operation = pythoncom.CoCreateInstance(
            shell.CLSID_FileOperation,
            None,
            pythoncom.CLSCTX_ALL,
            shell.IID_IFileOperation,
        )
        operation.SetOperationFlags(
            shellcon.FOF_ALLOWUNDO
            | shellcon.FOF_NOCONFIRMATION
            | shellcon.FOF_SILENT
            | shellcon.FOF_NOERRORUI
            | shellcon.FOF_WANTNUKEWARNING
        )
        items: list[str] = []
        for target in resolved:
            item = shell.SHCreateItemFromParsingName(
                target.path, None, shell.IID_IShellItem
            )
            operation.DeleteItem(item, None)
            items.append(target.path)
        operation.PerformOperations()
        aborted = bool(operation.GetAnyOperationsAborted())
    except FsError:
        raise
    except Exception as exc:  # noqa: BLE001 - COM errors are opaque
        raise FsError("FS_DELETE_FAILED", f"Windows refused the deletion: {exc}") from exc
    finally:
        pythoncom.CoUninitialize()

    remaining = [path for path in items if os.path.lexists(path)]
    if aborted or remaining:
        raise FsError(
            "FS_DELETE_ABORTED",
            "Windows did not move every item to the Recycle Bin; nothing was "
            "permanently deleted.",
        )
    return {
        "deleted": items,
        "item_count": len(items),
        "destination": "Recycle Bin",
        "recoverable": True,
    }


def restore_from_recycle_bin(paths: Iterable[str]) -> dict[str, Any]:
    """Restore previously recycled originals (the ``undo`` round-trip)."""
    import pythoncom
    from win32com.shell import shell, shellcon

    wanted = {comparison_key(path): path for path in paths}
    if not wanted:
        raise FsError("FS_NOTHING_TO_DO", "No target was supplied.")

    pythoncom.CoInitialize()
    restored: list[str] = []
    try:
        desktop = shell.SHGetDesktopFolder()
        bin_pidl = shell.SHGetSpecialFolderLocation(0, shellcon.CSIDL_BITBUCKET)
        bucket = desktop.BindToObject(bin_pidl, None, shell.IID_IShellFolder)
        operation = pythoncom.CoCreateInstance(
            shell.CLSID_FileOperation,
            None,
            pythoncom.CLSCTX_ALL,
            shell.IID_IFileOperation,
        )
        operation.SetOperationFlags(
            shellcon.FOF_NOCONFIRMATION | shellcon.FOF_SILENT | shellcon.FOF_NOERRORUI
        )
        queued = 0
        for child in bucket:
            original = bucket.GetDisplayNameOf(child, shellcon.SHGDN_NORMAL)
            key = comparison_key(original)
            match = wanted.get(key)
            if match is None:
                # The Recycle Bin drops a known extension for some item types;
                # match on the stem as well before giving up.
                stem, _ext = os.path.splitext(original)
                for candidate_key, candidate in wanted.items():
                    if comparison_key(os.path.splitext(candidate)[0]) == comparison_key(
                        original
                    ) or comparison_key(stem) == comparison_key(
                        os.path.splitext(candidate)[0]
                    ):
                        match = candidate
                        key = candidate_key
                        break
            if match is None:
                continue
            item = shell.SHCreateItemFromIDList(bin_pidl + child, shell.IID_IShellItem)
            parent = shell.SHCreateItemFromParsingName(
                os.path.dirname(match), None, shell.IID_IShellItem
            )
            operation.MoveItem(item, parent, os.path.basename(match))
            restored.append(match)
            wanted.pop(key, None)
            queued += 1
        if queued:
            operation.PerformOperations()
            aborted = bool(operation.GetAnyOperationsAborted())
        else:
            aborted = False
    except Exception as exc:  # noqa: BLE001 - COM errors are opaque
        raise FsError("FS_RESTORE_FAILED", f"Windows refused the restore: {exc}") from exc
    finally:
        pythoncom.CoUninitialize()

    missing = [path for path in restored if not os.path.lexists(path)]
    return {
        "restored": [path for path in restored if os.path.lexists(path)],
        "not_found": sorted(wanted.values()),
        "failed": missing,
        "aborted": aborted,
    }


def _quiet_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:  # pragma: no cover - best effort cleanup
        pass


def _os_message(exc: OSError) -> str:
    if exc.winerror == 32 if hasattr(exc, "winerror") else False:
        return "The file is in use by another process."
    if exc.errno == 13:
        return "Access denied by Windows."
    return "The operation failed."


__all__ = [
    "FsError",
    "LIST_MAX_ENTRIES",
    "MAX_BATCH_ITEMS",
    "READ_MAX_BYTES",
    "SEARCH_MAX_RESULTS",
    "copy_file",
    "create_directory",
    "decode_text",
    "delete_to_recycle_bin",
    "is_binary",
    "list_directory",
    "move_file",
    "read_file",
    "rename_file",
    "restore_from_recycle_bin",
    "search_files",
    "validate_leaf_name",
    "write_file",
]
