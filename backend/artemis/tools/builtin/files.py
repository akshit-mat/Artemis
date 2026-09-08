"""Filesystem tools (``docs/tools.md`` §6 "Files", roadmap Phase 5).

Every tool here is ``requires_paths=True`` and ``SUBPROCESS``: the work is
recursive, destructive or parses untrusted bytes, so timeout and cancel must be
*hard* (ADR-008).

The tool bodies contain no path logic.  Canonicalization happens in the policy
layer (parent process) and again — by handle, immediately before use — inside the
worker.  The tool body's only job is to hand the worker the validated arguments
and to turn the worker's structured reply into a :class:`ToolResult`.

Previews are backend-generated from validated arguments and resolved paths, never
from model prose (``docs/api.md`` §4, ``docs/ui.md`` §5).
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ...policy.taint import wrap_untrusted
from ..contract import (
    ActionPreview,
    Decision,
    ExecTier,
    ResolvedContext,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolResult,
    ToolSpec,
)
from ..fsops import LIST_MAX_ENTRIES, MAX_BATCH_ITEMS, READ_MAX_BYTES, SEARCH_MAX_RESULTS
from ..runtime import run_worker, truncate_context_view

#: Set once at startup by ``artemis.tools.builtin.bind_filesystem_scope``.
_scope: dict[str, Any] = {
    "allow_roots": [],
    "allow_unc": False,
    "max_read_bytes": READ_MAX_BYTES,
}


def bind_scope(*, allow_roots: list[str], allow_unc: bool, max_read_bytes: int) -> None:
    """Bind the authorization scope handed to the worker process."""
    _scope["allow_roots"] = list(allow_roots)
    _scope["allow_unc"] = bool(allow_unc)
    _scope["max_read_bytes"] = int(max_read_bytes)


def current_scope() -> dict[str, Any]:
    return dict(_scope)


# --------------------------------------------------------------------------
# Argument models
# --------------------------------------------------------------------------

_PATH = Field(min_length=3, max_length=32_000, description="Absolute Windows path.")


class ListDirectoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = _PATH


class SearchFilesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str = _PATH
    pattern: str = Field(
        min_length=1, max_length=260, description="File-name glob, e.g. '*.pdf'."
    )
    recursive: bool = Field(default=True, description="Search sub-folders.")
    limit: int = Field(default=SEARCH_MAX_RESULTS, ge=1, le=SEARCH_MAX_RESULTS)


class ReadFileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = _PATH


class WriteFileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = _PATH
    content: str = Field(max_length=READ_MAX_BYTES, description="Full new file contents.")
    overwrite: bool = Field(default=False, description="Replace an existing file.")
    encoding: str = Field(default="utf-8", max_length=16)


class CreateDirectoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = _PATH


class CopyMoveArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = _PATH
    destination: str = _PATH
    overwrite: bool = Field(default=False, description="Replace the destination if it exists.")


class RenameArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = _PATH
    new_name: str = Field(min_length=1, max_length=255, description="New name only, no folders.")
    overwrite: bool = False


class DeleteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paths: list[str] = Field(min_length=1, max_length=MAX_BATCH_ITEMS)


# --------------------------------------------------------------------------
# Result models
# --------------------------------------------------------------------------


class ListDirectoryResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    path: str
    entry_count: int
    truncated: bool
    entries: list[dict[str, Any]]


class SearchFilesResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    root: str
    pattern: str
    match_count: int
    truncated: bool
    matches: list[dict[str, Any]]


class ReadFileResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    path: str
    encoding: str
    bytes: int
    text: str


class MutationResult(BaseModel):
    model_config = ConfigDict(extra="allow")


# --------------------------------------------------------------------------
# Worker plumbing
# --------------------------------------------------------------------------


def _resolved_args(args: BaseModel, ctx: ToolContext, *fields: str) -> dict[str, Any]:
    """Replace path arguments with the canonical paths the policy layer resolved.

    Tools never re-resolve a model-supplied string (``docs/tools.md`` §8).
    """
    payload = args.model_dump(mode="json")
    resolved = ctx.resolved.paths if ctx.resolved else {}
    for field in fields:
        canonical = resolved.get(field)
        if canonical is None:
            continue
        if isinstance(payload.get(field), list):
            payload[field] = [item.path for item in canonical]
        else:
            payload[field] = canonical.path
    return payload


async def _call_worker(
    *,
    worker: str,
    args: BaseModel,
    ctx: ToolContext,
    spec_timeout: float,
    path_fields: tuple[str, ...],
) -> tuple[Optional[dict[str, Any]], Optional[ToolResult]]:
    payload = {
        "args": _resolved_args(args, ctx, *path_fields),
        "scope": current_scope(),
    }
    outcome = await run_worker(
        worker=worker,
        payload=payload,
        timeout_s=spec_timeout,
        cancel_token=ctx.cancel_token,
    )
    if outcome.status == "ok":
        return outcome.payload, None
    if outcome.status == "timeout":
        return None, ToolResult(
            status="timeout",
            summary="The filesystem operation exceeded its time limit and was stopped.",
            error_code="TOOL_TIMEOUT",
        )
    if outcome.status == "cancelled":
        return None, ToolResult(
            status="cancelled",
            summary="Cancelled. Nothing further was changed.",
            error_code="CANCELLED",
        )
    code = outcome.error_code or "TOOL_ERROR"
    message = outcome.stderr or _message_for(code)
    status = "denied" if code.startswith("PATH_") and code != "PATH_NOT_FOUND" else "error"
    return None, ToolResult(status=status, summary=message, error_code=code)


def _message_for(code: str) -> str:
    return {
        "PATH_NOT_FOUND": "The target does not exist.",
        "PATH_OUT_OF_SCOPE": "That path is outside the folders ARTEMIS may use.",
        "PATH_DENIED": "That path is protected.",
        "PATH_TOCTOU": "The target changed between validation and use; nothing was done.",
        "PATH_LOCKED": "The file is in use by another process.",
        "FS_COLLISION": "The destination already exists.",
        "FS_BINARY": "The file is binary and cannot be read as text.",
        "FS_TOO_LARGE": "The file is larger than the 512 KB read limit.",
        "WORKER_CRASH": "The filesystem worker stopped unexpectedly.",
    }.get(code, "The filesystem operation failed.")


# --------------------------------------------------------------------------
# Tool bodies
# --------------------------------------------------------------------------


async def _list_directory(args: ListDirectoryArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.list_directory",
        args=args,
        ctx=ctx,
        spec_timeout=LIST_DIRECTORY.timeout_s,
        path_fields=("path",),
    )
    if failure is not None:
        return failure
    assert data is not None
    lines = [
        f"{'[dir] ' if entry['kind'] == 'dir' else ''}{entry['name']}"
        + (f" ({entry['size']} bytes)" if entry["kind"] == "file" else "")
        for entry in data["entries"]
    ]
    body = "\n".join(lines)
    note = (
        f"{data['entry_count']} entries shown"
        + (" (list truncated)" if data["truncated"] else "")
    )
    view, truncated = truncate_context_view(
        wrap_untrusted(f"{data['path']}\n{body}", source=data["path"]),
        more_note="use read_more with the result_id for the rest.",
    )
    return ToolResult(
        status="ok",
        summary=f"{data['path']}: {note}.",
        data=data,
        context_view=view,
        trust="UNTRUSTED",
        truncated=truncated or bool(data["truncated"]),
    )


async def _search_files(args: SearchFilesArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.search_files",
        args=args,
        ctx=ctx,
        spec_timeout=SEARCH_FILES.timeout_s,
        path_fields=("root",),
    )
    if failure is not None:
        return failure
    assert data is not None
    lines = [match["path"] for match in data["matches"]]
    view, truncated = truncate_context_view(
        "\n".join(lines) or "(no matches)",
        more_note=f"{data['match_count']} matches. result_id has the full list.",
    )
    return ToolResult(
        status="ok",
        summary=f"{data['match_count']} match(es) for '{data['pattern']}' in {data['root']}.",
        data=data,
        context_view=view,
        trust="SYSTEM",
        truncated=truncated or bool(data["truncated"]),
    )


async def _read_file(args: ReadFileArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.read_file",
        args=args,
        ctx=ctx,
        spec_timeout=READ_FILE.timeout_s,
        path_fields=("path",),
    )
    if failure is not None:
        return failure
    assert data is not None
    view, truncated = truncate_context_view(
        wrap_untrusted(data["text"], source=data["path"]),
        more_note="use read_more with the result_id to continue.",
    )
    return ToolResult(
        status="ok",
        summary=f"Read {data['bytes']} bytes from {data['path']} ({data['encoding']}).",
        data=data,
        context_view=view,
        trust="UNTRUSTED",
        truncated=truncated,
    )


async def _write_file(args: WriteFileArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.write_file",
        args=args,
        ctx=ctx,
        spec_timeout=WRITE_FILE.timeout_s,
        path_fields=("path",),
    )
    if failure is not None:
        return failure
    assert data is not None
    verb = "Created" if data["created"] else "Overwrote"
    return ToolResult(
        status="ok",
        summary=f"{verb} {data['path']} ({data['bytes_written']} bytes).",
        data=data,
        context_view=f"{verb} {data['path']} ({data['bytes_written']} bytes)",
    )


async def _create_directory(args: CreateDirectoryArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.create_directory",
        args=args,
        ctx=ctx,
        spec_timeout=CREATE_DIRECTORY.timeout_s,
        path_fields=("path",),
    )
    if failure is not None:
        return failure
    assert data is not None
    summary = (
        f"Created folder {data['path']}."
        if data["created"]
        else f"Folder {data['path']} already existed."
    )
    return ToolResult(status="ok", summary=summary, data=data, context_view=summary)


async def _copy_file(args: CopyMoveArgs, ctx: ToolContext) -> ToolResult:
    return await _transfer(args, ctx, worker="fs.copy_file", spec=COPY_FILE, verb="Copied")


async def _move_file(args: CopyMoveArgs, ctx: ToolContext) -> ToolResult:
    return await _transfer(args, ctx, worker="fs.move_file", spec=MOVE_FILE, verb="Moved")


async def _transfer(
    args: CopyMoveArgs, ctx: ToolContext, *, worker: str, spec: ToolSpec, verb: str
) -> ToolResult:
    data, failure = await _call_worker(
        worker=worker,
        args=args,
        ctx=ctx,
        spec_timeout=spec.timeout_s,
        path_fields=("source", "destination"),
    )
    if failure is not None:
        return failure
    assert data is not None
    return _mutation_result(data, verb)


async def _rename_file(args: RenameArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.rename_file",
        args=args,
        ctx=ctx,
        spec_timeout=RENAME_FILE.timeout_s,
        path_fields=("path",),
    )
    if failure is not None:
        return failure
    assert data is not None
    return _mutation_result(data, "Renamed")


def _mutation_result(data: dict[str, Any], verb: str) -> ToolResult:
    from ..contract import UndoHandle

    undo_payload = data.pop("undo", None)
    undo = None
    if undo_payload:
        undo = UndoHandle(
            kind=undo_payload["kind"],
            token=json.dumps(undo_payload, sort_keys=True, ensure_ascii=False),
            description=f"Move {undo_payload['from']} back to {undo_payload['to']}",
        )
    summary = f"{verb} {data['source']} → {data['destination']}."
    return ToolResult(
        status="ok", summary=summary, data=data, context_view=summary, undo=undo
    )


async def _delete_file(args: DeleteArgs, ctx: ToolContext) -> ToolResult:
    data, failure = await _call_worker(
        worker="fs.delete_file",
        args=args,
        ctx=ctx,
        spec_timeout=DELETE_FILE.timeout_s,
        path_fields=("paths",),
    )
    if failure is not None:
        return failure
    assert data is not None
    from ..contract import UndoHandle

    undo_payload = data.pop("undo", None)
    undo = None
    if undo_payload:
        undo = UndoHandle(
            kind="recycle_bin",
            token=json.dumps(undo_payload, sort_keys=True, ensure_ascii=False),
            description="Restore from the Recycle Bin",
        )
    summary = (
        f"Moved {data['item_count']} item(s) to the Recycle Bin (restorable)."
    )
    return ToolResult(
        status="ok", summary=summary, data=data, context_view=summary, undo=undo
    )


# --------------------------------------------------------------------------
# Previews (backend-generated action text)
# --------------------------------------------------------------------------


def _resolved_path(resolved: ResolvedContext, field: str, fallback: str) -> str:
    canonical = resolved.paths.get(field) if resolved else None
    if canonical is None:
        return fallback
    if isinstance(canonical, list):
        return canonical[0].path if canonical else fallback
    return canonical.path


def _preview_read(args: ReadFileArgs, resolved: ResolvedContext) -> ActionPreview:
    path = _resolved_path(resolved, "path", args.path)
    return ActionPreview(
        action_text=f"Read the text of {path} into the conversation",
        targets=[path],
        item_count=1,
        reversible=True,
        detail="File contents are treated as untrusted input.",
    )


def _preview_write(args: WriteFileArgs, resolved: ResolvedContext) -> ActionPreview:
    path = _resolved_path(resolved, "path", args.path)
    canonical = resolved.paths.get("path") if resolved else None
    exists = bool(canonical.exists) if canonical is not None else False
    size = len(args.content.encode("utf-8", "replace"))
    if exists and args.overwrite:
        action = f"Overwrite {path} with {size} bytes"
    elif exists:
        action = f"Refuse to overwrite the existing {path}"
    else:
        action = f"Create {path} with {size} bytes"
    return ActionPreview(
        action_text=action,
        targets=[path],
        item_count=1,
        total_bytes=size,
        reversible=False,
        detail="Written atomically; a partial file is never left behind.",
    )


def _preview_create_directory(
    args: CreateDirectoryArgs, resolved: ResolvedContext
) -> ActionPreview:
    path = _resolved_path(resolved, "path", args.path)
    return ActionPreview(
        action_text=f"Create the folder {path}", targets=[path], item_count=1, reversible=True
    )


def _preview_copy(args: CopyMoveArgs, resolved: ResolvedContext) -> ActionPreview:
    source = _resolved_path(resolved, "source", args.source)
    destination = _resolved_path(resolved, "destination", args.destination)
    canonical = resolved.paths.get("source") if resolved else None
    size = canonical.identity.size if canonical and canonical.identity else None
    return ActionPreview(
        action_text=f"Copy {source} to {destination}",
        targets=[source, destination],
        item_count=1,
        total_bytes=size,
        reversible=True,
        detail="Overwrite" if args.overwrite else "Fails if the destination exists",
    )


def _preview_move(args: CopyMoveArgs, resolved: ResolvedContext) -> ActionPreview:
    source = _resolved_path(resolved, "source", args.source)
    destination = _resolved_path(resolved, "destination", args.destination)
    canonical = resolved.paths.get("source") if resolved else None
    size = canonical.identity.size if canonical and canonical.identity else None
    return ActionPreview(
        action_text=f"Move {source} to {destination}",
        targets=[source, destination],
        item_count=1,
        total_bytes=size,
        reversible=True,
        detail="Undo moves the item back.",
    )


def _preview_rename(args: RenameArgs, resolved: ResolvedContext) -> ActionPreview:
    path = _resolved_path(resolved, "path", args.path)
    return ActionPreview(
        action_text=f"Rename {path} to '{args.new_name}'",
        targets=[path],
        item_count=1,
        reversible=True,
        detail="Undo restores the previous name.",
    )


def _preview_delete(args: DeleteArgs, resolved: ResolvedContext) -> ActionPreview:
    canonical = resolved.paths.get("paths") if resolved else None
    targets = [item.path for item in canonical] if canonical else list(args.paths)
    total = 0
    for item in canonical or []:
        if item.identity is not None:
            total += item.identity.size
    noun = "item" if len(targets) == 1 else "items"
    return ActionPreview(
        action_text=(
            f"Move {len(targets)} {noun} to the Recycle Bin"
            + (f" ({total / 1024 / 1024:.1f} MB)" if total else "")
        ),
        targets=targets,
        item_count=len(targets),
        total_bytes=total or None,
        reversible=True,
        destructive=True,
        detail="→ Recycle Bin, restorable. Permanent deletion is not available.",
    )


def _preview_list(args: ListDirectoryArgs, resolved: ResolvedContext) -> ActionPreview:
    path = _resolved_path(resolved, "path", args.path)
    return ActionPreview(
        action_text=f"List the contents of {path}", targets=[path], item_count=1, reversible=True
    )


def _preview_search(args: SearchFilesArgs, resolved: ResolvedContext) -> ActionPreview:
    root = _resolved_path(resolved, "root", args.root)
    return ActionPreview(
        action_text=f"Search {root} for '{args.pattern}'",
        targets=[root],
        item_count=1,
        reversible=True,
    )


# --------------------------------------------------------------------------
# ToolSpecs
# --------------------------------------------------------------------------

SEARCH_FILES = ToolSpec(
    name="search_files",
    summary="Find files and folders by name pattern inside an allowed folder.",
    args_model=SearchFilesArgs,
    returns_model=SearchFilesResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=30.0,
    default_decision=Decision.ALLOW,
    execute=_search_files,
    requires_paths=True,
    path_args=("root",),
    preview=_preview_search,
    requires=frozenset({"windows"}),
)

LIST_DIRECTORY = ToolSpec(
    name="list_directory",
    summary="List the files and folders in a directory.",
    args_model=ListDirectoryArgs,
    returns_model=ListDirectoryResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=True,
    tier=ExecTier.SUBPROCESS,
    timeout_s=20.0,
    default_decision=Decision.ALLOW,
    execute=_list_directory,
    requires_paths=True,
    path_args=("path",),
    preview=_preview_list,
    requires=frozenset({"windows"}),
)

READ_FILE = ToolSpec(
    name="read_file",
    summary="Read the text contents of a file (max 512 KB, text only).",
    args_model=ReadFileArgs,
    returns_model=ReadFileResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=True,
    tier=ExecTier.SUBPROCESS,
    timeout_s=20.0,
    default_decision=Decision.ASK,
    execute=_read_file,
    requires_paths=True,
    path_args=("path",),
    preview=_preview_read,
    requires=frozenset({"windows"}),
)

WRITE_FILE = ToolSpec(
    name="write_file",
    summary="Create a file or replace its contents.",
    args_model=WriteFileArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.MODERATE,
    side_effects=True,
    reversible=False,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=30.0,
    default_decision=Decision.ASK,
    execute=_write_file,
    requires_paths=True,
    path_args=("path",),
    preview=_preview_write,
    requires=frozenset({"windows"}),
)

CREATE_DIRECTORY = ToolSpec(
    name="create_directory",
    summary="Create a new folder.",
    args_model=CreateDirectoryArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.LOW,
    side_effects=True,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=20.0,
    default_decision=Decision.ASK,
    execute=_create_directory,
    requires_paths=True,
    path_args=("path",),
    preview=_preview_create_directory,
    requires=frozenset({"windows"}),
)

COPY_FILE = ToolSpec(
    name="copy_file",
    summary="Copy a file to another location.",
    args_model=CopyMoveArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.MODERATE,
    side_effects=True,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=45.0,
    default_decision=Decision.ASK,
    execute=_copy_file,
    requires_paths=True,
    path_args=("source", "destination"),
    preview=_preview_copy,
    requires=frozenset({"windows"}),
)

MOVE_FILE = ToolSpec(
    name="move_file",
    summary="Move a file or folder to another location.",
    args_model=CopyMoveArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.MODERATE,
    side_effects=True,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=45.0,
    default_decision=Decision.ASK,
    execute=_move_file,
    requires_paths=True,
    path_args=("source", "destination"),
    preview=_preview_move,
    requires=frozenset({"windows"}),
)

RENAME_FILE = ToolSpec(
    name="rename_file",
    summary="Rename a file or folder in place.",
    args_model=RenameArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.MODERATE,
    side_effects=True,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=30.0,
    default_decision=Decision.ASK,
    execute=_rename_file,
    requires_paths=True,
    path_args=("path",),
    preview=_preview_rename,
    requires=frozenset({"windows"}),
)

DELETE_FILE = ToolSpec(
    name="delete_file",
    summary="Move files or folders to the Recycle Bin.",
    args_model=DeleteArgs,
    returns_model=MutationResult,
    category=ToolCategory.FILES,
    risk=RiskLevel.DESTRUCTIVE,
    side_effects=True,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.SUBPROCESS,
    timeout_s=60.0,
    default_decision=Decision.ASK,
    execute=_delete_file,
    requires_paths=True,
    path_args=("paths",),
    preview=_preview_delete,
    destructive=True,
    requires=frozenset({"windows"}),
)

FILE_TOOLS: tuple[ToolSpec, ...] = (
    SEARCH_FILES,
    LIST_DIRECTORY,
    READ_FILE,
    WRITE_FILE,
    CREATE_DIRECTORY,
    COPY_FILE,
    MOVE_FILE,
    RENAME_FILE,
    DELETE_FILE,
)

__all__ = ["FILE_TOOLS", "bind_scope", "current_scope"]
