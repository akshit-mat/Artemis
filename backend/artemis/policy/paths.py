"""Windows path canonicalization and containment — the highest-risk module.

``docs/security.md`` §5 is the specification.  Two rules govern this file:

1. **Nothing else in ARTEMIS resolves a path.**  Tools receive
   :class:`CanonicalPath` values produced here and never re-resolve a
   model-supplied string (``docs/tools.md`` §8).
2. **A path string is not trustworthy after validation.**  For read, write and
   delete the check is performed against an *open handle* and the handle (or the
   handle-derived final path plus an identity re-check) is what the tool uses —
   junction-swap races are otherwise real (``docs/security.md`` §5 step 11).

The pipeline order below is the documented order.  ``%VAR%`` expansion happens
against an allowlist immediately after the cheap character checks, and the
syntactic rejections are then re-applied to the expanded string, so expansion
cannot be used to smuggle a device name, an ADS or a UNC path past step 2–5.
"""

from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import sys
import unicodedata
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path, PurePath, PureWindowsPath
from typing import Final, Iterable, Optional, Sequence

from . import baseline

IS_WINDOWS: Final[bool] = sys.platform == "win32"

#: Environment variables that may appear in a model- or user-supplied path.
ENV_ALLOWLIST: Final[tuple[str, ...]] = ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "PUBLIC")

_ENV_RE: Final[re.Pattern[str]] = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

#: Characters never permitted anywhere in a path we accept.
_CONTROL_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

#: Zero-width / bidi controls stripped from untrusted text (``security.md`` §4).
_INVISIBLE_RE: Final[re.Pattern[str]] = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)


class PathRejected(Exception):
    """A path failed canonicalization or containment.  Always fail-closed."""

    def __init__(self, code: str, reason: str, *, raw: str | None = None) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.raw = raw


# --------------------------------------------------------------------------
# Win32 plumbing (ctypes — no new dependency, explicit and auditable)
# --------------------------------------------------------------------------

GENERIC_READ: Final = 0x80000000
GENERIC_WRITE: Final = 0x40000000
FILE_SHARE_READ: Final = 0x00000001
FILE_SHARE_WRITE: Final = 0x00000002
FILE_SHARE_DELETE: Final = 0x00000004
OPEN_EXISTING: Final = 3
CREATE_NEW: Final = 1
CREATE_ALWAYS: Final = 2
OPEN_ALWAYS: Final = 4
TRUNCATE_EXISTING: Final = 5
FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value
FILE_NAME_NORMALIZED: Final = 0x0
VOLUME_NAME_DOS: Final = 0x0

if IS_WINDOWS:  # pragma: no branch - platform constant

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable NTFS identity of an object: volume serial + 64-bit file index."""

    volume_serial: int
    file_index: int
    is_dir: bool
    is_reparse_point: bool
    size: int


class SafeHandle:
    """An owned Win32 handle plus the identity and final path it was verified at.

    Closing is idempotent.  ``fd()`` converts to a CRT file descriptor exactly
    once; after that the handle is owned by the descriptor and must not be
    closed directly.
    """

    __slots__ = ("_handle", "final_path", "identity", "_fd", "_closed")

    def __init__(self, handle: int, final_path: str, identity: FileIdentity) -> None:
        self._handle = handle
        self.final_path = final_path
        self.identity = identity
        self._fd: int | None = None
        self._closed = False

    @property
    def handle(self) -> int:
        if self._closed:
            raise PathRejected("PATH_INVALID", "handle already closed")
        return self._handle

    def fd(self, flags: int = os.O_RDONLY) -> int:
        if self._fd is None:
            self._fd = msvcrt.open_osfhandle(self._handle, flags)
        return self._fd

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:  # pragma: no cover - already closed
                pass
            return
        if IS_WINDOWS:
            _kernel32.CloseHandle(wintypes.HANDLE(self._handle))

    def __enter__(self) -> "SafeHandle":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _win_error(path: str) -> PathRejected:
    err = ctypes.get_last_error()
    if err in (2, 3):  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
        return PathRejected("PATH_NOT_FOUND", "The target does not exist.", raw=path)
    if err == 5:  # ERROR_ACCESS_DENIED
        return PathRejected("PATH_ACCESS_DENIED", "Access denied by Windows.", raw=path)
    if err == 32:  # ERROR_SHARING_VIOLATION
        return PathRejected("PATH_LOCKED", "The file is in use by another process.", raw=path)
    return PathRejected("PATH_INVALID", f"Windows error {err} opening the target.", raw=path)


def open_handle(
    path: str,
    *,
    write: bool = False,
    directory: bool = False,
    creation: int = OPEN_EXISTING,
    follow_reparse: bool = True,
    allow_delete_share: bool = False,
) -> SafeHandle:
    """Open *path* and capture its handle-derived final path and identity.

    ``follow_reparse=False`` opens the link itself, which is how we detect that
    an object became a junction/symlink between validation and use.
    ``allow_delete_share`` is off by default: withholding ``FILE_SHARE_DELETE``
    stops another process from renaming or deleting the object out from under a
    verified handle.
    """
    if not IS_WINDOWS:  # pragma: no cover - the product is Windows-only
        raise PathRejected("PATH_UNSUPPORTED", "handle-based path safety requires Windows")

    access = GENERIC_WRITE | GENERIC_READ if write else GENERIC_READ
    share = FILE_SHARE_READ | FILE_SHARE_WRITE
    if allow_delete_share:
        share |= FILE_SHARE_DELETE
    flags = 0
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    if not follow_reparse:
        flags |= FILE_FLAG_OPEN_REPARSE_POINT

    handle = _kernel32.CreateFileW(
        _extended(path), access, share, None, creation, flags, None
    )
    if handle is None or ctypes.c_void_p(handle).value == INVALID_HANDLE_VALUE:
        raise _win_error(path)

    try:
        final = final_path_from_handle(handle)
        identity = identity_from_handle(handle)
    except BaseException:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))
        raise
    return SafeHandle(handle, final, identity)


def final_path_from_handle(handle: int) -> str:
    """``GetFinalPathNameByHandleW`` — resolves reparse points and 8.3 names."""
    size = _kernel32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), None, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    )
    if size == 0:
        raise PathRejected("PATH_INVALID", "cannot resolve the final path of the target")
    buf = ctypes.create_unicode_buffer(size + 1)
    written = _kernel32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buf, size + 1, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    )
    if written == 0:
        raise PathRejected("PATH_INVALID", "cannot resolve the final path of the target")
    return _strip_extended(buf.value)


def identity_from_handle(handle: int) -> FileIdentity:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not _kernel32.GetFileInformationByHandle(wintypes.HANDLE(handle), ctypes.byref(info)):
        raise PathRejected("PATH_INVALID", "cannot read file identity")
    return FileIdentity(
        volume_serial=int(info.dwVolumeSerialNumber),
        file_index=(int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        is_dir=bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY),
        is_reparse_point=bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
        size=(int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
    )


def _extended(path: str) -> str:
    """Prefix with ``\\\\?\\`` so long paths work.  Never exposed to callers."""
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path.lstrip("\\")
    return "\\\\?\\" + path


def _strip_extended(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[len("\\\\?\\UNC\\") :]
    if path.startswith("\\\\?\\"):
        return path[len("\\\\?\\") :]
    return path


# --------------------------------------------------------------------------
# Canonical path value
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CanonicalPath:
    """A fully-resolved, contained path.  The only path form tools accept."""

    raw: str
    path: str
    key: str
    segments: tuple[str, ...]
    root: str
    exists: bool
    is_dir: bool
    identity: Optional[FileIdentity] = None

    @property
    def name(self) -> str:
        return self.segments[-1] if self.segments else self.path

    @property
    def parent(self) -> str:
        parent = PureWindowsPath(self.path).parent
        return str(parent)

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "exists": self.exists, "is_dir": self.is_dir}


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def comparison_key(path: str) -> str:
    """Casefolded, NFC-normalized comparison form (Windows FS is case-insensitive)."""
    return _nfc(path).casefold().rstrip("\\")


def segments_of(path: str) -> tuple[str, ...]:
    """Split a canonical absolute path into anchor + name segments."""
    pure = PureWindowsPath(path)
    anchor = pure.anchor.rstrip("\\")
    parts = [part for part in pure.parts[1:] if part not in ("", "\\")]
    return tuple([anchor, *parts])


def is_contained(child_segments: Sequence[str], root_segments: Sequence[str]) -> bool:
    """Segment-wise containment — never ``startswith`` on strings.

    ``C:\\Users\\bobby`` must not match root ``C:\\Users\\bob``.
    """
    if len(child_segments) < len(root_segments):
        return False
    for child, root in zip(child_segments, root_segments):
        if child.casefold() != root.casefold():
            return False
    return True


# --------------------------------------------------------------------------
# Path policy
# --------------------------------------------------------------------------


def default_allow_roots() -> list[str]:
    """``[Documents, Downloads, Desktop]`` (``docs/security.md`` §5 Defaults)."""
    profile = os.environ.get("USERPROFILE") or str(Path.home())
    return [str(Path(profile) / name) for name in ("Documents", "Downloads", "Desktop")]


def _expand_denied_env_prefixes() -> list[str]:
    resolved: list[str] = []
    for template in baseline.DENIED_ENV_PREFIXES:
        expanded = template
        for match in _ENV_RE.finditer(template):
            value = os.environ.get(match.group(1))
            if not value:
                expanded = ""
                break
            expanded = expanded.replace(match.group(0), value)
        if expanded:
            resolved.append(expanded)
    return resolved


class PathPolicy:
    """Canonicalization + containment for one configured filesystem scope."""

    def __init__(
        self,
        allow_roots: Iterable[str] | None = None,
        *,
        allow_unc: bool = False,
        extra_denied: Iterable[str] = (),
    ) -> None:
        roots: list[tuple[str, tuple[str, ...]]] = []
        for raw_root in list(allow_roots) if allow_roots is not None else default_allow_roots():
            root = self._normalize_root(str(raw_root))
            roots.append((root, segments_of(root)))
        self._roots = roots
        self.allow_unc = allow_unc
        denied = list(baseline.DENIED_ABSOLUTE_PREFIXES) + _expand_denied_env_prefixes()
        denied += [str(item) for item in extra_denied]
        self._denied = [
            (item.rstrip("\\"), segments_of(item.rstrip("\\"))) for item in denied if item
        ]

    # -- roots ---------------------------------------------------------------

    @staticmethod
    def _normalize_root(raw: str) -> str:
        candidate = _nfc(raw.strip().strip('"'))
        if not candidate:
            raise ValueError("allow_root must not be empty")
        pure = PureWindowsPath(candidate)
        if not pure.is_absolute():
            raise ValueError(f"allow_root must be absolute: {raw!r}")
        normalized = str(pure).rstrip("\\")
        segments = segments_of(normalized)
        # ``C:\`` as a root is refused (``docs/security.md`` §5 Defaults).
        if len(segments) <= 1:
            raise ValueError(f"a drive root may not be an allow_root: {raw!r}")
        return normalized

    @property
    def allow_roots(self) -> tuple[str, ...]:
        return tuple(root for root, _ in self._roots)

    def match_root(self, segments: Sequence[str]) -> str | None:
        for root, root_segments in self._roots:
            if is_contained(segments, root_segments):
                return root
        return None

    # -- syntactic validation (steps 1-6) ------------------------------------

    def _character_check(self, candidate: str, *, raw: str) -> None:
        """Cheap checks that are valid before ``%VAR%`` expansion.

        Applied to the raw string first so a hostile variable name cannot even
        be looked up, and then implied again by :meth:`_syntax_check` on the
        expanded string.
        """
        if not candidate or not candidate.strip():
            raise PathRejected("PATH_INVALID", "The path is empty.", raw=raw)
        if len(candidate) > baseline.MAX_PATH_CHARS:
            raise PathRejected("PATH_INVALID", "The path is too long.", raw=raw)
        if _CONTROL_RE.search(candidate):
            raise PathRejected("PATH_INVALID", "The path contains control characters.", raw=raw)
        if _INVISIBLE_RE.search(candidate):
            raise PathRejected(
                "PATH_INVALID", "The path contains invisible or bidi control characters.", raw=raw
            )
        if "\x00" in candidate:
            raise PathRejected("PATH_INVALID", "The path contains a NUL byte.", raw=raw)

        lowered = candidate.lower()
        # Step 2: device paths.
        if lowered.startswith("\\\\.\\") or lowered.startswith("//./"):
            raise PathRejected("PATH_DENIED", "Device paths are not permitted.", raw=raw)
        if "globalroot" in lowered:
            raise PathRejected("PATH_DENIED", "Device paths are not permitted.", raw=raw)
        if lowered.startswith("\\\\?\\") or lowered.startswith("//?/"):
            raise PathRejected(
                "PATH_DENIED", "Extended-length device syntax is not permitted.", raw=raw
            )

    def _syntax_check(self, candidate: str, *, raw: str) -> None:
        self._character_check(candidate, raw=raw)

        normalized = candidate.replace("/", "\\")

        # Step 4: drive-relative (``C:foo``) and rootless-relative paths.
        drive_relative = re.match(r"^[A-Za-z]:(?![\\/])", normalized)
        if drive_relative:
            raise PathRejected(
                "PATH_INVALID", "Drive-relative paths are not permitted; use an absolute path.", raw=raw
            )
        if normalized.startswith("\\") and not normalized.startswith("\\\\"):
            raise PathRejected(
                "PATH_INVALID", "Root-relative paths are not permitted; include the drive.", raw=raw
            )

        # Step 5: UNC / network locations.
        if normalized.startswith("\\\\"):
            if not self.allow_unc:
                raise PathRejected(
                    "PATH_DENIED", "Network (UNC) paths are disabled.", raw=raw
                )
        elif not re.match(r"^[A-Za-z]:\\", normalized):
            raise PathRejected(
                "PATH_INVALID", "Only absolute local paths are accepted.", raw=raw
            )

        body = normalized[2:] if normalized.startswith("\\\\") else normalized[3:]

        # Step 3: alternate data streams — a ``:`` anywhere after the drive letter.
        if ":" in body:
            raise PathRejected(
                "PATH_DENIED", "Alternate data streams are not permitted.", raw=raw
            )

        for segment in body.split("\\"):
            if not segment:
                continue
            if segment in (".", ".."):
                continue  # traversal handled by resolution + containment
            stem = segment.split(".")[0].strip().lower()
            if stem in baseline.RESERVED_DEVICE_NAMES:
                raise PathRejected(
                    "PATH_DENIED", f"Reserved device name in path: {segment}", raw=raw
                )
            if segment != segment.rstrip(" ."):
                raise PathRejected(
                    "PATH_INVALID",
                    "Path segments may not end with a space or a dot.",
                    raw=raw,
                )
            if any(ch in segment for ch in '<>"|?*'):
                raise PathRejected(
                    "PATH_INVALID", "The path contains characters Windows forbids.", raw=raw
                )

    def _expand_env(self, raw: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1).upper()
            if name not in ENV_ALLOWLIST:
                raise PathRejected(
                    "PATH_DENIED",
                    f"Environment variable %{match.group(1)}% is not on the allowlist.",
                    raw=raw,
                )
            value = os.environ.get(name)
            if not value:
                raise PathRejected(
                    "PATH_INVALID", f"Environment variable %{name}% is not set.", raw=raw
                )
            return value

        expanded = _ENV_RE.sub(replace, raw)
        if "%" in expanded:
            raise PathRejected(
                "PATH_INVALID", "Unresolved environment variable in the path.", raw=raw
            )
        return expanded

    # -- deny list (step 10) -------------------------------------------------

    def denial_reason(self, canonical: str, segments: Sequence[str]) -> str | None:
        for denied, denied_segments in self._denied:
            if is_contained(segments, denied_segments):
                return f"{denied} is permanently protected."
        for segment in segments[1:]:
            if segment.casefold() in baseline.DENIED_PATH_SEGMENTS:
                return f"'{segment}' is a protected location."
        name = segments[-1] if len(segments) > 1 else ""
        if name and baseline.is_secret_shaped_name(name):
            return "The name looks like credential material."
        return None

    # -- resolution (steps 7-9, 11) -----------------------------------------

    def canonicalize(self, raw_path: str, *, must_exist: bool = False) -> CanonicalPath:
        """Run the full pipeline.  Raises :class:`PathRejected` on any failure."""
        if not isinstance(raw_path, str):
            raise PathRejected("PATH_INVALID", "The path must be a string.")
        raw = raw_path
        self._character_check(raw, raw=raw)
        expanded = self._expand_env(_nfc(raw))
        self._syntax_check(expanded, raw=raw)

        resolved, exists, is_dir, identity = self._resolve(expanded, raw=raw)
        segments = segments_of(resolved)

        if must_exist and not exists:
            raise PathRejected("PATH_NOT_FOUND", "The target does not exist.", raw=raw)

        root = self.match_root(segments)
        if root is None:
            raise PathRejected(
                "PATH_OUT_OF_SCOPE",
                "The path is outside the folders ARTEMIS is allowed to use.",
                raw=raw,
            )

        denial = self.denial_reason(resolved, segments)
        if denial is not None:
            raise PathRejected("PATH_DENIED", denial, raw=raw)

        return CanonicalPath(
            raw=raw,
            path=resolved,
            key=comparison_key(resolved),
            segments=segments,
            root=root,
            exists=exists,
            is_dir=is_dir,
            identity=identity,
        )

    def _resolve(
        self, expanded: str, *, raw: str
    ) -> tuple[str, bool, bool, Optional[FileIdentity]]:
        """Resolve to a real path via an open handle where the object exists.

        For a non-existent leaf we resolve the deepest existing ancestor by
        handle (so junctions and 8.3 names in the ancestry are collapsed) and
        re-append the validated remaining segments.  ``..`` is resolved
        lexically *before* that walk so it cannot escape via a symlinked parent
        after the containment check.
        """
        normalized = str(PureWindowsPath(expanded.replace("/", "\\")))
        pure = PureWindowsPath(normalized)
        anchor = pure.anchor
        collapsed: list[str] = []
        for part in pure.parts[1:]:
            if part == ".":
                continue
            if part == "..":
                if not collapsed:
                    raise PathRejected(
                        "PATH_OUT_OF_SCOPE",
                        "The path traverses above the drive root.",
                        raw=raw,
                    )
                collapsed.pop()
                continue
            collapsed.append(part)

        if not IS_WINDOWS:  # pragma: no cover - Windows-only product
            lexical = str(PureWindowsPath(anchor, *collapsed)).rstrip("\\")
            return lexical, False, False, None

        # Walk from the deepest existing prefix.
        remaining: list[str] = []
        probe = list(collapsed)
        while True:
            candidate = str(PureWindowsPath(anchor, *probe)).rstrip("\\") or anchor.rstrip("\\")
            try:
                with open_handle(candidate, directory=True) as handle:
                    final = handle.final_path.rstrip("\\")
                    identity = handle.identity
                break
            except PathRejected as exc:
                if exc.code not in ("PATH_NOT_FOUND", "PATH_ACCESS_DENIED", "PATH_LOCKED"):
                    raise
                if exc.code == "PATH_ACCESS_DENIED" and not remaining and probe:
                    # The leaf exists but we cannot open it (e.g. locked system
                    # object).  Resolve the parent and keep the leaf name.
                    pass
                if not probe:
                    raise PathRejected(
                        "PATH_INVALID", "The path cannot be resolved.", raw=raw
                    ) from exc
                remaining.insert(0, probe.pop())
                identity = None
                continue

        if not remaining:
            resolved = final
            return resolved, True, identity.is_dir if identity else False, identity

        for segment in remaining:
            stem = segment.split(".")[0].strip().lower()
            if stem in baseline.RESERVED_DEVICE_NAMES:
                raise PathRejected(
                    "PATH_DENIED", f"Reserved device name in path: {segment}", raw=raw
                )
        resolved = str(PureWindowsPath(final, *remaining)).rstrip("\\")

        # The leaf may exist but have been unopenable; probe it cheaply.
        exists = os.path.lexists(resolved)
        is_dir = os.path.isdir(resolved) if exists else False
        return resolved, exists, is_dir, None

    # -- TOCTOU-safe access -------------------------------------------------

    def open_verified(
        self,
        canonical: CanonicalPath,
        *,
        write: bool = False,
        directory: bool = False,
        creation: int = OPEN_EXISTING,
    ) -> SafeHandle:
        """Open the *verified* object and re-check it before use.

        ``docs/security.md`` §5 step 11.  The handle is opened, its
        handle-derived final path is compared against the canonical path, the
        object is asserted not to be a reparse point, and containment plus the
        deny-list are re-evaluated on the handle-derived path.  A junction
        swapped in after canonicalization therefore fails closed here.
        """
        handle = open_handle(
            canonical.path,
            write=write,
            directory=directory,
            creation=creation,
            follow_reparse=True,
        )
        try:
            self.assert_handle_matches(handle, canonical)
        except BaseException:
            handle.close()
            raise
        return handle

    def assert_handle_matches(self, handle: SafeHandle, canonical: CanonicalPath) -> None:
        """Re-validate a freshly opened handle against a canonical path."""
        final_segments = segments_of(handle.final_path.rstrip("\\"))
        if comparison_key(handle.final_path) != canonical.key:
            raise PathRejected(
                "PATH_TOCTOU",
                "The target changed between validation and use.",
                raw=canonical.raw,
            )
        if self.match_root(final_segments) is None:
            raise PathRejected(
                "PATH_OUT_OF_SCOPE",
                "The resolved target is outside the allowed folders.",
                raw=canonical.raw,
            )
        denial = self.denial_reason(handle.final_path, final_segments)
        if denial is not None:
            raise PathRejected("PATH_DENIED", denial, raw=canonical.raw)

    def assert_not_reparse_point(self, canonical: CanonicalPath) -> FileIdentity:
        """Assert the object at ``canonical.path`` is not a link, by handle.

        Used immediately before an operation that must address a path rather
        than a handle (Recycle-Bin deletion).  Combined with the fully-resolved
        final path this closes the ancestor-junction-swap window.
        """
        handle = open_handle(
            canonical.path,
            directory=canonical.is_dir,
            follow_reparse=False,
            allow_delete_share=True,
        )
        try:
            if handle.identity.is_reparse_point:
                raise PathRejected(
                    "PATH_TOCTOU",
                    "The target became a link between validation and use.",
                    raw=canonical.raw,
                )
            self.assert_handle_matches(handle, canonical)
            if canonical.identity is not None:
                if (
                    handle.identity.volume_serial != canonical.identity.volume_serial
                    or handle.identity.file_index != canonical.identity.file_index
                ):
                    raise PathRejected(
                        "PATH_TOCTOU",
                        "The target was replaced between validation and use.",
                        raw=canonical.raw,
                    )
            return handle.identity
        finally:
            handle.close()


__all__ = [
    "CanonicalPath",
    "FileIdentity",
    "PathPolicy",
    "PathRejected",
    "SafeHandle",
    "comparison_key",
    "default_allow_roots",
    "is_contained",
    "open_handle",
    "segments_of",
    "CREATE_ALWAYS",
    "CREATE_NEW",
    "OPEN_ALWAYS",
    "OPEN_EXISTING",
    "TRUNCATE_EXISTING",
]
