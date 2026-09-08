"""Phase 5 path-security tests (``docs/security.md`` §9.1, roadmap Phase 5).

Gating: the corpus below plus the Hypothesis property must record **zero
escapes**.  An "escape" is any input that yields a :class:`CanonicalPath` whose
resolved path is not segment-wise contained in an allow_root, or that is
contained in a baseline-protected location.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from artemis.policy import baseline
from artemis.policy.paths import (
    CanonicalPath,
    PathPolicy,
    PathRejected,
    comparison_key,
    default_allow_roots,
    is_contained,
    segments_of,
)

WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "allowed"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "inner.txt").write_text("inner", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("nope", encoding="utf-8")
    return root


@pytest.fixture
def policy(sandbox: Path) -> PathPolicy:
    return PathPolicy([str(sandbox)])


def _mklink(args: list[str]) -> bool:
    """Create a junction/symlink via cmd's mklink.  Returns success."""
    completed = subprocess.run(
        ["cmd", "/c", "mklink", *args],
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.returncode == 0


# ---------------------------------------------------------------------------
# Containment primitive
# ---------------------------------------------------------------------------


def test_segment_containment_rejects_prefix_collision():
    """``C:\\Users\\bobby`` must not match root ``C:\\Users\\bob``."""
    assert not is_contained(segments_of(r"C:\Users\bobby"), segments_of(r"C:\Users\bob"))
    assert is_contained(segments_of(r"C:\Users\bob\x"), segments_of(r"C:\Users\bob"))
    assert is_contained(segments_of(r"C:\Users\BOB\x"), segments_of(r"C:\users\bob"))


def test_segment_containment_rejects_sibling():
    assert not is_contained(segments_of(r"C:\a\b2"), segments_of(r"C:\a\b"))


def test_segment_containment_rejects_parent():
    assert not is_contained(segments_of(r"C:\a"), segments_of(r"C:\a\b"))


# ---------------------------------------------------------------------------
# Allow roots
# ---------------------------------------------------------------------------


def test_drive_root_refused_as_allow_root():
    with pytest.raises(ValueError):
        PathPolicy(["C:\\"])
    with pytest.raises(ValueError):
        PathPolicy(["C:"])


def test_relative_root_refused():
    with pytest.raises(ValueError):
        PathPolicy(["not-absolute"])


def test_default_allow_roots_are_documents_downloads_desktop():
    roots = [Path(item).name for item in default_allow_roots()]
    assert roots == ["Documents", "Downloads", "Desktop"]


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------

#: Syntactic rejections that hold on any platform.
SYNTACTIC_REJECTIONS: list[tuple[str, str]] = [
    ("", "PATH_INVALID"),
    ("   ", "PATH_INVALID"),
    ("relative\\path.txt", "PATH_INVALID"),
    (".\\notes.txt", "PATH_INVALID"),
    ("..\\notes.txt", "PATH_INVALID"),
    ("C:notes.txt", "PATH_INVALID"),  # drive-relative
    ("C:sub\\notes.txt", "PATH_INVALID"),
    ("\\notes.txt", "PATH_INVALID"),  # root-relative
    ("\\\\?\\C:\\Windows", "PATH_DENIED"),  # extended device syntax
    ("\\\\.\\PhysicalDrive0", "PATH_DENIED"),
    ("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1", "PATH_DENIED"),
    ("//./PIPE/x", "PATH_DENIED"),
    ("\\\\server\\share\\file.txt", "PATH_DENIED"),  # UNC off by default
    ("C:\\dir\\CON", "PATH_DENIED"),
    ("C:\\dir\\con.txt", "PATH_DENIED"),
    ("C:\\dir\\PRN", "PATH_DENIED"),
    ("C:\\dir\\aux.log", "PATH_DENIED"),
    ("C:\\dir\\NUL", "PATH_DENIED"),
    ("C:\\dir\\COM1", "PATH_DENIED"),
    ("C:\\dir\\LPT9.txt", "PATH_DENIED"),
    ("C:\\dir\\file.txt:evil", "PATH_DENIED"),  # ADS
    ("C:\\dir\\file.txt::$DATA", "PATH_DENIED"),
    ("C:\\dir\\file.txt\x00.png", "PATH_INVALID"),
    ("C:\\dir\\file\x07.txt", "PATH_INVALID"),
    ("C:\\dir\\file\u202e.txt", "PATH_INVALID"),  # bidi override
    ("C:\\dir\\file\u200b.txt", "PATH_INVALID"),  # zero width
    ("C:\\dir\\trailing ", "PATH_INVALID"),
    ("C:\\dir\\trailing.", "PATH_INVALID"),
    ("C:\\dir\\file<>.txt", "PATH_INVALID"),
    ("C:\\dir\\file|pipe.txt", "PATH_INVALID"),
    ("C:\\dir\\file*.txt", "PATH_INVALID"),
    ("C:\\dir\\%PATH%\\x.txt", "PATH_DENIED"),  # env not on allowlist
    ("C:\\dir\\%NOT_SET_VAR%\\x.txt", "PATH_DENIED"),
]


@pytest.mark.parametrize("raw,expected", SYNTACTIC_REJECTIONS)
def test_syntactic_rejections(policy: PathPolicy, raw: str, expected: str):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(raw)
    assert excinfo.value.code == expected, f"{raw!r} -> {excinfo.value.code}"


@WINDOWS_ONLY
def test_traversal_out_of_root_is_rejected(policy: PathPolicy, sandbox: Path):
    escape = str(sandbox / ".." / "outside" / "secret.txt")
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(escape)
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_deep_traversal_returning_inside_root_is_allowed(policy: PathPolicy, sandbox: Path):
    inside = str(sandbox / "sub" / ".." / "notes.txt")
    resolved = policy.canonicalize(inside)
    assert comparison_key(resolved.path) == comparison_key(str(sandbox / "notes.txt"))


@WINDOWS_ONLY
def test_traversal_above_drive_root_rejected(policy: PathPolicy):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize("C:\\..\\..\\Windows\\System32\\config\\SAM")
    assert excinfo.value.code in ("PATH_OUT_OF_SCOPE", "PATH_DENIED")


@WINDOWS_ONLY
def test_outside_root_absolute_rejected(policy: PathPolicy, tmp_path: Path):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(tmp_path / "outside" / "secret.txt"))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_prefix_collision_root_rejected(tmp_path: Path):
    bob = tmp_path / "bob"
    bobby = tmp_path / "bobby"
    bob.mkdir()
    bobby.mkdir()
    (bobby / "x.txt").write_text("x", encoding="utf-8")
    policy = PathPolicy([str(bob)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(bobby / "x.txt"))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_case_insensitive_containment(policy: PathPolicy, sandbox: Path):
    upper = str(sandbox).upper() + "\\NOTES.TXT"
    resolved = policy.canonicalize(upper)
    assert resolved.exists
    assert comparison_key(resolved.path) == comparison_key(str(sandbox / "notes.txt"))


@WINDOWS_ONLY
def test_forward_slashes_normalized(policy: PathPolicy, sandbox: Path):
    resolved = policy.canonicalize(str(sandbox).replace("\\", "/") + "/notes.txt")
    assert resolved.exists


@WINDOWS_ONLY
def test_short_name_8dot3_is_resolved_to_long_name(tmp_path: Path):
    """``PROGRA~1``-style names must resolve; containment uses the long form."""
    import ctypes
    from ctypes import wintypes

    root = tmp_path / "Long Directory Name"
    root.mkdir()
    (root / "file.txt").write_text("x", encoding="utf-8")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.GetShortPathNameW.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(1024)
    written = kernel32.GetShortPathNameW(str(root), buffer, 1024)
    short = buffer.value if written else ""
    if not short or "~" not in short:
        pytest.skip("8.3 short names are disabled on this volume")

    policy = PathPolicy([str(root)])
    resolved = policy.canonicalize(short + "\\file.txt")
    assert "~" not in resolved.path
    assert comparison_key(resolved.path) == comparison_key(str(root / "file.txt"))


@WINDOWS_ONLY
def test_over_long_path_rejected(policy: PathPolicy):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize("C:\\" + "a" * 33_000)
    assert excinfo.value.code == "PATH_INVALID"


@WINDOWS_ONLY
def test_unc_allowed_only_when_enabled():
    enabled = PathPolicy([r"\\server\share\dir"], allow_unc=True)
    # Still rejected because the target cannot be resolved, but *not* as a
    # scheme denial — proving the switch is what gates UNC.
    with pytest.raises(PathRejected) as excinfo:
        enabled.canonicalize(r"\\server\share\dir\file.txt")
    assert excinfo.value.code != "PATH_DENIED"


@WINDOWS_ONLY
def test_env_allowlist_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "profile"
    (home / "Documents").mkdir(parents=True)
    (home / "Documents" / "a.txt").write_text("a", encoding="utf-8")
    monkeypatch.setenv("USERPROFILE", str(home))
    policy = PathPolicy([str(home / "Documents")])
    resolved = policy.canonicalize("%USERPROFILE%\\Documents\\a.txt")
    assert resolved.exists


@WINDOWS_ONLY
def test_env_expansion_cannot_smuggle_ads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Post-expansion re-validation blocks an ADS injected through a variable."""
    home = tmp_path / "profile"
    (home / "Documents").mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(home) + "\\Documents\\x.txt:stream")
    policy = PathPolicy([str(home / "Documents")])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize("%USERPROFILE%")
    assert excinfo.value.code == "PATH_DENIED"


# ---------------------------------------------------------------------------
# Protected paths / secret-shaped names
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
@pytest.mark.parametrize(
    "protected",
    [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\notepad.exe",
        r"C:\Program Files\anything\x.txt",
        r"C:\ProgramData\Microsoft\Crypto\keys.dat",
    ],
)
def test_protected_absolute_prefixes_denied(protected: str):
    """Even if someone configures the protected tree as a root, it is denied."""
    policy = PathPolicy([str(Path(protected).parent)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(protected)
    assert excinfo.value.code in ("PATH_DENIED", "PATH_NOT_FOUND", "PATH_OUT_OF_SCOPE")


@pytest.mark.parametrize(
    "name",
    [
        "server.pem",
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "key.ppk",
        "cert.pfx",
        "store.p12",
        "vault.kdbx",
        "keys.jks",
        ".env",
        ".env.local",
        ".netrc",
        ".git-credentials",
        "credentials.json",
        "secrets.yaml",
        "my-token.txt",
        "api_token",
        "database_password.txt",
    ],
)
def test_secret_shaped_names_are_recognised(name: str):
    assert baseline.is_secret_shaped_name(name), name


@pytest.mark.parametrize("name", ["notes.txt", "report.pdf", "image.png", "keyboard.md"])
def test_ordinary_names_are_not_secret_shaped(name: str):
    assert not baseline.is_secret_shaped_name(name), name


@WINDOWS_ONLY
def test_secret_shaped_path_denied_for_read_and_write(policy: PathPolicy, sandbox: Path):
    (sandbox / "id_rsa").write_text("KEY", encoding="utf-8")
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(sandbox / "id_rsa"))
    assert excinfo.value.code == "PATH_DENIED"
    # A *write* to a secret-shaped name that does not yet exist is equally denied.
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(sandbox / "new.pem"))
    assert excinfo.value.code == "PATH_DENIED"


@WINDOWS_ONLY
def test_browser_profile_segment_denied(sandbox: Path):
    target = sandbox / "User Data" / "Default" / "Login Data"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    policy = PathPolicy([str(sandbox)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(target))
    assert excinfo.value.code == "PATH_DENIED"


@WINDOWS_ONLY
def test_ssh_directory_segment_denied(sandbox: Path):
    target = sandbox / ".ssh" / "config"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    policy = PathPolicy([str(sandbox)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(target))
    assert excinfo.value.code == "PATH_DENIED"


# ---------------------------------------------------------------------------
# Symlinks / junctions / reparse points
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_junction_pointing_outside_root_is_rejected(tmp_path: Path):
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "loot.txt").write_text("loot", encoding="utf-8")
    link = inside / "escape"
    if not _mklink(["/J", str(link), str(outside)]):
        pytest.skip("cannot create a junction on this volume")
    policy = PathPolicy([str(inside)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(link / "loot.txt"))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_directory_symlink_outside_root_is_rejected(tmp_path: Path):
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "loot.txt").write_text("loot", encoding="utf-8")
    link = inside / "slink"
    if not _mklink(["/D", str(link), str(outside)]):
        pytest.skip("symlink creation requires Developer Mode or admin")
    policy = PathPolicy([str(inside)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(link / "loot.txt"))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_file_symlink_outside_root_is_rejected(tmp_path: Path):
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    target = outside / "loot.txt"
    target.write_text("loot", encoding="utf-8")
    link = inside / "link.txt"
    if not _mklink([str(link), str(target)]):
        pytest.skip("symlink creation requires Developer Mode or admin")
    policy = PathPolicy([str(inside)])
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(link))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_junction_inside_root_resolves_to_real_target(tmp_path: Path):
    inside = tmp_path / "allowed"
    (inside / "real").mkdir(parents=True)
    (inside / "real" / "a.txt").write_text("a", encoding="utf-8")
    link = inside / "alias"
    if not _mklink(["/J", str(link), str(inside / "real")]):
        pytest.skip("cannot create a junction on this volume")
    policy = PathPolicy([str(inside)])
    resolved = policy.canonicalize(str(link / "a.txt"))
    assert comparison_key(resolved.path) == comparison_key(str(inside / "real" / "a.txt"))


# ---------------------------------------------------------------------------
# TOCTOU — the junction swap
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_junction_swap_between_validation_and_open_is_rejected(tmp_path: Path):
    """The documented junction-swap race must fail closed.

    Validate ``allowed\\data\\file.txt``, then replace ``data`` with a junction
    to a directory outside the root that contains a same-named file.  The
    handle-verified open must refuse, because the handle's final path no longer
    matches the canonical path.
    """
    inside = tmp_path / "allowed"
    data = inside / "data"
    data.mkdir(parents=True)
    (data / "file.txt").write_text("legit", encoding="utf-8")
    outside = tmp_path / "attacker"
    outside.mkdir()
    (outside / "file.txt").write_text("stolen", encoding="utf-8")

    policy = PathPolicy([str(inside)])
    canonical = policy.canonicalize(str(data / "file.txt"))

    # The swap.
    (data / "file.txt").unlink()
    data.rmdir()
    if not _mklink(["/J", str(data), str(outside)]):
        pytest.skip("cannot create a junction on this volume")

    with pytest.raises(PathRejected) as excinfo:
        policy.open_verified(canonical)
    assert excinfo.value.code in ("PATH_TOCTOU", "PATH_OUT_OF_SCOPE")


@WINDOWS_ONLY
def test_reparse_point_swap_detected_by_assert_not_reparse_point(tmp_path: Path):
    inside = tmp_path / "allowed"
    inside.mkdir()
    victim = inside / "target"
    victim.mkdir()
    outside = tmp_path / "attacker"
    outside.mkdir()
    policy = PathPolicy([str(inside)])
    canonical = policy.canonicalize(str(victim))

    victim.rmdir()
    if not _mklink(["/J", str(victim), str(outside)]):
        pytest.skip("cannot create a junction on this volume")

    with pytest.raises(PathRejected) as excinfo:
        policy.assert_not_reparse_point(canonical)
    assert excinfo.value.code == "PATH_TOCTOU"


@WINDOWS_ONLY
def test_file_replaced_by_different_object_is_detected(tmp_path: Path, sandbox: Path):
    """Identity (volume serial + file index) is re-checked, not just the name."""
    policy = PathPolicy([str(sandbox)])
    canonical = policy.canonicalize(str(sandbox / "notes.txt"), must_exist=True)
    assert canonical.identity is not None

    (sandbox / "notes.txt").unlink()
    (sandbox / "notes.txt").write_text("different object", encoding="utf-8")

    with pytest.raises(PathRejected) as excinfo:
        policy.assert_not_reparse_point(canonical)
    assert excinfo.value.code == "PATH_TOCTOU"


@WINDOWS_ONLY
def test_open_verified_succeeds_for_unchanged_target(policy: PathPolicy, sandbox: Path):
    canonical = policy.canonicalize(str(sandbox / "notes.txt"), must_exist=True)
    with policy.open_verified(canonical) as handle:
        assert comparison_key(handle.final_path) == canonical.key
        assert handle.identity.size == 5


# ---------------------------------------------------------------------------
# Nonexistent targets
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_nonexistent_leaf_inside_root_is_allowed_for_creation(policy: PathPolicy, sandbox: Path):
    resolved = policy.canonicalize(str(sandbox / "new.txt"))
    assert not resolved.exists
    assert resolved.root == str(sandbox)


@WINDOWS_ONLY
def test_must_exist_rejects_missing_target(policy: PathPolicy, sandbox: Path):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(sandbox / "missing.txt"), must_exist=True)
    assert excinfo.value.code == "PATH_NOT_FOUND"


@WINDOWS_ONLY
def test_nonexistent_leaf_outside_root_rejected(policy: PathPolicy, tmp_path: Path):
    with pytest.raises(PathRejected) as excinfo:
        policy.canonicalize(str(tmp_path / "outside" / "new.txt"))
    assert excinfo.value.code == "PATH_OUT_OF_SCOPE"


@WINDOWS_ONLY
def test_nonexistent_deep_path_resolves_ancestor_by_handle(tmp_path: Path):
    root = tmp_path / "Long Directory Name"
    (root / "sub").mkdir(parents=True)
    policy = PathPolicy([str(root)])
    resolved = policy.canonicalize(str(root / "sub" / "a" / "b.txt"))
    assert not resolved.exists
    assert resolved.path.startswith(str(root))


# ---------------------------------------------------------------------------
# Hypothesis property: zero escapes
# ---------------------------------------------------------------------------

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_SEGMENT_ALPHABET = st.sampled_from(
    [
        "a",
        "b",
        "sub",
        "..",
        ".",
        "notes.txt",
        "CON",
        "nul",
        "x:y",
        " ",
        "..\\..",
        "%USERPROFILE%",
        "\u202e",
        "id_rsa",
        "..%5c..",
        "User Data",
    ]
)


@settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(segments=st.lists(_SEGMENT_ALPHABET, min_size=1, max_size=6))
def test_fuzz_never_escapes_root(policy: PathPolicy, sandbox: Path, segments: list[str]):
    candidate = str(sandbox) + "\\" + "\\".join(segments)
    try:
        resolved = policy.canonicalize(candidate)
    except PathRejected:
        return
    assert is_contained(resolved.segments, segments_of(str(sandbox))), resolved.path
    assert policy.denial_reason(resolved.path, resolved.segments) is None, resolved.path


@settings(max_examples=200, deadline=None)
@given(raw=st.text(min_size=0, max_size=64))
def test_fuzz_arbitrary_text_never_yields_out_of_scope_path(raw: str, tmp_path_factory):
    root = tmp_path_factory.mktemp("fuzzroot")
    (root / "keep").mkdir()
    policy = PathPolicy([str(root / "keep")])
    try:
        resolved = policy.canonicalize(raw)
    except PathRejected:
        return
    except (ValueError, OSError):
        return
    assert is_contained(resolved.segments, segments_of(str(root / "keep"))), resolved.path
