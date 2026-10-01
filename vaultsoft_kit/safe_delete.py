from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ReparseChecker = Callable[[Path], bool]
PROFILE_SENSITIVE_CHILDREN = ("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    path: Path | None = None
    reason: str = ""


@dataclass(frozen=True)
class DeleteResult:
    target: str
    category: str | None = None
    bytes_removed: int = 0
    deleted: bool = False
    blocked: bool = False
    error: str = ""


@dataclass
class CleanupOutcome:
    bytes_removed: int = 0
    deleted_count: int = 0
    blocked: list[DeleteResult] = field(default_factory=list)
    failed: list[DeleteResult] = field(default_factory=list)

    def add(self, result: DeleteResult) -> None:
        if result.deleted:
            self.deleted_count += 1
            self.bytes_removed += max(0, result.bytes_removed)
        elif result.blocked:
            self.blocked.append(result)
        elif result.error:
            self.failed.append(result)

    def extend(self, other: "CleanupOutcome") -> None:
        self.bytes_removed += max(0, other.bytes_removed)
        self.deleted_count += other.deleted_count
        self.blocked.extend(other.blocked)
        self.failed.extend(other.failed)


def _case_path(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _normalize_logical_path(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.normpath(os.path.expandvars(os.path.expanduser(str(path)))))


def _is_drive_or_filesystem_root(path: Path) -> bool:
    return path.parent == path


def _is_unc_or_device_path(path: Path) -> bool:
    return str(path).startswith("\\\\")


def _is_same_or_child(path: Path, root: Path) -> bool:
    path_s = _case_path(path)
    root_s = _case_path(root)
    try:
        return os.path.commonpath([path_s, root_s]) == root_s
    except ValueError:
        return False


def _is_same_path(left: Path, right: Path) -> bool:
    return _case_path(left) == _case_path(right)


def _is_same_or_inside_any(path: Path, roots: list[Path]) -> bool:
    return any(_is_same_path(path, root) or _is_same_or_child(path, root) for root in roots)


def _path_chain(path: Path) -> list[Path]:
    if not path.anchor:
        return [path]
    current = Path(path.anchor)
    chain = []
    for part in path.parts[1:]:
        current = current / part
        chain.append(current)
    return chain


def _is_reparse_point(path: Path, reparse_checker: ReparseChecker | None = None) -> bool:
    if path.is_symlink():
        return True
    if reparse_checker is not None:
        return reparse_checker(path)
    st = os.lstat(path)
    attrs = getattr(st, "st_file_attributes", None)
    if os.name == "nt" and attrs is None:
        raise OSError("Windows file attributes were not available")
    attrs = attrs or 0
    tag = getattr(st, "st_reparse_tag", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool((attrs & reparse_flag) or tag)


def _ensure_no_reparse_chain(
    path: Path,
    *,
    reparse_checker: ReparseChecker | None = None,
) -> ValidationResult:
    for component in _path_chain(path):
        try:
            if not component.exists() and not component.is_symlink():
                return ValidationResult(False, component, f"path component does not exist: {component}")
            if _is_reparse_point(component, reparse_checker):
                return ValidationResult(False, component, f"reparse-point path component is not safe: {component}")
        except (OSError, RuntimeError) as exc:
            return ValidationResult(False, component, f"could not inspect path component: {component}: {exc}")
    return ValidationResult(True, path)


def _ensure_no_reparse_subtree(
    path: Path,
    *,
    reparse_checker: ReparseChecker | None = None,
) -> ValidationResult:
    if not path.is_dir():
        return ValidationResult(True, path)

    errors: list[OSError] = []

    def onerror(exc):
        errors.append(exc)

    for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False, onerror=onerror):
        current = Path(dirpath)
        for name in list(dirnames) + filenames:
            child = current / name
            try:
                if _is_reparse_point(child, reparse_checker):
                    return ValidationResult(False, child, f"reparse-point child is not safe: {child}")
            except (OSError, RuntimeError) as exc:
                return ValidationResult(False, child, f"could not inspect child path: {child}: {exc}")
        if errors:
            return ValidationResult(False, current, f"could not inspect cleanup subtree: {errors[0]}")
    return ValidationResult(True, path)


def default_protected_roots(
    *,
    user_profile: str | os.PathLike[str] | None = None,
    environ: dict[str, str] | None = None,
) -> list[Path]:
    env = os.environ if environ is None else environ
    roots: list[str | os.PathLike[str]] = [
        user_profile or Path.home(),
        env.get("SystemRoot", r"C:\Windows"),
        env.get("WINDIR", r"C:\Windows"),
        env.get("ProgramFiles", r"C:\Program Files"),
        env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        env.get("ProgramData", r"C:\ProgramData"),
    ]
    system_root = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
    roots.append(os.path.join(system_root, "System32"))
    resolved = []
    for root in roots:
        if root:
            try:
                resolved.append(_normalize_logical_path(root))
            except (OSError, RuntimeError):
                pass
    return resolved


def default_sensitive_descendants(
    *,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    environ: dict[str, str] | None = None,
) -> list[Path]:
    env = os.environ if environ is None else environ
    roots = [_normalize_logical_path(root) for root in protected_roots or [] if root]
    user_profile = env.get("USERPROFILE")
    if user_profile:
        roots.append(_normalize_logical_path(user_profile))
    windows_root = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
    system_wide_sensitive = [
        env.get("ProgramFiles", r"C:\Program Files"),
        env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        env.get("ProgramData", r"C:\ProgramData"),
    ]

    sensitive: list[Path] = []
    for root in roots:
        for child in PROFILE_SENSITIVE_CHILDREN:
            sensitive.append(root / child)
        sensitive.append(root / "System32" / "config")
    sensitive.append(_normalize_logical_path(windows_root) / "System32" / "config")
    for root in system_wide_sensitive:
        if root:
            sensitive.append(_normalize_logical_path(root))

    unique: dict[str, Path] = {}
    for path in sensitive:
        unique[_case_path(path)] = path
    return list(unique.values())


def validate_cleanup_path(
    path: str | os.PathLike[str] | None,
    approved_roots: list[str | os.PathLike[str]],
    *,
    allow_root: bool = False,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    reparse_checker: ReparseChecker | None = None,
) -> ValidationResult:
    if path is None or str(path).strip() == "":
        return ValidationResult(False, reason="empty path")

    raw = Path(os.path.expandvars(os.path.expanduser(str(path))))
    if str(raw).strip() == ".":
        return ValidationResult(False, reason="relative current directory path")
    if not raw.is_absolute():
        return ValidationResult(False, reason="relative path")
    if ".." in raw.parts:
        return ValidationResult(False, reason="parent-directory traversal is not allowed")

    logical_path = _normalize_logical_path(raw)

    if _is_unc_or_device_path(logical_path):
        return ValidationResult(False, logical_path, "UNC and device namespace cleanup paths are not supported")

    if _is_drive_or_filesystem_root(logical_path):
        return ValidationResult(False, logical_path, "drive or filesystem root is not a cleanup target")

    chain_check = _ensure_no_reparse_chain(logical_path, reparse_checker=reparse_checker)
    if not chain_check.ok:
        return chain_check

    protected_paths = []
    for protected in protected_roots or default_protected_roots():
        protected_path = _normalize_logical_path(protected)
        protected_paths.append(protected_path)
        if _is_same_path(logical_path, protected_path):
            return ValidationResult(False, logical_path, f"protected root is not a cleanup target: {protected_path}")

    sensitive_paths = default_sensitive_descendants(protected_roots=protected_paths)
    if _is_same_or_inside_any(logical_path, sensitive_paths):
        return ValidationResult(False, logical_path, "sensitive protected descendant is not a cleanup target")

    logical_roots: list[Path] = []
    for root in approved_roots:
        if root is None or str(root).strip() == "":
            continue
        try:
            root_path = _normalize_logical_path(root)
        except (OSError, RuntimeError):
            continue
        if _is_unc_or_device_path(root_path):
            continue
        if _is_drive_or_filesystem_root(root_path):
            continue
        if any(_is_same_path(root_path, protected) for protected in protected_paths):
            continue
        if _is_same_or_inside_any(root_path, sensitive_paths):
            continue
        root_chain_check = _ensure_no_reparse_chain(root_path, reparse_checker=reparse_checker)
        if not root_chain_check.ok:
            continue
        logical_roots.append(root_path)

    if not logical_roots:
        return ValidationResult(False, logical_path, "no approved cleanup root is available")

    for root in logical_roots:
        if _is_same_path(logical_path, root):
            if allow_root:
                return ValidationResult(True, logical_path)
            return ValidationResult(False, logical_path, "refusing to delete cleanup root itself")
        if _is_same_or_child(logical_path, root):
            return ValidationResult(True, logical_path)

    return ValidationResult(False, logical_path, "path is outside approved cleanup roots")


def is_safe_cleanup_path(
    path: str | os.PathLike[str] | None,
    approved_roots: list[str | os.PathLike[str]],
    *,
    allow_root: bool = False,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    reparse_checker: ReparseChecker | None = None,
) -> bool:
    return validate_cleanup_path(
        path,
        approved_roots,
        allow_root=allow_root,
        protected_roots=protected_roots,
        reparse_checker=reparse_checker,
    ).ok


def is_reparse_point(path: str | os.PathLike[str]) -> bool:
    """True for symlinks, junctions and other reparse points; fails closed if it can't tell."""
    try:
        return _is_reparse_point(Path(path))
    except (OSError, RuntimeError):
        return True


def iter_scan_files(path: str | os.PathLike[str]):
    """Yield (file path, os.stat_result) for every file a scan may count under a cleanup root.

    Same reparse-point rule as cleanup: nothing is yielded for a root reached through a
    reparse point, and junctions, symlinks and other reparse points inside it are neither
    followed nor counted.
    """
    try:
        logical_path = _normalize_logical_path(path)
    except (OSError, RuntimeError):
        return
    if not _ensure_no_reparse_chain(logical_path).ok:
        return
    if logical_path.is_file():
        try:
            yield str(logical_path), os.lstat(logical_path)
        except (OSError, PermissionError):
            pass
        return
    try:
        for dirpath, dirnames, filenames in os.walk(logical_path, topdown=True, followlinks=False):
            dirnames[:] = [d for d in dirnames if not is_reparse_point(os.path.join(dirpath, d))]
            for filename in filenames:
                fp = os.path.join(dirpath, filename)
                if is_reparse_point(fp):
                    continue
                try:
                    yield fp, os.lstat(fp)
                except (OSError, PermissionError):
                    pass
    except (OSError, PermissionError):
        pass


def get_scan_size(path: str | os.PathLike[str]) -> int:
    """Bytes a scan should report for a cleanup root: only what cleanup could reach."""
    return sum(max(0, st.st_size) for _, st in iter_scan_files(path))


def get_path_size(path: str | os.PathLike[str]) -> int:
    p = Path(path)
    if p.is_file() or p.is_symlink():
        try:
            return max(0, p.stat().st_size)
        except (OSError, PermissionError):
            return 0
    total = 0
    try:
        for dirpath, _, filenames in os.walk(p):
            for filename in filenames:
                fp = os.path.join(dirpath, filename)
                try:
                    if not os.path.islink(fp):
                        total += os.path.getsize(fp)
                except (OSError, PermissionError):
                    pass
    except (OSError, PermissionError):
        pass
    return max(0, total)


def delete_validated_path(
    path: str | os.PathLike[str],
    *,
    approved_roots: list[str | os.PathLike[str]],
    category: str | None = None,
    allow_root: bool = False,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    reparse_checker: ReparseChecker | None = None,
) -> DeleteResult:
    validation = validate_cleanup_path(
        path,
        approved_roots,
        allow_root=allow_root,
        protected_roots=protected_roots,
        reparse_checker=reparse_checker,
    )
    target = str(path)
    if not validation.ok:
        return DeleteResult(target, category=category, blocked=True, error=validation.reason)

    resolved = validation.path
    if resolved is None:
        return DeleteResult(target, category=category, blocked=True, error="path could not be resolved")

    try:
        if not resolved.exists() and not resolved.is_symlink():
            return DeleteResult(str(resolved), category=category)
        subtree_check = _ensure_no_reparse_subtree(resolved, reparse_checker=reparse_checker)
        if not subtree_check.ok:
            return DeleteResult(str(subtree_check.path or resolved), category=category, blocked=True, error=subtree_check.reason)
        freed = get_path_size(resolved)
        if resolved.is_file() or resolved.is_symlink():
            resolved.unlink()
        elif resolved.is_dir():
            shutil.rmtree(resolved)
        else:
            return DeleteResult(str(resolved), category=category, blocked=True, error="unsupported filesystem item")
        return DeleteResult(str(resolved), category=category, bytes_removed=freed, deleted=True)
    except (OSError, PermissionError) as exc:
        return DeleteResult(str(resolved), category=category, error=str(exc))


def safe_delete_path(
    path: str | os.PathLike[str],
    *,
    approved_roots: list[str | os.PathLike[str]],
    category: str | None = None,
    allow_root: bool = False,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    reparse_checker: ReparseChecker | None = None,
) -> DeleteResult:
    return delete_validated_path(
        path,
        approved_roots=approved_roots,
        category=category,
        allow_root=allow_root,
        protected_roots=protected_roots,
        reparse_checker=reparse_checker,
    )


def cleanup_paths(
    paths: list[str | os.PathLike[str]],
    *,
    approved_roots: list[str | os.PathLike[str]],
    category: str | None = None,
    allow_root: bool = False,
    protected_roots: list[str | os.PathLike[str]] | None = None,
    reparse_checker: ReparseChecker | None = None,
    deleter=None,
) -> CleanupOutcome:
    outcome = CleanupOutcome()
    active_deleter = deleter or delete_validated_path
    for path in paths:
        result = active_deleter(
            path,
            approved_roots=approved_roots,
            category=category,
            allow_root=allow_root,
            protected_roots=protected_roots,
            reparse_checker=reparse_checker,
        )
        outcome.add(result)
    return outcome
