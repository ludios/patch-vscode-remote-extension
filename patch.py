#!/usr/bin/env python3
"""Patch VS Code Remote-SSH's concurrent exec-server bootstrap logfile race.

Remote-SSH 0.124.0 and 0.125.2026081318 use one shared remote logfile:

    ${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.log

Concurrent project windows can therefore overwrite/read one another's bootstrap
log. Each bootstrap has its own authentication token, so a window can discover
another window's exec-server port and authenticate with the wrong token,
producing CodeError(AuthChallengeBadToken).

This patch changes the logfile to include the bootstrap shell PID:

    ${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.$$.log

No JavaScript bundle is modified and no retry behavior is added.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Sequence


EXTENSION_ID        = "ms-vscode-remote.remote-ssh"
INSTALLER_RELATIVE  = Path("out/install-script/scripts/linux-exec-server-installer.sh")
OLD_LOG_LINE        = 'CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.log"'
NEW_LOG_LINE        = 'CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.$$.log"'
DISCOVERY_RELATIVE_DIRS = (".vscode/extensions", ".vscode-insiders/extensions", ".vscode-oss/extensions")


class PatchError(RuntimeError):
    """Raised when the requested target cannot be safely patched."""


def read_text(path: Path) -> str:
    """Read a UTF-8 text file.

    Args:
        path: File whose contents should be read.

    Returns:
        Decoded UTF-8 contents.
    """
    return path.read_text(encoding="utf-8")


def parse_package(path: Path) -> dict[str, object]:
    """Read and validate an extension package.json object.

    Args:
        path: package.json belonging to a candidate extension root.

    Returns:
        Parsed JSON object.
    """
    value = json.loads(read_text(path))
    if not isinstance(value, dict):
        raise PatchError(f"package metadata is not an object: {path}")
    return value


def is_remote_ssh(metadata: dict[str, object]) -> bool:
    """Test whether package metadata identifies Microsoft's Remote-SSH extension.

    Args:
        metadata: Parsed package.json object.

    Returns:
        True only for ms-vscode-remote.remote-ssh.
    """
    publisher = metadata.get("publisher")
    name      = metadata.get("name")
    return publisher == "ms-vscode-remote" and name == "remote-ssh"


def version_key(version: object) -> tuple[int, ...]:
    """Convert a VS Code extension version into a sortable numeric tuple.

    Args:
        version: package.json version value.

    Returns:
        Numeric components extracted from the version string.
    """
    parts = tuple(int(part) for part in re.findall(r"\d+", str(version)))
    return parts or (0,)


def validate_extension_root(root: Path) -> Path:
    """Validate a Remote-SSH extension root and return its installer template.

    Args:
        root: Candidate directory containing package.json and out/.

    Returns:
        Path to linux-exec-server-installer.sh.
    """
    package_path  = root / "package.json"
    installer_path = root / INSTALLER_RELATIVE
    if not package_path.is_file():
        raise PatchError(f"missing package.json under extension root: {root}")
    metadata = parse_package(package_path)
    if not is_remote_ssh(metadata):
        raise PatchError(f"not {EXTENSION_ID}: {root}")
    if not installer_path.is_file():
        raise PatchError(f"missing installer template: {installer_path}")
    return installer_path


def roots_under(directory: Path) -> list[Path]:
    """Find Remote-SSH extension roots at or immediately below a directory.

    Args:
        directory: Extension root or parent extensions directory.

    Returns:
        Candidate Remote-SSH extension roots.
    """
    candidates = [directory]
    candidates.extend(path for path in directory.glob(f"{EXTENSION_ID}-*") if path.is_dir())
    roots: list[Path] = []
    for candidate in candidates:
        package_path = candidate / "package.json"
        if not package_path.is_file():
            continue
        try:
            metadata = parse_package(package_path)
        except (OSError, ValueError, PatchError):
            continue
        if is_remote_ssh(metadata):
            roots.append(candidate)
    return roots


def newest_root(roots: Sequence[Path]) -> Path:
    """Choose the numerically newest Remote-SSH extension root.

    Args:
        roots: Candidate Remote-SSH installations.

    Returns:
        Root with the highest package.json version.
    """
    if not roots:
        raise PatchError("no Remote-SSH installation found")
    keyed: list[tuple[tuple[int, ...], Path]] = []
    for root in roots:
        metadata = parse_package(root / "package.json")
        keyed.append((version_key(metadata.get("version")), root))
    keyed.sort(key=lambda item: (item[0], str(item[1])))
    return keyed[-1][1]


def unique_paths(paths: Sequence[Path]) -> list[Path]:
    """Deduplicate filesystem paths using the host platform's path semantics.

    Args:
        paths: Candidate filesystem paths, possibly containing aliases or duplicates.

    Returns:
        Paths in first-seen order with platform-equivalent duplicates removed.
    """
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = os.path.normcase(os.path.abspath(os.fspath(path)))
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def candidate_home_directories() -> list[Path]:
    """Find plausible user-home directories for the current operating system.

    Returns:
        Candidate home directories, preferring native environment variables and
        falling back to pathlib's home-directory resolution.
    """
    candidates: list[Path] = []
    if os.name == "nt":
        user_profile = os.environ.get("USERPROFILE")
        home_drive   = os.environ.get("HOMEDRIVE")
        home_path    = os.environ.get("HOMEPATH")
        if user_profile:
            candidates.append(Path(user_profile))
        if home_drive and home_path:
            candidates.append(Path(home_drive + home_path))
    else:
        home = os.environ.get("HOME")
        if home:
            candidates.append(Path(home))
    try:
        candidates.append(Path.home())
    except RuntimeError:
        pass
    return unique_paths(candidates)


def discover_root() -> Path:
    """Find the newest Remote-SSH installation in standard VS Code directories.

    Returns:
        Newest discovered extension root.
    """
    roots: list[Path] = []
    for home in candidate_home_directories():
        for relative in DISCOVERY_RELATIVE_DIRS:
            directory = home / relative
            if directory.is_dir():
                roots.extend(roots_under(directory))
    return newest_root(roots)


def resolve_installer(target: Path | None) -> Path:
    """Resolve a CLI target into the installer template that must be patched.

    Args:
        target: Extension root, parent extensions directory, installer file, or
            None to auto-discover the newest installation.

    Returns:
        Validated path to linux-exec-server-installer.sh.
    """
    if target is None:
        return validate_extension_root(discover_root())
    resolved = target.expanduser().resolve()
    if resolved.is_file():
        if resolved.name != INSTALLER_RELATIVE.name:
            raise PatchError(f"file target must be {INSTALLER_RELATIVE.name}: {resolved}")
        root = resolved
        for _ in INSTALLER_RELATIVE.parts:
            root = root.parent
        expected = validate_extension_root(root)
        if expected != resolved:
            raise PatchError(f"installer is not at the expected package path: {resolved}")
        return resolved
    if not resolved.is_dir():
        raise PatchError(f"target does not exist: {resolved}")
    roots = roots_under(resolved)
    return validate_extension_root(newest_root(roots))


def patch_text(source: str) -> tuple[str, bool]:
    """Replace the shared bootstrap logfile with a process-specific logfile.

    Args:
        source: Original installer template contents.

    Returns:
        Pair of transformed contents and whether a change is required.
    """
    if NEW_LOG_LINE in source:
        if OLD_LOG_LINE in source:
            raise PatchError("installer contains both patched and unpatched logfile assignments")
        return source, False
    count = source.count(OLD_LOG_LINE)
    if count != 1:
        raise PatchError(f"expected exactly one shared CLI_LOG_FILE assignment; found {count}")
    patched = source.replace(OLD_LOG_LINE, NEW_LOG_LINE, 1)
    assert patched.count(NEW_LOG_LINE) == 1
    assert OLD_LOG_LINE not in patched
    return patched, True


def write_text_atomic(path: Path, text: str) -> None:
    """Atomically replace a file while preserving its permission bits.

    Args:
        path: Existing file to replace.
        text: Complete replacement contents.
    """
    assert path.is_file(), path
    mode = path.stat().st_mode
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def backup_file(path: Path) -> Path:
    """Create an adjacent .bak copy unless one already exists.

    Args:
        path: File that is about to be modified.

    Returns:
        Backup pathname.
    """
    backup = path.with_name(path.name + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    return backup


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line parser.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", type=Path, help="extension root, parent extensions directory, or installer script; omit to auto-discover")
    parser.add_argument("--check", action="store_true", help="validate and report without changing the installer")
    parser.add_argument("--no-backup", action="store_true", help="do not preserve installer.sh.bak before modifying it")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Patch the selected Remote-SSH installation.

    Args:
        argv: Command-line arguments excluding the executable name, or None to
            use sys.argv.

    Returns:
        Zero on success, or two when validation/patching fails.
    """
    args = build_parser().parse_args(argv)
    try:
        installer = resolve_installer(args.target)
        source    = read_text(installer)
        patched, changed = patch_text(source)
        if args.check:
            status = "needs patch" if changed else "already patched"
            print(f"{status}: {installer}")
            return 0
        if not changed:
            print(f"already patched: {installer}")
            return 0
        if not args.no_backup:
            backup = backup_file(installer)
            print(f"backup:  {backup}")
        write_text_atomic(installer, patched)
        print(f"patched: {installer}")
        print(f"changed: {OLD_LOG_LINE}")
        print(f"     to: {NEW_LOG_LINE}")
        return 0
    except (OSError, ValueError, PatchError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
