#!/usr/bin/env python3
"""Patch VS Code Remote-SSH to survive concurrent exec-server auth-token races.

The Remote-SSH 0.124.0 and 0.125.2026081318 Unix exec-server bootstrap uses
one shared log path, `.cli.${COMMIT_ID}.log`, for every concurrent connection.
Each bootstrap has a different auth token, so one window can read another
window's `Listening on ...` address and then authenticate to that server with
its own token, producing `CodeError(AuthChallengeBadToken)`.

This patcher:

1. Makes the Unix exec-server bootstrap log path process-specific, eliminating
   the observed shared-log race.
2. Wraps the top-level Remote-SSH resolve operation in a retry loop which catches
   only errors containing `AuthChallengeBadToken`. Each retry reruns the complete
   resolver/bootstrap path, which obtains a fresh matching server/token pair.

It accepts an installed extension directory, `out/extension.js`, a parent
extensions directory, or a .zip/.vsix archive. With no TARGET it discovers the
newest Remote-SSH installation in the usual VS Code extension directories.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PATCH_MARKER          = "[remote-ssh-auth-retry-patch:v1]"
EXTENSION_ID           = "ms-vscode-remote.remote-ssh"
EXTENSION_JS_SUFFIX    = "/out/extension.js"
INSTALLER_SUFFIX       = "/out/install-script/scripts/linux-exec-server-installer.sh"
PACKAGE_JSON_SUFFIX    = "/package.json"
OLD_LOG_LINE           = 'CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.log"'
NEW_LOG_LINE           = 'CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.$$.log"'
IDENTIFIER             = r"[A-Za-z_$][A-Za-z0-9_$]*"
RESOLVE_CALL_RE        = re.compile(
    rf"(?P<result>{IDENTIFIER})=await\(0,(?P<resolver>{IDENTIFIER})\.resolve\)"
    rf"\((?P<options>{IDENTIFIER}),(?P<authority>{IDENTIFIER}),"
    rf"this\.extensionContext,this\.disposables\),"
    rf"(?P<install>{IDENTIFIER})=(?P=result)\.serverInstallationResult;"
)


class PatchError(RuntimeError):
    """Raised when the target does not have the expected Remote-SSH structure."""


@dataclass(frozen=True)
class RetrySettings:
    """Settings embedded into the JavaScript retry loop.

    Attributes:
        max_retries: Number of retries after the first failure; zero means unlimited.
        min_delay_ms: Minimum randomized delay before a retry, in milliseconds.
        max_delay_ms: Maximum randomized delay cap before a retry, in milliseconds.
    """

    max_retries: int
    min_delay_ms: int
    max_delay_ms: int


@dataclass(frozen=True)
class PatchResult:
    """Result of patching one extension payload.

    Attributes:
        extension_js: Patched JavaScript bundle text.
        installer: Patched Unix exec-server installer text, if one was supplied.
        js_changed: Whether the JavaScript bundle changed.
        installer_changed: Whether the installer changed.
    """

    extension_js: str
    installer: str | None
    js_changed: bool
    installer_changed: bool


@dataclass(frozen=True)
class ExtensionPaths:
    """Important files belonging to an extracted Remote-SSH extension.

    Attributes:
        root: Extension package root directory.
        extension_js: Main Remote-SSH JavaScript bundle.
        installer: Unix exec-server installer script.
        package_json: Extension package metadata.
    """

    root: Path
    extension_js: Path
    installer: Path
    package_json: Path


def read_text(path: Path) -> str:
    """Read UTF-8 text without normalizing line endings.

    Args:
        path: File whose exact textual payload should be read.

    Returns:
        The decoded UTF-8 file contents.
    """
    return path.read_text(encoding="utf-8")


def write_text_atomic(path: Path, text: str) -> None:
    """Atomically replace a UTF-8 text file while retaining its mode bits.

    Args:
        path: Existing file to replace.
        text: Complete replacement contents.
    """
    assert path.is_file(), path
    original_mode = path.stat().st_mode
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def parse_package_json(text: str) -> dict[str, object]:
    """Decode extension metadata and verify that it is a JSON object.

    Args:
        text: Raw package.json contents.

    Returns:
        Parsed package metadata.
    """
    value = json.loads(text)
    if not isinstance(value, dict):
        raise PatchError("package.json is not a JSON object")
    return value


def is_remote_ssh_package(metadata: dict[str, object]) -> bool:
    """Determine whether package metadata describes Microsoft's Remote-SSH extension.

    Args:
        metadata: Parsed package.json object.

    Returns:
        True only for `ms-vscode-remote.remote-ssh`.
    """
    publisher = metadata.get("publisher")
    name      = metadata.get("name")
    return publisher == "ms-vscode-remote" and name == "remote-ssh"


def version_key(version: object) -> tuple[int, ...]:
    """Convert a dotted Remote-SSH version into a numerically sortable tuple.

    Args:
        version: package.json version value.

    Returns:
        Numeric version components; non-numeric suffixes are ignored.
    """
    text = str(version)
    parts = tuple(int(match) for match in re.findall(r"\d+", text))
    return parts or (0,)


def validate_retry_settings(settings: RetrySettings) -> None:
    """Reject retry settings which would create an invalid or abusive loop.

    Args:
        settings: User-selected retry limits and delay bounds.
    """
    if settings.max_retries < 0:
        raise PatchError("--max-retries must be >= 0")
    if settings.min_delay_ms < 0:
        raise PatchError("--min-delay-ms must be >= 0")
    if settings.max_delay_ms < settings.min_delay_ms:
        raise PatchError("--max-delay-ms must be >= --min-delay-ms")


def make_retry_expression(match: re.Match[str], settings: RetrySettings) -> str:
    """Build the minified JavaScript replacement for one resolver call.

    Args:
        match: Unique resolver-call match in the bundled extension JavaScript.
        settings: Retry limits and randomized backoff bounds to embed.

    Returns:
        JavaScript expression replacing the original one-shot resolve call.
    """
    result    = match.group("result")
    resolver  = match.group("resolver")
    options   = match.group("options")
    authority = match.group("authority")
    install   = match.group("install")
    max_retry = settings.max_retries
    min_delay = settings.min_delay_ms
    max_delay = settings.max_delay_ms
    assert result and resolver and options and authority and install
    return (
        f'{result}=await(async()=>{{let __rsar_count=0;for(;;){{try{{return await(0,{resolver}.resolve)'
        f'({options},{authority},this.extensionContext,this.disposables)}}catch(__rsar_error){{'
        f'const __rsar_message=String(__rsar_error?.message??__rsar_error);'
        f'if(!__rsar_message.includes("AuthChallengeBadToken"))throw __rsar_error;'
        f'__rsar_count++;if({max_retry}>0&&__rsar_count>{max_retry})throw __rsar_error;'
        f'const __rsar_cap=Math.min({max_delay},{min_delay}*Math.pow(2,Math.min(__rsar_count,5)));'
        f'const __rsar_delay={min_delay}+Math.floor(Math.random()*Math.max(1,__rsar_cap-{min_delay}+1));'
        f'this.logger.warn("{PATCH_MARKER} AuthChallengeBadToken for "+{authority}+"; retry "+__rsar_count+'
        f'" in "+__rsar_delay+"ms");await new Promise(__rsar_done=>setTimeout(__rsar_done,__rsar_delay))}}}}}})(),'
        f'{install}={result}.serverInstallationResult;'
    )


def patch_extension_js(source: str, settings: RetrySettings) -> tuple[str, bool]:
    """Inject the defensive AuthChallengeBadToken retry loop into extension.js.

    Args:
        source: Original minified Remote-SSH `out/extension.js` contents.
        settings: Retry limits and randomized backoff bounds to embed.

    Returns:
        A pair of patched source text and whether a modification was made.
    """
    if PATCH_MARKER in source:
        return source, False
    matches = list(RESOLVE_CALL_RE.finditer(source))
    if len(matches) != 1:
        raise PatchError(f"expected exactly one top-level Remote-SSH resolve call; found {len(matches)}")
    match = matches[0]
    before = source[max(0, match.start() - 6000):match.start()]
    after  = source[match.end():min(len(source), match.end() + 10000)]
    if "window.withProgress" not in before or "handleResolverFailure" not in after:
        raise PatchError("resolver call matched, but surrounding bundle structure is unfamiliar")
    replacement = make_retry_expression(match, settings)
    patched = source[:match.start()] + replacement + source[match.end():]
    if patched.count(PATCH_MARKER) != 1:
        raise AssertionError("retry patch marker invariant failed")
    return patched, True


def patch_installer(source: str) -> tuple[str, bool]:
    """Make the Unix exec-server bootstrap log path process-specific.

    Args:
        source: `linux-exec-server-installer.sh` contents.

    Returns:
        A pair of patched installer text and whether a modification was made.
    """
    if NEW_LOG_LINE in source:
        return source, False
    count = source.count(OLD_LOG_LINE)
    if count != 1:
        raise PatchError(f"expected exactly one shared CLI_LOG_FILE assignment; found {count}")
    patched = source.replace(OLD_LOG_LINE, NEW_LOG_LINE, 1)
    assert patched.count(NEW_LOG_LINE) == 1
    return patched, True


def patch_payload(extension_js: str, installer: str | None, settings: RetrySettings, patch_log_race: bool) -> PatchResult:
    """Apply all requested modifications to one Remote-SSH package payload.

    Args:
        extension_js: Main JavaScript bundle contents.
        installer: Unix exec-server installer contents, if available.
        settings: Retry settings embedded into the JavaScript bundle.
        patch_log_race: Whether to fix the shared Unix bootstrap logfile race.

    Returns:
        Patched contents plus per-file change flags.
    """
    patched_js, js_changed = patch_extension_js(extension_js, settings)
    if not patch_log_race:
        return PatchResult(patched_js, installer, js_changed, False)
    if installer is None:
        raise PatchError("Unix exec-server installer is missing; use --no-log-race-fix only if intentional")
    patched_installer, installer_changed = patch_installer(installer)
    return PatchResult(patched_js, patched_installer, js_changed, installer_changed)


def extension_paths_from_root(root: Path) -> ExtensionPaths:
    """Resolve and validate important files under an extracted extension root.

    Args:
        root: Candidate Remote-SSH package root.

    Returns:
        Validated paths belonging to a Remote-SSH package.
    """
    package_json = root / "package.json"
    extension_js = root / "out" / "extension.js"
    installer    = root / "out" / "install-script" / "scripts" / "linux-exec-server-installer.sh"
    if not package_json.is_file() or not extension_js.is_file():
        raise PatchError(f"not a Remote-SSH extension root: {root}")
    metadata = parse_package_json(read_text(package_json))
    if not is_remote_ssh_package(metadata):
        raise PatchError(f"package at {root} is not {EXTENSION_ID}")
    return ExtensionPaths(root, extension_js, installer, package_json)


def roots_under_directory(directory: Path) -> list[Path]:
    """Find plausible Remote-SSH extension roots immediately under a directory.

    Args:
        directory: Extension root itself or a parent containing extension roots.

    Returns:
        Candidate package roots which identify as Remote-SSH.
    """
    candidates = [directory]
    candidates.extend(path for path in directory.glob(f"{EXTENSION_ID}-*") if path.is_dir())
    roots: list[Path] = []
    for candidate in candidates:
        package_json = candidate / "package.json"
        if not package_json.is_file():
            continue
        try:
            metadata = parse_package_json(read_text(package_json))
        except (OSError, ValueError, PatchError):
            continue
        if is_remote_ssh_package(metadata):
            roots.append(candidate)
    return roots


def newest_extension_root(roots: Sequence[Path]) -> Path:
    """Select the numerically newest Remote-SSH extension from candidates.

    Args:
        roots: Candidate extracted extension roots.

    Returns:
        Root whose package.json has the highest numeric version.
    """
    if not roots:
        raise PatchError("no Remote-SSH extension installation found")
    keyed: list[tuple[tuple[int, ...], Path]] = []
    for root in roots:
        metadata = parse_package_json(read_text(root / "package.json"))
        keyed.append((version_key(metadata.get("version")), root))
    keyed.sort(key=lambda item: (item[0], str(item[1])))
    return keyed[-1][1]


def discover_extension_root() -> Path:
    """Find the newest Remote-SSH install in common VS Code extension directories.

    Returns:
        Newest discovered Remote-SSH extension root.
    """
    home = Path.home()
    roots: list[Path] = []
    for relative in (".vscode/extensions", ".vscode-insiders/extensions", ".vscode-oss/extensions"):
        directory = home / relative
        if directory.is_dir():
            roots.extend(roots_under_directory(directory))
    return newest_extension_root(roots)


def resolve_directory_target(target: Path | None) -> ExtensionPaths:
    """Turn a user target into validated extracted-extension paths.

    Args:
        target: Explicit extension root, extension.js, or parent directory; None enables discovery.

    Returns:
        Paths for the selected Remote-SSH extension.
    """
    if target is None:
        return extension_paths_from_root(discover_extension_root())
    target = target.expanduser().resolve()
    if target.is_file():
        if target.name != "extension.js" or target.parent.name != "out":
            raise PatchError("file TARGET must be Remote-SSH's out/extension.js")
        return extension_paths_from_root(target.parent.parent)
    if not target.is_dir():
        raise PatchError(f"target does not exist: {target}")
    return extension_paths_from_root(newest_extension_root(roots_under_directory(target)))


def backup_file(path: Path) -> Path:
    """Create a non-destructive `.bak` copy of a file if one does not already exist.

    Args:
        path: Existing file that is about to be modified.

    Returns:
        Backup path, whether newly created or already present.
    """
    backup = path.with_name(path.name + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    return backup


def patch_directory(paths: ExtensionPaths, settings: RetrySettings, patch_log_race: bool, make_backup: bool, check_only: bool) -> PatchResult:
    """Patch an extracted or installed Remote-SSH package.

    Args:
        paths: Validated extension file locations.
        settings: Retry settings to embed.
        patch_log_race: Whether to patch the shared Unix bootstrap logfile.
        make_backup: Whether to preserve `.bak` copies before modifying files.
        check_only: Whether to validate/preview without writing changes.

    Returns:
        Patch result describing the transformed payload.
    """
    extension_js = read_text(paths.extension_js)
    installer = read_text(paths.installer) if paths.installer.is_file() else None
    result = patch_payload(extension_js, installer, settings, patch_log_race)
    if check_only or not (result.js_changed or result.installer_changed):
        return result

    if make_backup and result.js_changed:
        backup_file(paths.extension_js)
    if make_backup and result.installer_changed:
        backup_file(paths.installer)
    if result.js_changed:
        write_text_atomic(paths.extension_js, result.extension_js)
    if result.installer_changed:
        assert result.installer is not None
        write_text_atomic(paths.installer, result.installer)
    return result


def normalized_archive_name(name: str) -> str:
    """Normalize an archive member name for suffix comparisons.

    Args:
        name: Zip member pathname.

    Returns:
        Slash-prefixed POSIX-style pathname.
    """
    return "/" + name.replace("\\", "/").lstrip("/")


def find_archive_member(names: Sequence[str], suffix: str, required: bool = True) -> str | None:
    """Locate exactly one archive member ending in a package-relative suffix.

    Args:
        names: All archive member names.
        suffix: Slash-prefixed package-relative suffix to match.
        required: Whether absence is an error.

    Returns:
        Matching archive member name, or None when optional and absent.
    """
    matches = [name for name in names if normalized_archive_name(name).endswith(suffix)]
    if not matches and not required:
        return None
    if len(matches) != 1:
        raise PatchError(f"expected exactly one archive member ending {suffix!r}; found {len(matches)}")
    return matches[0]


def validate_archive_package(archive: zipfile.ZipFile, names: Sequence[str]) -> None:
    """Verify that an archive contains Microsoft's Remote-SSH package metadata.

    Args:
        archive: Open source zip/vsix archive.
        names: Archive member names.
    """
    candidates = [name for name in names if normalized_archive_name(name).endswith(PACKAGE_JSON_SUFFIX)]
    matches = 0
    for candidate in candidates:
        try:
            metadata = parse_package_json(archive.read(candidate).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, PatchError):
            continue
        if is_remote_ssh_package(metadata):
            matches += 1
    if matches != 1:
        raise PatchError(f"expected one {EXTENSION_ID} package.json in archive; found {matches}")


def default_archive_output(source: Path) -> Path:
    """Construct a non-destructive default output name for a patched archive.

    Args:
        source: Input .zip or .vsix path.

    Returns:
        Sibling output path with `.auth-retry-patched` before the suffix.
    """
    return source.with_name(f"{source.stem}.auth-retry-patched{source.suffix}")


def patch_archive(source: Path, output: Path, settings: RetrySettings, patch_log_race: bool, check_only: bool) -> PatchResult:
    """Patch a zip/vsix package while preserving all unrelated members and metadata.

    Args:
        source: Input Remote-SSH archive.
        output: Destination archive; may equal source for atomic in-place replacement.
        settings: Retry settings to embed.
        patch_log_race: Whether to patch the shared Unix bootstrap logfile.
        check_only: Whether to validate/preview without writing an archive.

    Returns:
        Patch result describing transformed extension payloads.
    """
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    with zipfile.ZipFile(source, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        validate_archive_package(archive, names)
        js_name = find_archive_member(names, EXTENSION_JS_SUFFIX)
        installer_name = find_archive_member(names, INSTALLER_SUFFIX, required=patch_log_race)
        assert js_name is not None
        extension_js = archive.read(js_name).decode("utf-8")
        installer = archive.read(installer_name).decode("utf-8") if installer_name is not None else None
        result = patch_payload(extension_js, installer, settings, patch_log_race)
        if check_only or not (result.js_changed or result.installer_changed):
            return result

        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary, "w") as patched_archive:
                patched_archive.comment = archive.comment
                for info in infos:
                    data = archive.read(info.filename)
                    if info.filename == js_name:
                        data = result.extension_js.encode("utf-8")
                    elif installer_name is not None and info.filename == installer_name:
                        assert result.installer is not None
                        data = result.installer.encode("utf-8")
                    patched_archive.writestr(info, data)
            os.replace(temporary, output)
        finally:
            if temporary.exists():
                temporary.unlink()
    return result


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for the patcher.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", type=Path, help="extension directory, out/extension.js, parent extensions directory, .zip, or .vsix; omit to auto-discover")
    parser.add_argument("-o", "--output", type=Path, help="output archive path; archives default to *.auth-retry-patched.zip/.vsix")
    parser.add_argument("--max-retries", type=int, default=0, help="AuthChallengeBadToken retries after the first failure; 0 = unlimited (default: 0)")
    parser.add_argument("--min-delay-ms", type=int, default=200, help="minimum retry delay in milliseconds (default: 200)")
    parser.add_argument("--max-delay-ms", type=int, default=2000, help="maximum retry backoff cap in milliseconds (default: 2000)")
    parser.add_argument("--no-log-race-fix", action="store_true", help="inject only the retry loop; do not make the Unix exec-server logfile process-specific")
    parser.add_argument("--no-backup", action="store_true", help="for extracted installs, do not create adjacent .bak files")
    parser.add_argument("--check", action="store_true", help="validate and report what would change without writing anything")
    return parser


def describe_result(result: PatchResult, patch_log_race: bool) -> str:
    """Render a concise human-readable patch status.

    Args:
        result: Patch transformation outcome.
        patch_log_race: Whether the logfile race fix was requested.

    Returns:
        One-line status summary.
    """
    js_status = "changed" if result.js_changed else "already patched"
    if patch_log_race:
        installer_status = "changed" if result.installer_changed else "already patched"
    else:
        installer_status = "skipped"
    return f"retry loop: {js_status}; Unix logfile race fix: {installer_status}"


def main(argv: Sequence[str] | None = None) -> int:
    """Patch the requested Remote-SSH package and report the result.

    Args:
        argv: Command-line arguments excluding the executable name; None uses sys.argv.

    Returns:
        Process exit status: zero on success, two for validation/patch failures.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = RetrySettings(args.max_retries, args.min_delay_ms, args.max_delay_ms)
    patch_log_race = not args.no_log_race_fix
    try:
        validate_retry_settings(settings)
        target = args.target.expanduser() if args.target is not None else None
        is_archive = target is not None and target.suffix.lower() in {".zip", ".vsix"}
        if args.output is not None and not is_archive:
            raise PatchError("--output is supported only when TARGET is a .zip/.vsix archive")
        if is_archive:
            assert target is not None
            output = args.output if args.output is not None else default_archive_output(target)
            result = patch_archive(target, output, settings, patch_log_race, args.check)
            action = "would patch" if args.check else "patched"
            print(f"{action}: {target}")
            if not args.check:
                print(f"output:  {output.resolve()}")
        else:
            paths = resolve_directory_target(target)
            metadata = parse_package_json(read_text(paths.package_json))
            result = patch_directory(paths, settings, patch_log_race, not args.no_backup, args.check)
            action = "would patch" if args.check else "patched"
            print(f"{action}: {paths.root}")
            print(f"version: {metadata.get('version')}")
        print(describe_result(result, patch_log_race))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, PatchError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
