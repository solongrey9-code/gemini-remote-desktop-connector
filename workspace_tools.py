"""Confined, synchronous filesystem operations for Gemini Remote Desktop Connector.

A remote model drives these methods, so every argument is treated as untrusted:

* Only relative paths are accepted.  Drive-relative paths, UNC paths, device
  namespaces (``\\\\?\\``, ``\\\\.\\``), alternate data streams (``name:stream``)
  and ``..`` segments are rejected before touching the filesystem.
* Every existing component is inspected with ``lstat`` and any reparse point
  (symlink, junction, volume mount point, cloud placeholder) aborts the call, so
  a link is never followed out of the root.
* The resolved target is re-checked against the real root afterwards, which also
  neutralises short-name and letter-case tricks.
* Reads, writes and searches are bounded; writes are atomic and nothing is
  overwritten unless ``overwrite=True`` is requested explicitly.

Checks run per call.  A local process that can already write inside the root is
outside this module's threat model; the goal is that a remote caller cannot use
crafted paths or links to reach anything the root does not contain.

Rejections raise :class:`WorkspaceError` carrying a stable ``code``; the MCP layer
is expected to surface that as a tool error.  Mutating methods assume the caller
has already applied its own approval policy.  This module has no MCP, network or
process dependencies so it can be verified in isolation.

Codes in common use: ``invalid_path``/``traversal``/``absolute_path``/
``reserved_name``/``bad_argument`` (rejected input), ``outside_root``/
``reparse_point``/``unsafe_target`` (confinement), ``not_found``/``exists``/
``not_a_directory``/``not_a_file``/``parent_missing``, ``binary_file``/
``not_utf8``/``too_large``/``line_too_long`` and ``io_error``.
"""

from __future__ import annotations

import io
import os
import stat as statlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["Workspace", "WorkspaceError"]


FILE_ATTRIBUTE_REPARSE_POINT = getattr(statlib, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
FILE_ATTRIBUTE_READONLY = getattr(statlib, "FILE_ATTRIBUTE_READONLY", 0x0001)
FILE_ATTRIBUTE_HIDDEN = getattr(statlib, "FILE_ATTRIBUTE_HIDDEN", 0x0002)
FILE_ATTRIBUTE_SYSTEM = getattr(statlib, "FILE_ATTRIBUTE_SYSTEM", 0x0004)

MAX_PATH_CHARS = 1024
MAX_COMPONENT_CHARS = 255
MAX_LIST_LIMIT = 1000
MAX_LIST_SCAN = 5000
MAX_READ_LINES = 2000
MAX_SCAN_CHARS = 4 * 1024 * 1024
MAX_LINE_CHARS = 256 * 1024
MAX_WRITE_BYTES = 1024 * 1024
MAX_SEARCH_QUERY_CHARS = 512
MAX_SEARCH_LIMIT = 500
MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024
MAX_SEARCH_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SEARCH_FILES = 2000
MAX_SEARCH_DEPTH = 32
BINARY_PROBE_BYTES = 8192
MATCH_TEXT_CHARS = 400

_OPEN_BINARY = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)

_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{suffix}" for suffix in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3")}
    | {f"LPT{suffix}" for suffix in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3")}
)
_INVALID_NAME_CHARS = frozenset('<>:"|?*')


class WorkspaceError(Exception):
    """A rejected or failed workspace operation with a machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _within(root: str, target: str) -> bool:
    """True when ``target`` is ``root`` or lives underneath it."""
    try:
        common = os.path.commonpath([os.path.normcase(root), os.path.normcase(target)])
    except ValueError:  # different drives, or mixed absolute/relative input
        return False
    return common == os.path.normcase(root)


def _iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return None


def _wrapped(error: OSError) -> WorkspaceError:
    if isinstance(error, FileNotFoundError):
        code = "not_found"
    elif isinstance(error, FileExistsError):
        code = "exists"
    elif isinstance(error, PermissionError):
        code = "permission_denied"
    elif isinstance(error, NotADirectoryError):
        code = "not_a_directory"
    elif isinstance(error, IsADirectoryError):
        code = "is_directory"
    elif getattr(error, "winerror", None) in (80, 183):
        code = "exists"
    else:
        code = "io_error"
    detail = error.strerror or str(error)
    return WorkspaceError(code, detail)


def _path_text(value: object, name: str = "path") -> str:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str):
        raise WorkspaceError("bad_argument", f"{name} must be a string.")
    return value


def _require_int(value: object, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceError("bad_argument", f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise WorkspaceError("bad_argument", f"{name} must be between {minimum} and {maximum}.")
    return value


def _split_relative(value: object) -> tuple[str, ...]:
    """Validate a caller-supplied path and return its relative components.

    An empty tuple means the workspace root.  Components are validated against
    Win32 naming rules so a later ``lstat`` cannot be re-routed to a device,
    a data stream or a differently named file.
    """
    text = _path_text(value)
    if not text or text != text.strip():
        raise WorkspaceError("invalid_path", "Paths must be non-empty and have no surrounding whitespace.")
    if len(text) > MAX_PATH_CHARS:
        raise WorkspaceError("invalid_path", f"Paths are limited to {MAX_PATH_CHARS} characters.")
    if "\x00" in text or any(ord(char) < 32 for char in text):
        raise WorkspaceError("invalid_path", "Control characters are not allowed in paths.")

    normalized = text.replace("\\", "/")
    if normalized.startswith("/"):
        raise WorkspaceError("absolute_path", "Rooted, UNC and device paths are not allowed; use a relative path.")
    if ":" in normalized:
        raise WorkspaceError("invalid_path", "Drive letters and alternate data streams are not allowed.")

    parts = tuple(part for part in normalized.split("/") if part not in ("", "."))
    for part in parts:
        if part == "..":
            raise WorkspaceError("traversal", "Parent-directory segments are not allowed.")
        if any(char in _INVALID_NAME_CHARS for char in part):
            raise WorkspaceError("invalid_path", f"Invalid character in path segment {part[:64]!r}.")
        if len(part) > MAX_COMPONENT_CHARS:
            raise WorkspaceError("invalid_path", "Path segments are limited to 255 characters.")
        if part[-1] in ". ":
            raise WorkspaceError("invalid_path", "Path segments may not end with a dot or space.")
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if stem in _RESERVED_NAMES or part.upper() in _RESERVED_NAMES:
            raise WorkspaceError("reserved_name", f"{part[:64]!r} is a reserved Windows device name.")
    return parts


def _query_text(value: object) -> str:
    text = _path_text(value, "query")
    if not text:
        raise WorkspaceError("bad_argument", "query must be a non-empty string.")
    if len(text) > MAX_SEARCH_QUERY_CHARS:
        raise WorkspaceError("bad_argument", f"query is limited to {MAX_SEARCH_QUERY_CHARS} characters.")
    if "\x00" in text or "\n" in text or "\r" in text:
        raise WorkspaceError("bad_argument", "query must be a single line without NUL bytes.")
    return text


def _render(parts: tuple[str, ...]) -> str:
    return "/".join(parts) if parts else "."


class Workspace:
    """A filesystem view rooted at one existing directory.

    ``root`` must be an absolute path to a directory.  The root itself may be a
    reparse point if the operator chose it; confinement is relative to its real
    location.
    """

    def __init__(self, root: Path | str) -> None:
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ValueError("Workspace root must be an absolute path.")
        try:
            info = os.stat(candidate)
        except OSError as error:
            raise ValueError(f"Workspace root is not accessible: {error.strerror or error}") from error
        if not statlib.S_ISDIR(info.st_mode):
            raise ValueError("Workspace root must be a directory.")
        self.root = candidate
        self._root_real = os.path.realpath(str(candidate))

    def __repr__(self) -> str:
        return f"Workspace({str(self.root)!r})"

    # ------------------------------------------------------------------ reads

    def list_directory(self, path: str = ".", limit: int = 100) -> dict:
        """List one directory level in name order, directories first.

        Entries that are reparse points are reported with ``type == "link"`` and
        are never followed.
        """
        limit = _require_int(limit, 1, MAX_LIST_LIMIT, "limit")
        target = self._resolve(path, must_exist=True)
        info = self._lstat(target)
        if not statlib.S_ISDIR(info.st_mode):
            raise WorkspaceError("not_a_directory", f"{_render(_split_relative(path))!r} is not a directory.")

        entries: list[dict] = []
        scan_capped = False
        try:
            with os.scandir(target) as iterator:
                for entry in iterator:
                    if len(entries) >= MAX_LIST_SCAN:
                        scan_capped = True
                        break
                    entries.append(self._describe_entry(entry))
        except OSError as error:
            raise _wrapped(error) from error

        entries.sort(key=lambda item: (item["type"] != "directory", item["name"].casefold()))
        return {
            "path": self._relative(target),
            "entries": entries[:limit],
            "shown": min(len(entries), limit),
            "limit": limit,
            "truncated": len(entries) > limit,
            "scan_capped": scan_capped,
        }

    def get_file_info(self, path: str) -> dict:
        """Describe one existing file or directory without following links."""
        target = self._resolve(path, must_exist=True)
        info = self._lstat(target)
        attributes = getattr(info, "st_file_attributes", 0)
        if statlib.S_ISDIR(info.st_mode):
            kind = "directory"
        elif statlib.S_ISREG(info.st_mode):
            kind = "file"
        else:
            kind = "other"
        return {
            "path": self._relative(target),
            "type": kind,
            "size": info.st_size,
            "created_utc": _iso_timestamp(info.st_ctime),
            "modified_utc": _iso_timestamp(info.st_mtime),
            "accessed_utc": _iso_timestamp(info.st_atime),
            "readonly": bool(attributes & FILE_ATTRIBUTE_READONLY),
            "hidden": bool(attributes & FILE_ATTRIBUTE_HIDDEN),
            "system": bool(attributes & FILE_ATTRIBUTE_SYSTEM),
        }

    def read_text(self, path: str, start_line: int = 1, max_lines: int = 200) -> dict:
        """Read a UTF-8 text file by line range.

        Lines are returned without their terminators.  A UTF-8 BOM is tolerated
        and not included in the first line.
        """
        start_line = _require_int(start_line, 1, 10_000_000, "start_line")
        max_lines = _require_int(max_lines, 1, MAX_READ_LINES, "max_lines")
        target = self._resolve(path, must_exist=True)
        info = self._lstat(target)
        if not statlib.S_ISREG(info.st_mode):
            raise WorkspaceError("not_a_file", f"{self._relative(target)!r} is not a regular file.")

        lines: list[str] = []
        last_line = start_line - 1
        has_more = False
        scanned = 0
        handle = os.fdopen(self._open_verified(target, info), "rb")
        try:
            probe = handle.read(BINARY_PROBE_BYTES)
            if b"\x00" in probe:
                raise WorkspaceError("binary_file", "The file is binary, not UTF-8 text.")
            handle.seek(0)
            stream = io.TextIOWrapper(handle, encoding="utf-8-sig", errors="strict", newline="")
            try:
                for number, line in enumerate(stream, 1):
                    length = len(line)
                    if length > MAX_LINE_CHARS:
                        raise WorkspaceError("line_too_long", f"Line {number} exceeds {MAX_LINE_CHARS} characters.")
                    scanned += length
                    if scanned > MAX_SCAN_CHARS:
                        raise WorkspaceError(
                            "too_large",
                            f"Reading stopped after {MAX_SCAN_CHARS} characters; request a smaller line range.",
                        )
                    if number < start_line:
                        continue
                    if len(lines) == max_lines:
                        has_more = True
                        break
                    lines.append(line.rstrip("\r\n"))
                    last_line = number
            except UnicodeDecodeError as error:
                raise WorkspaceError("not_utf8", "The file is not valid UTF-8 text.") from error
            finally:
                stream.detach()
        except OSError as error:
            raise _wrapped(error) from error
        finally:
            handle.close()

        return {
            "path": self._relative(target),
            "encoding": "utf-8",
            "start_line": start_line,
            "end_line": last_line if lines else None,
            "lines": lines,
            "line_count": len(lines),
            "has_more": has_more,
            "next_line": last_line + 1 if has_more else None,
        }

    def search_text(self, query: str, path: str = ".", limit: int = 50) -> dict:
        """Search a subtree for a literal, case-sensitive substring.

        The walk never follows reparse points and stops at the file, byte, depth
        or match budgets; ``stopped_reason`` reports which budget ended the scan.
        """
        query = _query_text(query)
        limit = _require_int(limit, 1, MAX_SEARCH_LIMIT, "limit")
        base = self._resolve(path, must_exist=True)
        base_info = self._lstat(base)
        if not (statlib.S_ISREG(base_info.st_mode) or statlib.S_ISDIR(base_info.st_mode)):
            raise WorkspaceError("unsupported", "Search needs a regular file or a directory.")

        matches: list[dict] = []
        files_scanned = 0
        bytes_scanned = 0
        stopped: str | None = None

        def scan_file(file_path: Path) -> bool:
            nonlocal files_scanned, bytes_scanned
            try:
                info = os.lstat(file_path)
                if not statlib.S_ISREG(info.st_mode) or _is_reparse(info):
                    return False
                if info.st_size > MAX_SEARCH_FILE_BYTES:
                    return False
                files_scanned += 1
                bytes_scanned += info.st_size
                handle = os.fdopen(self._open_verified(file_path, info), "rb")
                try:
                    data = handle.read(MAX_SEARCH_FILE_BYTES + 1)
                finally:
                    handle.close()
            except (OSError, WorkspaceError):
                return False
            if len(data) > MAX_SEARCH_FILE_BYTES or b"\x00" in data[:BINARY_PROBE_BYTES]:
                return False
            for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                if query not in line:
                    continue
                text = line.rstrip()
                match = {"path": self._relative(file_path), "line": number, "text": text[:MATCH_TEXT_CHARS]}
                if len(text) > MATCH_TEXT_CHARS:
                    match["text_truncated"] = True
                matches.append(match)
                if len(matches) >= limit:
                    return True
            return False

        if statlib.S_ISREG(base_info.st_mode):
            if scan_file(base):
                stopped = "limit"
        else:
            pending: list[tuple[Path, int]] = [(base, 0)]
            while pending and stopped is None:
                directory, depth = pending.pop()
                try:
                    with os.scandir(directory) as iterator:
                        for entry in iterator:
                            if stopped is not None:
                                break
                            try:
                                info = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            if _is_reparse(info):
                                continue
                            entry_path = Path(entry.path)
                            if statlib.S_ISDIR(info.st_mode):
                                if depth >= MAX_SEARCH_DEPTH:
                                    stopped = stopped or "depth"
                                else:
                                    pending.append((entry_path, depth + 1))
                            elif statlib.S_ISREG(info.st_mode):
                                if files_scanned >= MAX_SEARCH_FILES:
                                    stopped = "files"
                                    break
                                if bytes_scanned + info.st_size > MAX_SEARCH_TOTAL_BYTES:
                                    stopped = "bytes"
                                    break
                                if scan_file(entry_path):
                                    stopped = "limit"
                except OSError:
                    continue

        return {
            "query": query,
            "path": self._relative(base),
            "matches": matches,
            "count": len(matches),
            "truncated": stopped == "limit",
            "stopped_reason": stopped,
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
        }

    # --------------------------------------------------------------- mutations

    def write_text(self, path: str, text: str, overwrite: bool = False) -> dict:
        """Atomically write UTF-8 text (no BOM), refusing to replace by default.

        The content is staged in a sibling temporary file, flushed to disk and
        then renamed into place, so readers never observe a partial file.
        """
        if not isinstance(text, str):
            raise WorkspaceError("bad_argument", "text must be a string.")
        if not isinstance(overwrite, bool):
            raise WorkspaceError("bad_argument", "overwrite must be a boolean.")
        payload = text.encode("utf-8")
        if len(payload) > MAX_WRITE_BYTES:
            raise WorkspaceError("too_large", f"Text is limited to {MAX_WRITE_BYTES} UTF-8 bytes.")

        target = self._resolve(path)
        if target == self.root:
            raise WorkspaceError("is_directory", "The workspace root cannot be replaced by a file.")
        existing = self._existing(target)
        if existing is not None:
            if not overwrite:
                raise WorkspaceError("exists", "The target already exists; pass overwrite=true to replace it.")
            if not statlib.S_ISREG(existing.st_mode):
                raise WorkspaceError("not_a_file", "Only regular files can be replaced.")

        parent_info = self._lstat(target.parent, missing_code="parent_missing")
        if not statlib.S_ISDIR(parent_info.st_mode):
            raise WorkspaceError("not_a_directory", "The parent of the target is not a directory.")

        staged = None
        try:
            descriptor, staged = tempfile.mkstemp(prefix=".bridge-", suffix=".part", dir=str(target.parent))
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if overwrite:
                os.replace(staged, target)
            else:
                # On Windows a plain rename is exclusive and atomic: it fails
                # instead of clobbering a file that appeared in the meantime.
                os.rename(staged, target)
        except FileExistsError as error:
            raise WorkspaceError("exists", "The target already exists.") from error
        except OSError as error:
            raise _wrapped(error) from error
        finally:
            if staged is not None and os.path.lexists(staged):
                try:
                    os.unlink(staged)
                except OSError:
                    pass

        return {
            "path": self._relative(target),
            "bytes_written": len(payload),
            "created": existing is None,
            "overwritten": existing is not None,
        }

    def create_directory(self, path: str) -> dict:
        """Create one directory; an existing directory is reported, not an error."""
        target = self._resolve(path)
        existing = self._existing(target)
        if existing is not None:
            if statlib.S_ISDIR(existing.st_mode):
                return {"path": self._relative(target), "created": False}
            raise WorkspaceError("exists", "A non-directory already occupies this path.")

        parent_info = self._lstat(target.parent, missing_code="parent_missing")
        if not statlib.S_ISDIR(parent_info.st_mode):
            raise WorkspaceError("not_a_directory", "The parent of the target is not a directory.")
        try:
            os.mkdir(target)
        except FileExistsError as error:
            raise WorkspaceError("exists", "The path was created concurrently.") from error
        except OSError as error:
            raise _wrapped(error) from error
        return {"path": self._relative(target), "created": True}

    def move_path(self, source: str, destination: str) -> dict:
        """Rename a file or directory inside the workspace; never overwrites."""
        origin = self._resolve(source, must_exist=True)
        target = self._resolve(destination)
        if origin == self.root:
            raise WorkspaceError("invalid_move", "The workspace root cannot be moved.")
        origin_info = self._lstat(origin)
        if not (statlib.S_ISREG(origin_info.st_mode) or statlib.S_ISDIR(origin_info.st_mode)):
            raise WorkspaceError("unsupported", "Only regular files and directories can be moved.")
        if self._existing(target) is not None:
            raise WorkspaceError("exists", "The destination already exists.")

        parent_info = self._lstat(target.parent, missing_code="parent_missing")
        if not statlib.S_ISDIR(parent_info.st_mode):
            raise WorkspaceError("not_a_directory", "The destination parent is not a directory.")
        if statlib.S_ISDIR(origin_info.st_mode):
            origin_real = os.path.normcase(os.path.realpath(str(origin)))
            target_real = os.path.normcase(os.path.realpath(str(target)))
            if _within(origin_real, target_real):
                raise WorkspaceError("invalid_move", "A directory cannot be moved inside itself.")

        try:
            os.rename(origin, target)
        except FileExistsError as error:
            raise WorkspaceError("exists", "The destination already exists.") from error
        except OSError as error:
            raise _wrapped(error) from error
        return {
            "source": self._relative(origin),
            "destination": self._relative(target),
            "type": "directory" if statlib.S_ISDIR(origin_info.st_mode) else "file",
        }

    # --------------------------------------------------------------- internals

    def _resolve(self, path: object, *, must_exist: bool | None = None) -> Path:
        """Validate ``path`` and return a confined candidate.

        ``must_exist=True`` requires the target to exist; ``False`` requires it
        to be absent; ``None`` accepts either.
        """
        parts = _split_relative(path)
        target = self.root.joinpath(*parts) if parts else self.root

        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                break
            except OSError as error:
                raise _wrapped(error) from error
            if _is_reparse(info):
                raise WorkspaceError(
                    "reparse_point",
                    f"Refusing to traverse the reparse point at {_render(parts[: index + 1])[:200]!r}.",
                )

        real = os.path.realpath(str(target))
        if not _within(self._root_real, real):
            raise WorkspaceError("outside_root", "The resolved path leaves the workspace.")

        if must_exist is True and not os.path.lexists(target):
            raise WorkspaceError("not_found", f"{_render(parts)!r} does not exist.")
        if must_exist is False and os.path.lexists(target):
            raise WorkspaceError("exists", f"{_render(parts)!r} already exists.")
        return target

    def _lstat(self, target: Path, *, missing_code: str = "not_found") -> os.stat_result:
        try:
            info = os.lstat(target)
        except FileNotFoundError as error:
            raise WorkspaceError(missing_code, f"{self._relative(target)!r} does not exist.") from error
        except OSError as error:
            raise _wrapped(error) from error
        if _is_reparse(info):
            raise WorkspaceError("reparse_point", f"{self._relative(target)!r} is a reparse point.")
        return info

    def _existing(self, target: Path) -> os.stat_result | None:
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise _wrapped(error) from error
        if _is_reparse(info):
            raise WorkspaceError("reparse_point", f"{self._relative(target)!r} is a reparse point.")
        return info

    def _open_verified(self, target: Path, expected: os.stat_result) -> int:
        """Open ``target`` for reading and prove it is still the inspected object."""
        try:
            descriptor = os.open(target, os.O_RDONLY | _OPEN_BINARY)
        except OSError as error:
            raise _wrapped(error) from error
        try:
            opened = os.fstat(descriptor)
            if _is_reparse(opened) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise WorkspaceError("unsafe_target", "The file changed or became a link while it was being opened.")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _relative(self, target: Path) -> str:
        relative = os.path.relpath(str(target), str(self.root))
        return "." if relative == "." else relative.replace(os.sep, "/")

    def _describe_entry(self, entry: os.DirEntry) -> dict:
        size = None
        modified = None
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            kind = "unknown"
        else:
            modified = _iso_timestamp(info.st_mtime)
            if _is_reparse(info):
                kind = "link"
            elif statlib.S_ISDIR(info.st_mode):
                kind = "directory"
            elif statlib.S_ISREG(info.st_mode):
                kind = "file"
                size = info.st_size
            else:
                kind = "other"
        return {
            "name": entry.name,
            "path": self._relative(Path(entry.path)),
            "type": kind,
            "size": size,
            "modified_utc": modified,
        }
