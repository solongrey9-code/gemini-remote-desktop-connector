"""Locally approved Windows actions for the Gemini PC bridge.

The MCP layer calls these helpers only after the user approved the exact local
operation. Importing this module changes no machine or process settings; the
module itself performs no network access, writes no files and leaves no
background workers running (PowerShell output readers are joined before return).
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import io
import locale
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any
from xml.etree import ElementTree

import pywintypes
import win32api
import win32con
import win32gui
import win32process
import win32ui


__all__ = ["list_processes", "run_powershell", "capture_screen"]


MAX_QUERY_CHARS = 256
MAX_PROCESS_LIMIT = 500
MAX_COMMAND_CHARS = 8000
MAX_ENCODED_COMMAND_CHARS = 30000
MAX_STDOUT_BYTES = 32 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_TIMEOUT_SECONDS = 300
MAX_JPEG_EDGE = 1600
JPEG_QUALITY = 72

# The preamble keeps redirected output valid UTF-8 and suppresses the
# first-use module progress record. The trailing guard makes a failing native
# command report its own exit code instead of PowerShell's generic 1.
_POWERSHELL_PREAMBLE = (
    "$ProgressPreference = 'SilentlyContinue'\r\n"
    "try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }\r\n"
)
_POWERSHELL_EXIT_GUARD = "\r\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }\r\n"

_CLIXML_HEADER = "#< CLIXML"
_CLIXML_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def _system_root() -> Path:
    return Path(os.environ.get("SystemRoot") or r"C:\Windows")


def _powershell_exe() -> Path:
    return _system_root() / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _taskkill_exe() -> Path:
    return _system_root() / "System32" / "taskkill.exe"


def list_processes(query: str = "", limit: int = 100) -> dict[str, Any]:
    """List running processes with their executable name and PID only.

    ``query`` is a case-insensitive substring of the executable name. ``limit``
    is clamped to 1..500 and the query is clamped to 256 characters. Processes
    whose image name cannot be read (idle/system/protected) are omitted.
    """
    if not isinstance(query, str):
        raise TypeError("query must be a string")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")

    needle = query[:MAX_QUERY_CHARS].strip().casefold()
    limit = max(1, min(limit, MAX_PROCESS_LIMIT))

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query_name = kernel32.QueryFullProcessImageNameW
    query_name.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    query_name.restype = wintypes.BOOL

    entries: list[dict[str, Any]] = []
    for pid in win32process.EnumProcesses():
        if pid <= 0:
            continue
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        except pywintypes.error:
            continue
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not query_name(int(handle), 0, buffer, ctypes.byref(size)):
                continue
            name = os.path.basename(buffer.value)
        finally:
            win32api.CloseHandle(handle)
        if name:
            entries.append({"name": name, "pid": int(pid)})

    entries.sort(key=lambda entry: (entry["name"].casefold(), entry["pid"]))
    matched = [entry for entry in entries if needle in entry["name"].casefold()]
    return {
        "processes": matched[:limit],
        "total": len(entries),
        "matched": len(matched),
        "truncated": len(matched) > limit,
        "limit": limit,
    }


def _read_limited(stream: Any, limit: int) -> tuple[bytes, bool]:
    """Drain a pipe, keeping at most ``limit`` bytes from the head."""
    kept = bytearray()
    truncated = False
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            room = limit - len(kept)
            if room > 0:
                kept.extend(chunk[:room])
            if len(chunk) > max(room, 0):
                truncated = True
    except (OSError, ValueError):
        pass
    return bytes(kept), truncated


def _decode_text(data: bytes) -> str:
    if not data:
        return ""
    encodings = ["utf-8"]
    preferred = locale.getpreferredencoding(False)
    if preferred and preferred.lower() not in {"utf-8", "utf8"}:
        encodings.append(preferred)
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", "replace")


def _simplify_stderr(text: str) -> str:
    """Turn PowerShell's CLIXML error records back into readable text."""
    if not text.lstrip("\ufeff \t\r\n").startswith(_CLIXML_HEADER):
        return text
    _, _, body = text.partition("\n")
    body = body.rstrip("\x00")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return text
    parts: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "S" and element.get("S") == "Error" and element.text:
            parts.append(element.text)
    if not parts:
        return text
    return _CLIXML_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), "".join(parts))


def _resolve_cwd(cwd: Any) -> tuple[Path | None, str | None]:
    try:
        path = Path(os.fspath(cwd))
    except TypeError:
        return None, "cwd must be a filesystem path"
    if not path.is_absolute():
        return None, "cwd must be an absolute path"
    try:
        if not path.is_dir():
            return None, f"cwd is not an existing directory: {path}"
    except OSError as error:
        return None, f"cwd is not usable: {error}"
    return path, None


def _terminate_tree(process: subprocess.Popen) -> None:
    taskkill = _taskkill_exe()
    if taskkill.is_file():
        try:
            subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_powershell(command: str, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run one approved PowerShell command in ``cwd`` and return its result.

    The command is passed with ``-EncodedCommand`` (no command-line quoting or
    code-page ambiguity), ``-NoProfile`` and ``-NonInteractive``, uses the fixed
    Windows PowerShell executable, runs without a visible console and cannot
    exceed 8000 characters or 300 seconds. On timeout the process tree is
    terminated with ``taskkill /T /F`` where available.

    Returns ``{"exit_code", "stdout", "stderr", "timed_out", "truncated",
    "duration_ms", "error"}``. ``exit_code`` is the real process exit code and
    is ``None`` only when the process could not be started or reaped. stdout is
    capped at 32 KiB and stderr at 16 KiB.
    """
    started = time.monotonic()

    def failed(message: str) -> dict[str, Any]:
        return {
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "truncated": False,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": message,
        }

    if not isinstance(command, str) or not command.strip():
        return failed("command must be a non-empty string")
    if len(command) > MAX_COMMAND_CHARS:
        return failed(f"command exceeds {MAX_COMMAND_CHARS} characters")

    path, cwd_error = _resolve_cwd(cwd)
    if cwd_error is not None:
        return failed(cwd_error)

    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError):
        return failed("timeout_seconds must be an integer")
    timeout = max(1, min(timeout, MAX_TIMEOUT_SECONDS))

    powershell = _powershell_exe()
    if not powershell.is_file():
        return failed(f"Windows PowerShell was not found at {powershell}")

    script = _POWERSHELL_PREAMBLE + command + _POWERSHELL_EXIT_GUARD
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    if len(encoded) > MAX_ENCODED_COMMAND_CHARS:
        return failed("encoded command is too long")

    try:
        process = subprocess.Popen(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            cwd=str(path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError as error:
        return failed(f"could not start PowerShell: {error}")

    results: dict[str, tuple[bytes, bool]] = {}

    def read(name: str, stream: Any, limit: int) -> None:
        results[name] = _read_limited(stream, limit)

    readers = [
        threading.Thread(target=read, args=("stdout", process.stdout, MAX_STDOUT_BYTES), daemon=True),
        threading.Thread(target=read, args=("stderr", process.stderr, MAX_STDERR_BYTES), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_tree(process)

    for reader in readers:
        reader.join(timeout=2)
    for stream in (process.stdout, process.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    stdout_bytes, stdout_truncated = results.get("stdout", (b"", False))
    stderr_bytes, stderr_truncated = results.get("stderr", (b"", False))
    stdout = _decode_text(stdout_bytes)
    stderr = _simplify_stderr(_decode_text(stderr_bytes))
    if stdout_truncated:
        stdout += "\n[output truncated]"
    if stderr_truncated:
        stderr += "\n[output truncated]"

    return {
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "truncated": stdout_truncated or stderr_truncated,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "error": None,
    }


def capture_screen() -> tuple[bytes, int, int]:
    """Capture the primary display as a downscaled JPEG held in memory.

    The longest edge is limited to 1600 px and the image is JPEG-encoded at
    quality 72. Nothing is written to disk. No DPI or console settings of the
    host process are changed.
    """
    try:
        from PIL import Image
    except ImportError as error:  # pragma: no cover - Pillow is a declared dependency
        raise RuntimeError("Screen capture requires Pillow.") from error

    width = int(win32api.GetSystemMetrics(win32con.SM_CXSCREEN))
    height = int(win32api.GetSystemMetrics(win32con.SM_CYSCREEN))
    if width <= 0 or height <= 0:
        raise RuntimeError("Windows reported no primary display size.")

    screen_dc = win32gui.GetDC(0)
    if not screen_dc:
        raise RuntimeError("Could not open the primary display device context.")
    try:
        source = win32ui.CreateDCFromHandle(screen_dc)
        memory = source.CreateCompatibleDC()
        bitmap = win32ui.CreateBitmap()
        try:
            bitmap.CreateCompatibleBitmap(source, width, height)
            memory.SelectObject(bitmap)
            memory.BitBlt((0, 0), (width, height), source, (0, 0), win32con.SRCCOPY)
            info = bitmap.GetInfo()
            bits = bitmap.GetBitmapBits(True)
        finally:
            try:
                memory.DeleteDC()
            except pywintypes.error:
                pass
    finally:
        win32gui.ReleaseDC(0, screen_dc)

    bitmap_width = int(info["bmWidth"])
    bitmap_height = int(info["bmHeight"])
    if bitmap_height < 0:
        bitmap_height = -bitmap_height
    if bitmap_width <= 0 or bitmap_height <= 0:
        raise RuntimeError("The primary display returned an empty bitmap.")

    bits_per_pixel = int(info["bmBitsPixel"])
    if bits_per_pixel == 32:
        raw_mode = "BGRX"
    elif bits_per_pixel == 24:
        raw_mode = "BGR"
    else:
        raise RuntimeError(f"Unsupported display depth: {bits_per_pixel} bpp")
    stride = ((bitmap_width * bits_per_pixel + 31) // 32) * 4

    image = Image.frombuffer(
        "RGB",
        (bitmap_width, bitmap_height),
        bits,
        "raw",
        raw_mode,
        stride,
        1,
    )

    longest = max(image.width, image.height)
    if longest > MAX_JPEG_EDGE:
        scale = MAX_JPEG_EDGE / longest
        target = (max(1, round(image.width * scale)), max(1, round(image.height * scale)))
        image = image.resize(target, Image.LANCZOS)
    image = image.convert("RGB")

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=JPEG_QUALITY, optimize=True)
    data = buffer.getvalue()
    if not data:
        raise RuntimeError("JPEG encoding produced no data.")
    return data, image.width, image.height
