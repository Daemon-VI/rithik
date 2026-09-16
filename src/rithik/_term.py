"""Terminal plumbing shared by the card and the scam report: colour, and output that never crashes.

The people most likely to paste a scam message into this tool are on stock Windows consoles,
so the defaults here are chosen for cmd.exe and PowerShell 5.1 first.
"""

from __future__ import annotations

import codecs
import os
from typing import TextIO

RESET = "\033[0m"
BOLD = "1"
DIM = "2"
RED = "1;31"
GREEN = "1;32"
YELLOW = "1;33"
CYAN = "36"
BOLD_CYAN = "1;36"

_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11


def paint(text: str, code: str, color: bool) -> str:
    if not color or not text:
        return text
    return f"\033[{code}m{text}{RESET}"


def enable_windows_ansi() -> bool:
    """Turn on escape-code handling for this console; False means colour must stay off."""
    try:
        import ctypes
        from ctypes import wintypes
    except (ImportError, ValueError):
        # Some older Pythons refuse to import wintypes off Windows at all.
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]

        handle = kernel32.GetStdHandle(wintypes.DWORD(_STD_OUTPUT_HANDLE).value)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if mode.value & _ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return bool(
            kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        )
    except (OSError, AttributeError, ValueError, TypeError, ctypes.ArgumentError):
        # Old conhost, a missing DLL, a sandbox: any failure just means plain text, never a crash.
        return False


def color_enabled(stream: TextIO, disabled: bool) -> bool:
    # no-color.org: the variable counts only when it is set to something non-empty.
    if disabled or os.environ.get("NO_COLOR"):
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError, OSError):
        return False
    if os.name == "nt":
        # Without VT processing the console prints the escape codes literally, which is worse
        # than no colour at all.
        return enable_windows_ansi()
    return os.environ.get("TERM") != "dumb"


def prepare(stream: TextIO | None) -> None:
    # A console that cannot encode a character (cp437, cp1252) would otherwise raise
    # UnicodeEncodeError halfway through a report; a "?" in its place is the lesser harm.
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(errors="replace")
    except (ValueError, OSError, TypeError):
        pass


def write(stream: TextIO, text: str) -> None:
    try:
        stream.write(text)
    except UnicodeEncodeError:
        # Streams without reconfigure() (wrappers some IDEs install) still get the text, with
        # the characters they cannot hold replaced.
        encoding = _encoding_of(stream)
        stream.write(text.encode(encoding, errors="replace").decode(encoding))
    stream.flush()


def _encoding_of(stream: TextIO) -> str:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        codecs.lookup(encoding)
    except LookupError:
        return "ascii"
    return encoding
