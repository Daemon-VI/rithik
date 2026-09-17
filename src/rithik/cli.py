"""Command-line entry point: `rithik`, `rithik card` and `rithik scam`."""

from __future__ import annotations

import argparse
import codecs
import json
import locale
import os
import re
import sys
import textwrap
from typing import TYPE_CHECKING, TextIO

from rithik import __version__, _term
from rithik.card import card_data, render_card
from rithik.scam import analyze
from rithik.scam.model import Report, Verdict

if TYPE_CHECKING:
    from collections.abc import Sequence

WIDTH = 78

# Messages are a few hundred bytes. The cap only stops an accidental `rithik scam - < disk.img`
# from sitting in the regexes for minutes.
STDIN_LIMIT = 1 << 20

USAGE_HINT = (
    "Give rithik scam a message to check, in quotes:\n"
    '  rithik scam "<message or link>"\n'
    "or pipe it in:\n"
    "  <command> | rithik scam -\n"
)

_HEADLINES = {
    Verdict.SCAM: ("LIKELY SCAM", _term.RED),
    Verdict.SUSPICIOUS: ("SUSPICIOUS", _term.YELLOW),
    Verdict.NO_SIGNALS: ("NO KNOWN SCAM SIGNALS", _term.GREEN),
}

_WARNING_ADVICE = (
    "Do not click the links, call the numbers or install anything the message asks for.",
    (
        "Never share an OTP, UPI PIN or card details, and remember that you never need your UPI "
        "PIN to receive money."
    ),
    (
        "Verify through your bank's official app, or the number printed on your card, not a "
        "number from the message."
    ),
    "If money was taken, call 1930 at once or report it at https://cybercrime.gov.in",
    "Report the fraud SMS or call through Chakshu at https://sancharsaathi.gov.in",
)

_NO_SIGNALS_ADVICE = (
    "None of the scam patterns this checker knows matched. That is not a guarantee that the "
    "message is genuine: new scams appear all the time. Before you pay, or share an OTP or PIN, "
    "verify through the official app or website."
)

_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_LINK_IN_TEXT = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\"']+")
_EVIDENCE_LIMIT = 120


def main(argv: Sequence[str] | None = None) -> int:
    out = sys.stdout
    _term.prepare(out)
    _term.prepare(sys.stderr)
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        # argparse exits on --version, --help and bad usage; a caller of main() wants a code.
        return _exit_code(exc)
    try:
        if args.command == "scam":
            return _run_scam(args, out)
        return _run_card(args, out)
    except BrokenPipeError:
        # `rithik | head` closing the pipe early is the reader's choice, not an error.
        _silence_stdout()
        return 0
    except KeyboardInterrupt:
        return 130


def render_report(report: Report, color: bool = False) -> str:
    verdict = Verdict(report.verdict)
    title, code = _HEADLINES[verdict]
    lines = [f"{_term.paint(title, code, color)}  (score {report.score:.2f} of 1.00)", ""]

    if report.reasons:
        lines.append(_term.paint("Why", _term.BOLD, color))
        for reason in report.reasons:
            text = reason.label
            if reason.evidence:
                # Labels are full sentences; the evidence follows a colon, so the full stop goes.
                text = text.removesuffix(".")
                text += f': "{_shorten(_defang_text(reason.evidence, report.urls))}"'
            if reason.weight < 0:
                text += " (lowers the score)"
            lines.extend(_bullet(text))
        lines.append("")

    if report.urls:
        lines.append(_term.paint("Links in the message", _term.BOLD, color))
        for url in report.urls:
            lines.extend(_bullet(_defang(url)))
        # People copy links out of terminals, and many terminals open them on click; the
        # brackets make both deliberate.
        lines.append("  (dots shown as [.] so the links cannot be opened by accident)")
        lines.append("")

    if verdict is Verdict.NO_SIGNALS:
        lines.extend(textwrap.wrap(_NO_SIGNALS_ADVICE, WIDTH))
    else:
        lines.append(_term.paint("What to do", _term.BOLD, color))
        for tip in _WARNING_ADVICE:
            lines.extend(_bullet(tip))
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rithik",
        description="Rithik Krishna T's card, and an offline checker for scam messages and links.",
        epilog='Examples:  rithik   |   rithik scam "<message or link>"   |   rithik card --json',
    )
    parser.add_argument("--version", action="version", version=f"rithik {__version__}")
    _add_shared_flags(parser, default=False)

    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    card = commands.add_parser("card", help="print the card (what plain `rithik` does)")
    _add_shared_flags(card, default=argparse.SUPPRESS)

    scam = commands.add_parser(
        "scam",
        help="check a message or link for scam signals, offline",
        description="Check a message or link for known scam patterns. Nothing leaves this machine.",
    )
    _add_shared_flags(scam, default=argparse.SUPPRESS)
    scam.add_argument(
        "text",
        nargs="*",
        metavar="TEXT",
        help='the message or link; "-" (or no TEXT with piped input) reads standard input',
    )
    return parser


def _add_shared_flags(parser: argparse.ArgumentParser, default: object) -> None:
    # The flags work before and after the subcommand. The subcommand copies default to
    # SUPPRESS so that `rithik --no-color scam ...` is not reset to False by the subparser.
    parser.add_argument(
        "--json", action="store_true", default=default, help="print machine-readable JSON only"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=default,
        help="plain text without colour (the NO_COLOR variable does the same)",
    )


def _exit_code(exc: SystemExit) -> int:
    if exc.code is None:
        return 0
    if isinstance(exc.code, int):
        return exc.code
    return 2


def _run_card(args: argparse.Namespace, out: TextIO) -> int:
    if args.json:
        _term.write(out, json.dumps(card_data(), indent=2) + "\n")
    else:
        _term.write(out, render_card(color=_term.color_enabled(out, args.no_color)))
    return 0


def _run_scam(args: argparse.Namespace, out: TextIO) -> int:
    words = list(args.text)
    if words == ["-"] or (not words and not _stdin_is_interactive()):
        text = _read_stdin()
    elif words:
        text = " ".join(words)
    else:
        _term.write(sys.stderr, USAGE_HINT)
        return 2

    if not text.strip():
        _term.write(sys.stderr, "rithik: the message was empty, so there is nothing to check.\n")
        _term.write(sys.stderr, USAGE_HINT)
        return 2

    report = analyze(text)
    if args.json:
        # ASCII-escaped JSON survives any console code page without a lossy "?" substitution.
        _term.write(out, json.dumps(report.to_dict(), indent=2) + "\n")
    else:
        _term.write(out, render_report(report, color=_term.color_enabled(out, args.no_color)))
    return 0


def _stdin_is_interactive() -> bool:
    stream = sys.stdin
    if stream is None:
        return True
    try:
        return stream.isatty()
    except (AttributeError, ValueError, OSError):
        # Unknown means "do not block waiting for input that may never come".
        return True


def _read_stdin() -> str:
    stream = sys.stdin
    if stream is None:
        return ""
    raw = getattr(stream, "buffer", None)
    if raw is None:
        text = stream.read(STDIN_LIMIT + 1)
        truncated = len(text) > STDIN_LIMIT
        text = text[:STDIN_LIMIT]
    else:
        # Bytes, not text: Windows decodes piped input with the ANSI code page, which garbles a
        # UTF-8 message and fails outright on bytes cp1252 leaves undefined.
        data = raw.read(STDIN_LIMIT + 1)
        truncated = len(data) > STDIN_LIMIT
        text = _decode(data[:STDIN_LIMIT])
    if truncated:
        _term.write(sys.stderr, "rithik: input is over 1 MiB; only the first 1 MiB was checked.\n")
    return text


def _decode(data: bytes) -> str:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    encoding = locale.getpreferredencoding(False) or "utf-8"
    try:
        return data.decode(encoding, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _defang(url: str) -> str:
    """Write a link so that no terminal or chat app will turn it back into a clickable one."""
    match = _SCHEME.match(url)
    scheme = ""
    rest = url
    if match:
        scheme = re.sub(r"(?i)^http", "hxxp", match.group(0))
        rest = url[match.end() :]
    host_end = len(rest)
    for mark in "/?#":
        index = rest.find(mark)
        if index != -1:
            host_end = min(host_end, index)
    return scheme + rest[:host_end].replace(".", "[.]") + rest[host_end:]


def _defang_text(text: str, urls: Sequence[str]) -> str:
    text = _LINK_IN_TEXT.sub(lambda m: _defang(m.group(0)), text)
    # Links without a scheme ("sbi-kyc.top/login") only show up because the engine found them.
    for url in sorted(urls, key=len, reverse=True):
        text = text.replace(url, _defang(url))
    return text


def _shorten(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= _EVIDENCE_LIMIT:
        return text
    return text[: _EVIDENCE_LIMIT - 3].rstrip() + "..."


def _bullet(text: str) -> list[str]:
    return textwrap.wrap(
        text,
        WIDTH,
        initial_indent="  - ",
        subsequent_indent="    ",
        break_on_hyphens=False,
    ) or ["  -"]


def _silence_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass
