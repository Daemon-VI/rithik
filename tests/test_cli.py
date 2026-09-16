"""CLI behaviour: argument handling, output shape, colour rules and console safety.

The rule engine is developed separately, so every scam test swaps in a stub that returns a
hand-built Report. These tests pin the presentation, not the verdicts.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import rithik
from rithik import _term, cli
from rithik.card import card_data, render_card
from rithik.scam.model import Reason, Report, Verdict

ESC = "\x1b["
SCAM_URL = "https://kyc-sbi-verify.top/update"
PUBLIC_REPOS = {
    "https://github.com/Daemon-VI/AegisToolkit",
    "https://github.com/Daemon-VI/Cascade",
    "https://github.com/Daemon-VI/optivision-rag",
    "https://github.com/Daemon-VI/carpool",
    "https://github.com/Daemon-VI/darkwatch",
    "https://github.com/Daemon-VI/rithik",
}


def make_report(verdict: Verdict = Verdict.SCAM, evidence: str = "update your KYC") -> Report:
    return Report(
        verdict=verdict,
        score={Verdict.SCAM: 0.91, Verdict.SUSPICIOUS: 0.48, Verdict.NO_SIGNALS: 0.02}[verdict],
        reasons=(
            Reason("kyc_update", "Asks you to update KYC", evidence, 0.4),
            Reason("lookalike_domain", "The link imitates a bank's website", SCAM_URL, 0.5),
            Reason("official_domain", "Mentions an official site", "onlinesbi.sbi", -0.2),
        ),
        urls=(SCAM_URL,),
    )


class Recorder:
    """Stands in for analyze() and remembers what it was asked to check."""

    def __init__(self, report: Report) -> None:
        self.report = report
        self.calls: list[str] = []

    def __call__(self, text: str) -> Report:
        self.calls.append(text)
        return self.report


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class FakeStdin(io.StringIO):
    def __init__(self, text: str = "", tty: bool = False) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class StrictStream:
    """A cp1252 console wrapper with no reconfigure(), like some IDE consoles."""

    encoding = "cp1252"

    def __init__(self) -> None:
        self.parts: list[str] = []

    def write(self, text: str) -> int:
        text.encode(self.encoding)  # raises UnicodeEncodeError, as a real console would
        self.parts.append(text)
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder(make_report())
    monkeypatch.setattr(cli, "analyze", recorder)
    return recorder


@pytest.fixture(autouse=True)
def plain_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")


# --- card -----------------------------------------------------------------------------------


def test_bare_command_prints_the_card(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "Rithik Krishna T" in out
    assert "https://github.com/Daemon-VI" in out
    assert "https://www.linkedin.com/in/rithikkrishnat/" in out
    assert "trithikkrishna@gmail.com" in out
    assert "HCLTech" in out
    assert out.rstrip("\n").splitlines()[-1] == 'Try: rithik scam "<message or link>"'


def test_card_subcommand_matches_bare_command(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main([])
    bare = capsys.readouterr().out
    assert cli.main(["card"]) == 0
    assert capsys.readouterr().out == bare


def test_card_fits_78_columns_in_plain_ascii() -> None:
    text = render_card(color=False)
    assert text.isascii()
    assert max(len(line) for line in text.splitlines()) <= 78


def test_coloured_card_has_the_same_layout() -> None:
    strip = re.compile(r"\x1b\[[0-9;]*m")
    assert strip.sub("", render_card(color=True)) == render_card(color=False)


def test_card_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["card", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == card_data()
    assert data["name"] == "Rithik Krishna T"
    assert data["links"]["github"] == "https://github.com/Daemon-VI"
    assert {e["institution"] for e in data["education"]} == {"MGIT Hyderabad", "IIT Madras"}
    assert data["experience"][0]["organisation"] == "HCLTech"


def test_json_flag_before_the_subcommand_also_works(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "Rithik Krishna T"


def test_card_links_only_public_repos_and_one_email() -> None:
    text = render_card() + json.dumps(card_data())
    repos = set(re.findall(r"https://github\.com/Daemon-VI/[\w.-]+", text))
    assert repos == PUBLIC_REPOS
    assert set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)) == {"trithikkrishna@gmail.com"}
    assert "cgpa" not in text.lower()
    assert not re.search(r"\+91|\b\d{10}\b", text)


def test_card_data_is_a_copy() -> None:
    card_data()["projects"][0]["name"] = "changed"
    assert card_data()["projects"][0]["name"] == "AegisToolkit"


# --- version and usage ------------------------------------------------------------------------


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out == f"rithik {rithik.__version__}\n"


def test_version_matches_pyproject() -> None:
    # PyPI takes its version from pyproject.toml and `rithik --version` from __init__.py; a
    # release with the two out of step would report the wrong number forever.
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match is not None
    assert match.group(1) == rithik.__version__


def test_python_dash_m_runs_the_cli() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "rithik", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"rithik {rithik.__version__}"


def test_scam_without_text_on_a_terminal_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stub: Recorder
) -> None:
    monkeypatch.setattr(sys, "stdin", FakeStdin(tty=True))
    assert cli.main(["scam"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert 'rithik scam "<message or link>"' in captured.err
    assert stub.calls == []


def test_empty_piped_input_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stub: Recorder
) -> None:
    monkeypatch.setattr(sys, "stdin", FakeStdin("  \n"))
    assert cli.main(["scam", "-"]) == 2
    assert "empty" in capsys.readouterr().err
    assert stub.calls == []


def test_unknown_flag_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--definitely-not-a-flag"]) == 2
    assert "usage:" in capsys.readouterr().err


# --- scam output ------------------------------------------------------------------------------


def test_scam_joins_words(stub: Recorder, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scam", "Your", "account", "is", "blocked"]) == 0
    assert stub.calls == ["Your account is blocked"]


def test_scam_json_is_the_report_and_nothing_else(
    stub: Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["scam", "--json", "hello"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == stub.report.to_dict()
    assert out.lstrip().startswith("{") and out.rstrip().endswith("}")
    assert SCAM_URL in json.loads(out)["urls"]  # machine output keeps the real link


def test_scam_human_output(stub: Recorder, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scam", "--no-color", "hello"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == "LIKELY SCAM  (score 0.91 of 1.00)"
    assert '  - Asks you to update KYC: "update your KYC"' in lines
    assert "  - hxxps://kyc-sbi-verify[.]top/update" in lines
    assert "(lowers the score)" in out
    assert SCAM_URL not in out  # never printed in a form a terminal would make clickable
    for needle in ("OTP", "UPI PIN", "1930", "https://cybercrime.gov.in", "Chakshu"):
        assert needle in out
    assert "https://sancharsaathi.gov.in" in out
    assert max(len(line) for line in lines) <= 78


def test_suspicious_headline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "analyze", Recorder(make_report(Verdict.SUSPICIOUS)))
    assert cli.main(["scam", "--no-color", "hello"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("SUSPICIOUS  (score 0.48 of 1.00)")
    assert "1930" in out


def test_no_signals_says_it_is_not_a_guarantee(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = Report(Verdict.NO_SIGNALS, 0.0, (), ())
    monkeypatch.setattr(cli, "analyze", Recorder(report))
    assert cli.main(["scam", "--no-color", "see you at 5"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("NO KNOWN SCAM SIGNALS  (score 0.00 of 1.00)")
    assert "not a guarantee" in out
    assert "Why" not in out and "Links in the message" not in out


def test_long_evidence_is_shortened(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "analyze", Recorder(make_report(evidence="word " * 200)))
    assert cli.main(["scam", "--no-color", "hello"]) == 0
    out = capsys.readouterr().out
    assert '..."' in out
    assert max(len(line) for line in out.splitlines()) <= 78


def test_defang_leaves_paths_alone() -> None:
    assert cli._defang("http://a.b.example/x.php?q=1.2") == "hxxp://a[.]b[.]example/x.php?q=1.2"
    assert cli._defang("bit.ly/abc") == "bit[.]ly/abc"
    text = cli._defang_text("go to www.fake.example or sbi-kyc.example/login", ["sbi-kyc.example"])
    assert text == "go to www[.]fake[.]example or sbi-kyc[.]example/login"


# --- stdin ------------------------------------------------------------------------------------


def test_dash_reads_utf8_stdin(
    monkeypatch: pytest.MonkeyPatch, stub: Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    message = "Pay ₹500 now केवाईसी"
    raw = io.TextIOWrapper(io.BytesIO(message.encode("utf-8")), encoding="cp1252")
    monkeypatch.setattr(sys, "stdin", raw)
    assert cli.main(["scam", "-"]) == 0
    assert stub.calls == [message]


def test_piped_stdin_is_read_without_dash(
    monkeypatch: pytest.MonkeyPatch, stub: Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", FakeStdin("KYC expired, click here\n"))
    assert cli.main(["scam", "--json"]) == 0
    assert stub.calls == ["KYC expired, click here\n"]


def test_utf16_stdin_is_decoded() -> None:
    message = "KYC ₹"
    assert cli._decode(b"\xff\xfe" + message.encode("utf-16-le")) == message


# --- colour -----------------------------------------------------------------------------------


def use_fake_terminal(monkeypatch: pytest.MonkeyPatch) -> FakeTTY:
    # Called from the test body: pytest's own capture replaces sys.stdout again after fixture
    # setup, so a stream installed by a fixture would never see the output.
    stream = FakeTTY()
    monkeypatch.setattr(sys, "stdout", stream)
    # The fake is not a real console, so pretend VT processing switched on.
    monkeypatch.setattr(_term, "enable_windows_ansi", lambda: True)
    return stream


def test_terminal_gets_colour(monkeypatch: pytest.MonkeyPatch, stub: Recorder) -> None:
    terminal = use_fake_terminal(monkeypatch)
    assert cli.main(["scam", "hello"]) == 0
    assert ESC + "1;31mLIKELY SCAM" in terminal.getvalue()


def test_terminal_gets_a_coloured_card(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = use_fake_terminal(monkeypatch)
    assert cli.main([]) == 0
    assert ESC in terminal.getvalue()


@pytest.mark.parametrize(
    "argv",
    [
        ["--no-color"],
        ["card", "--no-color"],
        ["scam", "--no-color", "x"],
        ["--no-color", "scam", "x"],
    ],
)
def test_no_color_flag(argv: list[str], monkeypatch: pytest.MonkeyPatch, stub: Recorder) -> None:
    terminal = use_fake_terminal(monkeypatch)
    assert cli.main(argv) == 0
    assert terminal.getvalue().strip()
    assert ESC not in terminal.getvalue()


@pytest.mark.parametrize("argv", [[], ["scam", "x"]])
def test_no_color_env(argv: list[str], monkeypatch: pytest.MonkeyPatch, stub: Recorder) -> None:
    terminal = use_fake_terminal(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.main(argv) == 0
    assert terminal.getvalue().strip()
    assert ESC not in terminal.getvalue()


def test_empty_no_color_env_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = use_fake_terminal(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "")
    assert cli.main([]) == 0
    assert ESC in terminal.getvalue()


def test_pipe_gets_no_colour(capsys: pytest.CaptureFixture[str], stub: Recorder) -> None:
    assert cli.main([]) == 0
    assert cli.main(["scam", "hello"]) == 0
    out = capsys.readouterr().out
    assert "LIKELY SCAM" in out
    assert ESC not in out


def test_failed_windows_setup_means_no_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = use_fake_terminal(monkeypatch)
    monkeypatch.setattr(_term.os, "name", "nt")
    monkeypatch.setattr(_term, "enable_windows_ansi", lambda: False)
    assert cli.main([]) == 0
    assert terminal.getvalue().strip()
    assert ESC not in terminal.getvalue()


# --- consoles that cannot encode everything -----------------------------------------------------


@pytest.mark.parametrize("argv", [[], ["scam", "hello"], ["scam", "--json", "hello"]])
def test_output_survives_a_cp1252_console(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    report = make_report(evidence="₹ केवाईसी \U0001f4b0")
    monkeypatch.setattr(cli, "analyze", Recorder(report))
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(argv) == 0
    stream.flush()
    text = buffer.getvalue().decode("cp1252")
    assert text.strip()
    if argv[-2:] == ["--json", "hello"]:
        # JSON is escaped, so nothing is lost even on this console.
        assert json.loads(text) == report.to_dict()
    elif argv:
        assert "Asks you to update KYC" in text and "?" in text


def test_output_survives_a_stream_without_reconfigure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "analyze", Recorder(make_report(evidence="₹500")))
    stream = StrictStream()
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(["scam", "hello"]) == 0
    assert '"?500"' in "".join(stream.parts)
