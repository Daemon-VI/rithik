"""Write the golden files the JavaScript port is tested against.

    uv run python scripts/export_golden.py          # rewrite js/test/golden/
    uv run python scripts/export_golden.py --check  # exit 1 if they are out of date

The Python package is the reference implementation. `npx rithik` runs a JavaScript port, and
that port is only trustworthy while it produces the same report, card and terminal output for
the same input, so every behaviour change here has to be followed by a regenerate and a green
`npm test`.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rithik import cli  # noqa: E402
from rithik.scam import analyze  # noqa: E402

GOLDEN = ROOT / "js" / "test" / "golden"
DATA = ROOT / "tests" / "data"

# Inputs chosen to hit the places where Python and JavaScript string handling differ:
# Unicode normalisation, case folding, \w and \b, URL parsing, and the regex engines.
EXTRA_CASES = [
    "",
    "   \n\t  ",
    "Your OTP is 482913. Do not share it with anyone. - HDFC Bank",
    "Please share the OTP you just received with our executive to stop the charge",
    "Sir kindly send otp fast, refund will be credited",
    "Never share your OTP, PIN or CVV with anyone. SBI never asks for these.",
    "Dear customer your SBI KYC expires today, update now at sbi-kyc-update.top/verify or account will be blocked",
    "KYC is complete for your account. Thank you for banking with us. - ICICI Bank",
    "Enter your UPI PIN to receive Rs 5000 cashback in your account",
    "Rs 500 debited from a/c XX1234 on 16-09. Not you? Call 18001234 or visit hdfcbank.com",
    "Sale ends tonight! Up to 70% off. Shop now at https://www.amazon.in/deals",
    "Your electricity connection will be disconnected tonight at 9:30 pm. Call officer 98XXXXXX01",
    "This is CBI. You are under digital arrest. Do not disconnect the video call.",
    "Download AnyDesk and share the code so our team can process your refund",
    "Install the app from http://203.0.113.7/pay.apk to claim your reward",
    "Verify at https://secure-login@sbi.example-bank.xyz/verify now",
    "Visit http://xn--hdfcbnk-9za.com/login immediately",
    "Your parcel is held at customs. Pay Rs 49 at bit.ly/3xYzAbc to release it",
    "Earn Rs 3000 daily by liking YouTube videos. Join on Telegram t.me/earnfast123",
    "Congratulations! You have won KBC lottery of 25 lakh. Contact WhatsApp wa.me/919000000001",
    "Income tax refund of Rs 15,490 is pending. Update your account at incometax-refund.click",
    "Aapka khata band ho jayega turant KYC update karein",
    "Pay your traffic e-challan of Rs 500 at echallan-parivahan.live/pay",
    "Check your results on https://www.mgit.ac.in and https://results.jntuh.ac.in",
    "Visit www.a.b.c.d.e.example.com/path?x=1 for more",
    "𝐔𝐫𝐠𝐞𝐧𝐭: your 𝐊𝐘𝐂 has 𝐞𝐱𝐩𝐢𝐫𝐞𝐝, update at sbi-help.top",
    "O​T​P share karo abhi, account block ho jayega",
    "İSTANBUL ŞUBESİ: hesabınız bloke edildi",
    "URGENT URGENT URGENT " * 50,
    "Hey, did you pay the electricity bill? Mom said the OTP came on her phone",
    "Your pre-approved loan of Rs 5,00,000 is ready. Pay processing fee of Rs 999 to get it",
    "Invest Rs 10,000 and get guaranteed double returns in 7 days. Crypto trading",
    "Your credit card reward points worth Rs 7,850 expire today. Redeem at hdfc-rewardz.top",
    "Your SIM will be deactivated in 2 hours by TRAI. Press 9 to speak to an officer",
    "Your PNR 4512345678 is confirmed. Coach B2 Seat 34. irctc.co.in",
    "Dear FedEx customer, your address is incomplete. Update at fedex-in.icu/track",
    "http://127.0.0.1:8000/ is where the dev server runs",
    "Check https://example.com/a(b)c and (https://example.org/x).",
    # Paths the corpus never reaches: lower() changing the length (so evidence is cut from the
    # lowered text), IPv6 hosts, dotted capitals inside a domain, non-ASCII digits, clipping.
    "İ KYC update now or your account will be blocked today",
    "Download the refund app from http://[2001:db8::1]/refund.apk and enter your UPI PIN",
    "Visit SBİ-kyc-update.top to avoid your account being blocked",
    "Pay ₹४९ at bit.ly/xyz to release your parcel held at customs",
    "😀😀 Your account will be blocked 😀 update KYC at "
    "https://sbi-kyc-update-portal-for-customers.top/" + "a" * 90 + " 😀",
    # The joined argv of the multi-word CLI case, so its rendering is checked without the engine.
    "Your parcel is held, pay at bit.ly/x1",
]

# Terminal output compared byte for byte. Error and --help text is left out on purpose:
# argparse's wording cannot be reproduced exactly and nobody depends on it.
CLI_CASES = [
    [],
    ["card"],
    ["card", "--json"],
    ["--no-color"],
    ["--version"],
    ["scam", "--no-color", EXTRA_CASES[6]],
    ["scam", "--no-color", EXTRA_CASES[2]],
    ["scam", "--no-color", EXTRA_CASES[10]],
    ["scam", "--no-color", EXTRA_CASES[8]],
    ["scam", "--no-color", EXTRA_CASES[18]],
    ["scam", "--no-color", "Your", "parcel", "is", "held,", "pay", "at", "bit.ly/x1"],
    ["scam", "--json", EXTRA_CASES[13]],
    ["scam", "--json", EXTRA_CASES[16]],
]


def _corpus() -> list[dict]:
    rows = []
    for split in ("dev", "test"):
        with open(DATA / f"{split}.jsonl", encoding="utf-8") as f:
            rows.extend(json.loads(line) for line in f if line.strip())
    return rows


def _scam_cases() -> list[dict]:
    inputs = [(row["id"], row["text"]) for row in _corpus()]
    inputs += [(f"extra-{i:03d}", text) for i, text in enumerate(EXTRA_CASES)]
    cases = []
    for case_id, text in inputs:
        report = analyze(text)
        expected = report.to_dict()
        # to_dict() rounds for display; the port must match the unrounded score too.
        expected["score_exact"] = report.score
        cases.append({"id": case_id, "input": text, "expected": expected})
    return cases


def _cli_cases() -> list[dict]:
    cases = []
    for argv in CLI_CASES:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        cases.append({"argv": argv, "exit": code, "stdout": out.getvalue()})
    return cases


def _render() -> dict[str, str]:
    files = {"scam.json": _scam_cases(), "cli.json": _cli_cases()}
    return {
        name: json.dumps(data, ensure_ascii=False, indent=1) + "\n" for name, data in files.items()
    }


def _diff(stored: list[dict], fresh: list[dict]) -> list[str]:
    """Differences that matter, by case. score_exact comes from the C library's exp(), which
    differs in the last bit between platforms, so it gets the same tolerance the JS tests use."""
    if len(stored) != len(fresh):
        return [f"{len(stored)} cases stored, {len(fresh)} generated"]
    problems = []
    for index, (old, new) in enumerate(zip(stored, fresh)):
        label = old.get("id", index)
        if "expected" in old and "expected" in new:
            old_e, new_e = dict(old["expected"]), dict(new["expected"])
            if abs(old_e.pop("score_exact") - new_e.pop("score_exact")) > 1e-12:
                problems.append(f"{label}: score_exact")
            fields = [k for k in old_e.keys() | new_e.keys() if old_e.get(k) != new_e.get(k)]
            if old["input"] != new["input"]:
                fields.append("input")
            problems += [f"{label}: {field}" for field in sorted(fields)]
        elif old != new:
            problems.append(f"{label}: differs")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    rendered = _render()
    if args.check:
        problems = []
        for name, text in rendered.items():
            path = GOLDEN / name
            if not path.exists():
                problems.append(f"{name}: missing")
                continue
            problems += [
                f"{name}: {p}" for p in _diff(json.loads(path.read_text("utf-8")), json.loads(text))
            ]
        for problem in problems:
            print(f"stale: js/test/golden/{problem}", file=sys.stderr)
        if problems:
            print("run scripts/export_golden.py to regenerate", file=sys.stderr)
        return 1 if problems else 0
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (GOLDEN / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote js/test/golden/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
