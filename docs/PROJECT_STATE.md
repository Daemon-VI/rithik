# Project state — rithik

_Last updated 2026-09-16._

`rithik` is a zero-dependency Python command-line tool. `rithik` prints Rithik Krishna T's
card, and `rithik scam "<text>"` checks a message offline for Indian scam patterns.

## Status

| Item | State |
|---|---|
| Card (`rithik`, `rithik card --json`) | VERIFIED: runs locally |
| Scam checker: rules, URL checks, scoring | IMPLEMENTED: docs/EVAL.md has the measured numbers |
| CLI tests (`tests/test_cli.py`) | VERIFIED: 39 pass |
| Unit tests for the rule engine (`tests/test_rules.py`) | MISSING: the build was cut short before they were written |
| Eval: held-out test, lenient point | precision 0.882, recall 0.750 (n=80, synthetic, untuned, scored once) |
| Lint (`ruff check`, `ruff format --check`) | VERIFIED clean, with rules pinned in pyproject |
| GitHub repo Daemon-VI/rithik | public; install with `pipx install git+https://github.com/Daemon-VI/rithik` |
| PyPI | NOT published. Needs the one-time trusted-publisher setup in docs/RELEASING.md |
| CI on Python 3.9 and Windows | not yet observed. Check the first Actions run |

## Next

1. Write `tests/test_rules.py`: a positive and a negative case for each signal family.
2. Tune on `dev` only (`uv run python scripts/eval.py --split dev --show-misses`), then
   score `test` once more and record that in EVAL.md.
3. Publish to PyPI (docs/RELEASING.md).
4. Review the codebase before it is advertised widely.
