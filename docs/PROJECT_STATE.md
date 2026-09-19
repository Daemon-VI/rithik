# Project state — rithik

_Last updated 2026-09-19._

`rithik` is a zero-dependency command-line tool that ships in two runtimes:
- the Python reference, installed with pipx or uvx;
- a JavaScript port, run with npx.

`rithik` prints Rithik Krishna T's card, and `rithik scam "<text>"` checks a message offline for
Indian scam patterns.

## Status

| Item | State |
|---|---|
| Card (`rithik`, `rithik card --json`) | VERIFIED in both runtimes, byte-identical output |
| Scam checker: rules, URL checks, scoring (Python) | IMPLEMENTED: docs/EVAL.md has the measured numbers |
| JavaScript port (`js/`) | VERIFIED against golden files: 330/330 `npm test` on Node 22 |
| Golden files (`js/test/golden/`) | 204 engine reports (160 corpus + 44 edge cases) and 13 CLI outputs, from `scripts/export_golden.py` |
| Packed npm tarball | VERIFIED: `npm pack`, then `npx ./rithik-0.1.0.tgz` prints the version, the card and a scam report (18 files, 51.7 kB) |
| Python tests (`tests/test_cli.py`) | VERIFIED: 39 pass |
| Unit tests for the Python rule engine (`tests/test_rules.py`) | MISSING: the golden parity and the eval cover behaviour, but there are no per-rule tests |
| Eval: held-out test, lenient point | precision 0.882, recall 0.750 (n=80, synthetic, untuned, scored once) |
| Lint (`ruff check`, `ruff format --check`) | VERIFIED clean, with rules pinned in pyproject |
| GitHub repo Daemon-VI/rithik | public |
| `npx github:Daemon-VI/rithik` | VERIFIED 2026-09-17 from a clean folder: version, card and scam report (about 9 s cold). npm 12 needs `--allow-git=root`, because its default is `allow-git=none` |
| `pipx install git+https://github.com/Daemon-VI/rithik` | VERIFIED 2026-09-16 in a throwaway venv |
| npm (`npx rithik`) | VERIFIED: 0.1.0 published by hand 2026-09-19. 0.1.1 published by the publish workflow through trusted publishing with signed provenance (run 35426170459, npm job rerun after the trusted publisher was configured); `npx rithik@0.1.1` runs from a clean folder |
| PyPI (`pipx install rithik`) | VERIFIED: 0.1.1 published 2026-09-19 by the publish workflow (trusted publishing, run 35426170459); `uvx --from rithik==0.1.1 rithik` runs from a clean environment |
| `.github/workflows/` (CI + publish) | VERIFIED: release v0.1.1 published to PyPI and npm with no stored token. Future releases need only a version bump and a GitHub release |
| CI | VERIFIED green 2026-09-19 (run 35424006519): 8/8 jobs, Python 3.9 and 3.13 and Node 18 and 24, on Ubuntu and Windows. The first run failed the golden check on Ubuntu (last-bit `exp` difference); the check now allows 1e-12 on `score_exact` |

## Findings from the port (2026-09-17)

- The engine port was fuzzed against Python with about 223k generated inputs, with no
  differences. The CLI port had about 42k checks per seed over 8 seeds; the only mismatches
  came from the test harness itself.
- `Math.exp` in V8 differs from the Windows C library by one ulp at raw scores 0.5 and 5.25.
  Over all reachable raw values the rounded score never changes, and the parity test allows
  1e-12.
- Python 3.12 uses Unicode 15.0 and Node 22 uses 17.0. The port excludes the newer ranges from
  its `\w`/`\d` equivalents, so it follows Python 3.12.
- Left different on purpose: on Windows, when the plain-text report is redirected to a file,
  Python writes the ANSI code page (so `₹` becomes `?`) while Node writes UTF-8. `--json` output
  is identical.
- The Python `task_job_offer.task` pattern takes 1.8 s on 1 MB of "like youtube videos "; the
  JS port takes 90 ms. This is worth tightening in Python.

## Next

1. ~~Push `.github/` and watch CI~~ (done 2026-09-19).
2. ~~Publish to npm and PyPI~~ (done 2026-09-19: both at 0.1.1 through the workflow).
3. Write `tests/test_rules.py`, a positive and a negative case per signal family.
4. Tune on `dev` only, score `test` once more, and record it in EVAL.md. Any rule change goes
   into both runtimes: Python first, then regenerate the golden files, then the port.
