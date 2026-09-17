# Project state — rithik

_Last updated 2026-09-17._

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
| `npx github:Daemon-VI/rithik`, `pipx install git+...` | work from GitHub (checked after each push) |
| npm (`npx rithik`) | NOT published. First publish is manual (`npm login`, `npm publish`); see docs/RELEASING.md |
| PyPI (`pipx install rithik`) | NOT published. Needs the pending-publisher setup in docs/RELEASING.md |
| `.github/workflows/` (CI + publish) | written but NOT pushed: gh's token lacks the `workflow` scope. Fix with `gh auth refresh -h github.com -s workflow` |
| CI on Python 3.9, Node 18, Windows | never observed, because the workflow files are not on GitHub yet |

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

1. `gh auth refresh -h github.com -s workflow`, then commit and push `.github/`, and watch the
   first CI run (Node 18 and Python 3.9 are unverified until then).
2. `npm login` and `npm publish` for the first npm release, then configure trusted publishing
   on npmjs.com (docs/RELEASING.md).
3. Write `tests/test_rules.py`, a positive and a negative case per signal family.
4. Tune on `dev` only, score `test` once more, and record it in EVAL.md. Any rule change goes
   into both runtimes: Python first, then regenerate the golden files, then the port.
5. PyPI release.
