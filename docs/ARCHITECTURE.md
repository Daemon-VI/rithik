# Architecture

- `src/rithik/cli.py`: argparse entry point (`rithik`, `rithik card`, `rithik scam`).
  Handles colour, `NO_COLOR` and Windows consoles.
- `src/rithik/card.py`: card data. It uses only public facts from the GitHub profile README.
- `src/rithik/scam/model.py`: the contract shared by the other modules: `Verdict`, `Reason`
  and `Report`.
- `src/rithik/scam/engine.py`: `analyze(text) -> Report`.
  - Normalises the text (NFKC, removes zero-width characters) and runs every rule.
  - Counts each reason code once, so a repeated phrase does not add up.
  - Maps the summed weights to a score with `1 - exp(-raw/scale)`, then applies the verdict
    thresholds.
  - Reassuring signals (official links, "do not share OTP") count for nothing once a strong
    signal is present.
- `src/rithik/scam/rules.py`: keyword and regex rule families, including negation handling
  for OTP requests.
- `src/rithik/scam/urls.py`: finds links and works out each link's registered domain
  without third-party libraries.
  - Checks for shorteners, bare IP addresses, punycode, `@` in the address, risky domain
    endings, `.apk` files and brand look-alikes.
  - Brand look-alikes are checked against an allowlist of official domains.
- `src/rithik/scam/weights.py`: every weight and threshold, in one table, so tuning touches
  one file.
- `scripts/eval.py`: scores both splits. It never lists individual misses for the held-out
  test split.

Why there are no runtime dependencies: `pipx install` should take seconds, and nothing
upstream can break it.

## The JavaScript port (`js/`)

`npx rithik` runs a port of the Python package, not a wrapper around it, so it needs nothing
but Node 18 or newer.

- `js/bin/rithik.js`: the npm `bin` entry. It must keep LF line endings, which
  `.gitattributes` enforces.
- `js/lib/cli.js`, `card.js`, `term.js`, `stdin.js`, `version.js`: mirror `cli.py`,
  `card.py` and `_term.py`. The version is read from `package.json`.
- `js/lib/scam/engine.js`, `rules.js`, `urls.js`, `weights.js`, `model.js`: mirror
  `src/rithik/scam/`, file for file. `rules.js` keeps the patterns in Python syntax, character
  for character.
- `js/lib/scam/pycompat.js`: translates the Python patterns and refuses any syntax it cannot
  carry over faithfully. It also holds the Python semantics JS lacks:
  - Unicode `\w`, `\d` and `\b`;
  - Python's whitespace set;
  - code-point lengths and slices;
  - `round(x, 3)` half to even;
  - `ipaddress` parsing.
- `js/lib/pyjson.js`, `js/lib/pytext.js`: `json.dumps(indent=2)` with Python float repr and
  `\uXXXX` escapes, and a port of `textwrap.wrap`. Together they make the terminal output
  byte-identical.

### How the two stay in step

`scripts/export_golden.py` runs the Python code and writes two golden files:
- `js/test/golden/scam.json`: a report for every corpus message and every edge case in
  `EXTRA_CASES`;
- `js/test/golden/cli.json`: stdout and the exit code for fixed argv lists.

`npm test` holds the port to both files. The checks are exact, except the unrounded score,
which allows 1e-12 because V8's `Math.exp` can differ in the last bit. CI runs
`export_golden.py --check`, so a Python change that skips regenerating the golden files fails.
When a new Python/JS difference turns up, add an input for it to `EXTRA_CASES`.
