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
