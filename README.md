# rithik

[![ci](https://github.com/Daemon-VI/rithik/actions/workflows/ci.yml/badge.svg)](https://github.com/Daemon-VI/rithik/actions/workflows/ci.yml)

`rithik` prints my card in your terminal, and it checks suspicious messages and links for the
scam patterns common in India, entirely offline. Paste in an SMS, a WhatsApp forward or a link,
and it tells you which known patterns matched, why they matter, and what to do next.

## Install

Works now, straight from GitHub:

```sh
pipx install git+https://github.com/Daemon-VI/rithik
```

Once it is published to PyPI:

```sh
pipx install rithik        # installs the `rithik` command
uvx rithik                 # or run it once without installing
```

It needs Python 3.9 or newer and has no dependencies outside the standard library. If the
`rithik` script is not on your `PATH`, `python -m rithik` does the same thing.

## Usage

```sh
rithik                     # the card
rithik card --json         # the card as JSON
rithik scam "<message or link>"
rithik scam -              # read the message from standard input
rithik --version
```

`--no-color` turns colour off, and so does the `NO_COLOR` environment variable. Colour is also
off whenever the output is not a terminal. `--json` prints only JSON, so scripts can use it.

### Checking a message

The quotes matter, because they keep your shell from interpreting the message.

```sh
rithik scam "Dear customer, your SBI account will be blocked today. Update KYC now: https://sbi-kyc-help-desk.top/update"
```

The output looks like this. Which reasons appear depends on what the rules find.

```text
LIKELY SCAM  (score 0.94 of 1.00)

Why
  - Threatens to block your account: "account will be blocked"
  - Asks you to update KYC through a message: "Update KYC"
  - Pushes you to act immediately: "today"
  - The link mentions SBI but is not an official SBI domain:
    "hxxps://sbi-kyc-help-desk[.]top/update"

Links in the message
  - hxxps://sbi-kyc-help-desk[.]top/update
  (dots shown as [.] so the links cannot be opened by accident)

What to do
  - Do not click the links, call the numbers or install anything the message
    asks for.
  - Never share an OTP, UPI PIN or card details, and remember that you never
    need your UPI PIN to receive money.
  - Verify through your bank's official app, or the number printed on your
    card, not a number from the message.
  - If money was taken, call 1930 at once or report it at
    https://cybercrime.gov.in
  - Report the fraud SMS or call through Chakshu at
    https://sancharsaathi.gov.in
```

The verdict is one of `LIKELY SCAM`, `SUSPICIOUS` or `NO KNOWN SCAM SIGNALS`. The last one is
worded that way on purpose, because it only means that none of the known patterns matched:

```text
NO KNOWN SCAM SIGNALS  (score 0.00 of 1.00)

None of the scam patterns this checker knows matched. That is not a guarantee
that the message is genuine: new scams appear all the time. Before you pay, or
share an OTP or PIN, verify through the official app or website.
```

A long message is easier to pipe in:

```sh
pbpaste | rithik scam -                      # macOS
Get-Clipboard | rithik scam -                # PowerShell
rithik scam - < message.txt
```

With `--json`, the report is printed as JSON. In JSON, links appear as the message wrote them:

```json
{
  "verdict": "scam",
  "score": 0.94,
  "reasons": [
    {
      "code": "kyc_update",
      "label": "Asks you to update KYC through a message",
      "evidence": "Update KYC",
      "weight": 0.3
    }
  ],
  "urls": [
    "https://sbi-kyc-help-desk.top/update"
  ]
}
```

The exit code is 0 whenever a check ran, whatever the verdict. It is 2 for a usage error, such
as a missing or empty message.

## What the checker looks for

The message text is checked for these families of signals:

- urgency and threats
- KYC, PAN and Aadhaar update requests
- blocked or suspended accounts
- electricity disconnection notices
- UPI PIN requests and UPI collect requests
- requests for an OTP
- prize and lottery wins
- task-based job offers
- parcels held by a courier or at customs
- "digital arrest" threats and impersonation of officials
- remote-access apps and APK files to install
- loan and investment offers
- reward points, tax refunds and traffic e-challans

Every link is checked for:

- URL shorteners, which hide where a link goes
- bare IP addresses used in place of a domain name
- punycode (`xn--`) domains, which can imitate other scripts
- lookalike domains that use a bank's or brand's name but are not on its list of official domains
- domain endings (TLDs) that are common in scam campaigns

Each signal carries a weight, and together they make the score that decides the verdict. Each
reason in the output names the words or the link that triggered it, so you can judge it for
yourself.

## Accuracy

Measured results, and how the evaluation set was built, are in
[docs/EVAL.md](https://github.com/Daemon-VI/rithik/blob/main/docs/EVAL.md).
This README gives no figures, so that it cannot drift out of step with that file.

## Limitations

- It is a heuristic. It recognises patterns that someone wrote down, and it will miss new or
  unusual scams.
- It understands English and Hinglish (Hindi written in the Latin alphabet) only.
- A result of `NO KNOWN SCAM SIGNALS` is not a guarantee that a message is safe.
- It never opens links, so it judges a link by its address alone, not by the page behind it.
- The evaluation set is synthetic: messages written from public fraud advisories rather than
  collected from real people. Its scores describe that set, not real-world accuracy.

## Privacy

Everything runs on your machine. `rithik` makes no network requests, stores nothing, and
collects no telemetry. The message you check exists only in the running process.

## Where to report fraud in India

- **Lost money?** Call the National Cyber Crime Helpline, **1930**, as soon as possible, or
  file a complaint at <https://cybercrime.gov.in>.
- **Fraud calls, SMS or WhatsApp messages:** report them through Chakshu at
  <https://sancharsaathi.gov.in>.
- Contact your bank directly, using the number printed on your card or the bank's official
  app.

## Contributing

To catch a new pattern, add a rule together with a unit test that shows it firing on a
message it should catch and staying quiet on a similar genuine one.

```sh
uv sync
uv run pytest -q
uv run ruff check
uv run ruff format
```

Some constraints apply:

- The code must run on Python 3.9 and use only the standard library.
- It must never touch the network.
- Test messages must be invented. Never use a real person's message, number or account.
- Scam links in tests must use invented domains.

Releases are covered in [docs/RELEASING.md](https://github.com/Daemon-VI/rithik/blob/main/docs/RELEASING.md).

## License

MIT. See [LICENSE](https://github.com/Daemon-VI/rithik/blob/main/LICENSE).

---

Made by [Rithik Krishna T](https://github.com/Daemon-VI).
