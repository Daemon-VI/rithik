"""Scores a message against the rule set and the link checks.

The engine never fetches a URL or resolves a name: everything it says comes from the text it
was given. That keeps it safe to run on a message you have not decided to trust yet.
"""

from __future__ import annotations

import math
import re
import unicodedata

from rithik.scam import rules, urls
from rithik.scam.model import Reason, Report, Verdict
from rithik.scam.weights import (
    EVIDENCE_MAX_CHARS,
    NEGATIVE_FLOOR,
    SCAM_THRESHOLD,
    SCORE_SCALE,
    STRONG_SIGNAL,
    SUSPICIOUS_THRESHOLD,
    WEIGHTS,
)

# Zero-width characters and soft hyphens are invisible in a phone's SMS view, and scammers
# drop them inside words ("O<ZWSP>TP") precisely so that keyword filters miss them.
_INVISIBLE = dict.fromkeys((0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
_QUOTES = {0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"'}
_WHITESPACE = re.compile(r"\s+")

_URL_LABELS: dict[str, str] = {
    "url_brand_impersonation": "Link uses a bank or brand name on a domain that brand does not own.",
    "url_apk": "Link downloads an Android app file (APK) directly.",
    "url_ip_host": "Link points at a bare IP address instead of a named website.",
    "url_punycode": "Link uses look-alike (punycode or non-Latin) characters in its domain.",
    "url_userinfo": "Link hides its real destination behind an '@' sign.",
    "url_risky_tld": "Link uses a cheap domain ending that is common in phishing.",
    "url_shortener": "Link is shortened, which hides where it really goes.",
    "url_many_subdomains": "Link stacks many subdomains, a trick to push the real domain out of view.",
    "url_plain_http": "Link is not encrypted (plain http).",
    "official_link": "Links only to an official domain of a bank, company or the government.",
    "chat_link_money": "WhatsApp or Telegram link offered together with money or job talk.",
    "link_with_request": "Asks for something and gives a link that is not an official site.",
}

_LABELS: dict[str, str] = {rule.code: rule.label for rule in rules.RULES}
_LABELS.update(_URL_LABELS)


def analyze(text: str) -> Report:
    """Score one message. Never raises on odd text and never touches the network."""
    if not isinstance(text, str):
        raise TypeError(f"analyze() expects str, not {type(text).__name__}")
    display = _normalise(text)
    if not display:
        return Report(verdict=Verdict.NO_SIGNALS, score=0.0, reasons=(), urls=())
    lowered = display.lower()
    # Lower-casing is length-preserving for almost all text; when it is, evidence can be cut
    # from the original casing, which reads better and matches what the user sees.
    source = display if len(lowered) == len(display) else lowered

    hits: dict[str, tuple[float, str]] = {}

    def add(key: str, evidence: str) -> None:
        code = key.split(".", 1)[0]
        weight = WEIGHTS[key]
        current = hits.get(code)
        # One entry per code: repeating a phrase ten times must not count ten times.
        if current is None or abs(weight) > abs(current[0]):
            hits[code] = (weight, evidence)

    seen: dict[str, bool] = {}
    for rule in rules.RULES:
        found = rule.scan(lowered, seen)
        if found is not None:
            add(found[0], _evidence(source, lowered, found[1]))

    links = urls.extract_links(display)
    official_only = bool(links)
    unofficial = False
    for link in links:
        findings = urls.link_findings(link)
        if not any(k == "official_link" for k, _ in findings):
            official_only = False
            unofficial = True
        for key, evidence in findings:
            if key != "official_link":
                add(key, evidence)
        if urls.is_chat_link(link) and rules.MONEY_OR_JOB.search(lowered):
            add("chat_link_money", link.raw)
    if official_only:
        add("official_link", links[0].raw)

    if unofficial:
        requesting = [code for code in hits if code in rules.REQUEST_CODES]
        if requesting:
            first_unofficial = next(
                link.raw for link in links if not urls.is_official(link.host) or link.has_userinfo
            )
            add("link_with_request", first_unofficial)
        if "echallan" in hits:
            add("echallan.link", hits["echallan"][1])

    return _score(hits, tuple(link.raw for link in links))


def _score(hits: dict[str, tuple[float, str]], found_urls: tuple[str, ...]) -> Report:
    strongest = max((w for w, _ in hits.values()), default=0.0)
    if strongest >= STRONG_SIGNAL:
        # A genuine link or an OTP warning pasted next to a PIN request buys nothing.
        hits = {code: hit for code, hit in hits.items() if hit[0] > 0}
    positive = sum(w for w, _ in hits.values() if w > 0)
    negative = max(NEGATIVE_FLOOR, sum(w for w, _ in hits.values() if w < 0))
    raw = max(0.0, positive + negative)
    score = 1.0 - math.exp(-raw / SCORE_SCALE)

    if score >= SCAM_THRESHOLD:
        verdict = Verdict.SCAM
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.NO_SIGNALS

    reasons = tuple(
        Reason(code=code, label=_LABELS[code], evidence=_clip(evidence), weight=weight)
        for code, (weight, evidence) in sorted(
            hits.items(), key=lambda item: (-item[1][0], item[0])
        )
    )
    return Report(verdict=verdict, score=score, reasons=reasons, urls=found_urls)


def _normalise(text: str) -> str:
    # NFKC folds the "bold" and full-width letters used to dodge filters back to plain ASCII.
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE).translate(_QUOTES)
    return _WHITESPACE.sub(" ", text).strip()


def _evidence(source: str, lowered: str, matched: str) -> str:
    if source is lowered:
        return matched
    index = lowered.find(matched)
    return source[index : index + len(matched)] if index >= 0 else matched


def _clip(evidence: str) -> str:
    evidence = evidence.strip()
    if len(evidence) <= EVIDENCE_MAX_CHARS:
        return evidence
    return evidence[: EVIDENCE_MAX_CHARS - 3].rstrip() + "..."
