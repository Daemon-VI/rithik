"""Text rules: the pretexts and asks that Indian scam messages are built from.

Each rule is a cheap substring prefilter plus a few precompiled patterns. The prefilter is what
keeps a megabyte of ordinary text fast: most rules never run a regex at all. Every gap in a
pattern is capped (".{0,40}?", never ".*"), so the worst case stays linear in input size.

Patterns run against text the engine has already lower-cased and whitespace-collapsed, which
is why they carry no case handling and use single spaces.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Callable, Optional

from rithik.scam.weights import WEIGHTS

# "no" is left out on purpose: "a/c no XX1234" is in half of all bank SMS. The lookahead
# keeps pressure phrases like "do not ignore" from reading as a negation of what follows.
_NEGATION_BEFORE = re.compile(
    r"\b(?:not|never|dont|don't|do not|no need|no such|without|nahi|nahin)\b"
    r"(?! (?:ignore|delay|miss|wait|worry|panic|forget|a (?:scam|fraud|fake)))"
)
# Inside the matched span itself ("OTP is 1234. Do not share").
_NEGATION_INSIDE = re.compile(r"\b(?:not|never|dont|don't|nahi|nahin|mat)\b")
# Hindi puts the negation after the verb: "OTP share na karein", "share mat karo".
_NEGATION_AFTER = re.compile(r"^\W{0,3}(?:na|mat|nahi|nahin|nhi)\b")
_NEGATION_WINDOW = 40

# How a rule treats a nearby negation. An "ask" rule is about a request, so "never share your
# OTP" flips its meaning; a "before" rule only checks the words leading up to the match; a
# rule with no negation handling describes a threat, where "do not" is usually part of it.
NEG_NONE = ""
NEG_BEFORE = "before"
NEG_ASK = "ask"

Benign = Callable[[str, "re.Match[str]"], bool]


@dataclass(frozen=True)
class Rule:
    code: str
    label: str
    triggers: tuple[str, ...]
    patterns: tuple[tuple[str, WordPattern], ...]  # (weight key, compiled pattern)
    negation: str = NEG_NONE
    benign: Optional[Benign] = None  # returns True when a match is harmless in context

    def scan(self, text: str, seen: dict[str, bool] | None = None) -> tuple[str, str] | None:
        """Return (weight key, evidence) for the heaviest pattern that matched, if any.

        ``seen`` memoises trigger lookups across rules; each lookup is a full pass over the
        text, and several rules share triggers.
        """
        if seen is None:
            seen = {}
        if not any(_contains(text, t, seen) for t in self.triggers):
            return None
        best: tuple[str, str] | None = None
        for key, pattern in self.patterns:
            if best is not None and WEIGHTS[key] <= WEIGHTS[best[0]]:
                continue
            for match in pattern.finditer(text):
                if self.negation and _negated(text, match, self.negation):
                    continue
                if self.benign is not None and self.benign(text, match):
                    continue
                best = (key, match.group(0))
                break
        return best


def _contains(text: str, trigger: str, seen: dict[str, bool]) -> bool:
    found = seen.get(trigger)
    if found is None:
        found = seen[trigger] = trigger in text
    return found


def _negated(text: str, match: re.Match[str], mode: str) -> bool:
    start, end = match.span()
    if _NEGATION_BEFORE.search(text[max(0, start - _NEGATION_WINDOW) : start]):
        return True
    if mode != NEG_ASK:
        return False
    if _NEGATION_INSIDE.search(match.group(0)):
        return True
    return _NEGATION_AFTER.search(text[end : end + 12]) is not None


class WordPattern:
    """A compiled pattern whose matches must start at a word boundary.

    A leading ``\\b`` stops the regex engine from skipping ahead to positions that can start a
    match, which makes a megabyte scan several times slower. So the ``\\b`` is removed before
    compiling and the boundary is checked here instead, on the few positions that matched.
    """

    __slots__ = ("regex", "word_start")

    def __init__(self, source: str) -> None:
        stripped, every_branch_bounded = _strip_leading_boundaries(source)
        self.word_start = every_branch_bounded
        self.regex = re.compile(stripped if every_branch_bounded else source)

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        if not self.word_start:
            yield from self.regex.finditer(text)
            return
        search = self.regex.search
        pos = 0
        while True:
            match = search(text, pos)
            if match is None:
                return
            start, end = match.span()
            if start and _is_word_char(text[start - 1]):
                pos = start + 1
                continue
            yield match
            pos = end if end > start else start + 1


def _is_word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _strip_leading_boundaries(source: str) -> tuple[str, bool]:
    """Drop the ``\\b`` that opens each top-level branch; report whether every branch had one."""
    out: list[str] = []
    depth = 0
    in_class = False
    at_branch_start = True
    all_bounded = True
    i = 0
    while i < len(source):
        if at_branch_start:
            at_branch_start = False
            if source.startswith(r"\b", i):
                i += 2
                continue
            all_bounded = False
        char = source[i]
        if char == "\\":
            out.append(source[i : i + 2])
            i += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            at_branch_start = True
        out.append(char)
        i += 1
    return "".join(out), all_bounded


def _c(pattern: str) -> WordPattern:
    return WordPattern(pattern)


# Context checks -----------------------------------------------------------------------------

_DELIVERY_WORDS = re.compile(
    r"\b(?:delivery|driver|captain|rider|pilot|courier boy|at the time of)\b"
)
_INLINE_CODE = re.compile(r"\b\d{4,8}\b")


def _otp_delivery_context(text: str, match: re.Match[str]) -> bool:
    # Delivery and ride apps send "share OTP 4821 with the delivery agent". The code is in the
    # message itself, which is what separates them from a request for an OTP you received.
    start, end = match.span()
    window = text[max(0, start - 40) : end + 60]
    return bool(_DELIVERY_WORDS.search(window) and _INLINE_CODE.search(window))


_ON_REQUEST = re.compile(r"\b(?:as per|on|at) your request\b|\bsuccessfully\b")


def _blocked_on_request(text: str, match: re.Match[str]) -> bool:
    return _ON_REQUEST.search(text[match.end() : match.end() + 40]) is not None


_AVOID = re.compile(r"\b(?:avoid|prevent|to escape)\b")


def _avoid_disconnection(text: str, match: re.Match[str]) -> bool:
    # "Pay by the due date to avoid disconnection" is an ordinary bill reminder.
    start = match.start()
    return _AVOID.search(text[max(0, start - 20) : match.end()]) is not None


_AWARENESS_BEFORE = re.compile(
    r"\b(?:beware|scams?|frauds?|fake|no such|there is no|is not a|awareness|be careful"
    r"|never)\b"
)
_AWARENESS_AFTER = re.compile(r"^\W{0,3}(?:scams?|frauds?|calls? are fake)\b")


def _awareness_message(text: str, match: re.Match[str]) -> bool:
    # Police and banks run "beware of digital arrest scams" campaigns over SMS; those name the
    # same agencies and threats, so they are told apart by the warning words around them.
    start, end = match.span()
    if _AWARENESS_BEFORE.search(text[max(0, start - 40) : start]):
        return True
    return _AWARENESS_AFTER.search(text[end : end + 20]) is not None


_WARNING_WORDS = re.compile(
    r"\b(?:beware|frauds?|fraudsters?|scams?|scammers?|never|do not|don't|dont)\b"
)


def _warning_nearby(text: str, match: re.Match[str]) -> bool:
    # Bank safety notices list the apps to refuse ("never install AnyDesk, beware of
    # fraudsters"); the warning can sit a sentence before or after the app name.
    start, end = match.span()
    return _WARNING_WORDS.search(text[max(0, start - 60) : end + 60]) is not None


# Shared vocabulary --------------------------------------------------------------------------

_ACCOUNT = (
    r"(?:a/?c|acct|account|bank account|khata|debit card|credit card|atm card|atm|card"
    r"|net ?banking|internet banking|mobile banking|yono|wallet|upi id|upi)"
)
_BLOCK_STATE = (
    r"(?:blocked|block|suspended|suspend|deactivated|deactivate|closed|frozen|freezed|on hold"
    r"|hold|restricted|disabled|terminated|locked)"
)
_FUTURE = r"(?:will|shall|is going to|may|would)(?: be| get)?"
_HI_WILL_CLOSE = (
    r"(?:band|bandh|block) ?(?:ho|kar|kr) ?(?:jayega|jaega|jayegi|jaegi|jaayega|diya jayega"
    r"|di jayegi|dia jayega|sakta|sakti)"
)
_MONEY = r"(?:rs\.? ?\d|inr ?\d|₹ ?\d|\d+ ?(?:lakh|lac|crore|cr)\b|rupees|rupaye)"
# A lakh or more, in words or in either digit grouping ("25,00,000" or "2,500,000").
_BIG_MONEY = (
    r"(?:\b\d+ ?(?:lakh|lac|crore)\b|(?:rs\.? ?|inr ?|₹ ?)(?:\d{1,2}(?:,\d\d)+,\d{3}"
    r"|\d{1,3}(?:,\d{3}){2,}|\d{6,})\b)"
)
_OTP = r"(?:otp|one ?time ?password|one-time password|verification code|otp code|o\.t\.p)"
_OTP_VERB = (
    r"(?:share|send|tell|forward|provide|give|read out|reply with|batao|bataye|bataiye"
    r"|bata do|bata dijiye|bhejo|bhej do|bhejiye|bhejein|de do|dedo|dijiye)"
)
_REMOTE_APPS = (
    r"(?:anydesk|any desk app|teamviewer|team viewer|quicksupport|rustdesk|rust desk|airdroid"
    r"|ammyy|ultraviewer|ultra viewer|alpemix|splashtop|screen ?share app|screen sharing app"
    r"|remote access app)"
)
_INSTALL = r"(?:download|install|instal|open|daal|dalo|launch)"
_PIN = r"(?:upi pin|upi-pin|mpin|m-pin|pin)"
_RECEIVE = (
    r"(?:receiv\w*|claim|accept (?:the )?(?:money|payment|amount)|get (?:the |your )?"
    r"(?:money|amount|payment|cashback|refund|prize)|credited|refund|cashback|prapt|milega"
    r"|paane|lene)"
)
_SIM_STATE = r"(?:blocked|deactivated|disconnected|suspended|barred|closed|terminated)"


RULES: tuple[Rule, ...] = (
    Rule(
        code="otp_request",
        label="Asks you to share an OTP; no bank, company or officer ever needs your OTP.",
        triggers=("otp", "one time", "one-time", "onetime", "verification code", "o.t.p"),
        patterns=(
            ("otp_request", _c(rf"\b{_OTP_VERB}\b.{{0,30}}?\b{_OTP}\b")),
            ("otp_request", _c(rf"\b{_OTP}\b.{{0,50}}?\b{_OTP_VERB}\b")),
        ),
        negation=NEG_ASK,
        benign=_otp_delivery_context,
    ),
    Rule(
        code="upi_pin_to_receive",
        label="Asks for a PIN to receive money; receiving money never needs your UPI PIN.",
        triggers=("pin",),
        patterns=(
            (
                "upi_pin_to_receive",
                _c(
                    r"\b(?:enter|type|put|provide|use|share|daal\w*|dalein|dale|dalo)"
                    rf" (?:your |ur |the |apna |aapka )?{_PIN}\b.{{0,50}}?\b{_RECEIVE}"
                ),
            ),
            (
                "upi_pin_to_receive",
                _c(
                    rf"\b{_RECEIVE}\b.{{0,50}}?\b(?:enter|type|put|provide|daal\w*|dalein)"
                    rf" (?:your |ur |the |apna )?{_PIN}\b"
                ),
            ),
            ("upi_pin_to_receive", _c(rf"\b{_PIN}\b.{{0,20}}?\b(?:to|for) (?:receive|claim)")),
        ),
        negation=NEG_ASK,
    ),
    Rule(
        code="upi_collect_refund",
        label="Dresses up a UPI collect request as a refund, prize or incoming payment.",
        triggers=("request",),
        patterns=(
            (
                "upi_collect_refund",
                _c(
                    r"\b(?:collect|payment|money) request\b.{0,60}?"
                    r"\b(?:refund|cashback|receive|prize|reward|credited)"
                ),
            ),
            (
                "upi_collect_refund",
                _c(
                    r"\b(?:refund|cashback|prize|reward)\w*\b.{0,60}?\b(?:approve|accept|pay)"
                    r" (?:the |this |our )?(?:collect |upi |payment )?request"
                ),
            ),
        ),
        negation=NEG_ASK,
    ),
    Rule(
        code="remote_access_app",
        label="Names a screen-sharing app; scammers use these to watch you type your PIN.",
        triggers=(
            "desk",
            "viewer",
            "quicksupport",
            "airdroid",
            "ammyy",
            "alpemix",
            "splashtop",
            "screen",
            "remote access",
        ),  # fmt: skip
        patterns=(
            ("remote_access_app.install", _c(rf"\b{_INSTALL}\w*\b.{{0,30}}?\b{_REMOTE_APPS}\b")),
            ("remote_access_app", _c(rf"\b{_REMOTE_APPS}\b")),
        ),
        negation=NEG_ASK,
        benign=_warning_nearby,
    ),
    Rule(
        code="apk_download",
        label="Asks you to install an app file (APK) from outside the Play Store.",
        triggers=("apk", "app file"),
        patterns=(
            ("apk_download", _c(rf"\b{_INSTALL}\w*\b.{{0,40}}?(?:\bapk\b|\.apk\b|\bapp file\b)")),
            ("apk_download.file", _c(r"(?<![\w-])[\w-]{1,40}\.apk\b")),
        ),
        negation=NEG_ASK,
    ),
    Rule(
        code="digital_arrest",
        label="Threatens a 'digital arrest'; no Indian agency arrests anyone over a call.",
        triggers=("arrest",),
        patterns=(("digital_arrest", _c(r"\bdigital(?:ly)? (?:house )?arrest\w*")),),
        benign=_awareness_message,
    ),
    Rule(
        code="authority_threat",
        label="Claims to be police, CBI, customs or another agency and threatens legal trouble.",
        triggers=(
            "police",
            "cbi",
            "ncb",
            "narcotic",
            "customs",
            "crime",
            "cyber",
            "enforcement",
            "interpol",
            "warrant",
            "laundering",
            "drugs",
            "court",
            "bailable",
            "against you",
        ),
        # fmt: skip
        patterns=(
            (
                "authority_threat.parcel_contraband",
                _c(
                    r"\b(?:parcel|package|courier|shipment|consignment)\b.{0,60}?"
                    r"\b(?:drugs|narcotics|mdma|ganja|contraband|fake passports?|illegal items)"
                ),
            ),
            (
                "authority_threat",
                _c(
                    r"\b(?:cbi|ncb|narcotics|crime branch|cyber ?(?:cell|crime|police)|police"
                    r"|customs|enforcement directorate|interpol|court)\b.{0,60}?"
                    r"\b(?:arrest|warrant|fir\b|case (?:registered|filed|against)|illegal"
                    r"|money laundering|seized|summons?|legal action|video call|skype)"
                ),
            ),
            (
                "authority_threat",
                _c(
                    r"\b(?:arrest warrant|money laundering case|non[- ]?bailable"
                    r"|(?:fir|case) (?:has been |is )?(?:registered|filed) against you)"
                ),
            ),
        ),
        benign=_awareness_message,
    ),
    Rule(
        code="utility_disconnection",
        label="Threatens to cut your electricity or gas; power boards do not warn like this.",
        triggers=("electric", "power", "bijli", "bijlee", "light", "gas", "eb "),
        patterns=(
            (
                "utility_disconnection",
                _c(
                    r"\b(?:your|ur|aapka|apka|aapki|apki|tumhara)"
                    r" (?:electricity|electric|power|bijli|bijlee|light|gas|eb)\b.{0,50}?"
                    r"\b(?:disconnect\w*|cut|kaat|kat|katt|band|bandh)\b"
                ),
            ),
            (
                "utility_disconnection",
                _c(
                    r"\b(?:electricity|electric|power|bijli|bijlee|light|gas)\b.{0,50}?"
                    r"\b(?:disconnect\w*|cut|kaat|kat|band)\b.{0,30}?"
                    r"\b(?:tonight|today|aaj raat|aaj|at \d{1,2}[:.]?\d{0,2} ?(?:pm|am|baje))"
                ),
            ),
            (
                "utility_disconnection.officer",
                _c(
                    r"\b(?:electricity|electric|bijli|power|eb|gas) (?:officer|office|department"
                    r"|dept|adhikari)\b"
                ),
            ),
            (
                "utility_disconnection.bill",
                _c(
                    r"\b(?:previous|last|pichle|pichhle) (?:month(?:'s)?|mahine ka)"
                    r" (?:electricity )?bill (?:was |is |has )?(?:not|nahi|nhi) (?:been )?"
                    r"(?:update|paid|pay|jama)"
                ),
            ),
            (
                "utility_disconnection.generic",
                _c(
                    r"\b(?:electricity|electric|bijli|power|gas)\b.{0,30}?"
                    r"\bdisconnect(?:ed|ion)\b"
                ),
            ),
        ),
        benign=_avoid_disconnection,
    ),
    Rule(
        code="sim_deactivation",
        label="Says your SIM or mobile number will be blocked; a classic pretext to get a call.",
        triggers=("sim", "number", "mobile", "trai"),
        patterns=(
            (
                "sim_deactivation.trai",
                _c(r"\btrai\b.{0,80}?\b(?:disconnect|block|deactivat|suspend|band|barred)"),
            ),
            (
                "sim_deactivation",
                _c(
                    r"\b(?:sim(?: card)?|mobile (?:number|connection|service)|phone number"
                    r"|your number)\b.{0,40}?"
                    rf"\b(?:{_FUTURE} (?:permanently |temporarily )?{_SIM_STATE}|{_HI_WILL_CLOSE})"
                ),
            ),
        ),
        negation=NEG_BEFORE,
        benign=_awareness_message,
    ),
    Rule(
        code="kyc_update",
        label="Asks you to update or verify KYC, PAN or Aadhaar through a message.",
        triggers=("kyc", "pan", "aadha", "adhar"),
        patterns=(
            (
                "kyc_update",
                _c(
                    r"\b(?:e-?|re-?|video )?kyc\b.{0,40}?"
                    r"(?:\bupdat(?:e\b|ion)|\bverify\b|\bverification (?:is )?(?:pending"
                    r"|required|due|failed)|\bpending|\bexpir(?:ed|es|ing|y)|\bincomplete"
                    r"|\bnot (?:updated|verified|completed?|done)|\bsuspend|\bblock|\bkarein"
                    r"|\bkare\b|\bkaro\b|\bkarwaye|\bnahi hua|\bnhi hua)"
                ),
            ),
            (
                "kyc_update",
                _c(
                    r"\b(?:update|verify|link|complete|submit|upload|updating|verifying)"
                    r" (?:your |ur |the |apna |aapka |apka )?"
                    r"(?:e-?kyc|kyc|pan(?: card)?|aadhaa?r(?: card)?|adhar(?: card)?)\b"
                ),
            ),
            (
                "kyc_update",
                _c(
                    r"\b(?:pan|aadhaa?r|adhar)(?: card)?(?: (?:no|number|details))?"
                    r" (?:is |has )?(?:not (?:been )?(?:updated|linked|verified)|expired|pending"
                    r"|update (?:karein|kare|karo|now)|link nahi)"
                ),
            ),
        ),
        negation=NEG_BEFORE,
    ),
    Rule(
        code="account_blocked",
        label="Claims your bank account, card or UPI will be blocked unless you act.",
        triggers=(
            "block",
            "suspend",
            "deactivat",
            "closed",
            "frozen",
            "freez",
            "hold",
            "restrict",
            "disabl",
            "terminat",
            "locked",
            "band",
        ),  # fmt: skip
        patterns=(
            (
                "account_blocked",
                _c(
                    rf"\b{_ACCOUNT}\b.{{0,30}}?\b{_FUTURE} ?(?:temporarily |permanently )?"
                    rf"{_BLOCK_STATE}\b"
                ),
            ),
            ("account_blocked", _c(rf"\b{_ACCOUNT}\b.{{0,30}}?\b{_HI_WILL_CLOSE}")),
            (
                "account_blocked",
                _c(
                    rf"\b{_ACCOUNT}\b.{{0,30}}?\b{_BLOCK_STATE}\b.{{0,15}}?"
                    r"\b(?:today|tonight|within|in \d+ ?(?:hours?|hrs?|minutes?|mins?))"
                ),
            ),
            (
                "account_blocked.past",
                _c(
                    rf"\b{_ACCOUNT}\b.{{0,30}}?\b(?:has been|have been|is|was|got|has got)"
                    rf" (?:temporarily |permanently )?{_BLOCK_STATE}\b"
                ),
            ),
        ),
        benign=_blocked_on_request,
    ),
    Rule(
        code="prize_lottery",
        label="Says you won a prize, lottery or lucky draw you never entered.",
        triggers=(
            "won",
            "win",
            "jeet",
            "lottery",
            "lucky",
            "jackpot",
            "kbc",
            "crorepati",
            "bumper",
        ),  # fmt: skip
        patterns=(
            (
                "prize_lottery",
                _c(
                    r"\b(?:you (?:have|are)|you've|u have|u hv) (?:been )?"
                    r"(?:won|win|selected for|jeet\w*)\b.{0,40}?"
                    rf"(?:{_MONEY}|\b(?:lottery|lucky draw|prize|jackpot|bumper|cash|gift|iphone"
                    r"|car|bike|reward|lakh|crore))"
                ),
            ),
            ("prize_lottery", _c(r"\baap(?:ne|ka|ki)?\b.{0,40}?\bjeet(?:e|a|i|ne)\b")),
            ("prize_lottery", _c(r"\b(?:you are|u r|you're) (?:the |our )?(?:lucky )?winner")),
            (
                "prize_lottery",
                _c(r"\bcongratulations?\b.{0,60}?\b(?:won|winner|jeet\w*|lucky draw|lottery)"),
            ),
            (
                "prize_lottery.big",
                _c(
                    r"\b(?:kbc|kaun banega crorepati|lottery|lucky draw|jackpot|bumper)\b"
                    r".{0,60}?\b(?:won|winner|jeet\w*|lakh|lac|crore|claim|prize money)\b"
                    rf"|\b(?:won|winner|jeet\w*)\b.{{0,40}}?{_BIG_MONEY}.{{0,40}}?"
                    r"\b(?:kbc|lottery|lucky draw|jackpot|bumper|prize)\b"
                ),
            ),
            ("prize_lottery.kbc", _c(r"\b(?:kbc|kaun banega crorepati)\b")),
            (
                "prize_lottery.mention",
                _c(r"\b(?:lottery|lucky draw|jackpot|bumper (?:prize|draw))\b"),
            ),
        ),
        negation=NEG_BEFORE,
    ),
    Rule(
        code="task_job_offer",
        label="Offers easy paid 'tasks' or part-time work, a common route into deposit scams.",
        triggers=(
            "part",
            "work from home",
            "wfh",
            "home based",
            "home-based",
            "ghar baithe",
            "earn",
            "kama",
            "task",
            "like",
            "subscrib",
            "rate",
            "rating",
            "review",
            "follow",
            "telegram",
            "whatsapp",
            "income",
            "salary",
        ),
        # fmt: skip
        patterns=(
            (
                "task_job_offer.task",
                _c(
                    r"\b(?:lik(?:e|es|ing)|subscrib(?:e|es|ing)|rat(?:e|es|ing)"
                    r"|review(?:s|ing)?|follow(?:s|ing)?) (?:\w+ ){0,2}(?:youtube|yt|google|hotels?|instagram|insta|videos?"
                    r"|restaurants?|movies?|channels?)\b.{0,80}?"
                    rf"(?:\bearn|\bpaid\b|\bsalary|\bincome|\bcommission|{_MONEY})"
                ),
            ),
            (
                "task_job_offer.task",
                _c(
                    r"\b(?:prepaid|pre-paid|advance|merchant|online) tasks?\b"
                    r"|\btask[- ]based\b"
                    r"|\btasks?\b.{0,40}?\b(?:commission|profit|recharge|deposit|prepay)"
                ),
            ),
            (
                "task_job_offer",
                _c(
                    r"\b(?:part[- ]?time|work from home|wfh|home[- ]based|ghar baithe)\b.{0,60}?"
                    r"\b(?:job|work|earn|income|kamaye|kamayein|kamao|salary|daily|per day"
                    r"|paise)\b"
                ),
            ),
            (
                "task_job_offer",
                _c(
                    rf"\b(?:earn|kamaye|kamayein|kamao|income of|salary of)\b.{{0,20}}?{_MONEY}"
                    r".{0,25}?(?:per day|a day|daily|/ ?day|every day|per hour|/ ?hr|pratidin"
                    r"|roz|rozana|din ke)"
                ),
            ),
            (
                "task_job_offer.chat",
                _c(
                    r"\b(?:job|hr manager|hr team|recruit\w*|hiring|vacancy|task)\b.{0,50}?"
                    r"\b(?:telegram|whatsapp)\b"
                    r"|\b(?:telegram|whatsapp)\b.{0,40}?\b(?:job|recruiter|task|earn\w*)\b"
                ),
            ),
        ),
    ),
    Rule(
        code="parcel_held",
        label="Says a parcel is held or undeliverable, usually to collect a fee or card details.",
        triggers=(
            "parcel",
            "package",
            "shipment",
            "courier",
            "consignment",
            "delivery",
            "address",
            "pin code",
            "pincode",
            "house number",
        ),  # fmt: skip
        patterns=(
            (
                "parcel_held",
                _c(
                    r"\b(?:parcel|package|shipment|courier|consignment|delivery)\b.{0,50}?"
                    r"\b(?:on hold|held|holding|could not be delivered|couldn't be delivered"
                    r"|cannot be delivered|can't be delivered|undeliver\w*|delivery failed"
                    r"|failed delivery|delivery attempt failed|suspended|seized|stuck|detained"
                    r"|rok (?:diya|liya|lia))"
                ),
            ),
            (
                "parcel_held",
                _c(
                    r"\b(?:address|pin ?code|house number)\b (?:is |was )?"
                    r"(?:incomplete|incorrect|invalid|wrong|not (?:complete|found|clear|correct))"
                    r"|\bincomplete (?:address|house number|street|delivery address)"
                ),
            ),
            (
                "parcel_held.address",
                _c(
                    r"\b(?:update|confirm|correct|re-?enter) (?:your |the )?"
                    r"(?:delivery |shipping )?address"
                ),
            ),
        ),
    ),
    Rule(
        code="advance_fee",
        label="Asks for a small fee up front to release a parcel, loan, job or prize.",
        triggers=("fee", "charge", "deposit", "amount", "pay", "send", "transfer"),
        patterns=(
            (
                "advance_fee",
                _c(
                    r"\b(?:redelivery|re-delivery|customs|clearance|unlock|activation|release"
                    r"|small|nominal|refundable|token) (?:fee|fees|charges?|amount|deposit)\b"
                ),
            ),
            (
                "advance_fee",
                _c(
                    r"\b(?:pay|deposit|transfer|send)\b (?:only |just )?"
                    r"(?:rs\.? ?|₹ ?|inr ?)\d{1,3}\b(?!,\d)(?! ?(?:lakh|lac|crore|k\b))"
                    r".{0,30}?\b(?:fee|charge|to (?:receive|release|reschedule|claim|redeliver))"
                ),
            ),
            (
                "advance_fee.processing",
                _c(
                    r"\b(?:processing|registration|security|verification|file|insurance"
                    r"|documentation) (?:fee|fees|charges?|deposit)\b"
                ),
            ),
        ),
    ),
    Rule(
        code="loan_offer",
        label="Pushes an instant or pre-approved loan, a common lure for fee and data theft.",
        triggers=("loan",),
        patterns=(
            (
                "loan_offer.no_checks",
                _c(
                    r"\bloan\b.{0,60}?\b(?:without|no) (?:cibil|credit score|credit check"
                    r"|documents?|document verification|income proof|paperwork)"
                ),
            ),
            (
                "loan_offer.no_checks",
                _c(
                    r"\bloan\b.{0,60}?\b(?:approved|sanctioned)\b.{0,40}?"
                    r"\b(?:pay|deposit|processing|registration|fee)"
                ),
            ),
            (
                "loan_offer",
                _c(
                    r"\b(?:instant|pre-?approved|preapproved|guaranteed|urgent|quick|easy)"
                    r" (?:personal |cash |mobile |app )?loans?\b"
                ),
            ),
        ),
    ),
    Rule(
        code="investment_scheme",
        label="Promises guaranteed, doubled or unrealistic investment returns.",
        triggers=(
            "return",
            "profit",
            "double",
            "tripl",
            "2x",
            "3x",
            "5x",
            "10x",
            "crypto",
            "bitcoin",
            "btc",
            "usdt",
            "forex",
            "trading",
            "market",
            "earning",
            "income",
        ),
        # fmt: skip
        patterns=(
            (
                "investment_scheme.doubling",
                _c(
                    r"\b(?:double|triple|2x|3x|5x|10x) (?:your )?(?:money|investment|amount"
                    r"|paisa|paise|capital)\b|\b(?:money|investment|amount|paisa|paise)"
                    r" (?:will |gets? |ho )?(?:be )?(?:doubled|tripled|double|triple)\b"
                ),
            ),
            (
                "investment_scheme.daily",
                _c(
                    r"\b(?:returns?|profits?)\b (?:of )?(?:up to |upto )?\d+ ?%"
                    r" ?(?:daily|per day|a day|weekly|per week|in \d+ days?)"
                ),
            ),
            (
                "investment_scheme",
                _c(
                    r"\b(?:guaranteed|assured|sure[- ]?shot|risk[- ]free|100 ?% ?"
                    r"(?:guaranteed|assured|sure|safe))"
                    r" (?:daily |weekly |monthly |high )?(?:returns?|profits?|income|earnings?)"
                ),
            ),
            (
                "investment_scheme.crypto",
                _c(
                    r"\b(?:crypto|bitcoin|btc|usdt|forex|trading|stock market|share market)\b"
                    r".{0,40}?\b(?:profit|returns?|earn\w*|guaranteed|vip group|signals?"
                    r"|tips group)"
                ),
            ),
        ),
        negation=NEG_BEFORE,
    ),
    Rule(
        code="reward_points",
        label="Says reward points are about to expire, to lure you to a card-details page.",
        triggers=("point", "pts"),
        patterns=(
            (
                "reward_points",
                _c(
                    r"\b(?:reward|redeem|redemption|loyalty|credit card|card) ?(?:points?|pts)\b"
                    r".{0,60}?\b(?:expir\w*|lapse|will be (?:lost|forfeited)|redeem (?:now"
                    r"|today|immediately)|worth (?:rs|inr|₹))"
                ),
            ),
        ),
    ),
    Rule(
        code="tax_refund",
        label="Says an income-tax refund is waiting; the department never asks you to claim it.",
        triggers=("refund",),
        patterns=(
            (
                "tax_refund",
                _c(
                    r"\b(?:income ?tax|it dept|it department|itr|tax) refund\b.{0,80}?"
                    r"\b(?:verify|update|click|claim|submit|confirm|link|account details"
                    r"|bank details)"
                ),
            ),
            (
                "tax_refund",
                _c(
                    r"\brefund of (?:rs\.? ?|₹ ?|inr ?)[\d,.]+.{0,60}?\b(?:income ?tax|itr)\b"
                    r".{0,60}?\b(?:verify|update|click|claim|submit|confirm)"
                ),
            ),
            (
                "tax_refund.status",
                _c(r"\b(?:income ?tax|itr) refund\b.{0,40}?\b(?:approved|pending|sanctioned)"),
            ),
        ),
    ),
    Rule(
        code="echallan",
        label="Mentions a traffic e-challan; fake challan links are a common phishing lure.",
        triggers=("challan",),
        patterns=(
            (
                "echallan",
                _c(
                    r"\b(?:e-? ?challan|traffic (?:challan|fine)"
                    r"|challan (?:of|no|number|pending|issued|amount))"
                ),
            ),
        ),
    ),
    Rule(
        code="mistaken_transfer",
        label="Claims money was sent to you by mistake and asks for it back.",
        triggers=("mistake", "galti", "wrongly"),
        patterns=(
            (
                "mistaken_transfer",
                _c(
                    r"\b(?:sent|send|transferred|credited|paid|bheja|bhej diya)\b.{0,40}?"
                    r"\b(?:by mistake|mistakenly|galti se|wrongly)"
                    r"|\b(?:galti se|by mistake)\b.{0,40}?\b(?:paise|money|payment|rs\b|rs\.)"
                ),
            ),
        ),
    ),
    Rule(
        code="threat_of_loss",
        label="Threatens a loss or penalty to rush you.",
        triggers=(
            "warning",
            "notice",
            "legal",
            "will be",
            "shall be",
            "band",
            "kaat",
            "block",
        ),  # fmt: skip
        patterns=(
            (
                "threat_of_loss",
                _c(
                    r"\b(?:last|final) (?:warning|notice|reminder before)\b|\blegal action\b"
                    r"|\b(?:will|shall) be (?:permanently )?(?:blocked|suspended|deactivated"
                    r"|disconnected|terminated|seized|frozen|closed)\b"
                    rf"|\b{_HI_WILL_CLOSE}|\bkaat (?:diya|di|dia) (?:jayega|jayegi|jaega)"
                ),
            ),
        ),
    ),
    Rule(
        code="urgency",
        label="Pushes you to act immediately, a pressure tactic.",
        triggers=(
            "expir",
            "within",
            "immediate",
            "urgent",
            "asap",
            "right now",
            "act now",
            "turant",
            "jaldi",
            "abhi",
            "limited",
            "hurry",
            "last date",
            "last day",
            "last chance",
            "next",
        ),
        # fmt: skip
        patterns=(
            (
                "urgency",
                _c(
                    r"\bexpir(?:e|es|ed|ing|y)\b (?:by |on )?(?:today|tonight|in \d+"
                    r" ?(?:hours?|hrs?)|within)"
                    r"|\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?)\b"
                    r"|\bin (?:the )?next \d+ ?(?:hours?|hrs?|minutes?|mins?)\b"
                    r"|\bimmediately\b|\burgent(?:ly)?\b|\basap\b|\bright now\b|\bact now\b"
                    r"|\bturant\b|\bjaldi\b|\babhi (?:karein|kare|karo|kijiye)\b"
                    r"|\blast (?:date|day|chance)\b"
                ),
            ),
            ("urgency.offer", _c(r"\blimited[- ]time\b|\bhurry\b")),
        ),
    ),
    Rule(
        code="otp_warning",
        label="Carries the standard 'never share your OTP or PIN' warning that genuine senders use.",
        triggers=("share", "never", "disclose", "ask", "batay", "batan", " mat ", " na "),
        patterns=(
            (
                "otp_warning",
                _c(
                    r"\b(?:do not|don't|dont|never|not to) (?:\w+ ){0,3}?"
                    r"(?:share|disclose|tell|give)\b.{0,30}?\b(?:otp|pin|password|cvv)\b"
                ),
            ),
            (
                "otp_warning",
                _c(
                    r"\b(?:otp|pin|password|cvv)\b.{0,40}?\b(?:do not|don't|dont|never)"
                    r" (?:share|disclose)"
                ),
            ),
            (
                "otp_warning",
                _c(
                    r"\b(?:never|will not|won't|does not|doesn't|do not) (?:ever )?"
                    r"(?:asks?|calls?|requests?)\b.{0,20}?"
                    r"\b(?:otp|pin|password|cvv|card details)\b"
                ),
            ),
            (
                "otp_warning",
                _c(
                    r"\b(?:otp|pin)\b.{0,30}?\b(?:share|bataye|batayein|batana)"
                    r" (?:na|mat|nahi)\b"
                ),
            ),
        ),
    ),
)

# Rules whose firing means the sender wants something from you; a link next to one of these
# is where that something gets collected.
REQUEST_CODES = frozenset(
    {
        "otp_request", "upi_pin_to_receive", "upi_collect_refund", "kyc_update",
        "account_blocked", "sim_deactivation", "prize_lottery", "task_job_offer",
        "parcel_held", "advance_fee", "loan_offer", "investment_scheme", "reward_points",
        "tax_refund", "utility_disconnection", "authority_threat", "mistaken_transfer",
    }
)  # fmt: skip

# Money or job language that turns a WhatsApp or Telegram link into a lure.
MONEY_OR_JOB = re.compile(
    r"\b(?:earn\w*|income|job|salary|profit|invest\w*|task|trading|crypto|lakh|crore|prize"
    r"|won|winner|refund|loan|cashback|bonus|commission|kamaye|kamao|paise|hiring|vacancy)\b"
    r"|rs\.? ?\d|₹ ?\d|inr ?\d"
)
