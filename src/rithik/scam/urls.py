"""Finds links in a message and judges them without ever resolving or fetching anything.

The registrable-domain logic is a deliberately small stand-in for the Public Suffix List: the
package has no runtime dependencies, and the only multi-part suffixes that matter for Indian
scam traffic fit in a short set.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from rithik.scam.weights import MAX_URLS

# Suffixes under which people register names, so "x.co.in" is its own domain rather than a
# subdomain of "co.in".
MULTI_PART_SUFFIXES = frozenset(
    {
        # India
        "co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "edu.in", "res.in",
        "firm.in", "gen.in", "ind.in", "mil.in", "bank.in", "fin.in",
        # places Indian users still get phished from
        "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "gov.au", "edu.au",
        "co.nz", "co.jp", "co.za", "co.id", "co.kr",
        "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "com.np", "com.lk",
        "com.hk", "com.tr", "com.mx", "com.ng", "com.ph", "com.vn",
    }
)  # fmt: skip

# Suffixes only a vetted body can register under. gov.in and nic.in are government-only;
# bank.in and fin.in are the RBI-mandated registries for regulated banks and financial firms;
# .sbi is State Bank of India's own top-level domain.
OFFICIAL_SUFFIXES = frozenset({"gov.in", "nic.in", "bank.in", "fin.in", "sbi"})

OFFICIAL_DOMAINS = frozenset(
    {
        # banks and their group companies, which share the brand token
        "sbi.co.in", "onlinesbi.com", "sbicard.com", "sbilife.co.in", "sbimf.com",
        "sbigeneral.in", "sbisecurities.in",
        "hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com",
        "hdfcfund.com",
        "icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com",
        "axisbank.com", "axismf.com", "axisdirect.in",
        "kotak.com", "kotaksecurities.com", "kotaklife.com",
        "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
        "yesbank.in", "idfcfirstbank.com", "indusind.com",
        "rbi.org.in", "npci.org.in", "bhimupi.org.in",
        # payments
        "paytm.com", "paytmbank.com", "paytmmoney.com", "phonepe.com", "google.com",
        "mobikwik.com",
        # shopping
        "amazon.in", "amazon.com", "amzn.in", "amzn.to", "primevideo.com", "flipkart.com",
        "myntra.com", "meesho.com",
        # telecom
        "airtel.in", "airtel.com", "jio.com", "jiomart.com", "jiocinema.com", "bsnl.co.in",
        "myvi.in",
        # travel and couriers
        "irctc.co.in", "fedex.com", "dhl.com", "bluedart.com", "delhivery.com", "dtdc.in",
    }
)  # fmt: skip

# Domains that contain a brand token for an innocent reason and are also abused to host
# phishing pages, so they get neither the impersonation flag nor the reassurance.
BRAND_NEUTRAL_DOMAINS = frozenset({"amazonaws.com"})

SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.com", "tinyurl.com", "cutt.ly", "is.gd", "v.gd", "t.ly", "rb.gy",
        "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "bit.do", "shorte.st", "adf.ly", "tiny.one", "surl.li", "u.to", "clck.ru", "qr.ae",
        "short.gy", "urlz.fr", "shorturl.gg", "lnkd.in", "db.tt", "bl.ink", "soo.gd",
        "l.ead.me", "linktr.ee", "tr.ee", "rebrandly.com", "t2m.io", "urlzs.com", "2.gy",
    }
)  # fmt: skip

RISKY_TLDS = frozenset(
    {
        "xyz", "top", "click", "buzz", "live", "icu", "monster", "rest", "cfd", "sbs",
        "cyou", "bond", "vip", "win", "loan", "work", "link", "online", "site", "website",
        "shop", "store", "club", "fun", "space", "tk", "ml", "ga", "cf", "gq", "pw", "cc",
        "su", "ws", "lol", "mom", "beauty", "hair", "skin", "quest", "autos", "boats",
        "homes", "pics", "cam", "support", "help", "zip", "mov", "cash", "money", "digital",
        "today", "life", "world", "email", "info", "biz", "rsvp", "cloud", "xin", "gdn",
    }
)  # fmt: skip

CHAT_LINK_DOMAINS = frozenset({"wa.me", "t.me", "telegram.me", "telegram.dog"})
CHAT_LINK_HOSTS = frozenset({"chat.whatsapp.com", "api.whatsapp.com"})

# How a brand token has to appear in a host label to count. Long tokens are distinctive enough
# to match anywhere; short ones only at the edge of a label ("sbi-kyc", "onlinesbi") because
# "sbi" also sits inside ordinary words; "exact" is for tokens that start common words.
_BRAND_TOKENS: dict[str, str] = {
    "sbi": "edge", "yono": "edge", "hdfc": "any", "icici": "any", "axis": "edge",
    "kotak": "any", "paytm": "any", "phonepe": "any", "gpay": "any", "googlepay": "any",
    "npci": "any", "bhim": "edge", "upi": "edge", "rbi": "edge", "pnb": "edge",
    "amazon": "any", "amzn": "any", "flipkart": "any", "indiapost": "any",
    "incometax": "any", "uidai": "any", "aadhaar": "any", "aadhar": "any", "irctc": "any",
    "airtel": "any", "jio": "edge", "bsnl": "edge", "bescom": "any", "tsspdcl": "any",
    "tgspdcl": "any", "msedcl": "any", "mahadiscom": "any", "tangedco": "any", "tneb": "edge",
    "epfo": "edge", "parivahan": "any", "echallan": "any", "fastag": "any", "nhai": "edge",
    "fedex": "any", "dhl": "edge", "bluedart": "any", "delhivery": "any", "trai": "exact",
}  # fmt: skip

# Ordinary words that carry a short brand token at their edge.
_BRAND_FALSE_FRIENDS = frozenset({"taxis", "praxis", "galaxis", "lesbi", "upin", "upit"})

# Bare domains ("sbi-kyc.top/update") are recognised only for these endings. Anything with a
# scheme or a "www." prefix is taken whatever its ending. The list leaves out endings that are
# mostly file extensions or abbreviations in SMS text (.md, .py, .no, .ltd, .care, .name).
_BARE_TLDS = frozenset(
    {
        "com", "net", "org", "in", "co", "io", "me", "ly", "gl", "gd", "gy", "at", "id",
        "cc", "to", "ai", "app", "dev", "uk", "au", "us", "ru", "cn", "tk", "ml", "ga", "cf",
        "gq", "pw", "ws", "su", "ee", "ae", "fr", "de", "info", "biz", "xyz", "top", "click",
        "buzz", "live", "icu", "monster", "rest", "cfd", "sbs", "cyou", "bond", "vip", "win",
        "loan", "work", "link", "online", "site", "website", "shop", "store", "club", "fun",
        "space", "lol", "mom", "beauty", "hair", "skin", "quest", "autos", "boats", "homes",
        "pics", "cam", "cash", "money", "digital", "today", "life", "world", "email", "cloud",
        "xin", "gdn", "rsvp", "sbi", "bank", "page", "tech", "gov", "edu",
    }
)  # fmt: skip

_STOP = r"\s<>\"'`"
# Bare matches may only start at a word start (and never inside an e-mail address). Besides
# avoiding false links, that keeps the engine from retrying the domain branch at every
# character. The ending is a plain letter run checked against _BARE_TLDS afterwards: an
# alternation of every ending here made backtracking over "a.a.a.a..." cost ~90 tries a label.
_URL_RE = re.compile(
    rf"""
    https?://[^{_STOP}]+
  | (?<![\w@.\-/])
    (?:
        www\.[^{_STOP}]+
      | (?:\d{{1,3}}\.){{3}}\d{{1,3}}(?::\d{{1,5}})?/[^{_STOP}]*
      | (?:[a-z0-9\-]{{1,63}}\.)+[a-z]{{2,24}}
        (?![\w@\-])
        (?::\d{{1,5}})?
        (?:[/?#][^{_STOP}]*)?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_SCHEME_RE = re.compile(r"(https?)://", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}'\"*"
_AUTHORITY_END = re.compile(r"[/?#\\]")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", re.IGNORECASE)
_BARE_HOST = re.compile(r"[a-z0-9.\-]+", re.IGNORECASE)
_MAX_HOST_CHARS = 253  # the DNS limit; anything longer cannot be a real link

# Label-before-TLD words that make "now.Click" or "here.co" a typo for a missing space, not a
# link. Only consulted for bare matches with no path.
_SENTENCE_WORDS = frozenset(
    {"now", "here", "today", "please", "pls", "plz", "sir", "madam", "customer", "details",
     "it", "this", "link", "below", "us", "you", "thanks", "done", "pvt", "ok", "hi", "dear"}
)  # fmt: skip


@dataclass(frozen=True)
class Link:
    raw: str  # as it appeared, minus trailing punctuation
    scheme: str  # "http", "https", or "" when the message gave none
    host: str  # lower-case, no port, no trailing dot
    path: str  # everything after the host, including query and fragment
    has_userinfo: bool
    is_ip: bool

    @property
    def registrable(self) -> str | None:
        return registrable_domain(self.host)


def registrable_domain(host: str) -> str | None:
    """Return the name someone actually registered, or None for IPs and bare suffixes.

    >>> registrable_domain("secure.login.sbi.co.in")
    'sbi.co.in'
    """
    host = host.strip().strip(".").lower()
    if not host or _is_ip(host):
        return None
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return None
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return ".".join(labels[-2:])


def is_official(host: str) -> bool:
    reg = registrable_domain(host)
    if reg is None:
        return False
    if reg in OFFICIAL_DOMAINS:
        return True
    return reg.split(".", 1)[1] in OFFICIAL_SUFFIXES


def brand_in_host(host: str) -> str | None:
    """Return the first brand token that appears in the host, if any."""
    parts = [p for p in re.split(r"[.\-_]", host.lower()) if p]
    for token, mode in _BRAND_TOKENS.items():
        for part in parts:
            if part in _BRAND_FALSE_FRIENDS:
                continue
            if mode == "any" and token in part:
                return token
            if mode == "edge" and (part.startswith(token) or part.endswith(token)):
                return token
            if mode == "exact" and part == token:
                return token
    return None


def extract_links(text: str) -> list[Link]:
    links: list[Link] = []
    seen: set[str] = set()
    # Counting examined matches, not just kept ones, bounds the work when the same domain is
    # repeated a hundred thousand times.
    for examined, match in enumerate(_URL_RE.finditer(text)):
        if examined >= MAX_URLS * 4:
            break
        link = _parse(match.group(0))
        if link is None or link.raw.lower() in seen:
            continue
        seen.add(link.raw.lower())
        links.append(link)
        if len(links) >= MAX_URLS:
            break
    return links


def _parse(candidate: str) -> Link | None:
    raw = candidate.rstrip(_TRAILING_PUNCT)
    if not raw:
        return None
    if not _SCHEME_RE.match(raw) and not raw.lower().startswith("www."):
        raw = _trim_bare(raw)
        if raw is None:
            return None
    scheme_match = _SCHEME_RE.match(raw)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        rest = raw[scheme_match.end() :]
    else:
        scheme = ""
        rest = raw
    end = _AUTHORITY_END.search(rest)
    authority = rest[: end.start()] if end else rest
    path = rest[end.start() :] if end else ""
    has_userinfo = "@" in authority
    hostport = authority.rsplit("@", 1)[-1]
    if hostport.startswith("["):
        close = hostport.find("]")
        host = hostport[1:close] if close > 0 else hostport[1:]
    else:
        host = hostport.split(":", 1)[0]
    host = host.strip(".").lower()
    if not host or len(host) > _MAX_HOST_CHARS:
        return None
    if not scheme and not raw.lower().startswith("www.") and _looks_like_typo(raw, host, path):
        return None
    return Link(
        raw=raw,
        scheme=scheme,
        host=host,
        path=path,
        has_userinfo=has_userinfo,
        is_ip=_is_ip(host),
    )


def _trim_bare(raw: str) -> str | None:
    """Cut a bare match back to its last known ending: "sbi.co.in.Thanks" -> "sbi.co.in"."""
    host_match = _BARE_HOST.match(raw)
    if host_match is None:
        return None
    host = host_match.group(0)
    labels = host.split(".")
    if labels[-1].lower() in _BARE_TLDS or all(label.isdigit() for label in labels):
        return raw
    for end in range(len(labels) - 1, 1, -1):
        if labels[end - 1].lower() in _BARE_TLDS:
            # The path belonged to the longer, bogus host, so it is dropped with it.
            return ".".join(labels[:end])
    return None


def _looks_like_typo(raw: str, host: str, path: str) -> bool:
    """A bare "now.Click" is a missing space after a full stop, not a link."""
    if path:
        return False
    labels = host.split(".")
    tld_as_written = raw.split(".")[-1]
    if tld_as_written[:1].isupper() and tld_as_written[1:].islower():
        return True
    return len(labels) == 2 and labels[0] in _SENTENCE_WORDS


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Browsers also accept decimal ("3232235777") and hex ("0x7f.1") hosts; phishers use them.
    return _NUMERIC_HOST.fullmatch(host) is not None


def link_findings(link: Link) -> list[tuple[str, str]]:
    """Return (weight key, evidence) pairs for one link."""
    found: list[tuple[str, str]] = []
    host = link.host
    reg = link.registrable
    evidence = link.raw

    if link.is_ip:
        found.append(("url_ip_host", evidence))
    if "xn--" in host or not host.isascii():
        found.append(("url_punycode", evidence))
    if link.has_userinfo:
        found.append(("url_userinfo", evidence))
    if link.path.split("?", 1)[0].split("#", 1)[0].lower().endswith(".apk"):
        found.append(("url_apk", evidence))
    if reg in SHORTENERS or host in SHORTENERS:
        found.append(("url_shortener", evidence))

    official = is_official(host)
    if official and not link.has_userinfo:
        found.append(("official_link", evidence))
        return found

    if reg is not None and reg not in BRAND_NEUTRAL_DOMAINS and brand_in_host(host):
        found.append(("url_brand_impersonation", evidence))
    if not link.is_ip and host.rsplit(".", 1)[-1] in RISKY_TLDS:
        found.append(("url_risky_tld", evidence))
    if link.scheme == "http":
        found.append(("url_plain_http", evidence))
    if reg is not None:
        extra = host.split(".")[: -len(reg.split("."))]
        if extra and extra[0] == "www":
            extra = extra[1:]
        if len(extra) >= 3:
            found.append(("url_many_subdomains", evidence))
    return found


def is_chat_link(link: Link) -> bool:
    return link.registrable in CHAT_LINK_DOMAINS or link.host in CHAT_LINK_HOSTS
