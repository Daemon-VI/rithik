// Mirrors src/rithik/scam/urls.py. Keep the two in step: the golden tests fail otherwise.
//
// Finds links in a message and judges them without ever resolving or fetching anything.
//
// The registrable-domain logic is a deliberately small stand-in for the Public Suffix List: the
// package has no runtime dependencies, and the only multi-part suffixes that matter for Indian
// scam traffic fit in a short set.
//
// Nothing here uses the WHATWG URL class. It normalises hosts (IDNA, percent-decoding, IPv4
// number forms) where Python's hand-rolled parsing does not, so the two would disagree.

import {
  SPACE_CLASS,
  WORD_CLASS,
  cpHead,
  cpLength,
  cpTail,
  isAscii,
  isDigit,
  isLower,
  isUpper,
  rsplit,
  rstrip,
  skipForward,
  split,
  strip,
} from "./pycompat.js";
import { MAX_URLS } from "./weights.js";

const R = String.raw;

// Suffixes under which people register names, so "x.co.in" is its own domain rather than a
// subdomain of "co.in".
export const MULTI_PART_SUFFIXES = new Set([
  // India
  "co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "edu.in", "res.in",
  "firm.in", "gen.in", "ind.in", "mil.in", "bank.in", "fin.in",
  // places Indian users still get phished from
  "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "gov.au", "edu.au",
  "co.nz", "co.jp", "co.za", "co.id", "co.kr",
  "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "com.np", "com.lk",
  "com.hk", "com.tr", "com.mx", "com.ng", "com.ph", "com.vn",
]);

// Suffixes only a vetted body can register under. gov.in and nic.in are government-only;
// bank.in and fin.in are the RBI-mandated registries for regulated banks and financial firms;
// .sbi is State Bank of India's own top-level domain.
export const OFFICIAL_SUFFIXES = new Set(["gov.in", "nic.in", "bank.in", "fin.in", "sbi"]);

export const OFFICIAL_DOMAINS = new Set([
  // banks and their group companies, which share the brand token
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
  // payments
  "paytm.com", "paytmbank.com", "paytmmoney.com", "phonepe.com", "google.com",
  "mobikwik.com",
  // shopping
  "amazon.in", "amazon.com", "amzn.in", "amzn.to", "primevideo.com", "flipkart.com",
  "myntra.com", "meesho.com",
  // telecom
  "airtel.in", "airtel.com", "jio.com", "jiomart.com", "jiocinema.com", "bsnl.co.in",
  "myvi.in",
  // travel and couriers
  "irctc.co.in", "fedex.com", "dhl.com", "bluedart.com", "delhivery.com", "dtdc.in",
]);

// Domains that contain a brand token for an innocent reason and are also abused to host
// phishing pages, so they get neither the impersonation flag nor the reassurance.
export const BRAND_NEUTRAL_DOMAINS = new Set(["amazonaws.com"]);

export const SHORTENERS = new Set([
  "bit.ly", "bitly.com", "tinyurl.com", "cutt.ly", "is.gd", "v.gd", "t.ly", "rb.gy",
  "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.co", "goo.gl", "ow.ly", "buff.ly",
  "bit.do", "shorte.st", "adf.ly", "tiny.one", "surl.li", "u.to", "clck.ru", "qr.ae",
  "short.gy", "urlz.fr", "shorturl.gg", "lnkd.in", "db.tt", "bl.ink", "soo.gd",
  "l.ead.me", "linktr.ee", "tr.ee", "rebrandly.com", "t2m.io", "urlzs.com", "2.gy",
]);

export const RISKY_TLDS = new Set([
  "xyz", "top", "click", "buzz", "live", "icu", "monster", "rest", "cfd", "sbs",
  "cyou", "bond", "vip", "win", "loan", "work", "link", "online", "site", "website",
  "shop", "store", "club", "fun", "space", "tk", "ml", "ga", "cf", "gq", "pw", "cc",
  "su", "ws", "lol", "mom", "beauty", "hair", "skin", "quest", "autos", "boats",
  "homes", "pics", "cam", "support", "help", "zip", "mov", "cash", "money", "digital",
  "today", "life", "world", "email", "info", "biz", "rsvp", "cloud", "xin", "gdn",
]);

export const CHAT_LINK_DOMAINS = new Set(["wa.me", "t.me", "telegram.me", "telegram.dog"]);
export const CHAT_LINK_HOSTS = new Set(["chat.whatsapp.com", "api.whatsapp.com"]);

// How a brand token has to appear in a host label to count. Long tokens are distinctive enough
// to match anywhere; short ones only at the edge of a label ("sbi-kyc", "onlinesbi") because
// "sbi" also sits inside ordinary words; "exact" is for tokens that start common words.
// An array, not an object, because the first token found wins and the order is Python's.
const BRAND_TOKENS = [
  ["sbi", "edge"], ["yono", "edge"], ["hdfc", "any"], ["icici", "any"], ["axis", "edge"],
  ["kotak", "any"], ["paytm", "any"], ["phonepe", "any"], ["gpay", "any"],
  ["googlepay", "any"], ["npci", "any"], ["bhim", "edge"], ["upi", "edge"], ["rbi", "edge"],
  ["pnb", "edge"], ["amazon", "any"], ["amzn", "any"], ["flipkart", "any"],
  ["indiapost", "any"], ["incometax", "any"], ["uidai", "any"], ["aadhaar", "any"],
  ["aadhar", "any"], ["irctc", "any"], ["airtel", "any"], ["jio", "edge"], ["bsnl", "edge"],
  ["bescom", "any"], ["tsspdcl", "any"], ["tgspdcl", "any"], ["msedcl", "any"],
  ["mahadiscom", "any"], ["tangedco", "any"], ["tneb", "edge"], ["epfo", "edge"],
  ["parivahan", "any"], ["echallan", "any"], ["fastag", "any"], ["nhai", "edge"],
  ["fedex", "any"], ["dhl", "edge"], ["bluedart", "any"], ["delhivery", "any"],
  ["trai", "exact"],
];

// Ordinary words that carry a short brand token at their edge.
const BRAND_FALSE_FRIENDS = new Set(["taxis", "praxis", "galaxis", "lesbi", "upin", "upit"]);

// Bare domains ("sbi-kyc.top/update") are recognised only for these endings. Anything with a
// scheme or a "www." prefix is taken whatever its ending. The list leaves out endings that are
// mostly file extensions or abbreviations in SMS text (.md, .py, .no, .ltd, .care, .name).
const BARE_TLDS = new Set([
  "com", "net", "org", "in", "co", "io", "me", "ly", "gl", "gd", "gy", "at", "id",
  "cc", "to", "ai", "app", "dev", "uk", "au", "us", "ru", "cn", "tk", "ml", "ga", "cf",
  "gq", "pw", "ws", "su", "ee", "ae", "fr", "de", "info", "biz", "xyz", "top", "click",
  "buzz", "live", "icu", "monster", "rest", "cfd", "sbs", "cyou", "bond", "vip", "win",
  "loan", "work", "link", "online", "site", "website", "shop", "store", "club", "fun",
  "space", "lol", "mom", "beauty", "hair", "skin", "quest", "autos", "boats", "homes",
  "pics", "cam", "cash", "money", "digital", "today", "life", "world", "email", "cloud",
  "xin", "gdn", "rsvp", "sbi", "bank", "page", "tech", "gov", "edu",
]);

// Python compiles the link regexes with re.IGNORECASE. Under that flag CPython matches a
// character by its simple lowercase plus a few extra case pairs, so [a-z] also takes İ (U+0130)
// and the Kelvin sign (U+212A), which lowercase into it, and ı (U+0131) and ſ (U+017F), which
// share an uppercase with i and s. JavaScript's /iu folds differently and rejects İ and ı, so
// the classes are spelled out. NFKC removes the Kelvin sign and ſ first, but İ and ı survive.
const LATIN = R`A-Za-z\u{130}\u{131}\u{17f}\u{212a}`;
const S = R`[sS\u{17f}]`;
// [^\s<>"'`] with Python's \s; \x60 is the backtick, which a template literal cannot hold raw.
const NOT_STOP = R`[^${SPACE_CLASS}<>"'\x60]`;

// Bare matches may only start at a word start (and never inside an e-mail address). Besides
// avoiding false links, that keeps the engine from retrying the domain branch at every
// character. The ending is a plain letter run checked against BARE_TLDS afterwards: an
// alternation of every ending here made backtracking over "a.a.a.a..." cost ~90 tries a label.
const URL_RE = new RegExp(
  R`[hH][tT][tT][pP]${S}?://${NOT_STOP}+` +
    R`|(?<![${WORD_CLASS}@.\-/])` +
    R`(?:` +
    R`[wW][wW][wW]\.${NOT_STOP}+` +
    R`|(?:\p{Nd}{1,3}\.){3}\p{Nd}{1,3}(?::\p{Nd}{1,5})?/${NOT_STOP}*` +
    R`|(?:[${LATIN}0-9\-]{1,63}\.)+[${LATIN}]{2,24}` +
    R`(?![${WORD_CLASS}@\-])` +
    R`(?::\p{Nd}{1,5})?` +
    R`(?:[/?#]${NOT_STOP}*)?` +
    R`)`,
  "gu",
);

const SCHEME_RE = new RegExp(R`^([hH][tT][tT][pP]${S}?)://`, "u");
const TRAILING_PUNCT = ".,;:!?)]}'\"*";
const AUTHORITY_END = /[/?#\\]/u;
// Python calls fullmatch, hence the anchors.
const NUMERIC_HOST = /^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*$/u;
const BARE_HOST = new RegExp(R`^[${LATIN}0-9.\-]+`, "u");
const MAX_HOST_CHARS = 253; // the DNS limit; anything longer cannot be a real link

// Label-before-TLD words that make "now.Click" or "here.co" a typo for a missing space, not a
// link. Only consulted for bare matches with no path.
const SENTENCE_WORDS = new Set([
  "now", "here", "today", "please", "pls", "plz", "sir", "madam", "customer", "details",
  "it", "this", "link", "below", "us", "you", "thanks", "done", "pvt", "ok", "hi", "dear",
]);

export class Link {
  /**
   * @param {object} fields
   * @param {string} fields.raw as it appeared, minus trailing punctuation
   * @param {string} fields.scheme "http", "https", or "" when the message gave none
   * @param {string} fields.host lower-case, no port, no trailing dot
   * @param {string} fields.path everything after the host, including query and fragment
   * @param {boolean} fields.hasUserinfo
   * @param {boolean} fields.isIp
   */
  constructor({ raw, scheme, host, path, hasUserinfo, isIp }) {
    this.raw = raw;
    this.scheme = scheme;
    this.host = host;
    this.path = path;
    this.hasUserinfo = hasUserinfo;
    this.isIp = isIp;
    Object.freeze(this);
  }

  /** @returns {string | null} */
  get registrable() {
    return registrableDomain(this.host);
  }
}

/**
 * Return the name someone actually registered, or null for IPs and bare suffixes.
 *
 * registrableDomain("secure.login.sbi.co.in") === "sbi.co.in"
 */
export function registrableDomain(host) {
  host = strip(strip(host), ".").toLowerCase();
  if (!host || isIp(host)) return null;
  const labels = host.split(".").filter((label) => label);
  if (labels.length < 2) return null;
  if (MULTI_PART_SUFFIXES.has(labels.slice(-2).join("."))) {
    return labels.length >= 3 ? labels.slice(-3).join(".") : null;
  }
  return labels.slice(-2).join(".");
}

export function isOfficial(host) {
  const reg = registrableDomain(host);
  if (reg === null) return false;
  if (OFFICIAL_DOMAINS.has(reg)) return true;
  return OFFICIAL_SUFFIXES.has(split(reg, ".", 1)[1]);
}

/** Return the first brand token that appears in the host, or null. */
export function brandInHost(host) {
  const parts = host
    .toLowerCase()
    .split(/[.\-_]/u)
    .filter((p) => p);
  for (const [token, mode] of BRAND_TOKENS) {
    for (const part of parts) {
      if (BRAND_FALSE_FRIENDS.has(part)) continue;
      if (mode === "any" && part.includes(token)) return token;
      if (mode === "edge" && (part.startsWith(token) || part.endsWith(token))) return token;
      if (mode === "exact" && part === token) return token;
    }
  }
  return null;
}

/** @returns {Link[]} */
export function extractLinks(text) {
  const links = [];
  const seen = new Set();
  // Counting examined matches, not just kept ones, bounds the work when the same domain is
  // repeated a hundred thousand times.
  let pos = 0;
  for (let examined = 0; ; examined++) {
    URL_RE.lastIndex = pos;
    const match = URL_RE.exec(text);
    if (match === null) break;
    const end = match.index + match[0].length;
    pos = end > match.index ? end : skipForward(text, match.index, 1);
    if (examined >= MAX_URLS * 4) break;
    const link = parse(match[0]);
    if (link === null || seen.has(link.raw.toLowerCase())) continue;
    seen.add(link.raw.toLowerCase());
    links.push(link);
    if (links.length >= MAX_URLS) break;
  }
  return links;
}

function parse(candidate) {
  let raw = rstrip(candidate, TRAILING_PUNCT);
  if (!raw) return null;
  if (!SCHEME_RE.test(raw) && !raw.toLowerCase().startsWith("www.")) {
    raw = trimBare(raw);
    if (raw === null) return null;
  }
  const schemeMatch = SCHEME_RE.exec(raw);
  let scheme;
  let rest;
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    rest = raw.slice(schemeMatch[0].length);
  } else {
    scheme = "";
    rest = raw;
  }
  // Indices from search() and slice() are both UTF-16, so the cut lands where Python's does.
  const end = rest.search(AUTHORITY_END);
  const authority = end >= 0 ? rest.slice(0, end) : rest;
  const path = end >= 0 ? rest.slice(end) : "";
  const hasUserinfo = authority.includes("@");
  const hostport = rsplit(authority, "@", 1).at(-1);
  let host;
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    host = close > 0 ? hostport.slice(1, close) : hostport.slice(1);
  } else {
    host = split(hostport, ":", 1)[0];
  }
  host = strip(host, ".").toLowerCase();
  if (!host || cpLength(host) > MAX_HOST_CHARS) return null;
  if (!scheme && !raw.toLowerCase().startsWith("www.") && looksLikeTypo(raw, host, path)) {
    return null;
  }
  return new Link({ raw, scheme, host, path, hasUserinfo, isIp: isIp(host) });
}

/** Cut a bare match back to its last known ending: "sbi.co.in.Thanks" -> "sbi.co.in". */
function trimBare(raw) {
  const hostMatch = BARE_HOST.exec(raw);
  if (hostMatch === null) return null;
  const labels = hostMatch[0].split(".");
  if (BARE_TLDS.has(labels.at(-1).toLowerCase()) || labels.every((label) => isDigit(label))) {
    return raw;
  }
  for (let end = labels.length - 1; end > 1; end--) {
    if (BARE_TLDS.has(labels[end - 1].toLowerCase())) {
      // The path belonged to the longer, bogus host, so it is dropped with it.
      return labels.slice(0, end).join(".");
    }
  }
  return null;
}

/** A bare "now.Click" is a missing space after a full stop, not a link. */
function looksLikeTypo(raw, host, path) {
  if (path) return false;
  const labels = host.split(".");
  const tldAsWritten = raw.slice(raw.lastIndexOf(".") + 1);
  // Python's [:1] and [1:] cut at the first code point, not the first UTF-16 unit.
  if (isUpper(cpHead(tldAsWritten, 1)) && isLower(cpTail(tldAsWritten, 1))) return true;
  return labels.length === 2 && SENTENCE_WORDS.has(labels[0]);
}

export function isIp(host) {
  // ipaddress.ip_address(host) tries IPv4 first, then IPv6.
  if (ipv4Address(host) !== null || isIpv6Address(host)) return true;
  // Browsers also accept decimal ("3232235777") and hex ("0x7f.1") hosts; phishers use them.
  return NUMERIC_HOST.test(host);
}

// The two parsers below follow CPython 3.12's ipaddress module step for step. They only need
// to say whether the string parses, so each returns null or false where Python raises.

/** ipaddress.IPv4Address(s): the address as an integer, or null when Python would raise. */
function ipv4Address(s) {
  if (s.includes("/")) return null;
  if (!s) return null;
  const octets = s.split(".");
  if (octets.length !== 4) return null;
  let value = 0;
  for (const octet of octets) {
    const n = parseOctet(octet);
    if (n === null) return null;
    value = value * 256 + n;
  }
  return value;
}

function parseOctet(octet) {
  if (!octet) return null;
  // Python rejects non-ASCII digits here even though str.isdigit() accepts them.
  if (!(isAscii(octet) && isDigit(octet))) return null;
  if (octet.length > 3) return null;
  // Leading zeros are refused, as strictly as glibc's inet_pton().
  if (octet !== "0" && octet[0] === "0") return null;
  const n = Number.parseInt(octet, 10);
  return n > 255 ? null : n;
}

const HEXTET_COUNT = 8;

/** ipaddress.IPv6Address(s) succeeds. */
function isIpv6Address(s) {
  if (s.includes("/")) return false;
  // _split_scope_id: "fe80::1%eth0" carries a zone after a single "%".
  let addr = s;
  const percent = s.indexOf("%");
  if (percent >= 0) {
    const scope = s.slice(percent + 1);
    if (!scope || scope.includes("%")) return false;
    addr = s.slice(0, percent);
  }
  if (!addr) return false;
  if (cpLength(addr) > 45) return false;
  // Python splits at most max_parts times so that the error for "too many parts" stays
  // accurate; the leftover colons end up inside the last part.
  const maxParts = HEXTET_COUNT + 1;
  const parts = split(addr, ":", maxParts);
  if (parts.length < 3) return false;
  if (parts.at(-1).includes(".")) {
    const ipv4 = ipv4Address(parts.pop());
    if (ipv4 === null) return false;
    parts.push(((ipv4 >>> 16) & 0xffff).toString(16));
    parts.push((ipv4 & 0xffff).toString(16));
  }
  if (parts.length > maxParts) return false;

  let skipIndex = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skipIndex !== null) return false; // more than one "::"
      skipIndex = i;
    }
  }
  let partsHi;
  let partsLo;
  if (skipIndex !== null) {
    partsHi = skipIndex;
    partsLo = parts.length - skipIndex - 1;
    if (!parts[0]) {
      partsHi -= 1;
      if (partsHi) return false; // a leading ":" must be part of "::"
    }
    if (!parts.at(-1)) {
      partsLo -= 1;
      if (partsLo) return false; // a trailing ":" must be part of "::"
    }
    if (HEXTET_COUNT - (partsHi + partsLo) < 1) return false;
  } else {
    if (parts.length !== HEXTET_COUNT) return false;
    if (!parts[0] || !parts.at(-1)) return false;
    partsHi = parts.length;
    partsLo = 0;
  }
  for (let i = 0; i < partsHi; i++) {
    if (!isHextet(parts[i])) return false;
  }
  for (let i = parts.length - partsLo; i < parts.length; i++) {
    if (!isHextet(parts[i])) return false;
  }
  return true;
}

// _parse_hextet: ASCII hex digits only, at most four, and int("", 16) rejects an empty one.
function isHextet(s) {
  return /^[0-9A-Fa-f]{1,4}$/.test(s);
}

/** Return [weight key, evidence] pairs for one link. */
export function linkFindings(link) {
  const found = [];
  const host = link.host;
  const reg = link.registrable;
  const evidence = link.raw;

  if (link.isIp) found.push(["url_ip_host", evidence]);
  if (host.includes("xn--") || !isAscii(host)) found.push(["url_punycode", evidence]);
  if (link.hasUserinfo) found.push(["url_userinfo", evidence]);
  if (split(split(link.path, "?", 1)[0], "#", 1)[0].toLowerCase().endsWith(".apk")) {
    found.push(["url_apk", evidence]);
  }
  if (SHORTENERS.has(reg) || SHORTENERS.has(host)) found.push(["url_shortener", evidence]);

  const official = isOfficial(host);
  if (official && !link.hasUserinfo) {
    found.push(["official_link", evidence]);
    return found;
  }

  if (reg !== null && !BRAND_NEUTRAL_DOMAINS.has(reg) && brandInHost(host)) {
    found.push(["url_brand_impersonation", evidence]);
  }
  if (!link.isIp && RISKY_TLDS.has(rsplit(host, ".", 1).at(-1))) {
    found.push(["url_risky_tld", evidence]);
  }
  if (link.scheme === "http") found.push(["url_plain_http", evidence]);
  if (reg !== null) {
    let extra = host.split(".").slice(0, -reg.split(".").length);
    if (extra.length && extra[0] === "www") extra = extra.slice(1);
    if (extra.length >= 3) found.push(["url_many_subdomains", evidence]);
  }
  return found;
}

export function isChatLink(link) {
  return CHAT_LINK_DOMAINS.has(link.registrable) || CHAT_LINK_HOSTS.has(link.host);
}
