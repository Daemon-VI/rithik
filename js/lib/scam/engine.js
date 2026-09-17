// Mirrors src/rithik/scam/engine.py. Keep the two in step: the golden tests fail otherwise.
//
// Scores a message against the rule set and the link checks.
//
// The engine never fetches a URL or resolves a name: everything it says comes from the text it
// was given. That keeps it safe to run on a message you have not decided to trust yet.

import { Verdict, makeReason, makeReport } from "./model.js";
import {
  SPACE_CLASS,
  cpHead,
  cpIndex,
  cpLength,
  pySum,
  rstrip,
  skipForward,
  strip,
} from "./pycompat.js";
import * as rules from "./rules.js";
import * as urls from "./urls.js";
import {
  EVIDENCE_MAX_CHARS,
  NEGATIVE_FLOOR,
  SCAM_THRESHOLD,
  SCORE_SCALE,
  STRONG_SIGNAL,
  SUSPICIOUS_THRESHOLD,
  weightOf,
} from "./weights.js";

// Zero-width characters and soft hyphens are invisible in a phone's SMS view, and scammers
// drop them inside words ("O<ZWSP>TP") precisely so that keyword filters miss them.
const INVISIBLE = /[\u{ad}\u{180e}\u{200b}\u{200c}\u{200d}\u{2060}\u{feff}]/gu;
const QUOTES = /[\u{2018}\u{2019}\u{201c}\u{201d}]/gu;
const QUOTE_FOR = { "\u{2018}": "'", "\u{2019}": "'", "\u{201c}": '"', "\u{201d}": '"' };
const WHITESPACE = new RegExp(`[${SPACE_CLASS}]+`, "gu");

const URL_LABELS = {
  url_brand_impersonation: "Link uses a bank or brand name on a domain that brand does not own.",
  url_apk: "Link downloads an Android app file (APK) directly.",
  url_ip_host: "Link points at a bare IP address instead of a named website.",
  url_punycode: "Link uses look-alike (punycode or non-Latin) characters in its domain.",
  url_userinfo: "Link hides its real destination behind an '@' sign.",
  url_risky_tld: "Link uses a cheap domain ending that is common in phishing.",
  url_shortener: "Link is shortened, which hides where it really goes.",
  url_many_subdomains: "Link stacks many subdomains, a trick to push the real domain out of view.",
  url_plain_http: "Link is not encrypted (plain http).",
  official_link: "Links only to an official domain of a bank, company or the government.",
  chat_link_money: "WhatsApp or Telegram link offered together with money or job talk.",
  link_with_request: "Asks for something and gives a link that is not an official site.",
};

const LABELS = new Map(rules.RULES.map((rule) => [rule.code, rule.label]));
for (const [code, label] of Object.entries(URL_LABELS)) LABELS.set(code, label);

/**
 * Score one message. Never throws on odd text and never touches the network.
 *
 * Throws a TypeError for anything that is not a primitive string, as Python raises for a
 * non-str. A String object counts as not a string: Python has no boxed strings to accept.
 */
export function analyze(text) {
  if (typeof text !== "string") {
    throw new TypeError(`analyze() expects str, not ${typeName(text)}`);
  }
  const display = normalise(text);
  if (!display) return makeReport(Verdict.NO_SIGNALS, 0.0, [], []);
  const lowered = display.toLowerCase();
  // Lower-casing is length-preserving for almost all text; when it is, evidence can be cut
  // from the original casing, which reads better and matches what the user sees. Python
  // compares code point counts, and "İ" -> "i̇" is the usual case where they differ.
  const cutFromDisplay = cpLength(lowered) === cpLength(display);

  /** @type {Map<string, [number, string]>} code -> [weight, evidence], in first-hit order */
  const hits = new Map();

  const add = (key, evidence) => {
    const code = key.split(".", 1)[0];
    const weight = weightOf(key);
    const current = hits.get(code);
    // One entry per code: repeating a phrase ten times must not count ten times.
    if (current === undefined || Math.abs(weight) > Math.abs(current[0])) {
      hits.set(code, [weight, evidence]);
    }
  };

  const seen = new Map();
  for (const rule of rules.RULES) {
    const found = rule.scan(lowered, seen);
    if (found !== null) {
      // Python's `_evidence(source, lowered, ...)` returns the match as-is when source is
      // lowered; that is the !cutFromDisplay case.
      add(found[0], cutFromDisplay ? evidenceFrom(display, lowered, found[1]) : found[1]);
    }
  }

  const links = urls.extractLinks(display);
  let officialOnly = links.length > 0;
  let unofficial = false;
  for (const link of links) {
    const findings = urls.linkFindings(link);
    if (!findings.some(([key]) => key === "official_link")) {
      officialOnly = false;
      unofficial = true;
    }
    for (const [key, evidence] of findings) {
      if (key !== "official_link") add(key, evidence);
    }
    if (urls.isChatLink(link) && rules.MONEY_OR_JOB.test(lowered)) {
      add("chat_link_money", link.raw);
    }
  }
  if (officialOnly) add("official_link", links[0].raw);

  if (unofficial) {
    const requesting = [...hits.keys()].some((code) => rules.REQUEST_CODES.has(code));
    if (requesting) {
      const firstUnofficial = links.find(
        (link) => !urls.isOfficial(link.host) || link.hasUserinfo,
      ).raw;
      add("link_with_request", firstUnofficial);
    }
    if (hits.has("echallan")) add("echallan.link", hits.get("echallan")[1]);
  }

  return score(
    hits,
    links.map((link) => link.raw),
  );
}

function score(hits, foundUrls) {
  let strongest = 0.0;
  let first = true;
  for (const [w] of hits.values()) {
    if (first || w > strongest) strongest = w;
    first = false;
  }
  if (strongest >= STRONG_SIGNAL) {
    // A genuine link or an OTP warning pasted next to a PIN request buys nothing.
    hits = new Map([...hits].filter(([, hit]) => hit[0] > 0));
  }
  const weights = [...hits.values()].map(([w]) => w);
  const positive = pySum(weights.filter((w) => w > 0));
  const negativeSum = pySum(weights.filter((w) => w < 0));
  const negative = negativeSum > NEGATIVE_FLOOR ? negativeSum : NEGATIVE_FLOOR;
  const total = positive + negative;
  const raw = total > 0.0 ? total : 0.0;
  const value = 1.0 - Math.exp(-raw / SCORE_SCALE);

  let verdict;
  if (value >= SCAM_THRESHOLD) verdict = Verdict.SCAM;
  else if (value >= SUSPICIOUS_THRESHOLD) verdict = Verdict.SUSPICIOUS;
  else verdict = Verdict.NO_SIGNALS;

  // Python sorts on (-weight, code); both sorts are stable and codes are ASCII, so comparing
  // UTF-16 units orders them exactly as Python compares code points.
  const ordered = [...hits].sort(([codeA, [weightA]], [codeB, [weightB]]) => {
    if (weightA !== weightB) return weightA > weightB ? -1 : 1;
    if (codeA === codeB) return 0;
    return codeA < codeB ? -1 : 1;
  });
  const reasons = ordered.map(([code, [weight, evidence]]) =>
    makeReason(code, LABELS.get(code), clip(evidence), weight),
  );
  return makeReport(verdict, value, reasons, foundUrls);
}

// Exported for the parity tooling only; index.js does not re-export it.
export function normalise(text) {
  // NFKC folds the "bold" and full-width letters used to dodge filters back to plain ASCII.
  text = text.normalize("NFKC");
  text = text.replace(INVISIBLE, "").replace(QUOTES, (quote) => QUOTE_FOR[quote]);
  return strip(text.replace(WHITESPACE, " "));
}

// Cut the matched text out of the display string at the same code point offset. find() is
// Python's, so the first occurrence wins even when the rule matched a later one.
function evidenceFrom(source, lowered, matched) {
  const index = lowered.indexOf(matched);
  if (index < 0) return matched;
  // Lower-casing kept the code point count, so every character mapped to exactly one; the
  // offsets agree in code points but not necessarily in UTF-16 units.
  const start = skipForward(source, 0, cpIndex(lowered, index));
  return source.slice(start, skipForward(source, start, cpLength(matched)));
}

function clip(evidence) {
  evidence = strip(evidence);
  // Python measures EVIDENCE_MAX_CHARS in code points, so an emoji counts once.
  if (skipForward(evidence, 0, EVIDENCE_MAX_CHARS) === evidence.length) return evidence;
  return `${rstrip(cpHead(evidence, EVIDENCE_MAX_CHARS - 3))}...`;
}

function typeName(value) {
  if (value === null) return "null";
  if (typeof value !== "object" && typeof value !== "function") return typeof value;
  return value.constructor?.name || "object";
}
