// Mirrors src/rithik/scam/rules.py. Keep the two in step: the golden tests fail otherwise.
//
// Text rules: the pretexts and asks that Indian scam messages are built from.
//
// Each rule is a cheap substring prefilter plus a few precompiled patterns. The prefilter is what
// keeps a megabyte of ordinary text fast: most rules never run a regex at all. Every gap in a
// pattern is capped (".{0,40}?", never ".*"), so the worst case stays linear in input size.
//
// Patterns run against text the engine has already lower-cased and whitespace-collapsed, which
// is why they carry no case handling and use single spaces.
//
// The patterns below are written in Python `re` syntax, character for character as in
// rules.py, and compilePattern() translates them. Keeping the Python spelling makes a diff
// against rules.py readable, and the translator refuses any syntax whose meaning it cannot
// carry over.

import { charBefore, compilePattern, isWordChar, skipBack, skipForward } from "./pycompat.js";
import { weightOf } from "./weights.js";

const R = String.raw;

// "no" is left out on purpose: "a/c no XX1234" is in half of all bank SMS. The lookahead
// keeps pressure phrases like "do not ignore" from reading as a negation of what follows.
const NEGATION_BEFORE = compilePattern(
  R`\b(?:not|never|dont|don't|do not|no need|no such|without|nahi|nahin)\b` +
    R`(?! (?:ignore|delay|miss|wait|worry|panic|forget|a (?:scam|fraud|fake)))`,
);
// Inside the matched span itself ("OTP is 1234. Do not share").
const NEGATION_INSIDE = compilePattern(R`\b(?:not|never|dont|don't|nahi|nahin|mat)\b`);
// Hindi puts the negation after the verb: "OTP share na karein", "share mat karo".
const NEGATION_AFTER = compilePattern(R`^\W{0,3}(?:na|mat|nahi|nahin|nhi)\b`);
const NEGATION_WINDOW = 40;

// How a rule treats a nearby negation. An "ask" rule is about a request, so "never share your
// OTP" flips its meaning; a "before" rule only checks the words leading up to the match; a
// rule with no negation handling describes a threat, where "do not" is usually part of it.
export const NEG_NONE = "";
export const NEG_BEFORE = "before";
export const NEG_ASK = "ask";

// Python slices count code points, so every context window is measured in code points too;
// otherwise an emoji near a match would shift the window by one.
const before = (text, index, count) => text.slice(skipBack(text, index, count), index);
const after = (text, index, count) => text.slice(index, skipForward(text, index, count));

export class Rule {
  /**
   * @param {object} spec
   * @param {string} spec.code
   * @param {string} spec.label
   * @param {string[]} spec.triggers
   * @param {Array<[string, WordPattern]>} spec.patterns (weight key, compiled pattern)
   * @param {string} [spec.negation]
   * @param {((text: string, match: Match) => boolean) | null} [spec.benign] true when a match
   *   is harmless in context
   */
  constructor({ code, label, triggers, patterns, negation = NEG_NONE, benign = null }) {
    this.code = code;
    this.label = label;
    this.triggers = Object.freeze(triggers);
    this.patterns = Object.freeze(patterns);
    this.negation = negation;
    this.benign = benign;
    Object.freeze(this);
  }

  /**
   * Return [weight key, evidence] for the heaviest pattern that matched, or null.
   *
   * `seen` memoises trigger lookups across rules; each lookup is a full pass over the text, and
   * several rules share triggers.
   */
  scan(text, seen = new Map()) {
    if (!this.triggers.some((t) => contains(text, t, seen))) return null;
    let best = null;
    for (const [key, pattern] of this.patterns) {
      if (best !== null && weightOf(key) <= weightOf(best[0])) continue;
      for (const match of pattern.finditer(text)) {
        if (this.negation && negated(text, match, this.negation)) continue;
        if (this.benign !== null && this.benign(text, match)) continue;
        best = [key, match.group];
        break;
      }
    }
    return best;
  }
}

function contains(text, trigger, seen) {
  let found = seen.get(trigger);
  if (found === undefined) {
    found = text.includes(trigger);
    seen.set(trigger, found);
  }
  return found;
}

function negated(text, match, mode) {
  const { start, end } = match;
  if (NEGATION_BEFORE.test(before(text, start, NEGATION_WINDOW))) return true;
  if (mode !== NEG_ASK) return false;
  if (NEGATION_INSIDE.test(match.group)) return true;
  return NEGATION_AFTER.test(after(text, end, 12));
}

/**
 * A match, shaped like the parts of Python's re.Match the rules use.
 * @typedef {{start: number, end: number, group: string}} Match
 * start and end are UTF-16 indices into the scanned text; group is match.group(0).
 */

/**
 * A compiled pattern whose matches must start at a word boundary.
 *
 * A leading \b stops the regex engine from skipping ahead to positions that can start a match,
 * which makes a megabyte scan several times slower. So the \b is removed before compiling and
 * the boundary is checked here instead, on the few positions that matched. The check is
 * Python's, not a true \b: only the character before the match is looked at.
 */
export class WordPattern {
  constructor(source) {
    const [stripped, everyBranchBounded] = stripLeadingBoundaries(source);
    this.wordStart = everyBranchBounded;
    this.regex = compilePattern(everyBranchBounded ? stripped : source, "g");
    Object.freeze(this);
  }

  /** @returns {Generator<Match>} */
  *finditer(text) {
    const regex = this.regex;
    let pos = 0;
    while (pos <= text.length) {
      // Set lastIndex on every step: the regex object is shared, and a caller could interleave
      // two scans of the same pattern.
      regex.lastIndex = pos;
      const found = regex.exec(text);
      if (found === null) return;
      const start = found.index;
      const end = start + found[0].length;
      if (this.wordStart && start && isWordChar(charBefore(text, start))) {
        // Python resumes one code point later; stepping one UTF-16 unit could land inside a
        // surrogate pair, where V8 steps back and would find the same match forever.
        pos = skipForward(text, start, 1);
        continue;
      }
      yield { start, end, group: found[0] };
      // No rule pattern can match the empty string, but never loop if one ever does.
      pos = end > start ? end : skipForward(text, start, 1);
      if (end === start && start === text.length) return;
    }
  }
}

/** Drop the \b that opens each top-level branch; report whether every branch had one. */
function stripLeadingBoundaries(source) {
  const out = [];
  let depth = 0;
  let inClass = false;
  let atBranchStart = true;
  let allBounded = true;
  let i = 0;
  while (i < source.length) {
    if (atBranchStart) {
      atBranchStart = false;
      if (source.startsWith(R`\b`, i)) {
        i += 2;
        continue;
      }
      allBounded = false;
    }
    const char = source[i];
    if (char === "\\") {
      out.push(source.slice(i, i + 2));
      i += 2;
      continue;
    }
    if (inClass) {
      inClass = char !== "]";
    } else if (char === "[") {
      inClass = true;
    } else if (char === "(") {
      depth += 1;
    } else if (char === ")") {
      depth -= 1;
    } else if (char === "|" && depth === 0) {
      atBranchStart = true;
    }
    out.push(char);
    i += 1;
  }
  return [out.join(""), allBounded];
}

const c = (pattern) => new WordPattern(pattern);

// Context checks -----------------------------------------------------------------------------

const DELIVERY_WORDS = compilePattern(
  R`\b(?:delivery|driver|captain|rider|pilot|courier boy|at the time of)\b`,
);
const INLINE_CODE = compilePattern(R`\b\d{4,8}\b`);

function otpDeliveryContext(text, match) {
  // Delivery and ride apps send "share OTP 4821 with the delivery agent". The code is in the
  // message itself, which is what separates them from a request for an OTP you received.
  const { start, end } = match;
  const window = text.slice(skipBack(text, start, 40), skipForward(text, end, 60));
  return DELIVERY_WORDS.test(window) && INLINE_CODE.test(window);
}

const ON_REQUEST = compilePattern(R`\b(?:as per|on|at) your request\b|\bsuccessfully\b`);

function blockedOnRequest(text, match) {
  return ON_REQUEST.test(after(text, match.end, 40));
}

const AVOID = compilePattern(R`\b(?:avoid|prevent|to escape)\b`);

function avoidDisconnection(text, match) {
  // "Pay by the due date to avoid disconnection" is an ordinary bill reminder.
  return AVOID.test(text.slice(skipBack(text, match.start, 20), match.end));
}

const AWARENESS_BEFORE = compilePattern(
  R`\b(?:beware|scams?|frauds?|fake|no such|there is no|is not a|awareness|be careful` +
    R`|never)\b`,
);
const AWARENESS_AFTER = compilePattern(R`^\W{0,3}(?:scams?|frauds?|calls? are fake)\b`);

function awarenessMessage(text, match) {
  // Police and banks run "beware of digital arrest scams" campaigns over SMS; those name the
  // same agencies and threats, so they are told apart by the warning words around them.
  const { start, end } = match;
  if (AWARENESS_BEFORE.test(before(text, start, 40))) return true;
  return AWARENESS_AFTER.test(after(text, end, 20));
}

const WARNING_WORDS = compilePattern(
  R`\b(?:beware|frauds?|fraudsters?|scams?|scammers?|never|do not|don't|dont)\b`,
);

function warningNearby(text, match) {
  // Bank safety notices list the apps to refuse ("never install AnyDesk, beware of
  // fraudsters"); the warning can sit a sentence before or after the app name.
  const { start, end } = match;
  return WARNING_WORDS.test(text.slice(skipBack(text, start, 60), skipForward(text, end, 60)));
}

// Shared vocabulary --------------------------------------------------------------------------

const ACCOUNT =
  R`(?:a/?c|acct|account|bank account|khata|debit card|credit card|atm card|atm|card` +
  R`|net ?banking|internet banking|mobile banking|yono|wallet|upi id|upi)`;
const BLOCK_STATE =
  R`(?:blocked|block|suspended|suspend|deactivated|deactivate|closed|frozen|freezed|on hold` +
  R`|hold|restricted|disabled|terminated|locked)`;
const FUTURE = R`(?:will|shall|is going to|may|would)(?: be| get)?`;
const HI_WILL_CLOSE =
  R`(?:band|bandh|block) ?(?:ho|kar|kr) ?(?:jayega|jaega|jayegi|jaegi|jaayega|diya jayega` +
  R`|di jayegi|dia jayega|sakta|sakti)`;
const MONEY = R`(?:rs\.? ?\d|inr ?\d|₹ ?\d|\d+ ?(?:lakh|lac|crore|cr)\b|rupees|rupaye)`;
// A lakh or more, in words or in either digit grouping ("25,00,000" or "2,500,000").
const BIG_MONEY =
  R`(?:\b\d+ ?(?:lakh|lac|crore)\b|(?:rs\.? ?|inr ?|₹ ?)(?:\d{1,2}(?:,\d\d)+,\d{3}` +
  R`|\d{1,3}(?:,\d{3}){2,}|\d{6,})\b)`;
const OTP = R`(?:otp|one ?time ?password|one-time password|verification code|otp code|o\.t\.p)`;
const OTP_VERB =
  R`(?:share|send|tell|forward|provide|give|read out|reply with|batao|bataye|bataiye` +
  R`|bata do|bata dijiye|bhejo|bhej do|bhejiye|bhejein|de do|dedo|dijiye)`;
const REMOTE_APPS =
  R`(?:anydesk|any desk app|teamviewer|team viewer|quicksupport|rustdesk|rust desk|airdroid` +
  R`|ammyy|ultraviewer|ultra viewer|alpemix|splashtop|screen ?share app|screen sharing app` +
  R`|remote access app)`;
const INSTALL = R`(?:download|install|instal|open|daal|dalo|launch)`;
const PIN = R`(?:upi pin|upi-pin|mpin|m-pin|pin)`;
const RECEIVE =
  R`(?:receiv\w*|claim|accept (?:the )?(?:money|payment|amount)|get (?:the |your )?` +
  R`(?:money|amount|payment|cashback|refund|prize)|credited|refund|cashback|prapt|milega` +
  R`|paane|lene)`;
const SIM_STATE = R`(?:blocked|deactivated|disconnected|suspended|barred|closed|terminated)`;

export const RULES = Object.freeze([
  new Rule({
    code: "otp_request",
    label: "Asks you to share an OTP; no bank, company or officer ever needs your OTP.",
    triggers: ["otp", "one time", "one-time", "onetime", "verification code", "o.t.p"],
    patterns: [
      ["otp_request", c(R`\b${OTP_VERB}\b.{0,30}?\b${OTP}\b`)],
      ["otp_request", c(R`\b${OTP}\b.{0,50}?\b${OTP_VERB}\b`)],
    ],
    negation: NEG_ASK,
    benign: otpDeliveryContext,
  }),
  new Rule({
    code: "upi_pin_to_receive",
    label: "Asks for a PIN to receive money; receiving money never needs your UPI PIN.",
    triggers: ["pin"],
    patterns: [
      [
        "upi_pin_to_receive",
        c(
          R`\b(?:enter|type|put|provide|use|share|daal\w*|dalein|dale|dalo)` +
            R` (?:your |ur |the |apna |aapka )?${PIN}\b.{0,50}?\b${RECEIVE}`,
        ),
      ],
      [
        "upi_pin_to_receive",
        c(
          R`\b${RECEIVE}\b.{0,50}?\b(?:enter|type|put|provide|daal\w*|dalein)` +
            R` (?:your |ur |the |apna )?${PIN}\b`,
        ),
      ],
      ["upi_pin_to_receive", c(R`\b${PIN}\b.{0,20}?\b(?:to|for) (?:receive|claim)`)],
    ],
    negation: NEG_ASK,
  }),
  new Rule({
    code: "upi_collect_refund",
    label: "Dresses up a UPI collect request as a refund, prize or incoming payment.",
    triggers: ["request"],
    patterns: [
      [
        "upi_collect_refund",
        c(
          R`\b(?:collect|payment|money) request\b.{0,60}?` +
            R`\b(?:refund|cashback|receive|prize|reward|credited)`,
        ),
      ],
      [
        "upi_collect_refund",
        c(
          R`\b(?:refund|cashback|prize|reward)\w*\b.{0,60}?\b(?:approve|accept|pay)` +
            R` (?:the |this |our )?(?:collect |upi |payment )?request`,
        ),
      ],
    ],
    negation: NEG_ASK,
  }),
  new Rule({
    code: "remote_access_app",
    label: "Names a screen-sharing app; scammers use these to watch you type your PIN.",
    triggers: [
      "desk",
      "viewer",
      "quicksupport",
      "airdroid",
      "ammyy",
      "alpemix",
      "splashtop",
      "screen",
      "remote access",
    ],
    patterns: [
      ["remote_access_app.install", c(R`\b${INSTALL}\w*\b.{0,30}?\b${REMOTE_APPS}\b`)],
      ["remote_access_app", c(R`\b${REMOTE_APPS}\b`)],
    ],
    negation: NEG_ASK,
    benign: warningNearby,
  }),
  new Rule({
    code: "apk_download",
    label: "Asks you to install an app file (APK) from outside the Play Store.",
    triggers: ["apk", "app file"],
    patterns: [
      ["apk_download", c(R`\b${INSTALL}\w*\b.{0,40}?(?:\bapk\b|\.apk\b|\bapp file\b)`)],
      ["apk_download.file", c(R`(?<![\w-])[\w-]{1,40}\.apk\b`)],
    ],
    negation: NEG_ASK,
  }),
  new Rule({
    code: "digital_arrest",
    label: "Threatens a 'digital arrest'; no Indian agency arrests anyone over a call.",
    triggers: ["arrest"],
    patterns: [["digital_arrest", c(R`\bdigital(?:ly)? (?:house )?arrest\w*`)]],
    benign: awarenessMessage,
  }),
  new Rule({
    code: "authority_threat",
    label: "Claims to be police, CBI, customs or another agency and threatens legal trouble.",
    triggers: [
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
    ],
    patterns: [
      [
        "authority_threat.parcel_contraband",
        c(
          R`\b(?:parcel|package|courier|shipment|consignment)\b.{0,60}?` +
            R`\b(?:drugs|narcotics|mdma|ganja|contraband|fake passports?|illegal items)`,
        ),
      ],
      [
        "authority_threat",
        c(
          R`\b(?:cbi|ncb|narcotics|crime branch|cyber ?(?:cell|crime|police)|police` +
            R`|customs|enforcement directorate|interpol|court)\b.{0,60}?` +
            R`\b(?:arrest|warrant|fir\b|case (?:registered|filed|against)|illegal` +
            R`|money laundering|seized|summons?|legal action|video call|skype)`,
        ),
      ],
      [
        "authority_threat",
        c(
          R`\b(?:arrest warrant|money laundering case|non[- ]?bailable` +
            R`|(?:fir|case) (?:has been |is )?(?:registered|filed) against you)`,
        ),
      ],
    ],
    benign: awarenessMessage,
  }),
  new Rule({
    code: "utility_disconnection",
    label: "Threatens to cut your electricity or gas; power boards do not warn like this.",
    triggers: ["electric", "power", "bijli", "bijlee", "light", "gas", "eb "],
    patterns: [
      [
        "utility_disconnection",
        c(
          R`\b(?:your|ur|aapka|apka|aapki|apki|tumhara)` +
            R` (?:electricity|electric|power|bijli|bijlee|light|gas|eb)\b.{0,50}?` +
            R`\b(?:disconnect\w*|cut|kaat|kat|katt|band|bandh)\b`,
        ),
      ],
      [
        "utility_disconnection",
        c(
          R`\b(?:electricity|electric|power|bijli|bijlee|light|gas)\b.{0,50}?` +
            R`\b(?:disconnect\w*|cut|kaat|kat|band)\b.{0,30}?` +
            R`\b(?:tonight|today|aaj raat|aaj|at \d{1,2}[:.]?\d{0,2} ?(?:pm|am|baje))`,
        ),
      ],
      [
        "utility_disconnection.officer",
        c(
          R`\b(?:electricity|electric|bijli|power|eb|gas) (?:officer|office|department` +
            R`|dept|adhikari)\b`,
        ),
      ],
      [
        "utility_disconnection.bill",
        c(
          R`\b(?:previous|last|pichle|pichhle) (?:month(?:'s)?|mahine ka)` +
            R` (?:electricity )?bill (?:was |is |has )?(?:not|nahi|nhi) (?:been )?` +
            R`(?:update|paid|pay|jama)`,
        ),
      ],
      [
        "utility_disconnection.generic",
        c(
          R`\b(?:electricity|electric|bijli|power|gas)\b.{0,30}?` +
            R`\bdisconnect(?:ed|ion)\b`,
        ),
      ],
    ],
    benign: avoidDisconnection,
  }),
  new Rule({
    code: "sim_deactivation",
    label: "Says your SIM or mobile number will be blocked; a classic pretext to get a call.",
    triggers: ["sim", "number", "mobile", "trai"],
    patterns: [
      [
        "sim_deactivation.trai",
        c(R`\btrai\b.{0,80}?\b(?:disconnect|block|deactivat|suspend|band|barred)`),
      ],
      [
        "sim_deactivation",
        c(
          R`\b(?:sim(?: card)?|mobile (?:number|connection|service)|phone number` +
            R`|your number)\b.{0,40}?` +
            R`\b(?:${FUTURE} (?:permanently |temporarily )?${SIM_STATE}|${HI_WILL_CLOSE})`,
        ),
      ],
    ],
    negation: NEG_BEFORE,
    benign: awarenessMessage,
  }),
  new Rule({
    code: "kyc_update",
    label: "Asks you to update or verify KYC, PAN or Aadhaar through a message.",
    triggers: ["kyc", "pan", "aadha", "adhar"],
    patterns: [
      [
        "kyc_update",
        c(
          R`\b(?:e-?|re-?|video )?kyc\b.{0,40}?` +
            R`(?:\bupdat(?:e\b|ion)|\bverify\b|\bverification (?:is )?(?:pending` +
            R`|required|due|failed)|\bpending|\bexpir(?:ed|es|ing|y)|\bincomplete` +
            R`|\bnot (?:updated|verified|completed?|done)|\bsuspend|\bblock|\bkarein` +
            R`|\bkare\b|\bkaro\b|\bkarwaye|\bnahi hua|\bnhi hua)`,
        ),
      ],
      [
        "kyc_update",
        c(
          R`\b(?:update|verify|link|complete|submit|upload|updating|verifying)` +
            R` (?:your |ur |the |apna |aapka |apka )?` +
            R`(?:e-?kyc|kyc|pan(?: card)?|aadhaa?r(?: card)?|adhar(?: card)?)\b`,
        ),
      ],
      [
        "kyc_update",
        c(
          R`\b(?:pan|aadhaa?r|adhar)(?: card)?(?: (?:no|number|details))?` +
            R` (?:is |has )?(?:not (?:been )?(?:updated|linked|verified)|expired|pending` +
            R`|update (?:karein|kare|karo|now)|link nahi)`,
        ),
      ],
    ],
    negation: NEG_BEFORE,
  }),
  new Rule({
    code: "account_blocked",
    label: "Claims your bank account, card or UPI will be blocked unless you act.",
    triggers: [
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
    ],
    patterns: [
      [
        "account_blocked",
        c(
          R`\b${ACCOUNT}\b.{0,30}?\b${FUTURE} ?(?:temporarily |permanently )?` +
            R`${BLOCK_STATE}\b`,
        ),
      ],
      ["account_blocked", c(R`\b${ACCOUNT}\b.{0,30}?\b${HI_WILL_CLOSE}`)],
      [
        "account_blocked",
        c(
          R`\b${ACCOUNT}\b.{0,30}?\b${BLOCK_STATE}\b.{0,15}?` +
            R`\b(?:today|tonight|within|in \d+ ?(?:hours?|hrs?|minutes?|mins?))`,
        ),
      ],
      [
        "account_blocked.past",
        c(
          R`\b${ACCOUNT}\b.{0,30}?\b(?:has been|have been|is|was|got|has got)` +
            R` (?:temporarily |permanently )?${BLOCK_STATE}\b`,
        ),
      ],
    ],
    benign: blockedOnRequest,
  }),
  new Rule({
    code: "prize_lottery",
    label: "Says you won a prize, lottery or lucky draw you never entered.",
    triggers: ["won", "win", "jeet", "lottery", "lucky", "jackpot", "kbc", "crorepati", "bumper"],
    patterns: [
      [
        "prize_lottery",
        c(
          R`\b(?:you (?:have|are)|you've|u have|u hv) (?:been )?` +
            R`(?:won|win|selected for|jeet\w*)\b.{0,40}?` +
            R`(?:${MONEY}|\b(?:lottery|lucky draw|prize|jackpot|bumper|cash|gift|iphone` +
            R`|car|bike|reward|lakh|crore))`,
        ),
      ],
      ["prize_lottery", c(R`\baap(?:ne|ka|ki)?\b.{0,40}?\bjeet(?:e|a|i|ne)\b`)],
      ["prize_lottery", c(R`\b(?:you are|u r|you're) (?:the |our )?(?:lucky )?winner`)],
      [
        "prize_lottery",
        c(R`\bcongratulations?\b.{0,60}?\b(?:won|winner|jeet\w*|lucky draw|lottery)`),
      ],
      [
        "prize_lottery.big",
        c(
          R`\b(?:kbc|kaun banega crorepati|lottery|lucky draw|jackpot|bumper)\b` +
            R`.{0,60}?\b(?:won|winner|jeet\w*|lakh|lac|crore|claim|prize money)\b` +
            R`|\b(?:won|winner|jeet\w*)\b.{0,40}?${BIG_MONEY}.{0,40}?` +
            R`\b(?:kbc|lottery|lucky draw|jackpot|bumper|prize)\b`,
        ),
      ],
      ["prize_lottery.kbc", c(R`\b(?:kbc|kaun banega crorepati)\b`)],
      [
        "prize_lottery.mention",
        c(R`\b(?:lottery|lucky draw|jackpot|bumper (?:prize|draw))\b`),
      ],
    ],
    negation: NEG_BEFORE,
  }),
  new Rule({
    code: "task_job_offer",
    label: "Offers easy paid 'tasks' or part-time work, a common route into deposit scams.",
    triggers: [
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
    ],
    patterns: [
      [
        "task_job_offer.task",
        c(
          R`\b(?:lik(?:e|es|ing)|subscrib(?:e|es|ing)|rat(?:e|es|ing)` +
            R`|review(?:s|ing)?|follow(?:s|ing)?) (?:\w+ ){0,2}(?:youtube|yt|google|hotels?|instagram|insta|videos?` +
            R`|restaurants?|movies?|channels?)\b.{0,80}?` +
            R`(?:\bearn|\bpaid\b|\bsalary|\bincome|\bcommission|${MONEY})`,
        ),
      ],
      [
        "task_job_offer.task",
        c(
          R`\b(?:prepaid|pre-paid|advance|merchant|online) tasks?\b` +
            R`|\btask[- ]based\b` +
            R`|\btasks?\b.{0,40}?\b(?:commission|profit|recharge|deposit|prepay)`,
        ),
      ],
      [
        "task_job_offer",
        c(
          R`\b(?:part[- ]?time|work from home|wfh|home[- ]based|ghar baithe)\b.{0,60}?` +
            R`\b(?:job|work|earn|income|kamaye|kamayein|kamao|salary|daily|per day` +
            R`|paise)\b`,
        ),
      ],
      [
        "task_job_offer",
        c(
          R`\b(?:earn|kamaye|kamayein|kamao|income of|salary of)\b.{0,20}?${MONEY}` +
            R`.{0,25}?(?:per day|a day|daily|/ ?day|every day|per hour|/ ?hr|pratidin` +
            R`|roz|rozana|din ke)`,
        ),
      ],
      [
        "task_job_offer.chat",
        c(
          R`\b(?:job|hr manager|hr team|recruit\w*|hiring|vacancy|task)\b.{0,50}?` +
            R`\b(?:telegram|whatsapp)\b` +
            R`|\b(?:telegram|whatsapp)\b.{0,40}?\b(?:job|recruiter|task|earn\w*)\b`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "parcel_held",
    label: "Says a parcel is held or undeliverable, usually to collect a fee or card details.",
    triggers: [
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
    ],
    patterns: [
      [
        "parcel_held",
        c(
          R`\b(?:parcel|package|shipment|courier|consignment|delivery)\b.{0,50}?` +
            R`\b(?:on hold|held|holding|could not be delivered|couldn't be delivered` +
            R`|cannot be delivered|can't be delivered|undeliver\w*|delivery failed` +
            R`|failed delivery|delivery attempt failed|suspended|seized|stuck|detained` +
            R`|rok (?:diya|liya|lia))`,
        ),
      ],
      [
        "parcel_held",
        c(
          R`\b(?:address|pin ?code|house number)\b (?:is |was )?` +
            R`(?:incomplete|incorrect|invalid|wrong|not (?:complete|found|clear|correct))` +
            R`|\bincomplete (?:address|house number|street|delivery address)`,
        ),
      ],
      [
        "parcel_held.address",
        c(
          R`\b(?:update|confirm|correct|re-?enter) (?:your |the )?` +
            R`(?:delivery |shipping )?address`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "advance_fee",
    label: "Asks for a small fee up front to release a parcel, loan, job or prize.",
    triggers: ["fee", "charge", "deposit", "amount", "pay", "send", "transfer"],
    patterns: [
      [
        "advance_fee",
        c(
          R`\b(?:redelivery|re-delivery|customs|clearance|unlock|activation|release` +
            R`|small|nominal|refundable|token) (?:fee|fees|charges?|amount|deposit)\b`,
        ),
      ],
      [
        "advance_fee",
        c(
          R`\b(?:pay|deposit|transfer|send)\b (?:only |just )?` +
            R`(?:rs\.? ?|₹ ?|inr ?)\d{1,3}\b(?!,\d)(?! ?(?:lakh|lac|crore|k\b))` +
            R`.{0,30}?\b(?:fee|charge|to (?:receive|release|reschedule|claim|redeliver))`,
        ),
      ],
      [
        "advance_fee.processing",
        c(
          R`\b(?:processing|registration|security|verification|file|insurance` +
            R`|documentation) (?:fee|fees|charges?|deposit)\b`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "loan_offer",
    label: "Pushes an instant or pre-approved loan, a common lure for fee and data theft.",
    triggers: ["loan"],
    patterns: [
      [
        "loan_offer.no_checks",
        c(
          R`\bloan\b.{0,60}?\b(?:without|no) (?:cibil|credit score|credit check` +
            R`|documents?|document verification|income proof|paperwork)`,
        ),
      ],
      [
        "loan_offer.no_checks",
        c(
          R`\bloan\b.{0,60}?\b(?:approved|sanctioned)\b.{0,40}?` +
            R`\b(?:pay|deposit|processing|registration|fee)`,
        ),
      ],
      [
        "loan_offer",
        c(
          R`\b(?:instant|pre-?approved|preapproved|guaranteed|urgent|quick|easy)` +
            R` (?:personal |cash |mobile |app )?loans?\b`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "investment_scheme",
    label: "Promises guaranteed, doubled or unrealistic investment returns.",
    triggers: [
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
    ],
    patterns: [
      [
        "investment_scheme.doubling",
        c(
          R`\b(?:double|triple|2x|3x|5x|10x) (?:your )?(?:money|investment|amount` +
            R`|paisa|paise|capital)\b|\b(?:money|investment|amount|paisa|paise)` +
            R` (?:will |gets? |ho )?(?:be )?(?:doubled|tripled|double|triple)\b`,
        ),
      ],
      [
        "investment_scheme.daily",
        c(
          R`\b(?:returns?|profits?)\b (?:of )?(?:up to |upto )?\d+ ?%` +
            R` ?(?:daily|per day|a day|weekly|per week|in \d+ days?)`,
        ),
      ],
      [
        "investment_scheme",
        c(
          R`\b(?:guaranteed|assured|sure[- ]?shot|risk[- ]free|100 ?% ?` +
            R`(?:guaranteed|assured|sure|safe))` +
            R` (?:daily |weekly |monthly |high )?(?:returns?|profits?|income|earnings?)`,
        ),
      ],
      [
        "investment_scheme.crypto",
        c(
          R`\b(?:crypto|bitcoin|btc|usdt|forex|trading|stock market|share market)\b` +
            R`.{0,40}?\b(?:profit|returns?|earn\w*|guaranteed|vip group|signals?` +
            R`|tips group)`,
        ),
      ],
    ],
    negation: NEG_BEFORE,
  }),
  new Rule({
    code: "reward_points",
    label: "Says reward points are about to expire, to lure you to a card-details page.",
    triggers: ["point", "pts"],
    patterns: [
      [
        "reward_points",
        c(
          R`\b(?:reward|redeem|redemption|loyalty|credit card|card) ?(?:points?|pts)\b` +
            R`.{0,60}?\b(?:expir\w*|lapse|will be (?:lost|forfeited)|redeem (?:now` +
            R`|today|immediately)|worth (?:rs|inr|₹))`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "tax_refund",
    label: "Says an income-tax refund is waiting; the department never asks you to claim it.",
    triggers: ["refund"],
    patterns: [
      [
        "tax_refund",
        c(
          R`\b(?:income ?tax|it dept|it department|itr|tax) refund\b.{0,80}?` +
            R`\b(?:verify|update|click|claim|submit|confirm|link|account details` +
            R`|bank details)`,
        ),
      ],
      [
        "tax_refund",
        c(
          R`\brefund of (?:rs\.? ?|₹ ?|inr ?)[\d,.]+.{0,60}?\b(?:income ?tax|itr)\b` +
            R`.{0,60}?\b(?:verify|update|click|claim|submit|confirm)`,
        ),
      ],
      [
        "tax_refund.status",
        c(R`\b(?:income ?tax|itr) refund\b.{0,40}?\b(?:approved|pending|sanctioned)`),
      ],
    ],
  }),
  new Rule({
    code: "echallan",
    label: "Mentions a traffic e-challan; fake challan links are a common phishing lure.",
    triggers: ["challan"],
    patterns: [
      [
        "echallan",
        c(
          R`\b(?:e-? ?challan|traffic (?:challan|fine)` +
            R`|challan (?:of|no|number|pending|issued|amount))`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "mistaken_transfer",
    label: "Claims money was sent to you by mistake and asks for it back.",
    triggers: ["mistake", "galti", "wrongly"],
    patterns: [
      [
        "mistaken_transfer",
        c(
          R`\b(?:sent|send|transferred|credited|paid|bheja|bhej diya)\b.{0,40}?` +
            R`\b(?:by mistake|mistakenly|galti se|wrongly)` +
            R`|\b(?:galti se|by mistake)\b.{0,40}?\b(?:paise|money|payment|rs\b|rs\.)`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "threat_of_loss",
    label: "Threatens a loss or penalty to rush you.",
    triggers: ["warning", "notice", "legal", "will be", "shall be", "band", "kaat", "block"],
    patterns: [
      [
        "threat_of_loss",
        c(
          R`\b(?:last|final) (?:warning|notice|reminder before)\b|\blegal action\b` +
            R`|\b(?:will|shall) be (?:permanently )?(?:blocked|suspended|deactivated` +
            R`|disconnected|terminated|seized|frozen|closed)\b` +
            R`|\b${HI_WILL_CLOSE}|\bkaat (?:diya|di|dia) (?:jayega|jayegi|jaega)`,
        ),
      ],
    ],
  }),
  new Rule({
    code: "urgency",
    label: "Pushes you to act immediately, a pressure tactic.",
    triggers: [
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
    ],
    patterns: [
      [
        "urgency",
        c(
          R`\bexpir(?:e|es|ed|ing|y)\b (?:by |on )?(?:today|tonight|in \d+` +
            R` ?(?:hours?|hrs?)|within)` +
            R`|\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?)\b` +
            R`|\bin (?:the )?next \d+ ?(?:hours?|hrs?|minutes?|mins?)\b` +
            R`|\bimmediately\b|\burgent(?:ly)?\b|\basap\b|\bright now\b|\bact now\b` +
            R`|\bturant\b|\bjaldi\b|\babhi (?:karein|kare|karo|kijiye)\b` +
            R`|\blast (?:date|day|chance)\b`,
        ),
      ],
      ["urgency.offer", c(R`\blimited[- ]time\b|\bhurry\b`)],
    ],
  }),
  new Rule({
    code: "otp_warning",
    label: "Carries the standard 'never share your OTP or PIN' warning that genuine senders use.",
    triggers: ["share", "never", "disclose", "ask", "batay", "batan", " mat ", " na "],
    patterns: [
      [
        "otp_warning",
        c(
          R`\b(?:do not|don't|dont|never|not to) (?:\w+ ){0,3}?` +
            R`(?:share|disclose|tell|give)\b.{0,30}?\b(?:otp|pin|password|cvv)\b`,
        ),
      ],
      [
        "otp_warning",
        c(
          R`\b(?:otp|pin|password|cvv)\b.{0,40}?\b(?:do not|don't|dont|never)` +
            R` (?:share|disclose)`,
        ),
      ],
      [
        "otp_warning",
        c(
          R`\b(?:never|will not|won't|does not|doesn't|do not) (?:ever )?` +
            R`(?:asks?|calls?|requests?)\b.{0,20}?` +
            R`\b(?:otp|pin|password|cvv|card details)\b`,
        ),
      ],
      [
        "otp_warning",
        c(
          R`\b(?:otp|pin)\b.{0,30}?\b(?:share|bataye|batayein|batana)` +
            R` (?:na|mat|nahi)\b`,
        ),
      ],
    ],
  }),
]);

// Rules whose firing means the sender wants something from you; a link next to one of these
// is where that something gets collected.
export const REQUEST_CODES = new Set([
  "otp_request", "upi_pin_to_receive", "upi_collect_refund", "kyc_update",
  "account_blocked", "sim_deactivation", "prize_lottery", "task_job_offer",
  "parcel_held", "advance_fee", "loan_offer", "investment_scheme", "reward_points",
  "tax_refund", "utility_disconnection", "authority_threat", "mistaken_transfer",
]);

// Money or job language that turns a WhatsApp or Telegram link into a lure.
export const MONEY_OR_JOB = compilePattern(
  R`\b(?:earn\w*|income|job|salary|profit|invest\w*|task|trading|crypto|lakh|crore|prize` +
    R`|won|winner|refund|loan|cashback|bonus|commission|kamaye|kamao|paise|hiring|vacancy)\b` +
    R`|rs\.? ?\d|₹ ?\d|inr ?\d`,
);
