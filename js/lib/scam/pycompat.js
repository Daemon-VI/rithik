// Python string and regex behaviour that JavaScript does not share.
//
// The Python package in src/rithik/scam/ is the reference, and the JavaScript port has to give
// the same answer for the same text. Python strings count code points while JavaScript strings
// count UTF-16 units. Python's str regexes are Unicode-aware while JavaScript's \w, \d and \b
// are ASCII-only. Python's round() and sum() also treat floats differently. Each helper here
// closes one of those gaps and names the Python behaviour it stands in for.

// --- character classes ---------------------------------------------------------------------

// Python's \s and str.isspace(): category Zs, or bidi class WS, B or S. JavaScript's \s adds
// U+FEFF and leaves out U+001C-U+001F and U+0085, so it cannot be used directly.
export const SPACE_CLASS = String.raw`\t-\r\x1c-\x20\x85\xa0\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}`;

// Python's \w and `str.isalnum() or "_"`: letters plus anything with a numeric value, which is
// every L* and N* code point.
export const WORD_CLASS = String.raw`\p{L}\p{N}_`;

const SPACE_CODES = new Set(
  [9, 10, 11, 12, 13, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2028, 0x2029]
    .concat([0x202f, 0x205f, 0x3000])
    .concat(Array.from({ length: 11 }, (_, i) => 0x2000 + i)),
);

const WORD_CHAR = new RegExp(`^[${WORD_CLASS}]$`, "u");
const UPPER_CHAR = /^\p{Uppercase}$/u;
const LOWER_CHAR = /^\p{Lowercase}$/u;
const TITLE_CHAR = /^\p{Lt}$/u;
// str.isdigit() also accepts Numeric_Type=Digit (superscripts, circled digits and so on),
// which JavaScript has no property escape for. Table taken from Python 3.12 (Unicode 15.0).
const DIGIT_CHARS = new RegExp(
  String.raw`^[\p{Nd}\u{b2}-\u{b3}\u{b9}\u{1369}-\u{1371}\u{19da}\u{2070}\u{2074}-\u{2079}` +
    String.raw`\u{2080}-\u{2089}\u{2460}-\u{2468}\u{2474}-\u{247c}\u{2488}-\u{2490}\u{24ea}` +
    String.raw`\u{24f5}-\u{24fd}\u{24ff}\u{2776}-\u{277e}\u{2780}-\u{2788}\u{278a}-\u{2792}` +
    String.raw`\u{10a40}-\u{10a43}\u{10e60}-\u{10e68}\u{11052}-\u{1105a}\u{1f100}-\u{1f10a}]+$`,
  "u",
);
const ASCII_ONLY = /^[\x00-\x7f]*$/;
const ANY_SURROGATE = /[\ud800-\udfff]/;

/** `ch.isalnum() or ch == "_"` for one code point, given as a string. */
export function isWordChar(ch) {
  return WORD_CHAR.test(ch);
}

/** Python str.isdigit(). */
export function isDigit(s) {
  return DIGIT_CHARS.test(s);
}

/** Python str.isascii(). */
export function isAscii(s) {
  return ASCII_ONLY.test(s);
}

// CPython flags a character upper or lower from the derived Uppercase and Lowercase
// properties, and title from category Lt; isupper()/islower() then scan the whole string.
/** Python str.isupper(). */
export function isUpper(s) {
  const chars = Array.from(s);
  if (chars.length === 1) return UPPER_CHAR.test(chars[0]);
  let cased = false;
  for (const ch of chars) {
    if (LOWER_CHAR.test(ch) || TITLE_CHAR.test(ch)) return false;
    if (!cased && UPPER_CHAR.test(ch)) cased = true;
  }
  return cased;
}

/** Python str.islower(). */
export function isLower(s) {
  const chars = Array.from(s);
  if (chars.length === 1) return LOWER_CHAR.test(chars[0]);
  let cased = false;
  for (const ch of chars) {
    if (UPPER_CHAR.test(ch) || TITLE_CHAR.test(ch)) return false;
    if (!cased && LOWER_CHAR.test(ch)) cased = true;
  }
  return cased;
}

// --- code points -----------------------------------------------------------------------------

const isHigh = (unit) => unit >= 0xd800 && unit <= 0xdbff;
const isLow = (unit) => unit >= 0xdc00 && unit <= 0xdfff;

/** Python len(): code points, with a lone surrogate counting as one, as Python counts it. */
export function cpLength(s) {
  if (!ANY_SURROGATE.test(s)) return s.length;
  let n = s.length;
  for (let i = 0; i + 1 < s.length; i++) {
    if (isHigh(s.charCodeAt(i)) && isLow(s.charCodeAt(i + 1))) {
      n--;
      i++;
    }
  }
  return n;
}

/** The UTF-16 index `count` code points after `index`, stopping at the end of `s`. */
export function skipForward(s, index, count) {
  let i = index;
  while (count > 0 && i < s.length) {
    i += isHigh(s.charCodeAt(i)) && i + 1 < s.length && isLow(s.charCodeAt(i + 1)) ? 2 : 1;
    count--;
  }
  return i;
}

/** The UTF-16 index `count` code points before `index`, stopping at the start of `s`. */
export function skipBack(s, index, count) {
  let i = index;
  while (count > 0 && i > 0) {
    i -= i > 1 && isLow(s.charCodeAt(i - 1)) && isHigh(s.charCodeAt(i - 2)) ? 2 : 1;
    count--;
  }
  return i;
}

/** Python `s[:count]` for a non-negative count. */
export function cpHead(s, count) {
  return s.slice(0, skipForward(s, 0, count));
}

/** Python `s[count:]` for a non-negative count. */
export function cpTail(s, count) {
  return s.slice(skipForward(s, 0, count));
}

/** How many code points lie in `s` before the UTF-16 index `index`. */
export function cpIndex(s, index) {
  return cpLength(s.slice(0, index));
}

/** The code point that ends just before the UTF-16 index `index`, as a string. */
export function charBefore(s, index) {
  return s.slice(skipBack(s, index, 1), index);
}

// --- str methods ---------------------------------------------------------------------------

// Every character set passed to these is BMP-only, so comparing UTF-16 units is exact: a
// surrogate unit can never equal one of the characters being stripped.
function inSet(chars) {
  if (chars === undefined) return (unit) => SPACE_CODES.has(unit);
  return (unit) => chars.includes(String.fromCharCode(unit));
}

/** Python str.lstrip(chars); whitespace when chars is omitted. */
export function lstrip(s, chars) {
  const strip = inSet(chars);
  let start = 0;
  while (start < s.length && strip(s.charCodeAt(start))) start++;
  return s.slice(start);
}

/** Python str.rstrip(chars); whitespace when chars is omitted. */
export function rstrip(s, chars) {
  const strip = inSet(chars);
  let end = s.length;
  while (end > 0 && strip(s.charCodeAt(end - 1))) end--;
  return s.slice(0, end);
}

/** Python str.strip(chars); whitespace when chars is omitted. */
export function strip(s, chars) {
  return rstrip(lstrip(s, chars), chars);
}

/** Python str.split(sep, maxsplit) for a non-empty separator. */
export function split(s, sep, maxsplit = -1) {
  if (maxsplit < 0) return s.split(sep);
  const parts = [];
  let pos = 0;
  for (; maxsplit > 0; maxsplit--) {
    const at = s.indexOf(sep, pos);
    if (at < 0) break;
    parts.push(s.slice(pos, at));
    pos = at + sep.length;
  }
  parts.push(s.slice(pos));
  return parts;
}

/** Python str.rsplit(sep, maxsplit) for a non-empty separator. */
export function rsplit(s, sep, maxsplit = -1) {
  if (maxsplit < 0) return s.split(sep);
  const parts = [];
  let end = s.length;
  for (; maxsplit > 0; maxsplit--) {
    const at = end - sep.length < 0 ? -1 : s.lastIndexOf(sep, end - sep.length);
    if (at < 0) break;
    parts.unshift(s.slice(at + sep.length, end));
    end = at;
  }
  parts.unshift(s.slice(0, end));
  return parts;
}

// --- numbers ---------------------------------------------------------------------------------

const bits = new DataView(new ArrayBuffer(8));

/**
 * Python round(x, ndigits) for ndigits >= 0.
 *
 * CPython rounds the exact binary value of x to a decimal string with correctly rounded dtoa,
 * ties to even, and parses the string back. Math.round and toFixed round ties away from zero
 * and start from x * 10**n, which is already rounded, so both disagree on values like 0.0625.
 */
export function pyRound(x, ndigits) {
  if (!Number.isInteger(ndigits) || ndigits < 0) {
    throw new RangeError("pyRound supports only a non-negative integer ndigits");
  }
  if (!Number.isFinite(x) || x === 0) return x;
  bits.setFloat64(0, x);
  const hi = bits.getUint32(0);
  const lo = bits.getUint32(4);
  const biased = (hi >>> 20) & 0x7ff;
  let mantissa = (BigInt(hi & 0xfffff) << 32n) | BigInt(lo);
  let exponent;
  if (biased === 0) {
    exponent = -1074; // subnormal: no implicit leading 1
  } else {
    mantissa |= 1n << 52n;
    exponent = biased - 1075;
  }
  if (exponent >= 0) return x; // an integer-valued double has no fraction to round
  // x = mantissa / 2**-exponent exactly, so x * 10**n is an exact fraction too.
  const denominator = 1n << BigInt(-exponent);
  const numerator = mantissa * 10n ** BigInt(ndigits);
  let quotient = numerator / denominator;
  const twiceRemainder = 2n * (numerator - quotient * denominator);
  if (twiceRemainder > denominator || (twiceRemainder === denominator && quotient % 2n === 1n)) {
    quotient += 1n;
  }
  // String-to-number conversion is correctly rounded, like CPython's _Py_dg_strtod.
  const rounded = Number(`${quotient}e-${ndigits}`);
  return hi >>> 31 ? -rounded : rounded;
}

/**
 * Python 3.12+ sum() over floats, starting from the int 0.
 *
 * CPython 3.12 switched float sums to Neumaier's compensated algorithm, so a plain running
 * total can land one ulp away once the weights stop being exact binary fractions.
 */
export function pySum(values) {
  let total = 0;
  let compensation = 0;
  let first = true;
  for (const x of values) {
    if (first) {
      total = 0 + x;
      first = false;
      continue;
    }
    const t = total + x;
    compensation += Math.abs(total) >= Math.abs(x) ? total - t + x : x - t + total;
    total = t;
  }
  return compensation && Number.isFinite(compensation) ? total + compensation : total;
}

// --- regular expressions -------------------------------------------------------------------

const WORD = `[${WORD_CLASS}]`;
// Python's \b spelled out. V8 runs this two-sided form over ten times slower than a single
// lookaround on text holding emoji, so it is only used where the pattern gives no hint about
// the characters on either side.
const FULL_BOUNDARY = `(?:(?<=${WORD})(?!${WORD})|(?<!${WORD})(?=${WORD}))`;
// When one side is certain to be a word character, \b reduces to a check of the other side.
const BOUNDARY_AFTER_WORD = `(?!${WORD})`;
const BOUNDARY_BEFORE_WORD = `(?<!${WORD})`;
const NEVER = "(?!)"; // word characters on both sides: \b cannot hold
const SYNTAX_CHARS = "^$\\.*+?()[]{}|/";
const GROUP_OPENERS = ["?:", "?=", "?!", "?<=", "?<!"];

/**
 * Translate a Python `re` pattern (str, no flags) into JavaScript `u`-mode source.
 *
 * Covers the syntax the rule set uses and refuses anything else, so a pattern edited on the
 * Python side cannot silently change meaning here. \w, \W, \d, \D, \s and \S become their
 * Unicode forms. `.` becomes [^\n], because JavaScript's `.` also stops at \r, U+2028 and
 * U+2029. \b becomes the cheapest lookaround that means the same thing at that spot.
 */
export function translatePattern(source) {
  const parser = new PatternParser(source);
  const tree = parser.parseAlternation();
  if (parser.pos !== parser.chars.length) parser.fail("unbalanced )");
  return emit(tree);
}

/** Compile a Python `re` pattern (str, no flags) for JavaScript; `flags` may add "g" or "y". */
export function compilePattern(source, flags = "") {
  return new RegExp(translatePattern(source), `u${flags}`);
}

// Syntax tree nodes:
//   {type: "alt", seqs}            {type: "seq", items}
//   {type: "group", open, body}    {type: "quant", atom, suffix, min}
//   {type: "char", js, word}       {type: "boundary"}      {type: "anchor", js}
// A "char" consumes exactly one code point; its `word` is true only when that code point is
// certain to be a word character.

class PatternParser {
  constructor(source) {
    this.source = source;
    this.chars = Array.from(source); // code points, so an astral literal stays one atom
    this.pos = 0;
  }

  fail(why) {
    throw new SyntaxError(`cannot translate Python pattern (${why}): ${this.source}`);
  }

  peek() {
    return this.chars[this.pos];
  }

  next() {
    return this.chars[this.pos++];
  }

  lookingAt(text) {
    return this.chars.slice(this.pos, this.pos + text.length).join("") === text;
  }

  parseAlternation() {
    const seqs = [this.parseSequence()];
    while (this.peek() === "|") {
      this.pos++;
      seqs.push(this.parseSequence());
    }
    return { type: "alt", seqs };
  }

  parseSequence() {
    const items = [];
    while (this.pos < this.chars.length && this.peek() !== "|" && this.peek() !== ")") {
      let item = this.parseAtom();
      const quantifier = this.parseQuantifier();
      if (quantifier) {
        const plainGroup = item.type === "group" && (item.open === "(" || item.open === "(?:");
        const repeatable = item.type === "char" || plainGroup;
        if (!repeatable) this.fail("quantified assertion");
        item = { type: "quant", atom: item, ...quantifier };
      }
      items.push(item);
    }
    return { type: "seq", items };
  }

  parseQuantifier() {
    const ch = this.peek();
    let suffix;
    let min;
    if (ch === "*" || ch === "+" || ch === "?") {
      suffix = ch;
      min = ch === "+" ? 1 : 0;
      this.pos++;
    } else if (ch === "{") {
      // Python also reads "{,n}" as a repeat and a malformed brace as a literal; neither
      // appears in the rules, so both are refused rather than guessed at.
      const ahead = this.chars.slice(this.pos, this.pos + 24).join("");
      const found = /^\{(\d+)(?:,(\d*))?\}/.exec(ahead);
      if (!found) this.fail("brace that is not a {m,n} repeat");
      suffix = found[0];
      min = Number(found[1]);
      this.pos += found[0].length;
    } else {
      return null;
    }
    if (this.peek() === "?") {
      suffix += "?";
      this.pos++;
    } else if (this.peek() === "+") {
      this.fail("possessive quantifier");
    }
    const following = this.peek();
    if (following !== undefined && "*+?{".includes(following)) this.fail("multiple repeat");
    return { suffix, min };
  }

  parseAtom() {
    const ch = this.next();
    switch (ch) {
      case "\\":
        return this.parseEscape();
      case "[":
        return this.parseClass();
      case "(":
        return this.parseGroup();
      case ".":
        return { type: "char", js: "[^\\n]", word: false };
      case "^":
        return { type: "anchor", js: "^" };
      case "$":
        return this.fail("$, which Python also matches before a final newline");
      case "*":
      case "+":
      case "?":
      case "{":
        return this.fail(`nothing to repeat before ${ch}`);
      default:
        return literal(ch);
    }
  }

  parseEscape() {
    const ch = this.next();
    switch (ch) {
      case undefined:
        return this.fail("trailing backslash");
      case "b":
        return { type: "boundary" };
      case "w":
        return { type: "char", js: WORD, word: true };
      case "W":
        return { type: "char", js: `[^${WORD_CLASS}]`, word: false };
      case "d": // every Nd character is also a word character
        return { type: "char", js: String.raw`\p{Nd}`, word: true };
      case "D":
        return { type: "char", js: String.raw`\P{Nd}`, word: false };
      case "s":
        return { type: "char", js: `[${SPACE_CLASS}]`, word: false };
      case "S":
        return { type: "char", js: `[^${SPACE_CLASS}]`, word: false };
      default:
        if (/^[A-Za-z0-9]$/.test(ch)) this.fail(`escape \\${ch}`);
        return literal(ch);
    }
  }

  parseClass() {
    let js = "[";
    if (this.peek() === "^") {
      js += "^";
      this.pos++;
    }
    // Python reads a ] straight after [ or [^ as a literal; JavaScript does not.
    if (this.peek() === "]") this.fail("] first in a class");
    for (;;) {
      const ch = this.next();
      if (ch === undefined) this.fail("unterminated class");
      if (ch === "]") break;
      if (ch === "[") this.fail("[ inside a class");
      if (ch !== "\\") {
        // A bare - keeps its meaning: a range between two characters, a literal at either end.
        js += ch === "-" ? "-" : classLiteral(ch);
        continue;
      }
      const escaped = this.next();
      if (escaped === "w") js += WORD_CLASS;
      else if (escaped === "d") js += String.raw`\p{Nd}`;
      else if (escaped === "s") js += SPACE_CLASS;
      else if (escaped === undefined || /^[A-Za-z0-9]$/.test(escaped)) {
        this.fail(`escape \\${escaped} in a class`);
      } else js += classLiteral(escaped);
    }
    // A class can hold non-word characters, so it never counts as a certain word character.
    return { type: "char", js: `${js}]`, word: false };
  }

  parseGroup() {
    let open = "(";
    if (this.peek() === "?") {
      const opener = GROUP_OPENERS.find((o) => this.lookingAt(o));
      if (!opener) this.fail("group syntax other than (?: (?= (?! (?<= (?<!");
      open += opener;
      this.pos += opener.length;
    }
    const body = this.parseAlternation();
    if (this.next() !== ")") this.fail("missing )");
    return { type: "group", open, body };
  }
}

function literal(ch) {
  return {
    type: "char",
    js: SYNTAX_CHARS.includes(ch) ? `\\${ch}` : ch,
    word: WORD_CHAR.test(ch),
  };
}

function classLiteral(ch) {
  return SYNTAX_CHARS.includes(ch) || ch === "-" ? `\\${ch}` : ch;
}

function emit(node) {
  switch (node.type) {
    case "alt":
      return node.seqs.map(emit).join("|");
    case "seq":
      return node.items
        .map((item, i) => (item.type === "boundary" ? boundary(node.items, i) : emit(item)))
        .join("");
    case "group":
      return `${node.open}${emit(node.body)})`;
    case "quant":
      return `${emit(node.atom)}${node.suffix}`;
    default:
      return node.js;
  }
}

// Python's \b at items[i], using what the neighbouring items guarantee. Only the items in the
// same sequence are consulted; a boundary at the edge of a group falls back to the full form.
function boundary(items, i) {
  const before = edgeOf(items.slice(0, i), true);
  const after = edgeOf(items.slice(i + 1), false);
  const wordBefore = before.word && !before.empty;
  const wordAfter = after.word && !after.empty;
  if (wordBefore && wordAfter) return NEVER;
  if (wordBefore) return BOUNDARY_AFTER_WORD;
  if (wordAfter) return BOUNDARY_BEFORE_WORD;
  return FULL_BOUNDARY;
}

// For a run of items: can it match without consuming anything (`empty`), and when it does
// consume, is its first character (or its last, fromEnd) always a word character (`word`)?
// Zero-width items are skipped over. Any doubt answers word: false, which only costs speed.
function edgeOf(items, fromEnd) {
  const ordered = fromEnd ? [...items].reverse() : items;
  for (const item of ordered) {
    const e = edge(item, fromEnd);
    if (!e.word) return { word: false, empty: false };
    if (!e.empty) return { word: true, empty: false };
  }
  return { word: true, empty: true };
}

function edge(node, fromEnd) {
  switch (node.type) {
    case "char":
      return { word: node.word, empty: false };
    case "boundary":
    case "anchor":
      return { word: true, empty: true };
    case "group":
      if (node.open.startsWith("(?") && node.open !== "(?:") return { word: true, empty: true };
      return edge(node.body, fromEnd);
    case "quant": {
      const inner = edge(node.atom, fromEnd);
      return { word: inner.word, empty: inner.empty || node.min === 0 };
    }
    case "alt": {
      let word = true;
      let empty = false;
      for (const seq of node.seqs) {
        const e = edge(seq, fromEnd);
        word &&= e.word;
        empty ||= e.empty;
      }
      return { word, empty };
    }
    case "seq":
      return edgeOf(node.items, fromEnd);
    default:
      throw new Error(`unknown node ${node.type}`);
  }
}

