// Python-compatible number formatting and json.dumps(obj, indent=...), byte for byte.
//
// Every JavaScript number is written as a Python float ("1.0", not "1"), because every number
// the CLI prints (scores and weights) is a float in the Python reference. Pass a BigInt to get
// Python int formatting.

const ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f",
};

/** json.dumps(s) with ensure_ascii=True: everything outside ' '..'~' becomes \uxxxx. */
export function encodeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const code = s.charCodeAt(i);
    if (ESCAPES[ch] !== undefined) out += ESCAPES[ch];
    else if (code < 0x20 || code > 0x7e) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  // Iterating UTF-16 units gives the surrogate pair Python writes for an astral character.
  return out + '"';
}

// The shortest round-trip digits of a positive finite number, and the position of the decimal
// point relative to them (value = 0.DIGITS x 10**decpt), taken from String(x), which ECMAScript
// defines with the same shortest-and-closest rule as Python's repr().
function shortestDigits(abs) {
  const str = String(abs);
  const e = str.indexOf("e");
  const mantissa = e >= 0 ? str.slice(0, e) : str;
  const exponent = e >= 0 ? Number(str.slice(e + 1)) : 0;
  const dot = mantissa.indexOf(".");
  const intPart = dot >= 0 ? mantissa.slice(0, dot) : mantissa;
  let digits = intPart + (dot >= 0 ? mantissa.slice(dot + 1) : "");
  let decpt = intPart.length + exponent;
  const leading = digits.length - digits.replace(/^0+/, "").length;
  digits = digits.slice(leading).replace(/0+$/, "");
  decpt -= leading;
  return { digits, decpt };
}

/** repr(float(x)): "1.0", "0.5", "1e-05", "1e+16", "-0.0", "nan", "inf". */
export function floatRepr(x) {
  if (Number.isNaN(x)) return "nan";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  const sign = x < 0 || Object.is(x, -0) ? "-" : "";
  if (x === 0) return `${sign}0.0`;
  const { digits, decpt } = shortestDigits(Math.abs(x));
  // CPython's format_float_short, mode 'r': exponent form outside 1e-4 <= |x| < 1e16.
  if (decpt <= -4 || decpt > 16) {
    const exp = decpt - 1;
    const mantissa = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const expDigits = String(Math.abs(exp)).padStart(2, "0");
    return `${sign}${mantissa}e${exp < 0 ? "-" : "+"}${expDigits}`;
  }
  if (decpt <= 0) return `${sign}0.${"0".repeat(-decpt)}${digits}`;
  if (decpt >= digits.length) return `${sign}${digits}${"0".repeat(decpt - digits.length)}.0`;
  return `${sign}${digits.slice(0, decpt)}.${digits.slice(decpt)}`;
}

// x = mantissa * 2**exponent, exactly.
function binaryParts(abs) {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, abs);
  const hi = view.getUint32(0);
  const lo = view.getUint32(4);
  const biased = (hi >>> 20) & 0x7ff;
  let mantissa = (BigInt(hi & 0xfffff) << 32n) | BigInt(lo);
  if (biased === 0) return { mantissa, exponent: -1074 };
  mantissa |= 1n << 52n;
  return { mantissa, exponent: biased - 1075 };
}

/**
 * format(x, f".{places}f"). Python rounds the exact binary value half to even; toFixed()
 * rounds exact ties up, so (0.125).toFixed(2) is "0.13" where Python prints "0.12".
 */
export function formatFixed(x, places) {
  if (Number.isNaN(x)) return "nan";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  const sign = x < 0 || Object.is(x, -0) ? "-" : "";
  const { mantissa, exponent } = binaryParts(Math.abs(x));
  let numerator = mantissa * 10n ** BigInt(places);
  let denominator = 1n;
  if (exponent >= 0) numerator <<= BigInt(exponent);
  else denominator <<= BigInt(-exponent);
  let quotient = numerator / denominator;
  const twiceRemainder = 2n * (numerator % denominator);
  if (twiceRemainder > denominator || (twiceRemainder === denominator && quotient % 2n === 1n)) {
    quotient += 1n;
  }
  const digits = quotient.toString().padStart(places + 1, "0");
  if (places === 0) return sign + digits;
  return `${sign}${digits.slice(0, -places)}.${digits.slice(-places)}`;
}

function encodeNumber(x) {
  // json.dumps writes the non-finite floats as JavaScript literals (allow_nan=True).
  if (Number.isNaN(x)) return "NaN";
  if (x === Infinity) return "Infinity";
  if (x === -Infinity) return "-Infinity";
  return floatRepr(x);
}

/**
 * json.dumps(value, indent=indent): ensure_ascii, insertion key order, and with an indent the
 * separators (",", ": ") and no trailing spaces. indent=null gives the one-line form.
 * Objects may be plain objects or Maps.
 */
export function dumps(value, indent = null) {
  const unit = indent === null ? null : typeof indent === "string" ? indent : " ".repeat(indent);
  const itemSep = unit === null ? ", " : ",";

  const encode = (item, level) => {
    if (item === null) return "null";
    if (item === true) return "true";
    if (item === false) return "false";
    if (typeof item === "string") return encodeString(item);
    if (typeof item === "number") return encodeNumber(item);
    if (typeof item === "bigint") return item.toString();
    if (typeof item !== "object") {
      throw new TypeError(`Object of type ${typeof item} is not JSON serializable`);
    }
    const isArray = Array.isArray(item);
    // A plain object lists integer-like keys ("9") first whatever the insertion order; a Map
    // keeps Python's dict order for those too.
    const pairs = item instanceof Map ? [...item] : Object.entries(item);
    const entries = isArray
      ? item.map((v) => encode(v, level + 1))
      : pairs.map(([k, v]) => `${encodeString(String(k))}: ${encode(v, level + 1)}`);
    const [open, close] = isArray ? ["[", "]"] : ["{", "}"];
    if (entries.length === 0) return open + close;
    if (unit === null) return open + entries.join(itemSep) + close;
    const inner = "\n" + unit.repeat(level + 1);
    return open + inner + entries.join(itemSep + inner) + "\n" + unit.repeat(level) + close;
  };
  return encode(value, 0);
}
