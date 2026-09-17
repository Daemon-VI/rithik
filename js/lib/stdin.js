// Reading a message from standard input: the 1 MiB cap and the decoding rules of cli.py's
// _read_stdin() and _decode().

import { execFileSync } from "node:child_process";
import { cpLength, cpSlice } from "./pytext.js";

// Messages are a few hundred bytes. The cap only stops an accidental `rithik scam - < disk.img`
// from sitting in the regexes for minutes.
export const STDIN_LIMIT = 1 << 20;

export class Interrupted extends Error {
  constructor() {
    super("interrupted");
    this.name = "Interrupted";
  }
}

const INTERRUPT = Symbol("interrupt");

// On a Windows console, Python's reader ends the input at a line that starts with Ctrl+Z (the
// rest of that line is dropped). libuv hands the Ctrl+Z through as a byte, so the rule is
// applied here. Returns the length to keep, or -1 when the chunk has no such line.
function consoleEofAt(bytes, atLineStart) {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x1a && (i === 0 ? atLineStart : bytes[i - 1] === 0x0a)) return i;
  }
  return -1;
}

/**
 * Read at most STDIN_LIMIT + 1 units (bytes, or code points from a stream that yields strings)
 * and stop there, as Python's read(n) does. Returns the text and whether it was truncated.
 * `onInterrupt(callback)` must return a function that removes the callback; an interrupt
 * rejects with Interrupted. `windowsConsole` turns on the Ctrl+Z end-of-input rule.
 */
export async function readLimited(stdin, { onInterrupt, preferredEncoding, windowsConsole = false }) {
  if (typeof stdin === "string") return finishText(stdin);
  if (stdin instanceof Uint8Array) return finishBytes(stdin, preferredEncoding);

  const iterator = stdin[Symbol.asyncIterator]();
  let signal;
  const interrupted = new Promise((resolve) => {
    signal = () => resolve(INTERRUPT);
  });
  const dispose = onInterrupt(signal);
  const byteChunks = [];
  let byteCount = 0;
  let lastByte = -1;
  let text = null;
  let done = false;
  try {
    while (true) {
      const step = await Promise.race([iterator.next(), interrupted]);
      if (step === INTERRUPT) throw new Interrupted();
      if (step.done) {
        done = true;
        break;
      }
      const chunk = step.value;
      if (typeof chunk === "string") {
        text = (text ?? "") + chunk;
        if (text.length > STDIN_LIMIT && cpLength(text) > STDIN_LIMIT) break;
      } else {
        let bytes = chunk instanceof Uint8Array ? chunk : Buffer.from(chunk);
        const eof = windowsConsole ? consoleEofAt(bytes, byteCount === 0 || lastByte === 0x0a) : -1;
        if (eof !== -1) bytes = bytes.subarray(0, eof);
        if (bytes.length) lastByte = bytes[bytes.length - 1];
        byteChunks.push(bytes);
        byteCount += bytes.length;
        if (eof !== -1 || byteCount > STDIN_LIMIT) break;
      }
    }
  } finally {
    dispose();
    // Stop reading what is left, as Python leaves it unread; for process.stdin this also
    // releases the handle so the process can exit.
    if (!done && typeof iterator.return === "function") {
      Promise.resolve(iterator.return()).catch(() => {});
    }
  }
  if (text !== null) return finishText(text);
  return finishBytes(Buffer.concat(byteChunks, byteCount), preferredEncoding);
}

function finishText(text) {
  const truncated = cpLength(text) > STDIN_LIMIT;
  return { text: truncated ? cpSlice(text, 0, STDIN_LIMIT) : text, truncated };
}

function finishBytes(data, preferredEncoding) {
  const truncated = data.length > STDIN_LIMIT;
  const kept = truncated ? data.subarray(0, STDIN_LIMIT) : data;
  return { text: decode(kept, preferredEncoding), truncated };
}

/**
 * Bytes to text, as cli.py's _decode(): a UTF-16 BOM wins, then strict UTF-8 (a UTF-8 BOM is
 * dropped), then the locale's preferred encoding with replacement characters.
 */
export function decode(data, preferredEncoding = () => defaultPreferredEncoding()) {
  const bytes = data instanceof Uint8Array ? data : Buffer.from(data);
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return decodeUtf16(bytes, false);
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return decodeUtf16(bytes, true);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    // not UTF-8; fall through to the locale encoding
  }
  return decodeWith(normaliseEncoding(preferredEncoding()), bytes);
}

function decodeUtf16(bytes, bigEndian) {
  // Python's "utf-16" codec reads the BOM, drops it and replaces what cannot be decoded; the
  // WHATWG decoder makes the same replacements. Big-endian input is byte-swapped first so only
  // the always-available utf-16le decoder is needed.
  let input = bytes;
  if (bigEndian) {
    input = Uint8Array.from(bytes);
    for (let i = 0; i + 1 < input.length; i += 2) {
      const first = input[i];
      input[i] = input[i + 1];
      input[i + 1] = first;
    }
  }
  return new TextDecoder("utf-16le").decode(input);
}

// Python's cp1252 leaves five bytes undefined (errors="replace" makes them U+FFFD); the WHATWG
// "windows-1252" decoder maps them to C1 controls, so it cannot be used as is.
const CP1252_HIGH = [
  0x20ac, 0xfffd, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039,
  0x0152, 0xfffd, 0x017d, 0xfffd, 0xfffd, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
  0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xfffd, 0x017e, 0x0178,
];

function decodeSingleByte(bytes, high) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    const codes = Array.from(bytes.subarray(i, i + 8192), (b) => high(b));
    out += String.fromCharCode(...codes);
  }
  return out;
}

const LATIN1_NAMES = new Set(["latin1", "latin_1", "iso8859_1", "iso_8859_1", "l1", "cp819", "cp28591", "8859"]);
const ASCII_NAMES = new Set(["ascii", "us_ascii", "ansi_x3_4_1968", "646", "cp20127"]);
const UTF8_NAMES = new Set(["utf8", "utf_8", "u8", "cp65001", "utf"]);
// Windows code pages with a close WHATWG decoder. Unlike Python, these decoders do not turn
// every byte the code page leaves undefined into U+FFFD.
const WHATWG_CODEPAGES = { cp932: "shift_jis", cp936: "gbk", cp949: "euc-kr", cp950: "big5", cp874: "windows-874" };

function normaliseEncoding(name) {
  return String(name || "utf-8")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_");
}

function decodeWith(encoding, bytes) {
  if (UTF8_NAMES.has(encoding)) return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
  if (encoding === "cp1252" || encoding === "windows_1252") {
    return decodeSingleByte(bytes, (b) => (b >= 0x80 && b < 0xa0 ? CP1252_HIGH[b - 0x80] : b));
  }
  if (LATIN1_NAMES.has(encoding)) return decodeSingleByte(bytes, (b) => b);
  if (ASCII_NAMES.has(encoding)) return decodeSingleByte(bytes, (b) => (b < 0x80 ? b : 0xfffd));
  const codepage = /^(?:cp|windows_)(\d+)$/.exec(encoding);
  const label = WHATWG_CODEPAGES[`cp${codepage?.[1]}`] ?? (codepage ? `windows-${codepage[1]}` : encoding);
  try {
    return new TextDecoder(label).decode(bytes);
  } catch {
    // Python falls back to UTF-8 when it has no codec by that name.
    return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
  }
}

let cachedEncoding;

/**
 * locale.getpreferredencoding(False) of a Python 3.12 started in this environment.
 * Windows: "cp" + the ANSI code page (GetACP), read from the registry because Node has no API
 * for it; this only runs for input that is neither UTF-8 nor UTF-16.
 * Elsewhere: the codeset of LC_ALL / LC_CTYPE / LANG; the C and POSIX locales put Python in
 * UTF-8 mode. (A locale without a codeset suffix is taken as UTF-8, where glibc would say
 * ISO-8859-1.)
 */
export function defaultPreferredEncoding(env = process.env, platform = process.platform) {
  if (cachedEncoding !== undefined && env === process.env && platform === process.platform) {
    return cachedEncoding;
  }
  let encoding = "utf-8";
  if (platform === "win32") {
    encoding = "cp1252";
    try {
      const out = execFileSync(
        "reg",
        ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage", "/v", "ACP"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], windowsHide: true, timeout: 5000 },
      );
      const match = /ACP\s+REG_SZ\s+(\d+)/.exec(out);
      if (match) encoding = `cp${match[1]}`;
    } catch {
      // keep the most common ANSI code page
    }
  } else {
    const locale = env.LC_ALL || env.LC_CTYPE || env.LANG || "";
    const codeset = /\.([^@]+)/.exec(locale);
    if (locale && locale !== "C" && locale !== "POSIX" && codeset) encoding = codeset[1];
  }
  if (env === process.env && platform === process.platform) cachedEncoding = encoding;
  return encoding;
}
