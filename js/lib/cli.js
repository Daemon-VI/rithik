// Command-line entry point: `rithik`, `rithik card` and `rithik scam`. The port of
// src/rithik/cli.py; its output must stay byte-identical to that file's (js/test/golden/).

import { fstatSync } from "node:fs";
import { isatty } from "node:tty";
import { cardData, renderCard } from "./card.js";
import { dumps, formatFixed } from "./pyjson.js";
import { PY_DIGIT, PY_WORD, PY_SPACE_CLASS, cpLength, cpSlice, pyRstrip, pySplit, pyStrip, wrap } from "./pytext.js";
import { Interrupted, defaultPreferredEncoding, readLimited } from "./stdin.js";
import * as term from "./term.js";
import { VERSION } from "./version.js";

const WIDTH = 78;

export const USAGE_HINT =
  "Give rithik scam a message to check, in quotes:\n" +
  '  rithik scam "<message or link>"\n' +
  "or pipe it in:\n" +
  "  <command> | rithik scam -\n";

const EMPTY_MESSAGE = "rithik: the message was empty, so there is nothing to check.\n";
const TRUNCATED = "rithik: input is over 1 MiB; only the first 1 MiB was checked.\n";

const HEADLINES = {
  scam: ["LIKELY SCAM", term.RED],
  suspicious: ["SUSPICIOUS", term.YELLOW],
  no_signals: ["NO KNOWN SCAM SIGNALS", term.GREEN],
};

const WARNING_ADVICE = [
  "Do not click the links, call the numbers or install anything the message asks for.",
  "Never share an OTP, UPI PIN or card details, and remember that you never need your UPI " +
    "PIN to receive money.",
  "Verify through your bank's official app, or the number printed on your card, not a " +
    "number from the message.",
  "If money was taken, call 1930 at once or report it at https://cybercrime.gov.in",
  "Report the fraud SMS or call through Chakshu at https://sancharsaathi.gov.in",
];

const NO_SIGNALS_ADVICE =
  "None of the scam patterns this checker knows matched. That is not a guarantee that the " +
  "message is genuine: new scams appear all the time. Before you pay, or share an OTP or PIN, " +
  "verify through the official app or website.";

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
// Python: (?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>"']+
// Its \b and \s are Unicode-aware and its case-insensitive [a-z] also takes U+0130, U+0131,
// U+017F and U+212A, so all three are spelled out rather than left to JavaScript's flags.
const CI_LETTER = "[A-Za-z\\u0130\\u0131\\u017f\\u212a]";
const LINK_IN_TEXT = new RegExp(
  `(?<!${PY_WORD})(?:${CI_LETTER}(?:${CI_LETTER}|[0-9+.-])*:\\/\\/|[wW]{3}\\.)[^${PY_SPACE_CLASS}<>"']+`,
  "gu",
);
const EVIDENCE_LIMIT = 120;

// ---------------------------------------------------------------------------------------------
// Rendering

/** The plain-text (or coloured) report, as cli.py's render_report(). */
export function renderReport(report, color = false) {
  const verdict = String(report.verdict);
  if (!Object.hasOwn(HEADLINES, verdict)) throw new RangeError(`'${verdict}' is not a valid Verdict`);
  const [title, code] = HEADLINES[verdict];
  const lines = [`${term.paint(title, code, color)}  (score ${formatFixed(report.score, 2)} of 1.00)`, ""];
  const urls = report.urls ?? [];

  if (report.reasons && report.reasons.length) {
    lines.push(term.paint("Why", term.BOLD, color));
    for (const reason of report.reasons) {
      let text = reason.label;
      if (reason.evidence) {
        // Mirrors cli.py: labels are full sentences, and the evidence follows a colon.
        if (text.endsWith(".")) text = text.slice(0, -1);
        text += `: "${shorten(defangText(reason.evidence, urls))}"`;
      }
      if (reason.weight < 0) text += " (lowers the score)";
      lines.push(...bullet(text));
    }
    lines.push("");
  }

  if (urls.length) {
    lines.push(term.paint("Links in the message", term.BOLD, color));
    for (const url of urls) lines.push(...bullet(defang(url)));
    // People copy links out of terminals, and many terminals open them on click; the
    // brackets make both deliberate.
    lines.push("  (dots shown as [.] so the links cannot be opened by accident)");
    lines.push("");
  }

  if (verdict === "no_signals") {
    lines.push(...wrap(NO_SIGNALS_ADVICE, WIDTH));
  } else {
    lines.push(term.paint("What to do", term.BOLD, color));
    for (const tip of WARNING_ADVICE) lines.push(...bullet(tip));
  }
  return lines.join("\n") + "\n";
}

/** What `--json` prints for a dict: Python's json.dumps(obj, indent=2) plus a newline. */
export function formatJson(obj) {
  return dumps(obj, 2) + "\n";
}

/** Write a link so that no terminal or chat app will turn it back into a clickable one. */
export function defang(url) {
  const match = SCHEME.exec(url);
  let scheme = "";
  let rest = url;
  if (match) {
    scheme = match[0].replace(/^http/i, "hxxp");
    rest = url.slice(match[0].length);
  }
  let hostEnd = rest.length;
  for (const mark of "/?#") {
    const index = rest.indexOf(mark);
    if (index !== -1) hostEnd = Math.min(hostEnd, index);
  }
  return scheme + rest.slice(0, hostEnd).split(".").join("[.]") + rest.slice(hostEnd);
}

export function defangText(text, urls) {
  let out = text.replace(LINK_IN_TEXT, (link) => defang(link));
  // Links without a scheme ("sbi-kyc.top/login") only show up because the engine found them.
  // (Array sort is stable, like Python's sorted(); split/join replaces every occurrence
  // without the $-patterns of String.replace. An empty URL defangs to itself.)
  const longestFirst = [...urls].sort((a, b) => cpLength(b) - cpLength(a));
  for (const url of longestFirst) {
    if (url !== "") out = out.split(url).join(defang(url));
  }
  return out;
}

function shorten(text) {
  const joined = pySplit(text).join(" ");
  if (cpLength(joined) <= EVIDENCE_LIMIT) return joined;
  return pyRstrip(cpSlice(joined, 0, EVIDENCE_LIMIT - 3)) + "...";
}

function bullet(text) {
  const lines = wrap(text, WIDTH, {
    initialIndent: "  - ",
    subsequentIndent: "    ",
    breakOnHyphens: false,
  });
  return lines.length ? lines : ["  -"];
}

// ---------------------------------------------------------------------------------------------
// Argument parsing: argparse's rules as far as they decide what runs and the exit code
// (prefix matching of long options, "--", "-h" bundles, the "A O A" limit of a nargs="*"
// positional, and actions running in order). The help and error wording is simplified.

class Exit extends Error {
  constructor(code) {
    super(`exit ${code}`);
    this.code = code;
  }
}

class ArgumentError extends Error {
  constructor(action, message) {
    super(action ? `argument ${action.names.join("/")}: ${message}` : message);
  }
}

const HELP = { kind: "help", names: ["-h", "--help"] };
const VERSION_ACTION = { kind: "version", names: ["--version"] };
const JSON_FLAG = { kind: "flag", dest: "json", names: ["--json"] };
const NO_COLOR_FLAG = { kind: "flag", dest: "no_color", names: ["--no-color"] };

const OPTION_HELP = [
  "  -h, --help  show this help message and exit",
  "  --json      print machine-readable JSON only",
  "  --no-color  plain text without colour (the NO_COLOR variable does the same)",
];

function optionMap(actions) {
  const map = new Map();
  for (const action of actions) for (const name of action.names) map.set(name, action);
  return map;
}

const CARD_PARSER = {
  prog: "rithik card",
  usage: "usage: rithik card [-h] [--json] [--no-color]\n",
  help: ["", "options:", ...OPTION_HELP, ""].join("\n"),
  options: optionMap([HELP, JSON_FLAG, NO_COLOR_FLAG]),
  positional: null,
  defaults: {},
};

const SCAM_PARSER = {
  prog: "rithik scam",
  usage: "usage: rithik scam [-h] [--json] [--no-color] [TEXT ...]\n",
  help: [
    "",
    "Check a message or link for known scam patterns. Nothing leaves this machine.",
    "",
    "positional arguments:",
    '  TEXT        the message or link; "-" (or no TEXT with piped input) reads',
    "              standard input",
    "",
    "options:",
    ...OPTION_HELP,
    "",
  ].join("\n"),
  options: optionMap([HELP, JSON_FLAG, NO_COLOR_FLAG]),
  positional: { kind: "text", nargs: "*", names: ["TEXT"] },
  defaults: { text: null },
};

const COMMANDS = { card: CARD_PARSER, scam: SCAM_PARSER };

const TOP_PARSER = {
  prog: "rithik",
  usage: "usage: rithik [-h] [--version] [--json] [--no-color] COMMAND ...\n",
  help: [
    "",
    "Rithik Krishna T's card, and an offline checker for scam messages and links.",
    "",
    "positional arguments:",
    "  COMMAND",
    "    card      print the card (what plain `rithik` does)",
    "    scam      check a message or link for scam signals, offline",
    "",
    "options:",
    OPTION_HELP[0],
    "  --version   show program's version number and exit",
    ...OPTION_HELP.slice(1),
    "",
    'Examples: rithik | rithik scam "<message or link>" | rithik card --json',
    "",
  ].join("\n"),
  options: optionMap([HELP, VERSION_ACTION, JSON_FLAG, NO_COLOR_FLAG]),
  positional: { kind: "command", nargs: "PARSER", names: ["COMMAND"] },
  defaults: { json: false, no_color: false, command: null },
};

const NEGATIVE_NUMBER = new RegExp(`^-${PY_DIGIT}+\\n?$|^-${PY_DIGIT}*\\.${PY_DIGIT}+\\n?$`, "u");

function pyRepr(s) {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  const body = s
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    .split(quote)
    .join(`\\${quote}`);
  return quote + body + quote;
}

function optionTuples(parser, arg) {
  const result = [];
  const [prefix, sep, explicit] = partition(arg, "=");
  if (arg[1] === "-") {
    for (const [name, action] of parser.options) {
      if (name.startsWith(prefix)) result.push({ action, name, sep: sep || null, explicit: sep ? explicit : null });
    }
  } else {
    const shortPrefix = cpSlice(arg, 0, 2);
    const shortExplicit = cpSlice(arg, 2);
    for (const [name, action] of parser.options) {
      if (name === shortPrefix) result.push({ action, name, sep: "", explicit: shortExplicit });
      else if (name.startsWith(prefix)) result.push({ action, name, sep: sep || null, explicit: sep ? explicit : null });
    }
  }
  return result;
}

function partition(s, sep) {
  const index = s.indexOf(sep);
  return index === -1 ? [s, "", ""] : [s.slice(0, index), sep, s.slice(index + sep.length)];
}

// argparse's _parse_optional: null means "a positional argument".
function parseOptional(parser, arg) {
  if (!arg || arg[0] !== "-") return null;
  if (parser.options.has(arg)) return [{ action: parser.options.get(arg), name: arg, sep: null, explicit: null }];
  if (cpLength(arg) === 1) return null;
  const [before, sep, explicit] = partition(arg, "=");
  if (sep && parser.options.has(before)) {
    return [{ action: parser.options.get(before), name: before, sep, explicit }];
  }
  const tuples = optionTuples(parser, arg);
  if (tuples.length) return tuples;
  if (NEGATIVE_NUMBER.test(arg)) return null;
  if (arg.includes(" ")) return null;
  return [{ action: null, name: arg, sep: null, explicit: null }];
}

function parseKnown(parser, args, ns, ctx) {
  for (const [dest, value] of Object.entries(parser.defaults)) {
    if (!Object.hasOwn(ns, dest)) ns[dest] = value;
  }

  const pattern = [];
  const optionsAt = new Map();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--") {
      pattern.push("-", ...Array(args.length - i - 1).fill("A"));
      break;
    }
    const tuples = parseOptional(parser, args[i]);
    if (tuples === null) pattern.push("A");
    else {
      optionsAt.set(i, tuples);
      pattern.push("O");
    }
  }
  const pat = pattern.join("");
  const extras = [];
  let positional = parser.positional;

  const takeAction = (action) => {
    if (action.kind === "help") {
      ctx.stdout.write(`${parser.usage}${parser.help}`);
      throw new Exit(0);
    }
    if (action.kind === "version") {
      ctx.stdout.write(`rithik ${VERSION}\n`);
      throw new Exit(0);
    }
    ns[action.dest] = true;
  };

  const consumePositionals = (start) => {
    if (!positional) return start;
    const selected = pat.slice(start);
    const match = (positional.nargs === "PARSER" ? /^(-*A[-AO]*)/ : /^(-*[A-]*)/).exec(selected);
    if (!match) return start;
    const count = match[1].length;
    // A zero-length match right before an option is dropped, leaving the positional for later.
    if (count === 0 && match[0].length < selected.length && selected[match[0].length] === "O") return start;
    const values = args.slice(start, start + count);
    const dashes = positional.nargs === "PARSER" ? pat[start] === "-" : pat.slice(start, start + count).includes("-");
    if (dashes) values.splice(values.indexOf("--"), 1);
    const action = positional;
    positional = null;
    takePositional(action, values);
    return start + count;
  };

  const takePositional = (action, values) => {
    if (action.kind === "text") {
      ns.text = values;
      return;
    }
    const [name, ...rest] = values;
    if (!Object.hasOwn(COMMANDS, name)) {
      throw new ArgumentError(action, `invalid choice: ${pyRepr(name)} (choose from card, scam)`);
    }
    ns.command = name;
    const sub = {};
    const subExtras = runParser(COMMANDS[name], rest, sub, ctx);
    Object.assign(ns, sub);
    if (subExtras.length) (ns.unrecognized ??= []).push(...subExtras);
  };

  const consumeOptional = (start) => {
    const tuples = optionsAt.get(start);
    if (tuples.length > 1) {
      const names = tuples.map((t) => t.name).join(", ");
      throw new ArgumentError(null, `ambiguous option: ${args[start]} could match ${names}`);
    }
    let { action, name, sep, explicit } = tuples[0];
    const actions = [];
    let stop;
    for (;;) {
      if (!action) {
        extras.push(args[start]);
        return start + 1;
      }
      if (explicit === null) {
        actions.push(action);
        stop = start + 1;
        break;
      }
      // Every option here takes no argument, so an explicit one is only acceptable as more
      // single-dash flags bundled after "-h".
      if (name[1] === "-" || explicit === "" || sep || explicit[0] === "-") {
        throw new ArgumentError(action, `ignored explicit argument ${pyRepr(explicit)}`);
      }
      actions.push(action);
      name = "-" + Array.from(explicit)[0];
      if (!parser.options.has(name)) {
        extras.push("-" + explicit);
        stop = start + 1;
        break;
      }
      action = parser.options.get(name);
      explicit = cpSlice(explicit, 1);
      if (!explicit) {
        sep = null;
        explicit = null;
      } else if (explicit[0] === "=") {
        sep = "=";
        explicit = explicit.slice(1);
      } else {
        sep = "";
      }
    }
    for (const a of actions) takeAction(a);
    return stop;
  };

  let start = 0;
  const maxOption = optionsAt.size ? Math.max(...optionsAt.keys()) : -1;
  while (start <= maxOption) {
    const nextOption = Math.min(...[...optionsAt.keys()].filter((i) => i >= start));
    if (start !== nextOption) {
      const end = consumePositionals(start);
      if (end > start) {
        start = end;
        continue;
      }
    }
    if (!optionsAt.has(start)) {
      extras.push(...args.slice(start, nextOption));
      start = nextOption;
    }
    start = consumeOptional(start);
  }
  const stop = consumePositionals(start);
  extras.push(...args.slice(stop));
  return extras;
}

// parse_known_args with exit_on_error: an ArgumentError prints this parser's usage and exits 2.
function runParser(parser, args, ns, ctx) {
  try {
    return parseKnown(parser, args, ns, ctx);
  } catch (err) {
    if (err instanceof ArgumentError) {
      ctx.stderr.write(`${parser.usage}${parser.prog}: error: ${err.message}\n`);
      throw new Exit(2);
    }
    throw err;
  }
}

function parseArgs(argv, ctx) {
  const ns = {};
  const extras = runParser(TOP_PARSER, argv, ns, ctx);
  extras.push(...(ns.unrecognized ?? []));
  if (extras.length) {
    ctx.stderr.write(`${TOP_PARSER.usage}rithik: error: unrecognized arguments: ${extras.join(" ")}\n`);
    throw new Exit(2);
  }
  return ns;
}

// ---------------------------------------------------------------------------------------------
// Running

// Windows' C runtime reports every character device as a terminal, NUL included, so Python
// treats `rithik scam < NUL` as interactive and prints the usage hint. Node only calls a real
// console a TTY, so the character-device test is repeated here.
// (process.stdin is only touched when a message is read: creating it opens the handle.)
function defaultIsTTY(name) {
  if (name !== "stdin") return Boolean(process[name] && process[name].isTTY);
  if (isatty(0)) return true;
  if (process.platform !== "win32") return false;
  try {
    return fstatSync(0).isCharacterDevice();
  } catch {
    return false;
  }
}

function resolveIo(io) {
  const usingProcess = io.stdout === undefined && io.stderr === undefined;
  const platform = io.platform ?? process.platform;
  const ctx = {
    stdout: io.stdout ?? term.processWriter(process.stdout, platform),
    stderr: io.stderr ?? term.processWriter(process.stderr, platform),
    get stdin() {
      return io.stdin === undefined ? process.stdin : io.stdin;
    },
    // Python's console reader, which ends input at a Ctrl+Z line, only applies to a real
    // Windows console on the process's own stdin.
    windowsConsole: () => io.stdin === undefined && platform === "win32" && isatty(0),
    env: io.env ?? process.env,
    platform,
    isTTY: io.isTTY ?? ((name) => (io[name] === undefined ? defaultIsTTY(name) : Boolean(io[name]?.isTTY))),
    onInterrupt:
      io.onInterrupt ??
      ((callback) => {
        process.once("SIGINT", callback);
        return () => process.removeListener("SIGINT", callback);
      }),
    preferredEncoding: io.preferredEncoding ?? (() => defaultPreferredEncoding()),
  };
  if (usingProcess) term.ignoreBrokenPipes(process);
  return ctx;
}

async function loadEngine() {
  const engine = await import("./scam/index.js");
  return { analyze: engine.analyze, toDict: engine.toDict };
}

/**
 * Run the CLI and resolve to its exit code.
 *
 * io (every field optional; the defaults are the real process):
 *   stdout, stderr     objects with write(text)
 *   stdin              a Readable / async iterable of Buffers or strings, a Buffer, a string,
 *                      or null for "no standard input"
 *   env                environment variables (NO_COLOR, TERM)
 *   isTTY(name)        whether "stdin" or "stdout" is a terminal
 *   platform           process.platform
 *   onInterrupt(cb)    call cb on Ctrl+C; returns a function that stops listening
 *   preferredEncoding  () => the locale encoding for input that is not UTF-8
 * engine: { analyze, toDict }, for tests; by default js/lib/scam/index.js, loaded on first use.
 */
export async function main(argv, io = {}, engine = null) {
  const ctx = resolveIo(io);
  const args = argv === undefined || argv === null ? process.argv.slice(2) : [...argv];
  let ns;
  try {
    ns = parseArgs(args, ctx);
  } catch (err) {
    // argparse exits on --version, --help and bad usage; a caller of main() wants a code.
    if (err instanceof Exit) return err.code;
    throw err;
  }
  try {
    if (ns.command === "scam") return await runScam(ns, ctx, engine);
    return runCard(ns, ctx);
  } catch (err) {
    if (err && err.code === "EPIPE") return 0;
    // Only the wait for standard input can be interrupted: a synchronous analysis cannot
    // receive the signal until it finishes, and a Ctrl+C there ends the process as Node's
    // default handler does.
    if (err instanceof Interrupted) return 130;
    throw err;
  }
}

function colorFor(ns, ctx) {
  return term.colorEnabled({
    disabled: ns.no_color,
    env: ctx.env,
    isTTY: () => ctx.isTTY("stdout"),
    platform: ctx.platform,
  });
}

function runCard(ns, ctx) {
  if (ns.json) ctx.stdout.write(formatJson(cardData()));
  else ctx.stdout.write(renderCard(colorFor(ns, ctx)));
  return 0;
}

async function runScam(ns, ctx, engine) {
  const words = ns.text ?? [];
  let text;
  if ((words.length === 1 && words[0] === "-") || (words.length === 0 && !stdinIsInteractive(ctx))) {
    text = await readStdin(ctx);
  } else if (words.length) {
    text = words.join(" ");
  } else {
    ctx.stderr.write(USAGE_HINT);
    return 2;
  }

  if (pyStrip(text) === "") {
    ctx.stderr.write(EMPTY_MESSAGE);
    ctx.stderr.write(USAGE_HINT);
    return 2;
  }

  const { analyze, toDict } = engine ?? (await loadEngine());
  const report = await analyze(text);
  if (ns.json) {
    // ASCII-escaped JSON survives any console code page without a lossy "?" substitution.
    ctx.stdout.write(formatJson(toDict(report)));
  } else {
    ctx.stdout.write(renderReport(report, colorFor(ns, ctx)));
  }
  return 0;
}

function stdinIsInteractive(ctx) {
  if (ctx.stdin === null) return true;
  try {
    return Boolean(ctx.isTTY("stdin"));
  } catch {
    // Unknown means "do not block waiting for input that may never come".
    return true;
  }
}

async function readStdin(ctx) {
  if (ctx.stdin === null) return "";
  const { text, truncated } = await readLimited(ctx.stdin, {
    onInterrupt: ctx.onInterrupt,
    preferredEncoding: ctx.preferredEncoding,
    windowsConsole: ctx.windowsConsole(),
  });
  if (truncated) ctx.stderr.write(TRUNCATED);
  return text;
}
