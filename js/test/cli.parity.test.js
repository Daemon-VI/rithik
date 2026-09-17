// The JavaScript CLI against the Python reference: js/test/golden/ is written by
// scripts/export_golden.py from the Python package, so equality here means `npx rithik` prints
// what `rithik` prints. Tests that need the scam engine (js/lib/scam/) skip until it exists.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import { USAGE_HINT, formatJson, main, renderReport } from "../lib/cli.js";
import { cardData, renderCard } from "../lib/card.js";
import { dumps, floatRepr, formatFixed } from "../lib/pyjson.js";
import { wrap } from "../lib/pytext.js";
import { STDIN_LIMIT, decode, readLimited } from "../lib/stdin.js";
import { VERSION } from "../lib/version.js";

const ROOT = new URL("../../", import.meta.url);
const BIN = fileURLToPath(new URL("js/bin/rithik.js", ROOT));
const engineExists = existsSync(new URL("js/lib/scam/index.js", ROOT));
const cliCases = JSON.parse(readFileSync(new URL("golden/cli.json", import.meta.url), "utf8"));
const scamCases = JSON.parse(readFileSync(new URL("golden/scam.json", import.meta.url), "utf8"));

const EMPTY_MESSAGE = "rithik: the message was empty, so there is nothing to check.\n";
const TRUNCATED = "rithik: input is over 1 MiB; only the first 1 MiB was checked.\n";
const GOLDEN_CARD = cliCases.find((c) => c.argv.length === 0).stdout;
const hasEscape = (s) => s.includes("\x1b");
const stripEscapes = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
const label = (argv) => {
  const text = `rithik ${argv.map((a) => (a.includes(" ") ? JSON.stringify(a) : a)).join(" ")}`;
  return text.length > 70 ? `${text.slice(0, 67)}...` : text;
};

async function run(argv, options = {}, engine = undefined) {
  const { stdin = null, env = {}, tty = {}, platform = "linux", ...rest } = options;
  const out = { stdout: "", stderr: "" };
  const io = {
    stdout: { write: (s) => void (out.stdout += s) },
    stderr: { write: (s) => void (out.stderr += s) },
    stdin,
    env,
    platform,
    isTTY: (name) => Boolean(tty[name]),
    ...rest,
  };
  const code = await main(argv, io, engine);
  return { code, ...out };
}

/** An engine that returns a golden report and records what it was asked to analyse. */
function stubEngine(expected, seen = []) {
  const { score_exact: scoreExact, ...dict } = expected;
  return {
    analyze(text) {
      seen.push(text);
      return { verdict: dict.verdict, score: scoreExact, reasons: dict.reasons, urls: dict.urls };
    },
    toDict: () => dict,
  };
}

const entryFor = (input) => scamCases.find((entry) => entry.input === input);
// A scam report with a link, and an input with astral characters, from EXTRA_CASES.
const PARCEL = entryFor("Your parcel is held at customs. Pay Rs 49 at bit.ly/3xYzAbc to release it");
const FANCY = scamCases.find((entry) => /[\u{10000}-\u{10FFFF}]/u.test(entry.input));
assert.ok(PARCEL && PARCEL.expected.urls.length && PARCEL.expected.reasons.length, "PARCEL fixture");
assert.ok(FANCY, "FANCY fixture");

describe("golden output from the Python CLI", () => {
  for (const c of cliCases.filter((c) => !c.argv.includes("scam"))) {
    test(label(c.argv), async () => {
      const result = await run(c.argv);
      assert.equal(result.stdout, c.stdout);
      assert.equal(result.code, c.exit);
      assert.equal(result.stderr, "");
    });
  }

  for (const c of cliCases.filter((c) => c.argv.includes("scam"))) {
    const message = c.argv.slice(1).filter((a) => !a.startsWith("--")).join(" ");
    const entry = entryFor(message);

    test(`${label(c.argv)} (golden report, stub engine)`, async () => {
      if (!entry) {
        // scam.json has no report for this input, so only the argument handling can be
        // checked without the engine: the words must reach analyze() joined by spaces.
        const seen = [];
        const result = await run(c.argv, {}, stubEngine(scamCases[0].expected, seen));
        assert.deepEqual(seen, [message]);
        assert.equal(result.code, c.exit);
        return;
      }
      const seen = [];
      const result = await run(c.argv, {}, stubEngine(entry.expected, seen));
      assert.deepEqual(seen, [message]);
      assert.equal(result.stdout, c.stdout);
      assert.equal(result.code, c.exit);
      assert.equal(result.stderr, "");

      // The same text straight from the exported renderers.
      const { score_exact: scoreExact, ...dict } = entry.expected;
      const direct = c.argv.includes("--json")
        ? formatJson(dict)
        : renderReport({ ...dict, score: scoreExact }, false);
      assert.equal(direct, c.stdout);
    });

    test(`${label(c.argv)} (real engine)`, { skip: !engineExists }, async () => {
      const result = await run(c.argv);
      assert.equal(result.stdout, c.stdout);
      assert.equal(result.code, c.exit);
    });
  }

  test("every scam.json report renders without error, with and without colour", () => {
    for (const { expected } of scamCases) {
      const { score_exact: scoreExact, ...dict } = expected;
      const report = { ...dict, score: scoreExact };
      const plain = renderReport(report, false);
      assert.ok(plain.endsWith("\n"));
      assert.equal(stripEscapes(renderReport(report, true)), plain);
      assert.ok(!hasEscape(formatJson(dict)));
    }
  });
});

describe("the rithik executable", () => {
  // Python's stdout turns "\n" into "\r\n" on Windows, and the port does the same.
  const native = (s) => (process.platform === "win32" ? s.replace(/\n/g, "\r\n") : s);
  const spawn = (args, input) =>
    spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", input, timeout: 30_000 });

  test("starts with a shebang and has LF line endings", () => {
    const source = readFileSync(BIN, "utf8");
    assert.match(source, /^#!\/usr\/bin\/env node\r?\n/);
    // A CR after "node" breaks direct execution on POSIX. A Windows checkout with
    // core.autocrlf may legitimately hold CRLF, so the byte check runs elsewhere.
    if (process.platform !== "win32") assert.ok(!source.includes("\r"), "CRLF in js/bin/rithik.js");
  });

  test("node js/bin/rithik.js --version", () => {
    const result = spawn(["--version"]);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, native(cliCases.find((c) => c.argv[0] === "--version").stdout));
    assert.equal(result.stdout.trim(), `rithik ${VERSION}`);
    assert.equal(result.stderr, "");
  });

  test("node js/bin/rithik.js card --json", () => {
    const golden = cliCases.find((c) => c.argv.join(" ") === "card --json").stdout;
    const result = spawn(["card", "--json"]);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, native(golden));
    assert.deepEqual(JSON.parse(result.stdout), cardData());
    assert.equal(result.stderr, "");
  });

  test("node js/bin/rithik.js with a bad argument exits 2", () => {
    const result = spawn(["bogus"]);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /usage: rithik/);
  });

  test("node js/bin/rithik.js scam - with piped input", { skip: !engineExists }, () => {
    const c = cliCases.find((c) => c.argv[0] === "scam" && c.argv[1] === "--no-color" && c.argv.length === 3);
    const result = spawn(["scam", "--no-color", "-"], Buffer.from(c.argv[2], "utf8"));
    assert.equal(result.status, 0);
    assert.equal(result.stdout, native(c.stdout));
  });
});

describe("colour", () => {
  const terminal = { tty: { stdout: true } };

  test("a terminal gets colour, and the padding ignores the escape codes", async () => {
    const result = await run([], terminal);
    assert.ok(hasEscape(result.stdout));
    assert.equal(stripEscapes(result.stdout), GOLDEN_CARD);
    assert.equal(stripEscapes(renderCard(true)), renderCard(false));
  });

  test("NO_COLOR turns it off", async () => {
    const result = await run([], { ...terminal, env: { NO_COLOR: "1" } });
    assert.ok(!hasEscape(result.stdout));
    assert.equal(result.stdout, GOLDEN_CARD);
  });

  test("an empty NO_COLOR does not count (no-color.org)", async () => {
    const result = await run(["card"], { ...terminal, env: { NO_COLOR: "" } });
    assert.ok(hasEscape(result.stdout));
  });

  test("--no-color turns it off before or after the subcommand", async () => {
    for (const argv of [["--no-color"], ["card", "--no-color"], ["--no-color", "card"], ["--no"]]) {
      const result = await run(argv, terminal);
      assert.equal(result.stdout, GOLDEN_CARD, label(argv));
    }
  });

  test("TERM=dumb turns it off, except on Windows where Python ignores TERM", async () => {
    const dumb = await run([], { ...terminal, env: { TERM: "dumb" }, platform: "linux" });
    assert.ok(!hasEscape(dumb.stdout));
    const windows = await run([], { ...terminal, env: { TERM: "dumb" }, platform: "win32" });
    assert.ok(hasEscape(windows.stdout));
  });

  test("output that is not a terminal is plain", async () => {
    const result = await run([], { tty: { stdout: false, stdin: true } });
    assert.ok(!hasEscape(result.stdout));
  });

  test("the scam report follows the same rules, and --json is never coloured", async () => {
    const engine = () => stubEngine(PARCEL.expected);
    const coloured = await run(["scam", "a message"], terminal, engine());
    assert.ok(hasEscape(coloured.stdout));
    const plain = await run(["scam", "a message"], {}, engine());
    assert.equal(stripEscapes(coloured.stdout), plain.stdout);
    for (const options of [{ ...terminal, env: { NO_COLOR: "x" } }]) {
      assert.equal((await run(["scam", "a message"], options, engine())).stdout, plain.stdout);
    }
    assert.equal((await run(["scam", "--no-color", "a message"], terminal, engine())).stdout, plain.stdout);
    assert.ok(!hasEscape((await run(["scam", "--json", "a message"], terminal, engine())).stdout));
    assert.ok(!hasEscape((await run(["card", "--json"], terminal)).stdout));
  });
});

describe("standard input", () => {
  const readsStdin = async (argv, options) => {
    const seen = [];
    const result = await run(argv, options, stubEngine(PARCEL.expected, seen));
    return { ...result, seen };
  };

  test("'-' reads UTF-8 from a stream, even when a character is split across chunks", async () => {
    const bytes = Buffer.from(FANCY.input, "utf8");
    const cut = bytes.indexOf(0xf0) + 2; // inside a four-byte character
    const stdin = Readable.from([bytes.subarray(0, cut), bytes.subarray(cut)]);
    const seen = [];
    const result = await run(["scam", "-"], { stdin }, stubEngine(FANCY.expected, seen));
    assert.deepEqual(seen, [FANCY.input]);
    const { score_exact: scoreExact, ...dict } = FANCY.expected;
    assert.equal(result.stdout, renderReport({ ...dict, score: scoreExact }));
    assert.equal(result.code, 0);
  });

  test("no TEXT and piped input reads standard input", async () => {
    const result = await readsStdin(["scam", "--json"], { stdin: Buffer.from("pay at bit.ly/x1\r\n") });
    assert.deepEqual(result.seen, ["pay at bit.ly/x1\r\n"]);
    const { score_exact: _, ...dict } = PARCEL.expected;
    assert.equal(result.stdout, formatJson(dict));
  });

  test("no TEXT at a terminal prints the usage hint and exits 2", async () => {
    const result = await readsStdin(["scam"], { stdin: Buffer.from("never read"), tty: { stdin: true } });
    assert.equal(result.code, 2);
    assert.equal(result.stderr, USAGE_HINT);
    assert.equal(result.stdout, "");
    assert.deepEqual(result.seen, []);
  });

  test("'-' reads standard input even from a terminal", async () => {
    const result = await readsStdin(["scam", "-"], { stdin: "typed text", tty: { stdin: true } });
    assert.deepEqual(result.seen, ["typed text"]);
  });

  test("no standard input at all counts as interactive, and '-' then reads nothing", async () => {
    const bare = await readsStdin(["scam"], { stdin: null });
    assert.equal(bare.code, 2);
    assert.equal(bare.stderr, USAGE_HINT);
    const dash = await readsStdin(["scam", "-"], { stdin: null });
    assert.equal(dash.code, 2);
    assert.equal(dash.stderr, EMPTY_MESSAGE + USAGE_HINT);
  });

  test("an empty or blank message is an error with exit code 2", async () => {
    const blankInputs = [
      [["scam", "-"], { stdin: Buffer.from(" \n\t\u3000 ") }],
      [["scam"], { stdin: Readable.from([]) }],
      [["scam", ""], {}],
      [["scam", " ", "\u2003"], {}],
    ];
    for (const [argv, options] of blankInputs) {
      const result = await readsStdin(argv, options);
      assert.equal(result.code, 2, label(argv));
      assert.equal(result.stderr, EMPTY_MESSAGE + USAGE_HINT);
      assert.equal(result.stdout, "");
      assert.deepEqual(result.seen, []);
    }
    // A zero-width space is not whitespace to Python, so it is a message.
    assert.equal((await readsStdin(["scam", "\u200b"], {})).code, 0);
  });

  test("more than 1 MiB is cut to exactly 1 MiB, with a warning", async () => {
    const over = await readsStdin(["scam", "-"], { stdin: Buffer.alloc(STDIN_LIMIT + 5, 0x61) });
    assert.equal(over.seen[0].length, STDIN_LIMIT);
    assert.equal(over.stderr, TRUNCATED);

    const exact = await readsStdin(["scam", "-"], { stdin: Buffer.alloc(STDIN_LIMIT, 0x61) });
    assert.equal(exact.seen[0].length, STDIN_LIMIT);
    assert.equal(exact.stderr, "");

    // A text stream is capped in code points, as Python's text read(n) is.
    const astral = "\u{1d40a}".repeat(STDIN_LIMIT + 1);
    const text = await readsStdin(["scam", "-"], { stdin: Readable.from([astral], { objectMode: true }) });
    assert.equal(text.seen[0].length, 2 * STDIN_LIMIT);
    assert.equal(text.stderr, TRUNCATED);
  });

  test("reading stops at the cap instead of draining an endless stream", async () => {
    let chunks = 0;
    const endless = new Readable({
      read() {
        chunks += 1;
        this.push(Buffer.alloc(64 * 1024, 0x62));
      },
    });
    const result = await readsStdin(["scam", "-"], { stdin: endless });
    assert.equal(result.seen[0].length, STDIN_LIMIT);
    assert.ok(chunks < 40, `read ${chunks} chunks`);
  });

  test("Ctrl+C while waiting for input exits 130", async () => {
    let listening = 0;
    const onInterrupt = (callback) => {
      listening += 1;
      setImmediate(callback);
      return () => {
        listening -= 1;
      };
    };
    const stuck = new Readable({ read() {} });
    const result = await readsStdin(["scam", "-"], { stdin: stuck, onInterrupt });
    assert.equal(result.code, 130);
    assert.deepEqual(result.seen, []);
    assert.equal(listening, 0);
  });

  test("a Windows console line starting with Ctrl+Z ends the input, as in Python", async () => {
    const read = (chunks) =>
      readLimited(Readable.from(chunks.map((c) => Buffer.from(c))), {
        onInterrupt: () => () => {},
        preferredEncoding: () => "cp1252",
        windowsConsole: true,
      });
    assert.equal((await read(["hello\r\n", "\x1arest\r\n", "more\r\n"])).text, "hello\r\n");
    assert.equal((await read(["ab\x1a\r\n", "cd\r\n", "\x1a\r\n"])).text, "ab\x1a\r\ncd\r\n");
    assert.equal((await read(["\x1a\r\n"])).text, "");
    const piped = await readLimited(Readable.from([Buffer.from("x\n\x1ay")]), {
      onInterrupt: () => () => {},
      preferredEncoding: () => "cp1252",
    });
    assert.equal(piped.text, "x\n\x1ay");
  });

  test("decoding: BOMs, strict UTF-8, then the locale encoding (values from Python's _decode)", async () => {
    const cp1252 = () => "cp1252";
    const cases = [
      [[0x93, 0x68, 0x69, 0x94, 0x81], "\u201chi\u201d\ufffd"],
      [[0xef, 0xbb, 0xbf, 0x68, 0x69], "hi"],
      [[0xff, 0xfe, 0x68, 0x00, 0x69, 0x00], "hi"],
      [[0xfe, 0xff, 0x00, 0x68, 0x00, 0x69, 0x00], "hi\ufffd"],
      [[0xff, 0xfe, 0x3d, 0xd8, 0x68], "\ufffd"],
    ];
    for (const [bytes, text] of cases) assert.equal(decode(Uint8Array.from(bytes), cp1252), text);
    assert.equal(decode(Uint8Array.from([0xe9, 0x41]), () => "cp65001"), "\ufffdA");
    assert.equal(decode(Uint8Array.from([0xe9, 0x81]), () => "latin-1"), "\u00e9\u0081");

    const seen = [];
    const stdin = Readable.from([Buffer.from([0xff, 0xfe, 0x4f, 0x00]), Buffer.from([0x54, 0x00, 0x50, 0x00])]);
    await run(["scam"], { stdin }, stubEngine(PARCEL.expected, seen));
    assert.deepEqual(seen, ["OTP"]);
  });
});

describe("arguments", () => {
  // Exit codes checked against Python's cli.main() for each argv.
  const exitCodes = [
    [["--help"], 0], [["-h"], 0], [["--he"], 0], [["-hx"], 0], [["-hh"], 0], [["card", "--help"], 0],
    [["scam", "-h"], 0], [["scam", "--bogus", "-h"], 0], [["--bogus", "--version"], 0],
    [["-h", "bogus"], 0], [["--v"], 0], [["--version", "bogus"], 0],
    [["bogus"], 2], [[""], 2], [["-"], 2], [["SCAM"], 2], [["car"], 2], [["--bogus"], 2],
    [["card", "extra"], 2], [["card", "--version"], 2], [["scam", "--version"], 2],
    [["--json=1"], 2], [["--json="], 2], [["-h=x"], 2], [["-h-"], 2], [["--=x"], 2], [["-="], 2],
    [["bogus", "-h"], 2], [["bogus", "--version"], 2], [["card", "--", "x"], 2],
    [["scam", "hello", "--json", "world"], 2], [["scam", "--json=1", "hi"], 2],
    [["scam", "hi", "--bogus"], 2], [["--x=y z"], 2],
  ];
  for (const [argv, code] of exitCodes) {
    test(`${label(argv)} exits ${code}`, async () => {
      const result = await run(argv, {}, stubEngine(PARCEL.expected));
      assert.equal(result.code, code);
      if (code === 2) {
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /^usage: rithik.*\n.*error: /s);
      } else if (!argv.includes("--version") && !argv.includes("--v")) {
        assert.match(result.stdout, /^usage: rithik/);
        assert.equal(result.stderr, "");
      } else {
        assert.equal(result.stdout, `rithik ${VERSION}\n`);
      }
    });
  }

  // TEXT as Python's parser produces it.
  const texts = [
    [["scam", "--", "--json"], "--json"],
    [["scam", "-5"], "-5"],
    [["scam", "--no hi"], "--no hi"],
    [["--", "scam", "--", "x"], "x"],
    [["scam", "--", "--", "x"], "-- x"],
    [["scam", "-", "x"], "- x"],
    [["scam", "-\u0663"], "-\u0663"],
    [["--no", "scam", "--js", "a", "b"], "a b"],
  ];
  for (const [argv, message] of texts) {
    test(`${label(argv)} checks ${JSON.stringify(message)}`, async () => {
      const seen = [];
      const result = await run(argv, {}, stubEngine(PARCEL.expected, seen));
      assert.equal(result.code, 0);
      assert.deepEqual(seen, [message]);
    });
  }

  test("-- before '-' still means standard input", async () => {
    const seen = [];
    await run(["scam", "--", "-"], { stdin: "from stdin" }, stubEngine(PARCEL.expected, seen));
    assert.deepEqual(seen, ["from stdin"]);
  });

  test("abbreviated flags work as in argparse", async () => {
    const result = await run(["--no", "scam", "--js", "x"], { tty: { stdout: true } }, stubEngine(PARCEL.expected));
    const { score_exact: _, ...dict } = PARCEL.expected;
    assert.equal(result.stdout, formatJson(dict));
  });
});

describe("Python formatting helpers (expected values from CPython 3.12)", () => {
  test("json.dumps(obj, indent=2)", () => {
    const obj = {
      a: 1.0, b: 0.5, c: -0, d: 1e-5, e: 1e16, f: 123456789012345680000,
      g: 'e\u0301\u00e9\u{1d40a}\x7f"\\n\t/', h: [], i: {}, j: [true, false, null],
      k: 0.1 + 0.2, l: 5e-324, m: 2.675,
    };
    const python =
      '{\n  "a": 1.0,\n  "b": 0.5,\n  "c": -0.0,\n  "d": 1e-05,\n  "e": 1e+16,\n' +
      '  "f": 1.2345678901234568e+20,\n  "g": "e\\u0301\\u00e9\\ud835\\udc0a\\u007f\\"\\\\n\\t/",\n' +
      '  "h": [],\n  "i": {},\n  "j": [\n    true,\n    false,\n    null\n  ],\n' +
      '  "k": 0.30000000000000004,\n  "l": 5e-324,\n  "m": 2.675\n}';
    assert.equal(dumps(obj, 2), python);
    assert.equal(dumps(new Map([["k", 1], ["9", [2n]]])), '{"k": 1.0, "9": [2]}');
  });

  test("repr(float) and format(x, '.2f')", () => {
    const reprs = [[1, "1.0"], [100, "100.0"], [0.0001, "0.0001"], [0.00001, "1e-05"],
      [9999999999999998, "9999999999999998.0"], [1e16, "1e+16"], [-2.5, "-2.5"], [1e300, "1e+300"]];
    for (const [x, text] of reprs) assert.equal(floatRepr(x), text);
    const fixed = [[0.125, "0.12"], [0.625, "0.62"], [0.375, "0.38"], [0.875, "0.88"],
      [2.675, "2.67"], [0.995, "0.99"], [-0.001, "-0.00"], [0, "0.00"]];
    for (const [x, text] of fixed) assert.equal(formatFixed(x, 2), text);
  });

  test("textwrap.wrap", () => {
    assert.deepEqual(wrap("Look, goof-ball -- use the -b option! x\u00a0y \u3000 z\tq", 10), [
      "Look,", "goof-ball", "-- use the", "-b option!", "x\u00a0y \u3000 z", "q",
    ]);
    const bulleted = wrap(
      "see https://sbi.co.in/a-b-c and a-very-long-hyphenated-word-that-goes-on-and-on-and-on-past-the-edge-of-the-line \u{1d40a}\u{1d40a}",
      78,
      { initialIndent: "  - ", subsequentIndent: "    ", breakOnHyphens: false },
    );
    assert.deepEqual(bulleted, [
      "  - see https://sbi.co.in/a-b-c and a-very-long-hyphenated-word-that-goes-on-a",
      "    nd-on-and-on-past-the-edge-of-the-line \u{1d40a}\u{1d40a}",
    ]);
  });

  test("links in evidence are defanged as Python does", () => {
    const report = {
      verdict: "suspicious",
      score: 0.3,
      reasons: [{
        code: "x",
        label: "L.",
        evidence: "Go to HTTPS://x.y.z/a.b?c.d, www.q.r or sbi-kyc.top/login; \u00e9www.no.pe \u212aTP://k.l",
        weight: 1.0,
      }],
      urls: ["sbi-kyc.top/login", "sbi-kyc.top"],
    };
    const why = renderReport(report).split("\n").slice(3, 6).join("\n");
    assert.equal(
      why,
      '  - L: "Go to hxxpS://x[.]y[.]z/a.b?c.d, www[.]q[.]r or sbi-kyc[.]top/login;\n' +
        '    \u00e9www.no.pe \u212aTP://k.l"\n',
    );
  });
});
