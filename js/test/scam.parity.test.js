// Holds the JavaScript scam engine (js/lib/scam/) to the Python reference (src/rithik/scam/).
//
// golden/scam.json is written by scripts/export_golden.py and never edited by hand. After any
// change to the Python rules, regenerate it and run `npm test`: a failure here means the port
// has drifted, not that the golden file needs touching.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { Verdict, analyze, toDict } from "../lib/scam/index.js";

const golden = JSON.parse(readFileSync(new URL("./golden/scam.json", import.meta.url), "utf8"));

// V8's Math.exp is not the C library's exp and can differ in the last bit, which is also why
// the rounded score is compared exactly and the raw one only to within this.
const SCORE_TOLERANCE = 1e-12;

describe("golden parity with the Python engine", () => {
  // The edge-case list grows whenever a new Python/JS difference is found, so only the corpus
  // size is pinned; a golden file that lost its edge cases entirely would still fail.
  test("the golden file holds the 160 corpus messages and the edge cases", () => {
    assert.equal(golden.filter((c) => /^(dev|test)-/.test(c.id)).length, 160);
    assert.ok(golden.filter((c) => c.id.startsWith("extra-")).length >= 38);
    assert.equal(new Set(golden.map((c) => c.id)).size, golden.length);
  });

  for (const { id, input, expected } of golden) {
    test(id, () => {
      const report = analyze(input);
      const field = (name) => report.reasons.map((r) => r[name]);
      const wanted = (name) => expected.reasons.map((r) => r[name]);

      assert.equal(report.verdict, expected.verdict, "verdict");
      assert.deepEqual(field("code"), wanted("code"), "reason codes, in order");
      assert.deepEqual(field("label"), wanted("label"), "labels");
      assert.deepEqual(field("evidence"), wanted("evidence"), "evidence");
      assert.deepEqual(field("weight"), wanted("weight"), "weights");
      assert.deepEqual([...report.urls], expected.urls, "urls");
      assert.ok(
        Math.abs(report.score - expected.score_exact) <= SCORE_TOLERANCE,
        `score ${report.score} is not within ${SCORE_TOLERANCE} of ${expected.score_exact}`,
      );

      const dict = toDict(report);
      assert.equal(dict.score, expected.score, "score rounded as Python rounds");
      const { score_exact: _unrounded, ...toDictOutput } = expected;
      assert.deepEqual(dict, toDictOutput);
      // JSON consumers see keys in this order, so it is part of the contract.
      assert.deepEqual(Object.keys(dict), ["verdict", "score", "reasons", "urls"]);
      for (const reason of dict.reasons) {
        assert.deepEqual(Object.keys(reason), ["code", "label", "evidence", "weight"]);
      }
    });
  }
});

describe("report shape", () => {
  test("analyze returns verdict, an unrounded score, reasons and urls", () => {
    const report = analyze(golden.find((c) => c.id === "extra-006").input);
    assert.deepEqual(Object.keys(report), ["verdict", "score", "reasons", "urls"]);
    assert.notEqual(report.score, toDict(report).score);
    for (const reason of report.reasons) {
      assert.deepEqual(Object.keys(reason), ["code", "label", "evidence", "weight"]);
    }
  });

  test("Verdict carries the Python enum values", () => {
    assert.deepEqual(
      { ...Verdict },
      { SCAM: "scam", SUSPICIOUS: "suspicious", NO_SIGNALS: "no_signals" },
    );
  });

  test("toDict returns fresh arrays the caller may change", () => {
    const text = "Pay your traffic e-challan of Rs 500 at echallan-parivahan.live/pay";
    const report = analyze(text);
    const dict = toDict(report);
    dict.reasons.pop();
    dict.urls.push("x");
    assert.deepEqual(toDict(report), toDict(analyze(text)));
  });
});

describe("toDict rounds like Python's round(x, 3)", () => {
  // Pairs from CPython 3.12. Python rounds the exact binary value, ties to even, so 0.0625
  // goes down while Math.round and toFixed take it up; 0.1235 is stored just below the tie.
  const pairs = [
    [0.0625, 0.062],
    [0.1875, 0.188],
    [0.3125, 0.312],
    [0.5625, 0.562],
    [0.8125, 0.812],
    [0.9375, 0.938],
    [0.0005, 0.001],
    [0.0045, 0.004],
    [0.1235, 0.123],
    [1.0005, 1.0],
    [0.9995, 1.0],
    [0.6321205588285577, 0.632],
    [0.0, 0.0],
  ];
  for (const [score, rounded] of pairs) {
    test(`${score} -> ${rounded}`, () => {
      const report = { verdict: Verdict.NO_SIGNALS, score, reasons: [], urls: [] };
      assert.equal(toDict(report).score, rounded);
    });
  }
});

describe("analyze rejects anything but a string, as Python raises TypeError", () => {
  const values = {
    undefined: undefined,
    null: null,
    number: 42,
    bigint: 42n,
    boolean: true,
    symbol: Symbol("otp"),
    object: { text: "share your otp" },
    array: ["share your otp"],
    Buffer: Buffer.from("share your otp"),
    "String object": new String("share your otp"),
    function: () => "share your otp",
  };
  for (const [name, value] of Object.entries(values)) {
    test(name, () => {
      assert.throws(() => analyze(value), TypeError);
    });
  }

  test("an empty or blank string is not an error", () => {
    for (const text of ["", "   \n\t  ", "\u{200b}\u{ad}"]) {
      assert.deepEqual(toDict(analyze(text)), {
        verdict: Verdict.NO_SIGNALS,
        score: 0,
        reasons: [],
        urls: [],
      });
    }
  });
});

describe("a 1 MB message finishes well under a second", () => {
  // At least 1,000,000 UTF-16 units, cut only at a whole repeat so no surrogate pair is split.
  const build = (unit) => unit.repeat(Math.ceil(1_000_000 / unit.length));
  const inputs = {
    // Every golden message, so every rule, the link parser and the 50-link cap all do work.
    "golden messages": build(`${golden.map((c) => c.input).join(" ")} `),
    // Surrogate pairs slow V8's Unicode regexes down; this is the slowest shape measured.
    "emoji between OTP words": build("😀 otp share 🙏 "),
    // A long run of labels is where the link regex could backtrack.
    "dotted labels": build("a."),
  };
  for (const [name, text] of Object.entries(inputs)) {
    test(name, (t) => {
      assert.ok(text.length >= 1_000_000);
      const started = performance.now();
      const report = analyze(text);
      const elapsed = performance.now() - started;
      t.diagnostic(`${name}: ${elapsed.toFixed(0)} ms for ${text.length} UTF-16 units`);
      assert.ok(elapsed < 1000, `took ${elapsed.toFixed(0)} ms`);
      assert.ok(Object.values(Verdict).includes(report.verdict));
    });
  }

  test("the golden messages together are a scam with the link list capped at 50", () => {
    const report = analyze(inputs["golden messages"]);
    assert.equal(report.verdict, Verdict.SCAM);
    assert.equal(report.urls.length, 50);
  });
});
