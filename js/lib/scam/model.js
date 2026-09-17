// Mirrors src/rithik/scam/model.py: the result types every part of the scam checker agrees on.
//
// This file is the contract between the rule engine, the CLI and the golden tests. Change a
// field here and all of them have to move together, on both the Python and the JavaScript side.

import { pyRound } from "./pycompat.js";

export const Verdict = Object.freeze({
  SCAM: "scam",
  SUSPICIOUS: "suspicious",
  // Deliberately not called "safe": the checker only knows the patterns it was written for,
  // so an absence of signals is not evidence that a message is genuine.
  NO_SIGNALS: "no_signals",
});

// Python's Reason and Report are frozen dataclasses holding tuples, so these are frozen too.

/**
 * @param {string} code stable identifier, e.g. "kyc_update"; tests and --json consumers key on it
 * @param {string} label one plain-English sentence shown to the user
 * @param {string} evidence the text or URL that triggered the rule
 * @param {number} weight contribution to the raw score; negative weights are reassuring signals
 */
export function makeReason(code, label, evidence, weight) {
  return Object.freeze({ code, label, evidence, weight });
}

/**
 * @param {string} verdict one of the Verdict values
 * @param {number} score 0.0 to 1.0, unrounded
 * @param {ReadonlyArray<ReturnType<typeof makeReason>>} reasons
 * @param {ReadonlyArray<string>} urls
 */
export function makeReport(verdict, score, reasons, urls) {
  return Object.freeze({
    verdict,
    score,
    reasons: Object.freeze([...reasons]),
    urls: Object.freeze([...urls]),
  });
}

/** Report.to_dict(): the same keys in the same order, with the score rounded as Python rounds. */
export function toDict(report) {
  return {
    verdict: report.verdict,
    score: pyRound(report.score, 3),
    reasons: report.reasons.map((r) => ({
      code: r.code,
      label: r.label,
      evidence: r.evidence,
      weight: r.weight,
    })),
    urls: [...report.urls],
  };
}
