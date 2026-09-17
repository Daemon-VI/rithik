// Mirrors src/rithik/scam/__init__.py: offline heuristics for Indian scam messages and links.
//
// The public surface is analyze(text) -> report, toDict(report) and Verdict; everything else in
// this directory is internal. The Python package in src/rithik/scam/ is the reference, and
// js/test/scam.parity.test.js holds this port to its golden output.

export { analyze } from "./engine.js";
export { Verdict, toDict } from "./model.js";
