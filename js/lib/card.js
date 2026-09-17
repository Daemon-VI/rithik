// The name card printed by `rithik` and `rithik card`. The port of src/rithik/card.py: keep the
// facts here identical to that file, which says where each one comes from.

import { BOLD, BOLD_CYAN, CYAN, DIM, paint } from "./term.js";
import { cpLength, wrap } from "./pytext.js";

export const NAME = "Rithik Krishna T";
export const TAGLINE = "AI/ML, Android and security. I build complete systems and measure them.";

const EDUCATION = Object.freeze([
  Object.freeze({
    degree: "B.Tech CSE (Data Science)",
    institution: "MGIT Hyderabad",
    graduation: "May 2027",
  }),
  Object.freeze({
    degree: "BS Data Science & Applications",
    institution: "IIT Madras",
    graduation: "May 2027",
  }),
]);

const EXPERIENCE = Object.freeze([
  Object.freeze({ role: "AI/ML Intern", organisation: "HCLTech", period: "Sep 2025 - Jan 2026" }),
]);

const LINKS = Object.freeze({
  github: "https://github.com/Daemon-VI",
  linkedin: "https://www.linkedin.com/in/rithikkrishnat/",
  email: "trithikkrishna@gmail.com",
});

const PROJECTS = Object.freeze([
  Object.freeze({
    name: "AegisToolkit",
    summary: "31-tool Android security toolkit, no root required",
    url: "https://github.com/Daemon-VI/AegisToolkit",
  }),
  Object.freeze({
    name: "Cascade",
    summary: "Drag-and-drop Android automation with 154 actions",
    url: "https://github.com/Daemon-VI/Cascade",
  }),
  Object.freeze({
    name: "optivision-rag",
    summary:
      "Visual-token compression for VLM document retrieval: 113.5x less storage per " +
      "page, 86.7% of baseline nDCG@5",
    url: "https://github.com/Daemon-VI/optivision-rag",
  }),
  Object.freeze({
    name: "carpool",
    summary: "Shared-commute cost settlement for iOS, Android and web",
    url: "https://github.com/Daemon-VI/carpool",
  }),
  Object.freeze({
    name: "darkwatch",
    summary: "Dark web exposure monitor for leak sites and breaches",
    url: "https://github.com/Daemon-VI/darkwatch",
  }),
  Object.freeze({
    name: "rithik",
    summary: "This card, plus an offline Indian scam-message checker",
    url: "https://github.com/Daemon-VI/rithik",
  }),
]);

export const HINT_COMMAND = 'rithik scam "<message or link>"';

const WIDTH = 78;
const INNER = WIDTH - 6; // each row is "|  " + text + "  |"
const LABEL_COL = 13;
const PROJECT_COL = 17;

const copyAll = (items) => items.map((item) => ({ ...item }));

/** The card as plain data, in the key order `rithik card --json` prints. Always a fresh copy. */
export function cardData() {
  return {
    name: NAME,
    tagline: TAGLINE,
    education: copyAll(EDUCATION),
    experience: copyAll(EXPERIENCE),
    links: { ...LINKS },
    projects: copyAll(PROJECTS),
  };
}

export function renderCard(color = false) {
  // Rows are [plain, styled] pairs: padding has to be measured on the plain text, because
  // escape codes take up characters but no columns.
  const rows = [["", ""]];
  rows.push([NAME, paint(NAME, BOLD_CYAN, color)]);
  rows.push(...wrapped(TAGLINE));
  rows.push(["", ""]);

  let degrees = EDUCATION.map((e) => `${e.degree}, ${e.institution}`);
  const graduations = new Set(EDUCATION.map((e) => e.graduation));
  if (graduations.size === 1) {
    degrees.push(`Both graduating ${[...graduations][0]}`);
  } else {
    degrees = degrees.map((d, i) => `${d} (${EDUCATION[i].graduation})`);
  }
  degrees.forEach((line, i) => {
    rows.push(...twoCol(i === 0 ? "Education" : "", line, LABEL_COL, CYAN, color));
  });
  EXPERIENCE.forEach((job, i) => {
    const line = `${job.role}, ${job.organisation}, ${job.period}`;
    rows.push(...twoCol(i === 0 ? "Experience" : "", line, LABEL_COL, CYAN, color));
  });
  rows.push(["", ""]);

  for (const [label, key] of [
    ["GitHub", "github"],
    ["LinkedIn", "linkedin"],
    ["Email", "email"],
  ]) {
    rows.push(...twoCol(label, LINKS[key], LABEL_COL, CYAN, color));
  }
  rows.push(["", ""]);

  const heading = "Public projects";
  rows.push([heading, paint(heading, BOLD, color)]);
  for (const project of PROJECTS) {
    rows.push(...twoCol(project.name, project.summary, PROJECT_COL, BOLD, color));
    rows.push(...twoCol("", project.url, PROJECT_COL, BOLD, color));
  }
  rows.push(["", ""]);

  const border = paint("+" + "-".repeat(WIDTH - 2) + "+", DIM, color);
  const bar = paint("|", DIM, color);
  const lines = [border];
  for (const [plain, styled] of rows) {
    lines.push(`${bar}  ${styled}${spaces(INNER - cpLength(plain))}  ${bar}`);
  }
  lines.push(border);
  lines.push("Try: " + paint(HINT_COMMAND, BOLD, color));
  return lines.join("\n") + "\n";
}

// " " * n in Python is "" for a negative n; String.prototype.repeat would throw.
const spaces = (n) => " ".repeat(Math.max(0, n));

function wrapped(text) {
  return wrapLines(text, INNER).map((piece) => [piece, piece]);
}

function twoCol(left, right, leftWidth, leftCode, color) {
  return wrapLines(right, INNER - leftWidth).map((piece, i) => {
    const head = i === 0 ? left : "";
    const pad = spaces(leftWidth - cpLength(head));
    return [head + pad + piece, paint(head, leftCode, color) + pad + piece];
  });
}

function wrapLines(text, width) {
  // breakOnHyphens: false keeps names like "Drag-and-drop" and URLs in one piece.
  const lines = wrap(text, width, { breakOnHyphens: false });
  return lines.length ? lines : [""];
}
