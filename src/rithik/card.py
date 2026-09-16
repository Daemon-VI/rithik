"""The name card printed by `rithik` and `rithik card`.

Every fact here is taken from a public page: the GitHub profile README and the READMEs of the
public repos listed. Numbers are quoted as those pages state them, so the card never claims more
than a reader can check, and nothing links to a private repo.
"""

from __future__ import annotations

import copy
import textwrap

from rithik._term import BOLD, BOLD_CYAN, CYAN, DIM, paint

NAME = "Rithik Krishna T"
TAGLINE = "AI/ML, Android and security. I build complete systems and measure them."

EDUCATION = (
    {
        "degree": "B.Tech CSE (Data Science)",
        "institution": "MGIT Hyderabad",
        "graduation": "May 2027",
    },
    {
        "degree": "BS Data Science & Applications",
        "institution": "IIT Madras",
        "graduation": "May 2027",
    },
)

EXPERIENCE = ({"role": "AI/ML Intern", "organisation": "HCLTech", "period": "Sep 2025 - Jan 2026"},)

LINKS = {
    "github": "https://github.com/Daemon-VI",
    "linkedin": "https://www.linkedin.com/in/rithikkrishnat/",
    "email": "trithikkrishna@gmail.com",
}

PROJECTS = (
    {
        "name": "AegisToolkit",
        "summary": "31-tool Android security toolkit, no root required",
        "url": "https://github.com/Daemon-VI/AegisToolkit",
    },
    {
        "name": "Cascade",
        "summary": "Drag-and-drop Android automation with 154 actions",
        "url": "https://github.com/Daemon-VI/Cascade",
    },
    {
        "name": "optivision-rag",
        "summary": (
            "Visual-token compression for VLM document retrieval: 113.5x less storage per "
            "page, 86.7% of baseline nDCG@5"
        ),
        "url": "https://github.com/Daemon-VI/optivision-rag",
    },
    {
        "name": "carpool",
        "summary": "Shared-commute cost settlement for iOS, Android and web",
        "url": "https://github.com/Daemon-VI/carpool",
    },
    {
        "name": "darkwatch",
        "summary": "Dark web exposure monitor for leak sites and breaches",
        "url": "https://github.com/Daemon-VI/darkwatch",
    },
    {
        "name": "rithik",
        "summary": "This card, plus an offline Indian scam-message checker",
        "url": "https://github.com/Daemon-VI/rithik",
    },
)

HINT_COMMAND = 'rithik scam "<message or link>"'

WIDTH = 78
_INNER = WIDTH - 6  # each row is "|  " + text + "  |"
_LABEL_COL = 13
_PROJECT_COL = 17


def card_data() -> dict:
    # Deep copies, so a caller that edits the result cannot change what the next render prints.
    return {
        "name": NAME,
        "tagline": TAGLINE,
        "education": copy.deepcopy(list(EDUCATION)),
        "experience": copy.deepcopy(list(EXPERIENCE)),
        "links": dict(LINKS),
        "projects": copy.deepcopy(list(PROJECTS)),
    }


def render_card(color: bool = False) -> str:
    # Rows are (plain, styled) pairs: padding has to be measured on the plain text, because
    # escape codes take up characters but no columns.
    rows: list[tuple[str, str]] = [("", "")]
    rows.append((NAME, paint(NAME, BOLD_CYAN, color)))
    rows.extend(_wrapped(TAGLINE))
    rows.append(("", ""))

    degrees = [f"{e['degree']}, {e['institution']}" for e in EDUCATION]
    graduations = {e["graduation"] for e in EDUCATION}
    if len(graduations) == 1:
        degrees.append(f"Both graduating {graduations.pop()}")
    else:
        degrees = [f"{d} ({e['graduation']})" for d, e in zip(degrees, EDUCATION)]
    for i, line in enumerate(degrees):
        rows.extend(_two_col("Education" if i == 0 else "", line, _LABEL_COL, CYAN, color))
    for i, job in enumerate(EXPERIENCE):
        line = f"{job['role']}, {job['organisation']}, {job['period']}"
        rows.extend(_two_col("Experience" if i == 0 else "", line, _LABEL_COL, CYAN, color))
    rows.append(("", ""))

    for label, key in (("GitHub", "github"), ("LinkedIn", "linkedin"), ("Email", "email")):
        rows.extend(_two_col(label, LINKS[key], _LABEL_COL, CYAN, color))
    rows.append(("", ""))

    heading = "Public projects"
    rows.append((heading, paint(heading, BOLD, color)))
    for project in PROJECTS:
        rows.extend(_two_col(project["name"], project["summary"], _PROJECT_COL, BOLD, color))
        rows.extend(_two_col("", project["url"], _PROJECT_COL, BOLD, color))
    rows.append(("", ""))

    border = paint("+" + "-" * (WIDTH - 2) + "+", DIM, color)
    bar = paint("|", DIM, color)
    lines = [border]
    for plain, styled in rows:
        lines.append(f"{bar}  {styled}{' ' * (_INNER - len(plain))}  {bar}")
    lines.append(border)
    lines.append("Try: " + paint(HINT_COMMAND, BOLD, color))
    return "\n".join(lines) + "\n"


def _wrapped(text: str) -> list[tuple[str, str]]:
    return [(piece, piece) for piece in _wrap(text, _INNER)]


def _two_col(
    left: str, right: str, left_width: int, left_code: str, color: bool
) -> list[tuple[str, str]]:
    rows = []
    for i, piece in enumerate(_wrap(right, _INNER - left_width)):
        head = left if i == 0 else ""
        pad = " " * (left_width - len(head))
        rows.append((head + pad + piece, paint(head, left_code, color) + pad + piece))
    return rows


def _wrap(text: str, width: int) -> list[str]:
    # break_on_hyphens=False keeps names like "Drag-and-drop" and URLs in one piece.
    return textwrap.wrap(text, width, break_on_hyphens=False) or [""]
