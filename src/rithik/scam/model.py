"""The result types every part of the scam checker agrees on.

This file is the contract between the rule engine, the CLI and the evaluation script. Change a
field here and all three have to move together.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    # Deliberately not called "safe": the checker only knows the patterns it was written for,
    # so an absence of signals is not evidence that a message is genuine.
    NO_SIGNALS = "no_signals"


@dataclass(frozen=True)
class Reason:
    code: str  # stable identifier, e.g. "kyc_update"; tests and --json consumers key on it
    label: str  # one plain-English sentence shown to the user
    evidence: str  # the text or URL that triggered the rule
    weight: float  # contribution to the raw score; negative weights are reassuring signals


@dataclass(frozen=True)
class Report:
    verdict: Verdict
    score: float  # 0.0 to 1.0
    reasons: tuple[Reason, ...]
    urls: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "score": round(self.score, 3),
            "reasons": [
                {"code": r.code, "label": r.label, "evidence": r.evidence, "weight": r.weight}
                for r in self.reasons
            ],
            "urls": list(self.urls),
        }
