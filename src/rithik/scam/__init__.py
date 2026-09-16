"""Offline heuristics for Indian scam messages and links.

The public surface is `analyze(text) -> Report`; everything else in this package is internal.
"""

from rithik.scam.engine import analyze
from rithik.scam.model import Reason, Report, Verdict

__all__ = ["Reason", "Report", "Verdict", "analyze"]
