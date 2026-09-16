"""Score the rule engine against the labeled corpus in tests/data/.

    uv run python scripts/eval.py                          # aggregates for both splits
    uv run python scripts/eval.py --split dev --show-misses

dev.jsonl may be inspected while tuning rules. test.jsonl is held out, so this script refuses to
list its individual misses: looking at them is how a held-out set quietly becomes a training set.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rithik.scam import Verdict, analyze  # noqa: E402

DATA = ROOT / "tests" / "data"
SPLITS = ("dev", "test")
OPERATING_POINTS = {
    "strict": {Verdict.SCAM},
    "lenient": {Verdict.SCAM, Verdict.SUSPICIOUS},
}


def load(split: str) -> list[dict]:
    with open(DATA / f"{split}.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def metrics(rows: list[tuple[dict, object]], positive: set) -> dict:
    tp = fp = fn = tn = 0
    for item, report in rows:
        predicted = report.verdict in positive
        actual = item["label"] == "scam"
        if predicted and actual:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return dict(
        tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1, accuracy=accuracy
    )


def report_split(split: str, show_misses: bool) -> None:
    items = load(split)
    rows = [(item, analyze(item["text"])) for item in items]
    scams = sum(1 for i in items if i["label"] == "scam")
    print(f"== {split}: n={len(items)} (scam {scams}, ham {len(items) - scams})")
    for name, positive in OPERATING_POINTS.items():
        m = metrics(rows, positive)
        print(
            f"  {name:<8} TP={m['tp']:<3} FP={m['fp']:<3} FN={m['fn']:<3} TN={m['tn']:<3} "
            f"precision={m['precision']:.3f} recall={m['recall']:.3f} "
            f"F1={m['f1']:.3f} accuracy={m['accuracy']:.3f}"
        )
    if not show_misses:
        return
    print("  misses (lenient operating point):")
    for item, report in rows:
        predicted = report.verdict in OPERATING_POINTS["lenient"]
        if predicted != (item["label"] == "scam"):
            codes = ",".join(r.code for r in report.reasons) or "-"
            text = item["text"].replace("\n", " ")[:90]
            print(
                f"    {item['id']} label={item['label']} verdict={report.verdict.value} "
                f"score={report.score:.2f} [{codes}] {text}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=SPLITS)
    parser.add_argument("--show-misses", action="store_true")
    args = parser.parse_args(argv)
    if args.show_misses and args.split != "dev":
        print(
            "refusing: misses can only be listed for --split dev; test is held out", file=sys.stderr
        )
        return 2
    for split in (args.split,) if args.split else SPLITS:
        report_split(split, args.show_misses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
