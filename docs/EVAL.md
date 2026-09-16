# Evaluation

## What the numbers are measured on

`tests/data/` holds 160 synthetic messages: 80 in `dev.jsonl` and 80 in `test.jsonl`, each split
half scam and half legitimate. They were written from public fraud-advisory patterns by a
process that never saw the rules, and the legitimate half is deliberately hard: bank OTPs that
say "do not share", debit alerts, sales with urgency language, and so on.

`test.jsonl` is held out. `scripts/eval.py` refuses to list its individual misses.

## Result (v0.1.0, scored once, before any tuning)

The rule engine was written without seeing either split, and neither split has been used for
tuning yet. The test split has been scored **once**.

```
$ uv run python scripts/eval.py
== dev: n=80 (scam 40, ham 40)
  strict   TP=27  FP=1   FN=13  TN=39  precision=0.964 recall=0.675 F1=0.794 accuracy=0.825
  lenient  TP=33  FP=2   FN=7   TN=38  precision=0.943 recall=0.825 F1=0.880 accuracy=0.887
== test: n=80 (scam 40, ham 40)
  strict   TP=22  FP=1   FN=18  TN=39  precision=0.957 recall=0.550 F1=0.698 accuracy=0.762
  lenient  TP=30  FP=4   FN=10  TN=36  precision=0.882 recall=0.750 F1=0.811 accuracy=0.825
```

- **strict**: only a `LIKELY SCAM` verdict counts as flagged.
- **lenient**: `LIKELY SCAM` or `SUSPICIOUS` counts as flagged.

## Reading it

- Precision is high (0.88-0.96 on test): when it flags something, it is usually right.
- Recall is the weak side. On the held-out set it flags 30 of 40 scams at the lenient
  point, and only 22 of 40 as outright `LIKELY SCAM`.
- 4 of 40 legitimate test messages were flagged at the lenient point, and 1 at the strict point.

## Caveats

- n = 80 per split, so a single message moves recall by 2.5 points.
- The messages are synthetic. These numbers describe this set, not real-world accuracy.
- The rules cover English and Hinglish only.
- Next step: tune on `dev` only, then score `test` again and record here how many times it has
  been scored.
