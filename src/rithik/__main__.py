"""`python -m rithik` behaves exactly like the `rithik` script, for machines without it on PATH."""

from rithik.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
