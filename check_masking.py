#!/usr/bin/env python3
"""Parse a masked AES simulation log and verify all output KATs passed."""

from __future__ import annotations

import re
import sys
from pathlib import Path


EXPECTED_TOTAL = 20 * 5

PASS_RE = re.compile(r"^MASKED_AES_PASS\s+vector=(\d+)\s+trial=(\d+)\b")
FAIL_RE = re.compile(r"^MASKED_AES_FAIL\b")
SUMMARY_RE = re.compile(
    r"^MASKED_AES_SUMMARY\s+passed=(\d+)\s+total=(\d+)\s+failed=(\d+)\b"
)


def main() -> int:
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("masked_sim.log")
    if not log_path.exists():
        print(f"ERROR: simulation log not found: {log_path}", file=sys.stderr)
        return 1

    pass_pairs: set[tuple[int, int]] = set()
    fail_lines: list[str] = []
    summary: tuple[int, int, int] | None = None

    log_bytes = log_path.read_bytes()
    if log_bytes.startswith(b"\xff\xfe") or log_bytes.startswith(b"\xfe\xff"):
        log_text = log_bytes.decode("utf-16")
    elif len(log_bytes) > 1 and log_bytes[1] == 0:
        log_text = log_bytes.decode("utf-16-le")
    else:
        log_text = log_bytes.decode("utf-8", errors="replace")

    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        pass_match = PASS_RE.match(line)
        if pass_match:
            pass_pairs.add((int(pass_match.group(1)), int(pass_match.group(2))))
            continue

        if FAIL_RE.match(line):
            fail_lines.append(line)
            continue

        summary_match = SUMMARY_RE.match(line)
        if summary_match:
            summary = tuple(int(summary_match.group(idx)) for idx in range(1, 4))

    expected_pairs = {(vec_idx, trial_idx) for vec_idx in range(20) for trial_idx in range(5)}
    missing_pairs = sorted(expected_pairs - pass_pairs)
    unexpected_pairs = sorted(pass_pairs - expected_pairs)

    errors: list[str] = []
    if len(pass_pairs) != EXPECTED_TOTAL:
        errors.append(f"expected {EXPECTED_TOTAL} unique pass lines, found {len(pass_pairs)}")
    if missing_pairs:
        errors.append(f"missing pass records: {missing_pairs}")
    if unexpected_pairs:
        errors.append(f"unexpected pass records: {unexpected_pairs}")
    if fail_lines:
        errors.append(f"found {len(fail_lines)} fail lines")
    if summary is None:
        errors.append("missing MASKED_AES_SUMMARY line")
    elif summary != (EXPECTED_TOTAL, EXPECTED_TOTAL, 0):
        errors.append(
            "bad summary: "
            f"passed={summary[0]} total={summary[1]} failed={summary[2]}"
        )

    if errors:
        print("ERROR: masking verification log check failed", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        if fail_lines:
            print("First fail line:", fail_lines[0], file=sys.stderr)
        return 1

    print(
        "Functional recombination regression passed: "
        f"{EXPECTED_TOTAL} tested mask trials matched the expected ciphertext"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
