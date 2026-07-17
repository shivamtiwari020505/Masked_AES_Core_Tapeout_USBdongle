#!/usr/bin/env python3
"""Welch t-test TVLA utility for fixed-vs-random power traces.

Input files are CSV text matrices with one trace per row and one sample per
column. Use one file for fixed-input traces and one for random-input traces.
Rows beginning with "#" and blank rows are ignored.

Example:
  python3 tvla_welch.py --fixed fixed.csv --random random.csv --out tvla.csv

The script reports the maximum absolute t-statistic and exits non-zero when it
meets or exceeds the default first-order screening threshold of 4.5. A result
below that threshold is not a certification or proof of leakage resistance.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class OnlineStats:
    n: int
    mean: list[float]
    m2: list[float]

    @classmethod
    def empty(cls) -> "OnlineStats":
        return cls(0, [], [])

    def add(self, row: list[float], source: Path, lineno: int) -> None:
        if self.n == 0:
            self.mean = [0.0] * len(row)
            self.m2 = [0.0] * len(row)
        elif len(row) != len(self.mean):
            raise ValueError(
                f"{source}:{lineno}: expected {len(self.mean)} samples, got {len(row)}"
            )

        self.n += 1
        for idx, value in enumerate(row):
            delta = value - self.mean[idx]
            self.mean[idx] += delta / self.n
            delta2 = value - self.mean[idx]
            self.m2[idx] += delta * delta2

    def variance(self, idx: int) -> float:
        if self.n < 2:
            return 0.0
        return self.m2[idx] / (self.n - 1)


def parse_trace_row(row: list[str]) -> list[float] | None:
    if not row:
        return None
    stripped = [item.strip() for item in row]
    if stripped[0].startswith("#"):
        return None
    if all(not item for item in stripped):
        return None
    if any(not item for item in stripped):
        raise ValueError("trace row contains an empty sample")
    return [float(item) for item in stripped]


def load_stats(path: Path) -> OnlineStats:
    stats = OnlineStats.empty()
    with path.open("r", encoding="utf-8", newline="") as fin:
        reader = csv.reader(fin)
        for lineno, row in enumerate(reader, start=1):
            try:
                parsed = parse_trace_row(row)
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
            if parsed is not None:
                stats.add(parsed, path, lineno)
    if stats.n < 2:
        raise ValueError(f"{path}: need at least two traces")
    return stats


def welch_t(fixed: OnlineStats, random: OnlineStats) -> list[float]:
    if len(fixed.mean) != len(random.mean):
        raise ValueError(
            f"sample-count mismatch: fixed has {len(fixed.mean)}, "
            f"random has {len(random.mean)}"
        )

    t_values: list[float] = []
    for idx in range(len(fixed.mean)):
        numerator = fixed.mean[idx] - random.mean[idx]
        denom = math.sqrt(
            (fixed.variance(idx) / fixed.n) + (random.variance(idx) / random.n)
        )
        if denom == 0.0:
            t_values.append(0.0 if numerator == 0.0 else math.copysign(math.inf, numerator))
        else:
            t_values.append(numerator / denom)
    return t_values


def write_results(path: Path, t_values: list[float]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerow(["sample", "t"])
        for idx, value in enumerate(t_values):
            writer.writerow([idx, f"{value:.12g}"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed", required=True, type=Path, help="CSV fixed-input traces")
    parser.add_argument("--random", required=True, type=Path, help="CSV random-input traces")
    parser.add_argument("--out", type=Path, default=Path("tvla_results.csv"))
    parser.add_argument("--threshold", type=float, default=4.5)
    args = parser.parse_args()

    fixed = load_stats(args.fixed)
    random = load_stats(args.random)
    t_values = welch_t(fixed, random)
    write_results(args.out, t_values)

    max_idx, max_t = max(
        enumerate(t_values),
        key=lambda item: abs(item[1]),
    )
    print(f"fixed_traces={fixed.n} random_traces={random.n} samples={len(t_values)}")
    print(f"max_abs_t={abs(max_t):.6f} sample={max_idx} signed_t={max_t:.6f}")
    print(f"results={args.out}")

    if abs(max_t) >= args.threshold:
        print(
            f"TVLA SCREEN: threshold crossing |t| >= {args.threshold}",
            file=sys.stderr,
        )
        return 1

    print(f"TVLA SCREEN: no |t| crossing at threshold {args.threshold}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
