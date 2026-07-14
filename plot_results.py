#!/usr/bin/env python3
"""Plot CPA correlation traces and attack convergence.

Install:
    python3 -m pip install chipwhisperer numpy matplotlib

Typical use:
    python3 plot_results.py --key 000102030405060708090a0b0c0d0e0f

Output:
    unmasked_cpa_results.png
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from cpa_attack import (
    correlation_trace_for_guess,
    key_to_hex,
    load_inputs,
    parse_key,
    run_cpa,
)


def load_or_run_artifacts(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    artifact_path: Path,
    chunk_size: int,
) -> tuple[np.ndarray, np.ndarray]:
    if artifact_path.exists():
        data = np.load(artifact_path)
        return data["recovered_key"].astype(np.uint8), data["correlation_peaks"]

    recovered, peaks, _, _ = run_cpa(
        traces,
        plaintexts,
        chunk_size=chunk_size,
        verbose=False,
    )
    return recovered, peaks


def second_best_guess(peaks: np.ndarray, byte_idx: int, excluded_guess: int) -> int:
    row = peaks[byte_idx].copy()
    row[excluded_guess] = -np.inf
    return int(np.argmax(row))


def default_trace_counts(num_traces: int) -> list[int]:
    candidates = [50, 100, 200, 500, 1000, 2000, 3000, 5000, 10000, num_traces]
    return sorted({count for count in candidates if 2 <= count <= num_traces})


def convergence_data(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    reference_key: np.ndarray,
    counts: list[int],
    chunk_size: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    correct_mean = np.zeros(len(counts), dtype=np.float64)
    wrong_mean = np.zeros(len(counts), dtype=np.float64)
    recovered_counts = np.zeros(len(counts), dtype=np.int64)

    for idx, count in enumerate(counts):
        recovered, peaks, _, _ = run_cpa(
            traces[:count],
            plaintexts[:count],
            chunk_size=chunk_size,
            verbose=False,
        )
        correct_peaks = np.array([peaks[b, reference_key[b]] for b in range(16)])
        wrong_peaks = np.array(
            [peaks[b, second_best_guess(peaks, b, int(reference_key[b]))] for b in range(16)]
        )
        correct_mean[idx] = float(np.mean(correct_peaks))
        wrong_mean[idx] = float(np.mean(wrong_peaks))
        recovered_counts[idx] = int(np.sum(recovered == reference_key))

    return np.array(counts), correct_mean, wrong_mean, recovered_counts


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plot unmasked AES CPA results")
    parser.add_argument("--traces", type=Path, default=Path("traces.npy"))
    parser.add_argument("--plaintexts", type=Path, default=Path("plaintexts.npy"))
    parser.add_argument("--artifacts", type=Path, default=Path("cpa_attack_artifacts.npz"))
    parser.add_argument("--key", type=parse_key, default=None, help="optional true AES key")
    parser.add_argument("--max-traces", type=int, default=None)
    parser.add_argument("--sample-start", type=int, default=0)
    parser.add_argument("--sample-end", type=int, default=None)
    parser.add_argument("--chunk-size", type=int, default=4096)
    parser.add_argument("--trace-counts", default=None, help="comma-separated convergence counts")
    parser.add_argument("--output", type=Path, default=Path("unmasked_cpa_results.png"))
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    traces, plaintexts = load_inputs(args)
    recovered_key, peaks = load_or_run_artifacts(
        traces,
        plaintexts,
        args.artifacts,
        chunk_size=args.chunk_size,
    )

    reference_key = args.key if args.key is not None else recovered_key
    reference_label = "true key" if args.key is not None else "recovered key"
    print(f"Plotting against {reference_label}: {key_to_hex(reference_key)}")

    if args.trace_counts:
        counts = sorted({int(item) for item in args.trace_counts.split(",") if item.strip()})
        counts = [count for count in counts if 2 <= count <= traces.shape[0]]
    else:
        counts = default_trace_counts(traces.shape[0])

    fig = plt.figure(figsize=(18, 16), constrained_layout=True)
    grid = fig.add_gridspec(5, 4, height_ratios=[1, 1, 1, 1, 1.35])

    sample_axis = np.arange(traces.shape[1]) + args.sample_start
    for byte_idx in range(16):
        ax = fig.add_subplot(grid[byte_idx // 4, byte_idx % 4])
        ref_guess = int(reference_key[byte_idx])
        wrong_guess = second_best_guess(peaks, byte_idx, ref_guess)
        ref_corr = correlation_trace_for_guess(
            traces,
            plaintexts[:, byte_idx],
            ref_guess,
            chunk_size=args.chunk_size,
        )
        wrong_corr = correlation_trace_for_guess(
            traces,
            plaintexts[:, byte_idx],
            wrong_guess,
            chunk_size=args.chunk_size,
        )

        ax.plot(sample_axis, ref_corr, linewidth=0.9, label=f"{reference_label} 0x{ref_guess:02x}")
        ax.plot(sample_axis, wrong_corr, linewidth=0.8, alpha=0.75, label=f"wrong 0x{wrong_guess:02x}")
        ax.set_title(f"Byte {byte_idx}")
        ax.grid(True, alpha=0.25)
        if byte_idx >= 12:
            ax.set_xlabel("Sample")
        if byte_idx % 4 == 0:
            ax.set_ylabel("Pearson r")
        ax.legend(fontsize=7, loc="upper right")

    ax_conv = fig.add_subplot(grid[4, :])
    counts_np, correct_mean, wrong_mean, recovered_counts = convergence_data(
        traces,
        plaintexts,
        reference_key,
        counts,
        chunk_size=args.chunk_size,
    )

    ax_conv.plot(counts_np, correct_mean, marker="o", label=f"mean {reference_label} peak")
    ax_conv.plot(counts_np, wrong_mean, marker="o", label="mean best wrong peak")
    ax_conv.set_xscale("log")
    ax_conv.set_xlabel("Number of traces")
    ax_conv.set_ylabel("Max absolute correlation")
    ax_conv.grid(True, which="both", alpha=0.25)
    ax_conv.legend(loc="upper left")

    ax_count = ax_conv.twinx()
    ax_count.step(counts_np, recovered_counts, where="post", color="tab:green", label="bytes recovered")
    ax_count.set_ylabel("Bytes matching reference key")
    ax_count.set_ylim(0, 16.5)
    ax_count.legend(loc="lower right")

    fig.suptitle(
        "Figure 1: CPA correlation traces per key byte\n"
        "Figure 2: CPA attack convergence vs trace count",
        fontsize=16,
    )
    fig.savefig(args.output, dpi=180)
    print(f"Saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
