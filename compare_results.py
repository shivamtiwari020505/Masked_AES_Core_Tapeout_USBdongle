#!/usr/bin/env python3
"""Generate the unmasked-vs-masked CPA comparison figure.

Install:
    python3 -m pip install chipwhisperer numpy matplotlib

Required inputs:
    unmasked_correlation_peaks.npy
    masked_correlation_peaks.npy
    traces/plaintexts for unmasked and masked captures

Typical use:
    python3 compare_results.py \
        --key 000102030405060708090a0b0c0d0e0f \
        --unmasked-traces traces.npy --unmasked-plaintexts plaintexts.npy \
        --masked-traces masked_traces.npy --masked-plaintexts masked_plaintexts.npy
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from cpa_attack import aes_sbox_hw_hypotheses, cpa_for_byte, parse_key


def load_trace_set(
    traces_path: Path,
    plaintexts_path: Path,
    max_traces: int | None,
    sample_start: int,
    sample_end: int | None,
) -> tuple[np.ndarray, np.ndarray]:
    traces = np.load(traces_path).astype(np.float64, copy=False)
    plaintexts = np.load(plaintexts_path).astype(np.uint8, copy=False)
    if traces.ndim != 2:
        raise ValueError(f"{traces_path} must have shape (N, samples)")
    if plaintexts.ndim != 2 or plaintexts.shape[1] != 16:
        raise ValueError(f"{plaintexts_path} must have shape (N, 16)")
    if traces.shape[0] != plaintexts.shape[0]:
        raise ValueError(f"N mismatch: {traces_path} and {plaintexts_path}")

    if max_traces is not None:
        traces = traces[:max_traces]
        plaintexts = plaintexts[:max_traces]
    traces = traces[:, sample_start:sample_end]
    return traces, plaintexts


def correlation_matrix_for_byte(
    traces: np.ndarray,
    plaintext_byte: np.ndarray,
    chunk_size: int,
) -> np.ndarray:
    hyp = aes_sbox_hw_hypotheses(plaintext_byte)
    hyp -= hyp.mean(axis=0, keepdims=True)
    hyp_norm = np.sqrt(np.sum(hyp * hyp, axis=0))
    hyp_norm[hyp_norm == 0.0] = np.inf

    corr = np.zeros((256, traces.shape[1]), dtype=np.float32)
    for start in range(0, traces.shape[1], chunk_size):
        end = min(start + chunk_size, traces.shape[1])
        block = traces[:, start:end].astype(np.float64, copy=True)
        block -= block.mean(axis=0, keepdims=True)
        block_norm = np.sqrt(np.sum(block * block, axis=0))
        block_norm[block_norm == 0.0] = np.inf
        corr[:, start:end] = ((hyp.T @ block) / (hyp_norm[:, None] * block_norm[None, :])).astype(
            np.float32
        )
    return corr


def parse_counts(value: str | None, n_traces: int) -> list[int]:
    if value:
        counts = sorted({int(item) for item in value.split(",") if item.strip()})
    else:
        counts = [50, 100, 200, 500, 1000, 2000, 3000, 5000, 10000, n_traces]
    return [count for count in counts if 2 <= count <= n_traces]


def first_recovery_count(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    byte_idx: int,
    correct_guess: int,
    counts: list[int],
    chunk_size: int,
) -> int | None:
    for count in counts:
        peaks, _, _ = cpa_for_byte(
            traces[:count],
            plaintexts[:count, byte_idx],
            chunk_size=chunk_size,
        )
        if int(np.argmax(peaks)) == correct_guess:
            return count
    return None


def plot_panel(
    ax,
    corr: np.ndarray,
    correct_guess: int,
    sample_axis: np.ndarray,
    title: str,
) -> None:
    for guess in range(256):
        if guess == correct_guess:
            continue
        ax.plot(sample_axis, corr[guess], color="0.65", alpha=0.18, linewidth=0.45)
    ax.plot(
        sample_axis,
        corr[correct_guess],
        color="red",
        linewidth=1.6,
        label=f"correct guess 0x{correct_guess:02x}",
    )
    ax.set_title(title)
    ax.set_xlabel("Sample")
    ax.set_ylabel("Pearson correlation")
    ax.grid(True, alpha=0.25)
    ax.legend(loc="upper right")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare unmasked and masked CPA results")
    parser.add_argument("--unmasked-peaks", type=Path, default=Path("unmasked_correlation_peaks.npy"))
    parser.add_argument("--masked-peaks", type=Path, default=Path("masked_correlation_peaks.npy"))
    parser.add_argument("--unmasked-traces", type=Path, default=Path("traces.npy"))
    parser.add_argument("--unmasked-plaintexts", type=Path, default=Path("plaintexts.npy"))
    parser.add_argument("--masked-traces", type=Path, default=Path("masked_traces.npy"))
    parser.add_argument("--masked-plaintexts", type=Path, default=Path("masked_plaintexts.npy"))
    parser.add_argument("--key", type=parse_key, default=None)
    parser.add_argument("--byte", type=int, default=0)
    parser.add_argument("--max-traces", type=int, default=None)
    parser.add_argument("--sample-start", type=int, default=0)
    parser.add_argument("--sample-end", type=int, default=None)
    parser.add_argument("--chunk-size", type=int, default=4096)
    parser.add_argument("--trace-counts", default=None)
    parser.add_argument("--output", type=Path, default=Path("side_channel_comparison.png"))
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    if not 0 <= args.byte < 16:
        raise ValueError("--byte must be in range 0..15")

    unmasked_peaks = np.load(args.unmasked_peaks)
    masked_peaks = np.load(args.masked_peaks)
    if unmasked_peaks.shape != (16, 256):
        raise ValueError(f"{args.unmasked_peaks} must have shape (16, 256)")
    if masked_peaks.shape != (16, 256):
        raise ValueError(f"{args.masked_peaks} must have shape (16, 256)")

    unmasked_traces, unmasked_pts = load_trace_set(
        args.unmasked_traces,
        args.unmasked_plaintexts,
        args.max_traces,
        args.sample_start,
        args.sample_end,
    )
    masked_traces, masked_pts = load_trace_set(
        args.masked_traces,
        args.masked_plaintexts,
        args.max_traces,
        args.sample_start,
        args.sample_end,
    )

    correct_guess = int(args.key[args.byte]) if args.key is not None else int(np.argmax(unmasked_peaks[args.byte]))
    unmasked_corr = correlation_matrix_for_byte(
        unmasked_traces,
        unmasked_pts[:, args.byte],
        args.chunk_size,
    )
    masked_corr = correlation_matrix_for_byte(
        masked_traces,
        masked_pts[:, args.byte],
        args.chunk_size,
    )

    sample_axis = np.arange(unmasked_corr.shape[1]) + args.sample_start
    masked_sample_axis = np.arange(masked_corr.shape[1]) + args.sample_start

    counts = parse_counts(args.trace_counts, min(unmasked_traces.shape[0], masked_traces.shape[0]))
    unmasked_recovery = first_recovery_count(
        unmasked_traces,
        unmasked_pts,
        args.byte,
        correct_guess,
        counts,
        args.chunk_size,
    )
    masked_recovery = first_recovery_count(
        masked_traces,
        masked_pts,
        args.byte,
        correct_guess,
        counts,
        args.chunk_size,
    )

    x_text = str(unmasked_recovery) if unmasked_recovery is not None else f">{counts[-1]}"
    if masked_recovery is None:
        masked_text = f"Masked: no recovery at {masked_traces.shape[0]} traces"
    else:
        masked_text = f"Masked: recovered at {masked_recovery} traces"
    annotation = f"Unmasked: key recovered in {x_text} traces | {masked_text}"

    fig, axes = plt.subplots(1, 2, figsize=(16, 6), constrained_layout=True, sharey=True)
    plot_panel(
        axes[0],
        unmasked_corr,
        correct_guess,
        sample_axis,
        f"Unmasked AES CPA, byte {args.byte}",
    )
    plot_panel(
        axes[1],
        masked_corr,
        correct_guess,
        masked_sample_axis,
        f"Masked AES CPA, byte {args.byte}",
    )

    fig.suptitle(annotation, fontsize=14)
    fig.text(
        0.5,
        0.01,
        f"Max |r| byte {args.byte}: unmasked={unmasked_peaks[args.byte, correct_guess]:.4f}, "
        f"masked={masked_peaks[args.byte, correct_guess]:.4f}",
        ha="center",
    )
    fig.savefig(args.output, dpi=200)
    print(annotation)
    print(f"Saved {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
