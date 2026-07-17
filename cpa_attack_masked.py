#!/usr/bin/env python3
"""First-round CPA utility for a trace set labelled as masked.

No measured trace set for this project is included. Failure to recover a key
under this model does not demonstrate masking security; trace count, alignment,
measurement quality, leakage order, and alternative models still matter.

Install:
    python3 -m pip install numpy

Typical use:
    python3 cpa_attack_masked.py \
        --traces masked_traces.npy \
        --plaintexts masked_plaintexts.npy \
        --key 000102030405060708090a0b0c0d0e0f

This intentionally runs the same first-round model used for the unmasked core:
HW(SBOX[plaintext_byte XOR key_guess]). The comparison is a single diagnostic,
not a pass/fail security test.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

from cpa_attack import key_to_hex, load_inputs, parse_key, run_cpa


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="First-round CPA utility for a trace set labelled as masked"
    )
    parser.add_argument("--traces", type=Path, default=Path("masked_traces.npy"))
    parser.add_argument("--plaintexts", type=Path, default=Path("masked_plaintexts.npy"))
    parser.add_argument("--key", type=parse_key, default=None, help="optional true AES key")
    parser.add_argument("--max-traces", type=int, default=None)
    parser.add_argument("--sample-start", type=int, default=0)
    parser.add_argument("--sample-end", type=int, default=None)
    parser.add_argument("--chunk-size", type=int, default=4096)
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    traces, plaintexts = load_inputs(args)
    recovered_key, peaks, peak_indices, peak_signed = run_cpa(
        traces,
        plaintexts,
        chunk_size=args.chunk_size,
    )

    recovered_hex = key_to_hex(recovered_key)
    (args.out_dir / "masked_recovered_key.txt").write_text(
        recovered_hex + "\n",
        encoding="ascii",
    )
    np.save(args.out_dir / "masked_correlation_peaks.npy", peaks)
    np.savez(
        args.out_dir / "masked_cpa_attack_artifacts.npz",
        recovered_key=recovered_key,
        true_key=args.key if args.key is not None else np.array([], dtype=np.uint8),
        correlation_peaks=peaks,
        peak_sample_indices=peak_indices,
        peak_signed_correlations=peak_signed,
        sample_start=np.array(args.sample_start, dtype=np.int64),
        sample_end=np.array(-1 if args.sample_end is None else args.sample_end, dtype=np.int64),
        num_traces=np.array(traces.shape[0], dtype=np.int64),
    )

    print(f"Recovered key: {recovered_hex}")
    if args.key is not None:
        print(f"Correct: {bool(np.array_equal(recovered_key, args.key))}")
    else:
        print("Correct: Unknown")
    print("Saved masked_correlation_peaks.npy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
