#!/usr/bin/env python3
"""Correlation Power Analysis attack against first-round AES SubBytes.

Install:
    python3 -m pip install chipwhisperer numpy matplotlib

Typical use:
    python3 cpa_attack.py --key 000102030405060708090a0b0c0d0e0f

Inputs:
    traces.npy      shape (N, num_samples)
    plaintexts.npy  shape (N, 16)

Outputs:
    recovered_key.txt
    correlation_peaks.npy      shape (16, 256)
    unmasked_correlation_peaks.npy
    cpa_attack_artifacts.npz
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np


SBOX = np.array(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ],
    dtype=np.uint8,
)

HW = np.array([int(i).bit_count() for i in range(256)], dtype=np.uint8)


def parse_key(value: str | None) -> np.ndarray | None:
    if value is None:
        return None
    cleaned = value.strip().replace("0x", "").replace("_", "")
    key = bytes.fromhex(cleaned)
    if len(key) != 16:
        raise argparse.ArgumentTypeError("AES-128 key must be 16 bytes / 32 hex chars")
    return np.frombuffer(key, dtype=np.uint8).copy()


def key_to_hex(key: np.ndarray) -> str:
    return bytes(np.asarray(key, dtype=np.uint8)).hex()


def load_inputs(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    traces = np.load(args.traces).astype(np.float64, copy=False)
    plaintexts = np.load(args.plaintexts).astype(np.uint8, copy=False)

    if plaintexts.ndim != 2 or plaintexts.shape[1] != 16:
        raise ValueError(f"plaintexts must have shape (N, 16), got {plaintexts.shape}")
    if traces.ndim != 2 or traces.shape[0] != plaintexts.shape[0]:
        raise ValueError(
            f"traces must have shape (N, samples) with same N as plaintexts; "
            f"got traces={traces.shape}, plaintexts={plaintexts.shape}"
        )

    if args.max_traces is not None:
        traces = traces[: args.max_traces]
        plaintexts = plaintexts[: args.max_traces]

    traces = traces[:, args.sample_start : args.sample_end]
    return traces, plaintexts


def aes_sbox_hw_hypotheses(plaintext_byte: np.ndarray) -> np.ndarray:
    guesses = np.arange(256, dtype=np.uint8)
    intermediates = SBOX[np.bitwise_xor(plaintext_byte[:, None], guesses[None, :])]
    return HW[intermediates].astype(np.float64)


def cpa_for_byte(
    traces: np.ndarray,
    plaintext_byte: np.ndarray,
    chunk_size: int = 4096,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    hyp = aes_sbox_hw_hypotheses(plaintext_byte)
    hyp -= hyp.mean(axis=0, keepdims=True)
    hyp_norm = np.sqrt(np.sum(hyp * hyp, axis=0))
    hyp_norm[hyp_norm == 0.0] = np.inf

    num_samples = traces.shape[1]
    peaks = np.zeros(256, dtype=np.float64)
    peak_indices = np.zeros(256, dtype=np.int64)
    peak_signed = np.zeros(256, dtype=np.float64)

    for start in range(0, num_samples, chunk_size):
        end = min(start + chunk_size, num_samples)
        block = traces[:, start:end].astype(np.float64, copy=True)
        block -= block.mean(axis=0, keepdims=True)
        block_norm = np.sqrt(np.sum(block * block, axis=0))
        block_norm[block_norm == 0.0] = np.inf

        corr = (hyp.T @ block) / (hyp_norm[:, None] * block_norm[None, :])
        abs_corr = np.abs(corr)
        local_indices = np.argmax(abs_corr, axis=1)
        local_peaks = abs_corr[np.arange(256), local_indices]
        local_signed = corr[np.arange(256), local_indices]
        update = local_peaks > peaks

        peaks[update] = local_peaks[update]
        peak_indices[update] = start + local_indices[update]
        peak_signed[update] = local_signed[update]

    return peaks, peak_indices, peak_signed


def correlation_trace_for_guess(
    traces: np.ndarray,
    plaintext_byte: np.ndarray,
    guess: int,
    chunk_size: int = 4096,
) -> np.ndarray:
    hyp = HW[SBOX[np.bitwise_xor(plaintext_byte, np.uint8(guess))]].astype(np.float64)
    hyp -= hyp.mean()
    hyp_norm = np.sqrt(np.sum(hyp * hyp))
    if hyp_norm == 0.0:
        return np.zeros(traces.shape[1], dtype=np.float64)

    corr = np.zeros(traces.shape[1], dtype=np.float64)
    for start in range(0, traces.shape[1], chunk_size):
        end = min(start + chunk_size, traces.shape[1])
        block = traces[:, start:end].astype(np.float64, copy=True)
        block -= block.mean(axis=0, keepdims=True)
        block_norm = np.sqrt(np.sum(block * block, axis=0))
        block_norm[block_norm == 0.0] = np.inf
        corr[start:end] = (hyp @ block) / (hyp_norm * block_norm)
    return corr


def run_cpa(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    chunk_size: int = 4096,
    verbose: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    correlation_peaks = np.zeros((16, 256), dtype=np.float64)
    peak_indices = np.zeros((16, 256), dtype=np.int64)
    peak_signed = np.zeros((16, 256), dtype=np.float64)
    recovered_key = np.zeros(16, dtype=np.uint8)

    for byte_idx in range(16):
        peaks, indices, signed = cpa_for_byte(
            traces,
            plaintexts[:, byte_idx],
            chunk_size=chunk_size,
        )
        correlation_peaks[byte_idx] = peaks
        peak_indices[byte_idx] = indices
        peak_signed[byte_idx] = signed
        recovered_key[byte_idx] = int(np.argmax(peaks))
        if verbose:
            print(
                f"byte {byte_idx:02d}: guess=0x{recovered_key[byte_idx]:02x} "
                f"peak={peaks[recovered_key[byte_idx]]:.6f} "
                f"sample={indices[recovered_key[byte_idx]]}"
            )

    return recovered_key, correlation_peaks, peak_indices, peak_signed


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CPA attack on unmasked AES traces")
    parser.add_argument("--traces", type=Path, default=Path("traces.npy"))
    parser.add_argument("--plaintexts", type=Path, default=Path("plaintexts.npy"))
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
    (args.out_dir / "recovered_key.txt").write_text(recovered_hex + "\n", encoding="ascii")
    np.save(args.out_dir / "correlation_peaks.npy", peaks)
    np.save(args.out_dir / "unmasked_correlation_peaks.npy", peaks)
    np.savez(
        args.out_dir / "cpa_attack_artifacts.npz",
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
