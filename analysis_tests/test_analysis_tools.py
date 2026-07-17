"""Deterministic checks for the repository's numerical analysis utilities.

These tests use synthetic data to catch implementation regressions. They are
not side-channel evidence for any RTL or physical device.
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from capture import aes128_encrypt
from cpa_attack import HW, SBOX, run_cpa
from tvla_welch import OnlineStats, parse_trace_row, welch_t


SEED = 20260717


def test_capture_reference_cipher_matches_fips_kat() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    assert aes128_encrypt(key, plaintext).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def build_stats(rows: np.ndarray) -> OnlineStats:
    stats = OnlineStats.empty()
    for lineno, row in enumerate(rows, start=1):
        stats.add(
            row.astype(float).tolist(),
            source=Path("synthetic"),
            lineno=lineno,
        )
    return stats


def test_cpa_recovers_key_from_deliberate_synthetic_leakage() -> None:
    rng = np.random.default_rng(SEED)
    num_traces = 600
    key = np.array(
        [
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
        ],
        dtype=np.uint8,
    )
    plaintexts = rng.integers(0, 256, size=(num_traces, 16), dtype=np.uint8)
    traces = rng.normal(0.0, 0.35, size=(num_traces, 24))

    for byte_idx in range(16):
        intermediate = SBOX[np.bitwise_xor(plaintexts[:, byte_idx], key[byte_idx])]
        traces[:, byte_idx] += HW[intermediate].astype(np.float64)

    recovered, peaks, sample_indices, _ = run_cpa(
        traces,
        plaintexts,
        chunk_size=7,
        verbose=False,
    )

    np.testing.assert_array_equal(recovered, key)
    assert peaks.shape == (16, 256)
    np.testing.assert_array_equal(sample_indices[np.arange(16), key], np.arange(16))


def test_welch_t_detects_deliberate_mean_shift() -> None:
    rng = np.random.default_rng(SEED)
    fixed_rows = rng.normal(0.0, 1.0, size=(500, 5))
    random_rows = rng.normal(0.0, 1.0, size=(500, 5))
    fixed_rows[:, 3] += 1.0

    t_values = welch_t(build_stats(fixed_rows), build_stats(random_rows))

    assert int(np.argmax(np.abs(t_values))) == 3
    assert abs(t_values[3]) >= 4.5


def test_welch_t_handles_zero_variance_explicitly() -> None:
    fixed = build_stats(np.array([[1.0, 3.0], [1.0, 3.0]]))
    random = build_stats(np.array([[1.0, 2.0], [1.0, 2.0]]))

    t_values = welch_t(fixed, random)

    assert t_values[0] == 0.0
    assert math.isinf(t_values[1]) and t_values[1] > 0


def test_trace_parser_rejects_missing_samples() -> None:
    assert parse_trace_row([]) is None
    assert parse_trace_row(["# comment"]) is None
    assert parse_trace_row([" ", " "]) is None

    try:
        parse_trace_row(["1.0", "", "2.0"])
    except ValueError as exc:
        assert "empty sample" in str(exc)
    else:
        raise AssertionError("partially empty trace row was accepted")
