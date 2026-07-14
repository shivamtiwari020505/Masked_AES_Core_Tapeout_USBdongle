#!/usr/bin/env python3
"""Capture unmasked AES traces from a CW305 target.

Install:
    python3 -m pip install chipwhisperer numpy matplotlib

Typical use:
    python3 capture.py path/to/cw305_aes.bit --num-traces 5000 --samples 5000

This script supports two common CW305 AES wrappers:
  * --interface cw305: uses target.loadInput(), target.go(), target.readOutput()
  * --interface simpleserial: uses SimpleSerial 'p' plaintext and 'r' ciphertext

The requested chipwhisperer.common.results.glitch import is attempted below for
compatibility with older ChipWhisperer notebook environments. Actual capture
triggering is done through the normal ChipWhisperer hardware path:
scope.trigger.triggers, scope.arm(), target start, scope.capture().
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Iterable

import numpy as np


def parse_hex16(value: str, name: str) -> bytes:
    value = value.strip().replace("0x", "").replace("_", "")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be hex") from exc
    if len(data) != 16:
        raise argparse.ArgumentTypeError(f"{name} must be 16 bytes / 32 hex chars")
    return data


def bytes16(value: Iterable[int] | bytes | bytearray) -> np.ndarray:
    data = bytes(value)
    if len(data) != 16:
        raise RuntimeError(f"expected 16-byte value from target, got {len(data)} bytes")
    return np.frombuffer(data, dtype=np.uint8).copy()


def connect_and_program(args: argparse.Namespace):
    try:
        import chipwhisperer as cw
    except ImportError as exc:
        raise SystemExit(
            "Missing ChipWhisperer. Install with:\n"
            "  python3 -m pip install chipwhisperer numpy matplotlib"
        ) from exc

    try:
        from chipwhisperer.common.results import glitch as cw_glitch_results  # noqa: F401
    except Exception:
        cw_glitch_results = None  # noqa: F841

    scope = cw.scope()
    target = cw.target(
        scope,
        cw.targets.CW305,
        bsfile=str(args.bitstream),
        force=args.force_program,
    )

    configure_scope(scope, args)
    configure_cw305_target(target, args)
    return scope, target


def configure_scope(scope, args: argparse.Namespace) -> None:
    if hasattr(scope, "default_setup"):
        try:
            scope.default_setup()
        except Exception:
            pass

    scope.adc.samples = args.samples
    scope.adc.offset = args.offset
    scope.adc.timeout = args.timeout
    scope.gain.db = args.gain

    if args.adc_src:
        scope.clock.adc_src = args.adc_src
    if args.trigger:
        scope.trigger.triggers = args.trigger

    if hasattr(scope.clock, "extclk_freq") and args.target_freq:
        try:
            scope.clock.extclk_freq = args.target_freq
        except Exception:
            pass


def configure_cw305_target(target, args: argparse.Namespace) -> None:
    if hasattr(target, "vccint_set"):
        target.vccint_set(args.vccint)

    if hasattr(target, "pll") and args.target_freq:
        try:
            target.pll.pll_outfreq_set(args.target_freq, 1)
            target.pll.pll_outenable_set(True, 1)
        except Exception as exc:
            print(f"Warning: could not configure CW305 PLL: {exc}", file=sys.stderr)

    if args.key is not None:
        key = list(args.key)
        for method_name in ("loadEncryptionKey", "set_key"):
            if hasattr(target, method_name):
                try:
                    getattr(target, method_name)(key)
                    return
                except TypeError:
                    getattr(target, method_name)(bytearray(args.key))
                    return
                except Exception:
                    pass

        if hasattr(target, "simpleserial_write"):
            target.simpleserial_write("k", bytearray(args.key))
            if hasattr(target, "simpleserial_wait_ack"):
                target.simpleserial_wait_ack()


def capture_cw305_native(scope, target, plaintext: bytes, args: argparse.Namespace):
    target.loadInput(list(plaintext))
    scope.arm()
    target.go()
    timed_out = scope.capture()
    if timed_out:
        raise TimeoutError("scope timed out waiting for CW305 trigger")

    if hasattr(target, "is_done"):
        deadline = time.time() + (args.done_timeout_ms / 1000.0)
        while not target.is_done():
            if time.time() > deadline:
                raise TimeoutError("CW305 target did not report done")
            time.sleep(0.001)

    ciphertext = target.readOutput()
    return np.asarray(scope.get_last_trace(), dtype=np.float32), bytes16(ciphertext)


def capture_simpleserial(scope, target, plaintext: bytes, args: argparse.Namespace):
    scope.arm()
    target.simpleserial_write(args.pt_cmd, bytearray(plaintext))
    timed_out = scope.capture()
    if timed_out:
        raise TimeoutError("scope timed out waiting for SimpleSerial trigger")

    ciphertext = target.simpleserial_read(
        args.ct_cmd,
        16,
        timeout=args.read_timeout_ms,
        ack=args.read_ack,
    )
    return np.asarray(scope.get_last_trace(), dtype=np.float32), bytes16(ciphertext)


def capture_one(scope, target, plaintext: bytes, args: argparse.Namespace):
    if args.interface == "cw305":
        return capture_cw305_native(scope, target, plaintext, args)
    if args.interface == "simpleserial":
        return capture_simpleserial(scope, target, plaintext, args)
    raise ValueError(f"unknown interface: {args.interface}")


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture AES traces from CW305")
    parser.add_argument("bitstream", type=Path, help="CW305 FPGA bitstream path")
    parser.add_argument("-n", "--num-traces", type=int, default=5000)
    parser.add_argument("--samples", type=int, default=5000)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--gain", type=float, default=25.0)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--target-freq", type=float, default=10_000_000.0)
    parser.add_argument("--adc-src", default="extclk_x4")
    parser.add_argument("--trigger", default="tio4")
    parser.add_argument("--vccint", type=float, default=1.0)
    parser.add_argument("--interface", choices=("cw305", "simpleserial"), default="cw305")
    parser.add_argument("--pt-cmd", default="p", help="SimpleSerial plaintext command")
    parser.add_argument("--ct-cmd", default="r", help="SimpleSerial ciphertext command")
    parser.add_argument("--read-timeout-ms", type=int, default=250)
    parser.add_argument("--done-timeout-ms", type=int, default=250)
    parser.add_argument("--read-ack", action="store_true")
    parser.add_argument("--force-program", action="store_true", default=True)
    parser.add_argument("--no-force-program", action="store_false", dest="force_program")
    parser.add_argument("--key", type=lambda s: parse_hex16(s, "key"), default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    return parser


def main() -> int:
    args = build_argparser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(args.seed)
    scope, target = connect_and_program(args)

    traces: list[np.ndarray] = []
    plaintexts = np.zeros((args.num_traces, 16), dtype=np.uint8)
    ciphertexts = np.zeros((args.num_traces, 16), dtype=np.uint8)

    try:
        for trace_idx in range(args.num_traces):
            plaintext = rng.integers(0, 256, size=16, dtype=np.uint8).tobytes()
            last_error: Exception | None = None

            for attempt in range(args.retries + 1):
                try:
                    wave, ciphertext = capture_one(scope, target, plaintext, args)
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt >= args.retries:
                        raise
                    print(
                        f"Trace {trace_idx}: retry {attempt + 1}/{args.retries} after {exc}",
                        file=sys.stderr,
                    )
            else:
                raise RuntimeError(f"capture failed: {last_error}")

            traces.append(wave)
            plaintexts[trace_idx] = np.frombuffer(plaintext, dtype=np.uint8)
            ciphertexts[trace_idx] = ciphertext

            if (trace_idx + 1) % max(1, args.num_traces // 20) == 0:
                print(f"Captured {trace_idx + 1}/{args.num_traces}")

    finally:
        for obj in (target, scope):
            if hasattr(obj, "dis"):
                try:
                    obj.dis()
                except Exception:
                    pass

    traces_np = np.vstack(traces).astype(np.float32, copy=False)
    np.save(args.out_dir / "traces.npy", traces_np)
    np.save(args.out_dir / "plaintexts.npy", plaintexts)
    np.save(args.out_dir / "ciphertexts.npy", ciphertexts)

    print(f"Saved {traces_np.shape[0]} traces with {traces_np.shape[1]} samples")
    print(f"Output directory: {args.out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
