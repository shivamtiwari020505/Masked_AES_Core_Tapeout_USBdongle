#!/usr/bin/env python3
"""Generic CW305 AES acquisition utility; not a project target adapter.

The repository does not include a CW305 top level or bitstream for this RTL,
and this utility cannot drive the Tiny Tapeout wrapper's serialized protocol.
It has not produced validation evidence for this project. Use it only with an
identified AES-compatible CW305 wrapper and record that wrapper separately.

Install:
    python3 -m pip install chipwhisperer numpy pycryptodome

Typical use:
    python3 capture.py path/to/cw305_aes.bit --num-traces 5000 --samples 5000

This script supports two common CW305 AES wrappers:
  * --interface cw305: uses target.loadInput(), target.go(), target.readOutput()
  * --interface simpleserial: uses SimpleSerial 'p' plaintext and 'r' ciphertext

Every captured ciphertext is checked against software AES when --key is
provided. A capture without that functional check is acquisition scaffolding,
not a verification result.
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
            "  python3 -m pip install chipwhisperer numpy pycryptodome"
        ) from exc

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
        errors: list[str] = []
        for method_name in ("loadEncryptionKey", "set_key"):
            if hasattr(target, method_name):
                for payload in (key, bytearray(args.key)):
                    try:
                        getattr(target, method_name)(payload)
                        return
                    except Exception as exc:
                        errors.append(f"{method_name}: {exc}")

        if hasattr(target, "simpleserial_write"):
            try:
                target.simpleserial_write("k", bytearray(args.key))
                if hasattr(target, "simpleserial_wait_ack"):
                    target.simpleserial_wait_ack()
                return
            except Exception as exc:
                errors.append(f"simpleserial key command: {exc}")

        detail = "; ".join(errors) if errors else "no supported key interface"
        raise RuntimeError(f"could not configure the requested AES key: {detail}")


def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError(
            "--key requires PyCryptodome for per-capture ciphertext checks"
        ) from exc
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


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
    parser = argparse.ArgumentParser(
        description="Generic CW305 AES capture utility; not a project target adapter"
    )
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


def validate_args(args: argparse.Namespace) -> None:
    if not args.bitstream.is_file():
        raise ValueError(f"bitstream does not exist or is not a file: {args.bitstream}")
    if args.num_traces <= 0:
        raise ValueError("--num-traces must be positive")
    if args.samples <= 0:
        raise ValueError("--samples must be positive")
    if args.retries < 0:
        raise ValueError("--retries must not be negative")


def main() -> int:
    args = build_argparser().parse_args()
    validate_args(args)
    if args.key is None:
        print(
            "Warning: --key was not supplied; captured ciphertexts cannot be "
            "checked against software AES.",
            file=sys.stderr,
        )
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
                    if args.key is not None:
                        expected = aes128_encrypt(args.key, plaintext)
                        actual = bytes(ciphertext)
                        if actual != expected:
                            raise RuntimeError(
                                "ciphertext check failed: "
                                f"expected={expected.hex()} actual={actual.hex()}"
                            )
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
