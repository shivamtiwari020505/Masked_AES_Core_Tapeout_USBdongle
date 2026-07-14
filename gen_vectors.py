#!/usr/bin/env python3
"""Generate AES-128 known-answer vectors for aes_core.sv.

The output file uses whitespace-separated 128-bit hex words:

    KEY PLAINTEXT EXPECTED_CIPHERTEXT

$readmemh can read this file into a flat 128-bit memory because each line
contains three ordinary hex tokens.
"""

from __future__ import annotations

import secrets
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit(
        "Missing PyCryptodome. Install it with one of:\n"
        "  python3 -m pip install pycryptodome\n"
        "  sudo apt install python3-pycryptodome"
    ) from exc


OUT_FILE = Path("vectors.txt")
NUM_RANDOM_VECTORS = 10


def h(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(plaintext) != 16:
        raise ValueError(f"AES plaintext block must be 16 bytes, got {len(plaintext)}")
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def checked_vector(name: str, key_hex: str, plaintext_hex: str, expected_hex: str):
    key = h(key_hex)
    plaintext = h(plaintext_hex)
    expected = h(expected_hex)
    actual = aes128_encrypt(key, plaintext)
    if actual != expected:
        raise RuntimeError(
            f"{name} expected ciphertext mismatch: "
            f"expected={expected.hex()} actual={actual.hex()}"
        )
    return name, key, plaintext, expected


# FIPS-197 Appendix B/C only contain two full AES-128 encryption vectors.
# The remaining three fixed AES-128 KATs below are NIST SP800-38A ECB examples.
FIXED_OFFICIAL_VECTORS = [
    checked_vector(
        "FIPS-197 Appendix B",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
    ),
    checked_vector(
        "FIPS-197 Appendix C.1",
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    ),
    checked_vector(
        "SP800-38A ECB block 0",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97",
    ),
    checked_vector(
        "SP800-38A ECB block 1",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf",
    ),
    checked_vector(
        "SP800-38A ECB block 2",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "43b1cd7f598ece23881b00e3ed030688",
    ),
]


ZERO = bytes(16)
ONES = bytes([0xFF] * 16)
COUNTING = h("00112233445566778899aabbccddeeff")
FIPS_KEY = h("000102030405060708090a0b0c0d0e0f")

ZERO_COMBINATION_INPUTS = [
    ("zero key, zero plaintext", ZERO, ZERO),
    ("zero key, ones plaintext", ZERO, ONES),
    ("ones key, zero plaintext", ONES, ZERO),
    ("zero key, counting plaintext", ZERO, COUNTING),
    ("counting key, zero plaintext", COUNTING, ZERO),
]


def computed_vector(name: str, key: bytes, plaintext: bytes):
    return name, key, plaintext, aes128_encrypt(key, plaintext)


def main() -> None:
    vectors = list(FIXED_OFFICIAL_VECTORS)

    vectors.extend(
        computed_vector(name, key, plaintext)
        for name, key, plaintext in ZERO_COMBINATION_INPUTS
    )

    for idx in range(NUM_RANDOM_VECTORS):
        key = secrets.token_bytes(16)
        plaintext = secrets.token_bytes(16)
        vectors.append(computed_vector(f"random {idx}", key, plaintext))

    if len(vectors) != 20:
        raise RuntimeError(f"expected 20 vectors, generated {len(vectors)}")

    with OUT_FILE.open("w", encoding="ascii") as fout:
        for _, key, plaintext, ciphertext in vectors:
            fout.write(f"{key.hex()} {plaintext.hex()} {ciphertext.hex()}\n")

    print(f"Wrote {len(vectors)} AES-128 vectors to {OUT_FILE}")


if __name__ == "__main__":
    main()
