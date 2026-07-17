## How it works

This project is a serialized AES-128 round-core demonstrator. It stores the AES
state as two Boolean shares, applies the linear round operations share-wise, and
uses a randomized two-share Boolean S-box built from Boyar-Peralta equations.
Its combinational cross-share construction is functionally tested but has not
been shown to satisfy Domain-Oriented Masking, probing, or glitch-security
requirements. Plaintext bytes and precomputed round-key bytes are streamed
through the eight-bit input.

The Tiny Tapeout interface supplies only eight randomness bits per S-box
evaluation. The RTL expands that byte internally for functional compatibility,
so this wrapper is not a production side-channel countermeasure and no leakage
resistance is claimed.

## How to test

Pulse uio_in[0] to start, then stream 16 plaintext bytes, the initial key, and
ten precomputed AES-128 round keys as described in the repository README. The
included cocotb test uses the FIPS-197 known-answer vector and checks the 16
output bytes plus the done pulse.

## External hardware

RTL and gate-level tests need no external hardware. After fabrication, bring-up
would require a compatible Tiny Tapeout demoboard and a controller for the
serialized byte and randomness streams. This project has not yet been submitted
or verified in silicon.
