# Validation Status

Updated: 2026-07-17

No physical side-channel experiment has been completed for this project. The
previous draft report described a ChipWhisperer campaign as if it had happened;
that text was removed because no trace data or completed result exists.

## Reproduced functional results

The following simulations were run locally on 2026-07-17 with Icarus Verilog:

- unmasked AES core: 20 of 20 AES-128 vectors passed;
- compatibility masked core: 100 of 100 trials passed across 20 vectors and
  five starting masks per vector;
- DOM32 S-box: all 256 input values recombined to the expected AES S-box value;
  and
- DOM32 AES core: the FIPS-197 AES-128 known-answer ciphertext passed.

These results show functional correctness for the tested cases. They do not
show resistance to power, electromagnetic, timing, fault, probing, or
higher-order attacks.

The GitHub `test` workflow now regenerates the 20-vector corpus from a fixed
seed and runs the unmasked, compatibility-masked, 32-bit-randomness, and Tiny
Tapeout regressions. Exact vector and log artifacts are retained per workflow
run. Deterministic generation supports reproducibility; it is not a model for a
security randomness source.

## Physical implementation evidence

A previous TT06-compatible GitHub workflow completed GDS hardening, precheck,
gate-level simulation, and viewer generation for the serialized Tiny Tapeout
wrapper. The repository now targets the current TTSKY26c flow; evidence for a
release must reference a successful workflow on that exact commit. No shuttle
submission or fabricated device exists.

## Missing security evidence

- measured fixed-versus-random TVLA;
- first- and higher-order CPA;
- post-layout power or electromagnetic simulation;
- glitch-aware or probing-model proof;
- independent masking review;
- fault-injection testing; and
- silicon bring-up and characterization.

## Planned measurement sequence

1. Prototype the security-oriented candidate on an FPGA measurement target.
2. Define the key, plaintext, masks, randomness source, trigger, sampling
   window, and trace-retention format before capture.
3. Run fixed-versus-random TVLA with fresh masks and randomness for every
   encryption.
4. Run attack-based CPA against unmasked and masked references under identical
   acquisition conditions.
5. Preserve raw traces, scripts, tool versions, board details, plots, and signed
   result summaries.
6. Repeat the agreed tests on post-layout data and then on the fabricated proof
   device.

A non-detection result applies only to the measured setup and trace count. It
must not be presented as a general proof of side-channel resistance.
