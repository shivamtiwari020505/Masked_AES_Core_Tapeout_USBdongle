# Measurement Readiness

Updated: 2026-07-17

Status: preparation only. No file in this repository is measured leakage
evidence for this RTL or for a fabricated device.

## Present hardware boundary

The repository does not contain:

- fabricated Tiny Tapeout silicon;
- an FPGA top level or bitstream for the masked core;
- a ChipWhisperer target firmware or register map;
- a Tiny Tapeout demo-board capture adapter;
- an acquisition trigger validated against an AES operation; or
- power or electromagnetic traces captured from this design.

`capture.py` is a generic CW305 acquisition utility. It assumes an external
AES-compatible CW305 wrapper and bitstream that are not supplied here. The
CW305 native API does not drive the byte-serialized Tiny Tapeout protocol in
`src/masked_aes_round_only.sv`. Running the script against some other AES target
does not validate this project.

## Analysis-tool boundary

| Utility | Current evidence | Limit |
| --- | --- | --- |
| `cpa_attack.py` | Deterministic synthetic leakage test in CI | No measured project trace has been analysed |
| `cpa_attack_masked.py` | Reuses the same first-round Hamming-weight model | Non-recovery under one model is not a masking-security result |
| `tvla_welch.py` | Deterministic synthetic mean-shift and edge-case tests in CI | A threshold non-crossing would apply only to the measured setup and trace set |
| `plot_results.py` and `compare_results.py` | Presentation utilities | Figures are not evidence without trace provenance and reproducible inputs |
| `capture.py` | Source review only | No project-specific target adapter or hardware run |

Synthetic tests establish only that selected numerical code paths behave as
expected on constructed data. They do not model physical leakage and must not
be reported as CPA or TVLA results for the core.

## Evidence package required after hardware exists

Before publishing a silicon or side-channel result, preserve:

1. Device identity, board revision, package, supply, clock, temperature, probe,
   amplifier, scope, sample rate, gain, trigger, and firmware or controller
   revision.
2. Exact RTL commit, GDS artifact, shuttle identifier, test program, protocol,
   key, plaintext class definition, masking and entropy configuration, and
   randomness-reuse rules.
3. Immutable raw traces and inputs with file sizes and SHA-256 hashes. Processed
   arrays and figures must be reproducible from versioned scripts.
4. Per-capture functional ciphertext checks so communication or trigger faults
   cannot silently enter the leakage dataset.
5. Fixed-versus-random methodology, trace counts, exclusions, alignment and
   filtering choices, statistical order, CPA models, and every attempted key
   hypothesis.
6. Results for an unmasked control and the candidate under comparable
   conditions, plus an independent review of the acquisition and analysis.

No-threshold-crossing or key-non-recovery language must identify the exact
device, setup, model, trace count, and confidence limitations. It must not be
presented as universal side-channel resistance or product certification.
