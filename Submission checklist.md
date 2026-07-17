# TTSKY26c Proof-Artifact Checklist

Submit at: https://tinytapeout.com/runs

Tiny Tapeout app entry point: https://app.tinytapeout.com/

Date checked: 2026-07-17

Current state: preparation only. This repository has not been submitted or
fabricated. A successful GitHub workflow does not register the project for a
shuttle; registration and submission must also be completed in the Tiny
Tapeout app.

## Current Shuttle Deadlines

The Tiny Tapeout chips page currently lists `TTSKY26c` as open. It launched on
2026-05-26 and closes on 2026-09-07, with shuttle code `CI-2609`. Future listed
targets are `TTIHP26b` in Sep 2026, `TTGF26c` in 2026 Q4, and `TTSKY26d` in Dec
2026. Verify these dates on the submission page before paying or submitting,
because shuttle dates can move.

## Required Files

| File | Status | Notes |
| --- | --- | --- |
| `info.yaml` | Done | Unique top module is `tt_um_shivamtiwari020505_masked_aes`; tiles set to `2x2`. |
| `src/masked_aes_round_only.sv` | Done | Tiny Tapeout top-level serialized AES wrapper. |
| `src/masked_sbox.sv` | Done | Masked S-box dependency. |
| `src/config.json` | Done | TTSKY26c configuration with a 50 ns clock period. |
| `.github/workflows/gds.yml` | Done | TTSKY26c GDS, precheck, GL test, and viewer workflow. |
| `.github/workflows/test.yml` | Done | Installs pinned cocotb dependencies and runs the RTL KAT. |
| `.github/workflows/docs.yml` | Done | Builds the Tiny Tapeout datasheet with the TTSKY26c action. |
| `docs/info.md` | Done | Datasheet behavior, test, and hardware notes. |
| `README.md` | Done | Project behavior, protocol, testing, and hardware notes. |
| `test/test.py` | Done | cocotb FIPS AES-128 known-answer test. |
| `test/tb.v` | Done | Tiny Tapeout cocotb wrapper. |
| `test/Makefile` | Done | RTL and gate-level cocotb simulation flow. |
| `test/requirements.txt` | Done | Pinned pytest and cocotb versions. |
| `check_synth.py` | Done | Local Yosys feasibility report script. |

## Local Checks Before Submission

- [ ] Run RTL cocotb simulation:

```sh
cd test
make -B
```

- [ ] Run Yosys feasibility check:

```sh
python3 check_synth.py --top tt_um_shivamtiwari020505_masked_aes --rtl src/masked_sbox.sv src/masked_aes_round_only.sv
```

- [ ] Confirm the report recommends `2x2` or smaller.
- [ ] Commit and push to GitHub.
- [ ] Enable GitHub Actions and GitHub Pages if the repo template requires it.
- [ ] Confirm the TTSKY26c `gds`, `precheck`, `gl_test`, and `viewer` jobs pass
      for the exact revision intended for submission.
- [ ] Confirm the RTL test and datasheet workflows pass for the same revision.
- [ ] Update repository URL/metadata in the Tiny Tapeout app if requested by the target run.
- [ ] Submit through https://tinytapeout.com/runs before the selected shuttle deadline.
- [ ] Record the accepted submission identifier and immutable commit SHA.

## Security Evidence Boundaries

- [ ] Do not claim production side-channel resistance from RTL simulation alone.
- [ ] Use true fresh randomness for S-box issue cycles in hardware tests.
- [ ] Avoid randomness reuse across byte/round evaluations.
- [ ] Review synthesis/layout for domain-preserving implementation.
- [ ] Run TVLA and CPA leakage validation on silicon before making security claims.

These items are validation gates, not completed signoff. See
[Validation Status](VALIDATION_STATUS.md) for the evidence currently available.
