# Tiny Tapeout Submission Checklist

Submit at: https://tinytapeout.com/runs

Tiny Tapeout app entry point: https://app.tinytapeout.com/

Date checked: 2026-07-14

## Current Shuttle Deadlines

The Tiny Tapeout chips page currently lists `TTSKY26c` as open. It launched on
2026-05-26 and closes on 2026-09-07, with shuttle code `CI-2609`. Future listed
targets are `TTIHP26b` in Sep 2026, `TTGF26c` in 2026 Q4, and `TTSKY26d` in Dec
2026. Verify these dates on the submission page before paying or submitting,
because shuttle dates can move.

## Required Files

| File | Status | Notes |
| --- | --- | --- |
| `info.yaml` | Done | Top module is `tt_um_masked_aes_round_only`; tiles set to `2x2`. |
| `src/masked_aes_round_only.sv` | Done | Tiny Tapeout top-level serialized AES wrapper. |
| `src/masked_sbox.sv` | Done | Masked S-box dependency. |
| `config.tcl` | Done | OpenLane settings: 50 ns clock, fanout constraint 8, scan/DFT disabled. |
| `.github/workflows/gds.yml` | Done | TT06-style GDS, precheck, GL test, and viewer workflow. |
| `README.md` | Done | Project behavior, protocol, testing, and hardware notes. |
| `test/test.py` | Done | cocotb FIPS AES-128 known-answer test. |
| `test/tb.v` | Done | Tiny Tapeout cocotb wrapper. |
| `test/Makefile` | Done | RTL and gate-level cocotb simulation flow. |
| `check_synth.py` | Done | Local Yosys feasibility report script. |

## Local Checks Before Submission

- [ ] Run RTL cocotb simulation:

```sh
cd test
make -B
```

- [ ] Run Yosys feasibility check:

```sh
python3 check_synth.py --top tt_um_masked_aes_round_only --rtl src/masked_sbox.sv src/masked_aes_round_only.sv
```

- [ ] Confirm the report recommends `2x2` or smaller.
- [ ] Commit and push to GitHub.
- [ ] Enable GitHub Actions and GitHub Pages if the repo template requires it.
- [ ] Confirm `gds`, `precheck`, `gl_test`, and `viewer` jobs pass.
- [ ] Update repository URL/metadata in the Tiny Tapeout app if requested by the target run.
- [ ] Submit through https://tinytapeout.com/runs before the selected shuttle deadline.

## Security Signoff Items

- [ ] Do not claim production side-channel resistance from RTL simulation alone.
- [ ] Use true fresh randomness for S-box issue cycles in hardware tests.
- [ ] Avoid randomness reuse across byte/round evaluations.
- [ ] Review synthesis/layout for domain-preserving implementation.
- [ ] Run TVLA and CPA leakage validation on silicon before making security claims.
