# Masked AES Security Signoff Notes

This repository now has two masked implementations:

- `masked_sbox.sv` / `masked_aes_core.sv`: compatibility version matching the original requested 8-bit randomness port.
- `masked_sbox_dom32.sv` / `masked_aes_core_dom32.sv`: stronger DOM32 version with 32 fresh random bits per S-box and masked key-schedule SubWord.

Use the DOM32 version for security-oriented work.

## Randomness Contract

For each AES encryption in `masked_aes_core_dom32`:

- `state_mask[127:0]` must be fresh per encryption.
- `key0_in[127:0]` must be an independent key share; `key1_in = key ^ key0_in`.
- `rand_data_sbox[511:0]` must be fresh for each `SUB_BYTES` state, covering 16 bytes x 32 DOM bits.
- `rand_key_sbox[127:0]` must be fresh for each `KEY_SUBWORD` state, covering 4 bytes x 32 DOM bits.
- If key expansion is performed per encryption, the core consumes 6400 DOM randomness bits per encryption: 10 data rounds x 512 bits plus 10 key-schedule SubWord steps x 128 bits.
- Randomness must come from an external TRNG/DRBG/randomness distribution network. LFSR-only values are acceptable for simulation but not for a side-channel security claim.

The `sim_dom32` Makefile target enables `MASKING_ASSERTIONS`, which catches obvious simulation misuse such as all-zero randomness and full-bus reuse across active S-box evaluations. These checks are not proof of independence.

## Synthesis And Layout Constraints

The DOM32 RTL marks the S-box and top-level masked core with `keep_hierarchy` and `dont_touch` attributes, and marks key share/state share registers with `keep` attributes. Preserve these in the synthesis flow.

Required flow rules:

- Do not flatten `masked_sbox_dom32` instances.
- Do not perform logic sharing between share-0 and share-1 cones.
- Do not optimize `state0_q` together with `state1_q`, or `key_words0_q` together with `key_words1_q`.
- Do not insert scan compression or test logic that recombines shares.
- Keep each DOM S-box boundary visible through synthesis and place-and-route.
- Review gate-level netlists for accidental XOR/recombination of shares except at the final `ciphertext_out` assignment.
- Run gate-level simulation with SDF after layout.

The sample TCL in `constraints/masking_preserve.tcl` is intentionally generic and should be adapted to the chosen ASIC/FPGA tools.

## TVLA Validation

A real TVLA requires measured traces or post-layout power traces. Simulation pass/fail alone is not evidence of side-channel security.

See `TVLA_TODO.md` for the short reminder/runbook.

Recommended first-order fixed-vs-random procedure:

1. Program a fixed key and keep the same key shares generation policy used in the real product.
2. Capture at least 5000 fixed-input traces and 5000 random-input traces; more is better.
3. Align traces to the encryption start and trim to the active encryption window.
4. Store traces as CSV matrices: one trace per row, one time sample per column.
5. Run:

```bash
python3 tvla_welch.py --fixed fixed.csv --random random.csv --out tvla_results.csv
```

Use the common first-order threshold `|t| >= 4.5` as a leakage flag. Passing this test is not a complete proof; follow with higher-order TVLA, key-dependent tests, and attack-based evaluation.
