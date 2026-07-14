# TVLA TODO For Masked AES

You still need to run a real TVLA before making any production side-channel security claim.

RTL simulation passing is not a TVLA result. A real TVLA needs measured traces from an FPGA prototype, silicon, or a realistic post-layout power simulation.

## When To Do This

Run TVLA after one of these exists:

- FPGA prototype of `masked_aes_core_dom32`
- post-layout gate-level/power simulation with realistic switching and parasitics
- silicon measurement after tapeout

For tapeout confidence, run FPGA or post-layout TVLA before tapeout, then repeat on silicon.

## What To Capture

Use fixed-vs-random first-order TVLA:

- group A: fixed key, fixed plaintext
- group B: same fixed key, random plaintexts
- keep `state_mask`, `rand_data_sbox`, and `rand_key_sbox` fresh for every encryption in both groups
- capture the full encryption power/EM window
- collect at least 5000 fixed traces and 5000 random traces; 20000+ each is better

Do not reuse masks/randomness. Fixed masks invalidate the test.

## File Format

Save traces as CSV matrices:

- one trace per row
- one time sample per column
- two files: `fixed.csv` and `random.csv`

Example:

```text
fixed.csv
0.12,0.15,0.13,...
0.11,0.16,0.14,...

random.csv
0.09,0.20,0.18,...
0.10,0.19,0.17,...
```

## Run

```bash
cd /mnt/c/Masked_AES_Core_Tapeout_USBdongle
python3 tvla_welch.py --fixed fixed.csv --random random.csv --out tvla_results.csv
```

## Interpret

The usual first-order TVLA threshold is:

```text
PASS: max |t| < 4.5
FAIL: max |t| >= 4.5
```

A pass means no first-order leakage was detected in that trace set. It is not a proof of security. Follow up with higher-order TVLA, key-dependent tests, and attack-based evaluation.
