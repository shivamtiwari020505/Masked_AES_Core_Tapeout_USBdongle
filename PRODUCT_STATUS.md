# Product Status

Updated: 2026-07-17

This repository is a public engineering demonstrator, not a production IP
release. Its immediate purpose is to create a real, testable Tiny Tapeout proof
artifact while the commercial core, verification package, and licensing
process are developed separately.

## What exists today

| Track | Files | Verified evidence | Current limit |
| --- | --- | --- | --- |
| Tiny Tapeout proof wrapper | src/masked_sbox.sv and src/masked_aes_round_only.sv | FIPS-197 functional KAT; prior SKY130A GDS, precheck, gate-level test, and viewer jobs passed | Eight external randomness bits are expanded internally; this is not sufficient for a production masking claim |
| Compatibility masked core | masked_sbox.sv and masked_aes_core.sv | 20 AES vectors, five mask trials per vector | Functional masking demonstrator only |
| DOM32 candidate | masked_sbox_dom32.sv and masked_aes_core_dom32.sv | All 256 S-box values recombine correctly; AES-128 FIPS KAT passes | No glitch-aware proof, physical signoff, leakage measurement, or silicon result |

The current Tiny Tapeout configuration targets the TTSKY26c/Sky130A flow. Use
the workflow result for the exact commit being evaluated; an older successful
run is not evidence for a newer revision. The project has not been submitted to
a shuttle, manufactured, or tested in silicon.

## Evidence that is not available

- no ChipWhisperer, CPA, TVLA, or higher-order leakage dataset;
- no post-layout power or electromagnetic assessment;
- no completed masking-security proof or independent review;
- no production PPA report for a customer process;
- no DFT, scan, ATPG, fault-injection, reliability, or qualification package;
- no NIST algorithm-validation certificate;
- no completed source-provenance and freedom-to-operate review; and
- no executed commercial licence, support SLA, or indemnity policy.

## Commercial release gates

A licensable release needs all of the following before it is represented as
production-ready:

1. Confirm authorship and provenance for every delivered source file and
   document any third-party material.
2. Freeze the product specification: complete AES function, key handling,
   interfaces, latency, throughput, error behavior, and randomness contract.
3. Run lint, CDC/reset analysis, broad randomized regression, formal functional
   equivalence, and customer-tool compatibility checks.
4. Replace the demonstration masking network with an implementation supported
   by a stated security model and independent review.
5. Complete FPGA or post-layout leakage work before tapeout, followed by
   measured bring-up and leakage testing on the fabricated proof device.
6. Produce versioned RTL, integration guide, verification evidence, PPA data,
   release notes, known limitations, and reproducible build scripts.
7. Have qualified counsel prepare the evaluation and production licence,
   royalty reporting, audit, support, warranty, and indemnity terms.

## Manufacturing boundary

Shivam Tiwari's intended role is IP designer and licensor. A production
licensee remains responsible for its SoC, target PDK and EDA flow, physical
implementation, foundry and design-service contracts, masks, wafers, packaging,
test, qualification, regulatory obligations, yield, inventory, and shipment.

A Tiny Tapeout device can demonstrate that the public wrapper functions in one
SKY130 implementation. It does not establish PPA, yield, qualification, or
side-channel performance for a TSMC or GlobalFoundries production process.
