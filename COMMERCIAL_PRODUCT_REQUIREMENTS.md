# Commercial Product Requirements

Product identifier: `MAES128-IP`

Status: planning baseline for a future commercial release. This is not a
datasheet, offer, security certification, or statement that the requirements
are implemented.

## Product boundary

`MAES128-IP` is intended to be a process-independent, synthesizable
SystemVerilog AES-128 encryption core for integration into a customer's ASIC or
SoC. The base product supplies RTL and integration evidence. It does not include
a TRNG, software driver, bus fabric, foundry PDK, physical implementation,
packaging, production test, or manufactured chips unless a signed statement of
work adds a specific item.

The public Tiny Tapeout wrapper remains a proof vehicle. It is not the
commercial product baseline.

## Required v1 behavior

| Area | v1 requirement | Evidence available today |
| --- | --- | --- |
| Cryptographic function | AES-128 block encryption with internal key expansion | Functional cores pass a small vector corpus; the Tiny Tapeout wrapper still requires external round keys |
| Transaction interface | Technology-neutral request/response handshake with defined backpressure, busy, completion, and error behavior | Not implemented |
| Secret interface | Separately supplied Boolean key shares; shared-state loading rules must prevent an unintended unmasked key signal | DOM32-named candidate accepts key shares; interface review is incomplete |
| Randomness interface | Ready/valid entropy stream, exact per-transaction budget, reuse rules, starvation handling, and health/error indication | Current candidates expose fixed buses without a production handshake |
| Zeroization | Verified clearing of key, state, intermediate shares, and pending transactions on commanded zeroize and defined reset events | Not implemented as a product feature |
| Configuration | AES-128 encryption only in v1; decryption and modes remain separate options | Encryption datapaths exist |
| Portability | Clean synthesis in agreed customer tool versions without PDK material embedded in RTL | SKY130 Tiny Tapeout wrapper hardens; commercial candidate portability is unverified |

## Security requirements

Before security-oriented RTL is frozen, the release must state its protection
order, probing/glitch model, assumptions, entropy model, physical-design rules,
fault scope, and excluded attacks. The masking construction must then be
designed or selected against that model and independently reviewed.

The current `masked_sbox_dom32` name is historical. Its combinational
randomized gadget and 32-bit input do not establish Domain-Oriented Masking or
first-order security. It is a functional experiment and must not become the v1
security baseline without redesign and proof.

Production acceptance requires, at minimum:

- no intentional unmasked key or nonlinear secret intermediate at the defined
  RTL boundary;
- formally checked functional equivalence of share recombination to AES-128;
- documented fresh-randomness consumption with no silent reuse;
- synthesis and layout controls reviewed in the target implementation flow;
- independent masking-architecture review;
- fixed-versus-random leakage testing and attack-based CPA with preserved raw
  data, scripts, setup details, and trace counts; and
- explicit wording that a non-detection result applies only to the measured
  setup and does not prove universal resistance.

## Verification package

A release candidate must include:

1. Reproducible FIPS 197 and SP 800-38A known-answer tests plus a substantially
   broader randomized regression.
2. Formal properties for protocol behavior, zeroization, key/state lifetime,
   output validity, and share recombination.
3. Lint, reset, CDC, synthesis, and customer-tool compatibility reports.
4. Versioned constraints and an integration guide covering clock, reset,
   entropy, DFT/scan, test modes, and physical share-separation assumptions.
5. PPA reports tied to named library, corner, constraints, tool versions, and
   RTL release; no cross-process performance promise may be inferred.
6. Release notes, known limitations, source bill of materials, provenance
   record, and signed verification summary.

NIST algorithm-validation material, leakage data, masking signoff, or a support
SLA may be delivered only after that item actually exists and is named in the
signed agreement.

## Commercial and manufacturing boundary

Evaluation, production, integration/NRE, maintenance, and royalty terms belong
in separate signed agreements. The production agreement must identify the RTL
release, named products and processes, royalty-bearing unit, reporting period,
audit rights, support scope, acceptance criteria, liability limits, and
third-party exclusions.

The customer remains responsible for foundry and design-service access,
physical implementation, masks, wafers, packaging, production test,
qualification, yield, regulatory obligations, inventory, and shipment. A
process-porting engagement may assist the customer without making Shivam Tiwari
the chip manufacturer.

## Release decision

The product is not licensable as production-ready until every requirement above
has objective evidence, the provenance gate in
[SOURCE_PROVENANCE.md](SOURCE_PROVENANCE.md) is closed, and qualified counsel
has approved the commercial agreements and any offered indemnity.
