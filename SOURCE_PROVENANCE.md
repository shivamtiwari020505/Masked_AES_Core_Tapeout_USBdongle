# Source Provenance Record

Updated: 2026-07-17

Status: open diligence record. This document identifies known technical
antecedents and missing evidence; it is not a legal clearance or
freedom-to-operate opinion.

## Repository history

The current Git history begins with commit `ec1875b` on 2026-07-14. That commit
introduced the RTL, tests, constraints, scripts, and draft documentation as one
initial import. The commit authors in this repository are name variants tied to
Shivam Tiwari's GitHub account. There are no commits from an unrelated account.

This establishes repository custody, but it does not establish who originated
every algorithmic circuit, equation, or source fragment before the initial
import. No earlier design history, invention notes, contributor assignments, or
third-party clearance records are present.

## Identified technical antecedents

| Material | Repository use | Identified source | Diligence state |
| --- | --- | --- | --- |
| AES-128 algorithm, S-box values, round constants, and known-answer values | Functional RTL and tests | [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) and [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final) | Technical references identified; transcription history should be recorded |
| `y`, `t`, and `z` Boolean equations in `masked_sbox.sv`, `src/masked_sbox.sv`, and `masked_sbox_dom32.sv` | Nonlinear AES S-box network | Joan Boyar and Rene Peralta, [A depth-16 circuit for the AES S-box](https://www.nist.gov/publications/depth-16-circuit-aes-s-box), 2011 | Technical origin identified; permission/licensing analysis is not documented |
| Domain-Oriented Masking terminology | Design inspiration and naming | Hannes Gross, Stefan Mangard, and Thomas Korak, [Domain-Oriented Masking](https://eprint.iacr.org/2016/486), 2016 | Citation identified; current RTL is not claimed to be a conforming or proven implementation |
| Pytest, Cocotb, PyCryptodome, and NumPy | CI, simulation, vector generation, and synthetic analysis tests only | Installed from pinned versions in `test/requirements.txt`; not included in synthesizable RTL | Versions pinned; dependency licence and notice inventory remains a release-packaging action |
| ChipWhisperer and Matplotlib | Optional acquisition and plotting utilities | User-installed; not included in synthesizable RTL or the CI environment | No project capture adapter; versions and dependency notices are not frozen |
| Tiny Tapeout actions and SKY130 PDK | CI hardening, precheck, gate-level test, and viewer | Downloaded by GitHub Actions | Build dependencies, not commercial RTL deliverables; their terms remain separate |

No foundry PDK, standard-cell library, generated gate-level netlist, or customer
confidential material is tracked in the repository.

## Commercial release gate

Before any production licence, warranty, or IP indemnity is offered:

1. Qualified counsel must determine whether the Boyar-Peralta-derived circuit
   can be used and commercially relicensed on the intended terms, or require a
   cleared replacement.
2. Shivam Tiwari must document the origin of each delivered source file and
   preserve design notes, review records, and tool-generated provenance.
3. Every third-party dependency and reference must be listed with its version,
   licence, notice obligations, and whether it is redistributed.
4. Future contributors must sign the contributor agreement described in
   [CONTRIBUTING.md](CONTRIBUTING.md) before code is merged.
5. The commercial source package must contain only cleared material and a
   release-specific bill of materials.

The repository's Apache 2.0 notice grants rights only to material the licensor
has authority to license. It does not resolve rights in an unidentified or
uncleared antecedent.
