# Masking Implementation Notes

This repository contains two masked implementation families. Neither currently
has a production side-channel-security claim.

## Tiny Tapeout and compatibility implementation

The files masked_sbox.sv and masked_aes_core.sv use an eight-bit external
randomness interface. The S-box deterministically expands those eight bits into
32 internal values. This preserves functional recombination but does not
provide 32 independent fresh random bits. Use this implementation only as a
functional demonstrator.

## 32-bit-randomness candidate

The files `masked_sbox_dom32.sv` and `masked_aes_core_dom32.sv` retain their
historical DOM32 names and expose 32 randomness input bits per S-box. The
key-schedule SubWord is also represented as shares.

For each encryption:

- state_mask must be fresh;
- key0_in must be an independent key share, with key1_in forming the other
  share;
- rand_data_sbox supplies 512 fresh bits for every SUB_BYTES state;
- rand_key_sbox supplies 128 fresh bits for every KEY_SUBWORD state; and
- the interface consumes 6,400 randomness input bits when key expansion is run
  for every encryption.

The simulation assertions detect all-zero buses and direct bus reuse. They do
not prove statistical independence or physical security.

## Security limitation

The randomized nonlinear network is combinational between input and output
registers and combines cross-domain products inside one logic cone. It has not
been accompanied by a probing-model proof, a glitch-aware hardware proof, or an
independent review. The name DOM32 is historical and describes the input width;
it must not be interpreted as a conforming Domain-Oriented Masking construction
or certification.

The underlying `y`/`t`/`z` Boolean equations follow the Boyar-Peralta AES S-box
circuit. See [SOURCE_PROVENANCE.md](SOURCE_PROVENANCE.md) for attribution and
the unresolved commercial clearance action.

## Physical implementation requirements

A security-oriented implementation must preserve share separation through
synthesis and layout, prevent logic sharing between domains, review scan and
test insertion, inspect the gate-level netlist for unintended recombination,
and run timing-annotated simulation. The generic constraints under constraints/
are examples only and must be adapted and signed off for the customer's EDA
flow and process.

See VALIDATION_STATUS.md for measured and missing evidence.
