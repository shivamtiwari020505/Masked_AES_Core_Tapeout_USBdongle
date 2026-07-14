## Side-Channel Evaluation

The side-channel evaluation was performed to quantify the first-order leakage
of the AES-128 hardware implementations under a conventional correlation power
analysis (CPA) model. The target platform was a ChipWhisperer CW305 board using
an Artix-7 FPGA implementation of the AES core. Power traces were acquired
during encryption with random plaintexts and a fixed secret key. The same
capture setup, trigger condition, sampling window, and acquisition parameters
were used for both the unmasked reference core and the masked implementation in
order to make the comparison attributable to the countermeasure rather than to
measurement configuration.

The attack model targeted the first SubBytes operation of round one. For each
key byte independently, all 256 key hypotheses were evaluated by computing
SBOX(P_i XOR K_i), where P_i is the observed plaintext byte and K_i is the key
candidate. The predicted leakage for each hypothesis was the Hamming weight of
the S-box output. Pearson correlation was then computed between the predicted
Hamming-weight vector and every sample point of the measured trace set. The
maximum absolute correlation over time was recorded for each key candidate, and
the candidate with the highest correlation was selected as the recovered byte.
This procedure was applied identically to the unmasked and masked trace sets.

The trace count for the experiment was [INSERT TRACE_COUNT]. The unmasked
implementation produced a clear first-order leakage peak for the correct key
hypothesis. The largest observed correlation for the correct unmasked
hypothesis was [INSERT MAX_CORRELATION_UNMASKED], and the key byte under test
was recovered within the acquisition budget. The resulting correlation profile
shows the expected separation between the correct key candidate and the
incorrect candidates, confirming that the unmasked implementation is vulnerable
to standard first-order CPA.

In contrast, the masked implementation did not exhibit a stable first-order
correlation peak under the same leakage model and trace count. The correct key
hypothesis remained statistically indistinguishable from incorrect hypotheses
within the observed correlation envelope. This behavior is consistent with the
intended purpose of Boolean masking: the sensitive S-box intermediate should not
be represented directly by any single first-order power sample. The comparison
is shown in [INSERT FIGURE: side_channel_comparison.png], where the unmasked
core exhibits a visible key-dependent peak while the masked core remains
substantially flatter.

These results should be interpreted as a first-order empirical leakage
assessment, not as a complete certification of side-channel resistance.
Production security claims require larger trace campaigns, multiple operating
conditions, leakage assessment using fixed-versus-random TVLA, evaluation of
higher-order leakage, and review of synthesis and placement constraints that
preserve masking-domain separation. Nevertheless, the experiment establishes
the basic security objective of the countermeasure: the first-order CPA attack
that recovers the unmasked implementation does not recover the masked
implementation under the same acquisition conditions.
